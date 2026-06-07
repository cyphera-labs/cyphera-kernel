use alloc::string::{String, ToString};
use alloc::sync::Arc;

use crate::errno::{
    EACCES, EBADF, EFAULT, EINTR, EINVAL, EISDIR, EMFILE, ENAMETOOLONG, ENOENT, ENOSYS, ENOTDIR,
    EPERM, ERANGE,
};
use crate::sched;
use crate::vfs::{self, Inode, InodeKind, OpenFile, OpenFlags, Stat, TimeSpec, Whence};

use super::util::{read_timespec, read_user_cstr};
use super::{AT_FDCWD, PATH_MAX};

const AT_REMOVEDIR: u64 = 0x200;

pub(super) const WRITE_BUF_MAX: usize = 1024 * 1024;
pub(super) const READ_BUF_MAX: usize = 256 * 1024;
const DIRENT_BUF_MAX: usize = 4096;
const GETCWD_BUF_MAX: usize = 4096;
const STAT_SIZE: usize = 144;

pub(super) fn sys_write(fd: u64, buf: u64, count: u64) -> i64 {
    if count == 0 {
        return 0;
    }
    let n = (count as usize).min(WRITE_BUF_MAX);
    let mut buffer = alloc::vec![0u8; n];
    if frame::user::copy_from_user(buf, &mut buffer).is_err() {
        return EFAULT;
    }
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    match file.write(&buffer) {
        Ok(w) => w as i64,
        Err(e) => write_err_to_errno(e),
    }
}

fn write_err_to_errno(e: crate::vfs::FsError) -> i64 {
    if matches!(e, crate::vfs::FsError::BrokenPipe) {
        const SIGPIPE: u32 = 13;
        let pid = sched::current_pid();
        let info = crate::signal::SigInfo::for_fault(SIGPIPE, 0);
        let _ = sched::send_signal_with_info(pid, SIGPIPE, info);
    }
    e.errno()
}

pub(super) fn sys_read(fd: u64, buf: u64, count: u64) -> i64 {
    if count == 0 {
        return 0;
    }
    let n = (count as usize).min(READ_BUF_MAX);
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let mut tmp = alloc::vec![0u8; n];
    let read = match file.read(&mut tmp) {
        Ok(r) => r,
        Err(e) => return e.errno(),
    };
    if read > 0 && frame::user::copy_to_user(buf, &tmp[..read]).is_err() {
        return EFAULT;
    }
    read as i64
}

pub(super) fn sys_close(fd: u64) -> i64 {
    let removed = sched::with_current_fds(|t| t.remove(fd as i32));
    let of = match removed {
        Some(of) => of,
        None => return EBADF,
    };
    if !of.flags().contains(vfs::OpenFlags::PATH) {
        let inode_id = of.inode.inode_id();
        crate::vfs::locks::posix::drop_owner_inode(sched::current_pid(), inode_id);
    }
    0
}

pub(super) fn sys_lseek(fd: u64, offset: u64, whence: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let w = match whence {
        0 => Whence::Set,
        1 => Whence::Cur,
        2 => Whence::End,
        _ => return EINVAL,
    };
    match file.seek(w, offset as i64) {
        Ok(p) => p as i64,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_openat(dirfd: u64, pathname: u64, flags: u64, mode: u64) -> i64 {
    let mut path_buf = [0u8; PATH_MAX];
    let len = match frame::user::copy_cstr_from_user(pathname, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let path = match core::str::from_utf8(&path_buf[..len]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    if !path.starts_with('/') && (dirfd as i64) != AT_FDCWD {
        if path.is_empty() {
            return ENOENT;
        }
        let dir_file = match sched::with_current_fds(|t| t.get(dirfd as i32)) {
            Some(f) => f,
            None => return EBADF,
        };
        if dir_file.inode.kind() != InodeKind::Directory {
            return -20;
        }
        let ctx = vfs::path::Context::current();
        let open_flags = OpenFlags::from_bits_truncate(flags as u32);
        let (inode, mount_tag) = match vfs::path::resolve_with_mount(&ctx, &dir_file.inode, path) {
            Ok(pair) => pair,
            Err(vfs::FsError::NotFound) if open_flags.contains(OpenFlags::CREAT) => {
                match vfs::path::resolve_parent(&ctx, &dir_file.inode, path) {
                    Ok((parent, leaf)) => match parent.create(leaf, InodeKind::Regular) {
                        Ok(i) => {
                            apply_create_owner(&i);
                            apply_create_mode(&i, mode as u16);
                            let mount_tag =
                                vfs::path::resolve_with_mount(&ctx, &dir_file.inode, path)
                                    .ok()
                                    .and_then(|(_, t)| t);
                            (i, mount_tag)
                        }
                        Err(e) => return e.errno(),
                    },
                    Err(e) => return e.errno(),
                }
            }
            Err(e) => return e.errno(),
        };
        if open_flags.contains(OpenFlags::TRUNC) && open_flags.is_writable() {
            let _ = inode.truncate(0);
        }
        let mount_guard = mount_tag.map(vfs::MountInUseGuard::new);
        let file = Arc::new(OpenFile::new_with_mount(inode, open_flags, mount_guard));
        return match sched::with_current_fds(|t| t.install(file)) {
            Ok(fd) => fd as i64,
            Err(_) => EMFILE,
        };
    }

    let normalized = match resolve_user_path(dirfd as i64, path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    if normalized == "/dev/ptmx" {
        let pty = crate::pty::allocate_pair();
        let master: Arc<dyn vfs::Inode> = Arc::new(crate::pty::MasterInode(pty));
        let open_flags = OpenFlags::from_bits_truncate(flags as u32);
        let file = Arc::new(vfs::OpenFile::new(master, open_flags));
        return match sched::with_current_fds(|t| t.install(file)) {
            Ok(fd) => fd as i64,
            Err(e) => e as i64,
        };
    }
    if let Some(rest) = normalized.strip_prefix("/dev/pts/") {
        if let Ok(n) = rest.parse::<u32>() {
            if let Some(pty) = crate::pty::lookup(n) {
                let slave: Arc<dyn vfs::Inode> = Arc::new(crate::pty::SlaveInode(pty));
                let open_flags = OpenFlags::from_bits_truncate(flags as u32);
                let file = Arc::new(vfs::OpenFile::new(slave, open_flags));
                return match sched::with_current_fds(|t| t.install(file)) {
                    Ok(fd) => fd as i64,
                    Err(e) => e as i64,
                };
            }
        }
    }

    let open_flags = OpenFlags::from_bits_truncate(flags as u32);
    let ctx = vfs::path::Context::current();
    let (inode, mount_tag, created) =
        match vfs::path::resolve_with_mount(&ctx, &ctx.root, &normalized) {
            Ok((i, t)) => (i, t, false),
            Err(vfs::FsError::NotFound) if open_flags.contains(OpenFlags::CREAT) => {
                let (parent, leaf) = match vfs::path::resolve_parent(&ctx, &ctx.root, &normalized) {
                    Ok(p) => p,
                    Err(e) => return e.errno(),
                };
                match parent.create(leaf, InodeKind::Regular) {
                    Ok(i) => {
                        apply_create_owner(&i);
                        apply_create_mode(&i, mode as u16);
                        let mount_tag = vfs::path::resolve_with_mount(&ctx, &ctx.root, &normalized)
                            .ok()
                            .and_then(|(_, t)| t);
                        (i, mount_tag, true)
                    }
                    Err(e) => return e.errno(),
                }
            }
            Err(e) => return e.errno(),
        };

    if !created {
        let st = inode.stat();
        let mut mode_req: u8 = 0;
        if open_flags.is_readable() {
            mode_req |= 0o4;
        }
        if open_flags.is_writable() {
            mode_req |= 0o2;
        }
        if mode_req != 0 {
            let allowed =
                sched::with_current_creds(|c| c.can_access(st.uid, st.gid, st.mode, mode_req));
            if !allowed {
                return -13;
            }
        }
    }

    if open_flags.contains(OpenFlags::TRUNC) && open_flags.is_writable() {
        let _ = inode.truncate(0);
    }

    let mount_guard = mount_tag.map(vfs::MountInUseGuard::new);
    let file = Arc::new(OpenFile::new_with_mount(inode, open_flags, mount_guard));
    match sched::with_current_fds(|t| t.install(file)) {
        Ok(fd) => fd as i64,
        Err(_) => EMFILE,
    }
}

pub(crate) fn resolve_user_path(dirfd: i64, path: &str) -> Result<String, i64> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    if path.starts_with('/') {
        return Ok(vfs::path::normalize("/", path));
    }
    if dirfd != AT_FDCWD {
        return Err(ENOSYS);
    }
    let cwd_path = sched::with_current_cwd(|c| c.path.clone()).unwrap_or_else(|| String::from("/"));
    Ok(vfs::path::normalize(&cwd_path, path))
}

#[allow(dead_code)]
fn resolve_at_inode(dirfd: i64, path: &str) -> Result<Arc<dyn Inode>, i64> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    let ctx = vfs::path::Context::current();
    if path.starts_with('/') {
        return vfs::path::resolve(&ctx, &ctx.root, path).map_err(|e| e.errno());
    }
    let start = if dirfd == AT_FDCWD {
        sched::with_current_cwd(|c| c.inode.clone()).unwrap_or_else(|| ctx.root.clone())
    } else {
        let f = sched::with_current_fds(|t| t.get(dirfd as i32)).ok_or(EBADF)?;
        if f.inode.kind() != InodeKind::Directory {
            return Err(-20);
        }
        f.inode.clone()
    };
    vfs::path::resolve(&ctx, &start, path).map_err(|e| e.errno())
}

fn resolve_at_parent(
    dirfd: i64,
    path: &str,
) -> Result<(Arc<dyn Inode>, alloc::string::String), i64> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    let ctx = vfs::path::Context::current();
    let (start_inode, search_path): (Arc<dyn Inode>, &str) = if path.starts_with('/') {
        (ctx.root.clone(), path)
    } else if dirfd == AT_FDCWD {
        let cwd = sched::with_current_cwd(|c| c.inode.clone()).unwrap_or_else(|| ctx.root.clone());
        (cwd, path)
    } else {
        let f = sched::with_current_fds(|t| t.get(dirfd as i32)).ok_or(EBADF)?;
        if f.inode.kind() != InodeKind::Directory {
            return Err(-20);
        }
        (f.inode.clone(), path)
    };
    let (parent, leaf) =
        vfs::path::resolve_parent(&ctx, &start_inode, search_path).map_err(|e| e.errno())?;
    Ok((parent, leaf.to_string()))
}

pub(super) fn sys_chdir(pathname: u64) -> i64 {
    let mut path_buf = [0u8; PATH_MAX];
    let len = match frame::user::copy_cstr_from_user(pathname, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let target = match core::str::from_utf8(&path_buf[..len]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    if target.is_empty() {
        return ENOENT;
    }
    let cwd_path = sched::with_current_cwd(|c| c.path.clone()).unwrap_or_else(|| String::from("/"));
    let normalized = vfs::path::normalize(&cwd_path, target);
    let ctx = vfs::path::Context::current();
    let inode = match vfs::path::resolve(&ctx, &ctx.root, &normalized) {
        Ok(i) => i,
        Err(e) => return e.errno(),
    };
    if inode.kind() != InodeKind::Directory {
        return ENOTDIR;
    }
    sched::set_current_cwd(inode, normalized);
    0
}

pub(super) fn sys_getcwd(buf: u64, size: u64) -> i64 {
    let path = match sched::with_current_cwd(|c| c.path.clone()) {
        Some(p) => p,
        None => return EFAULT,
    };
    let bytes = path.as_bytes();
    let needed = bytes.len() + 1;
    if (size as usize) < needed {
        return ERANGE;
    }
    if needed > GETCWD_BUF_MAX {
        return ENAMETOOLONG;
    }
    let mut tmp = [0u8; GETCWD_BUF_MAX];
    tmp[..bytes.len()].copy_from_slice(bytes);
    tmp[bytes.len()] = 0;
    if frame::user::copy_to_user(buf, &tmp[..needed]).is_err() {
        return EFAULT;
    }
    needed as i64
}

pub(super) fn sys_fstat(fd: u64, statbuf: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let stat = build_stat(&file.inode);
    if frame::user::copy_to_user(statbuf, &stat).is_err() {
        return EFAULT;
    }
    0
}

const AT_EMPTY_PATH: u64 = 0x1000;

pub(super) fn sys_newfstatat(dirfd: u64, pathname: u64, statbuf: u64, flags: u64) -> i64 {
    let mut path_buf = [0u8; PATH_MAX];
    let len = match frame::user::copy_cstr_from_user(pathname, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let path = match core::str::from_utf8(&path_buf[..len]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    if path.is_empty() && (flags & AT_EMPTY_PATH) != 0 {
        let fd = dirfd as i64;
        let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
            Some(f) => f,
            None => return EBADF,
        };
        let stat = build_stat(&file.inode);
        if frame::user::copy_to_user(statbuf, &stat).is_err() {
            return EFAULT;
        }
        return 0;
    }

    let normalized = match resolve_user_path(dirfd as i64, path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let ctx = vfs::path::Context::current();
    let inode = match vfs::path::resolve(&ctx, &ctx.root, &normalized) {
        Ok(i) => i,
        Err(e) => return e.errno(),
    };
    let stat = build_stat(&inode);
    if frame::user::copy_to_user(statbuf, &stat).is_err() {
        return EFAULT;
    }
    0
}

fn build_stat(inode: &Arc<dyn Inode>) -> [u8; STAT_SIZE] {
    let st = inode.stat();
    pack_stat(&st)
}

fn pack_stat(st: &Stat) -> [u8; STAT_SIZE] {
    const S_IFREG: u32 = 0o100_000;
    const S_IFDIR: u32 = 0o040_000;
    const S_IFCHR: u32 = 0o020_000;
    const S_IFLNK: u32 = 0o120_000;
    const S_IFIFO: u32 = 0o010_000;

    let kind_bits = match st.kind {
        InodeKind::Regular => S_IFREG,
        InodeKind::Directory => S_IFDIR,
        InodeKind::CharDevice => S_IFCHR,
        InodeKind::Symlink => S_IFLNK,
        InodeKind::Pipe => S_IFIFO,
    };
    let mode = kind_bits | st.mode as u32;

    let mut buf = [0u8; STAT_SIZE];
    buf[0..8].copy_from_slice(&st.dev_id.to_le_bytes());
    buf[8..16].copy_from_slice(&st.inode_id.to_le_bytes());
    buf[16..24].copy_from_slice(&(st.nlink as u64).to_le_bytes());
    buf[24..28].copy_from_slice(&mode.to_le_bytes());
    let (vis_uid, vis_gid) = crate::sched::with_current_creds(|c| {
        (c.uid_from_kernel(st.uid), c.gid_from_kernel(st.gid))
    });
    buf[28..32].copy_from_slice(&vis_uid.to_le_bytes());
    buf[32..36].copy_from_slice(&vis_gid.to_le_bytes());
    buf[48..56].copy_from_slice(&st.size.to_le_bytes());
    buf[56..64].copy_from_slice(&(st.blksize as i64).to_le_bytes());
    buf[64..72].copy_from_slice(&(st.blocks as i64).to_le_bytes());
    buf[72..80].copy_from_slice(&st.atime.sec.to_le_bytes());
    buf[80..88].copy_from_slice(&(st.atime.nsec as i64).to_le_bytes());
    buf[88..96].copy_from_slice(&st.mtime.sec.to_le_bytes());
    buf[96..104].copy_from_slice(&(st.mtime.nsec as i64).to_le_bytes());
    buf[104..112].copy_from_slice(&st.ctime.sec.to_le_bytes());
    buf[112..120].copy_from_slice(&(st.ctime.nsec as i64).to_le_bytes());
    buf
}

pub(super) fn sys_getdents(fd: u64, dirp: u64, count: u64) -> i64 {
    let count = count as usize;
    if count < 24 {
        return EINVAL;
    }
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if file.inode.kind() != InodeKind::Directory {
        return ENOTDIR;
    }
    let entries = match file.inode.list() {
        Ok(e) => e,
        Err(e) => return e.errno(),
    };

    let mut out = [0u8; DIRENT_BUF_MAX];
    let cap = count.min(out.len());
    let mut written = 0usize;
    let mut idx = *file.offset.lock() as usize;

    while idx < entries.len() {
        let entry = &entries[idx];
        let name = entry.name.as_bytes();
        let raw = 8 + 8 + 2 + name.len() + 1 + 1 + 1;
        let reclen = (raw + 7) & !7;
        if written + reclen > cap {
            break;
        }
        let d_off = (idx + 1) as u64;
        let d_type: u8 = match entry.kind {
            InodeKind::Regular => 8,
            InodeKind::Directory => 4,
            InodeKind::CharDevice => 2,
            InodeKind::Symlink => 10,
            InodeKind::Pipe => 1,
        };
        let p = written;
        out[p..p + 8].copy_from_slice(&entry.inode_id.to_le_bytes());
        out[p + 8..p + 16].copy_from_slice(&d_off.to_le_bytes());
        out[p + 16..p + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
        out[p + 18..p + 18 + name.len()].copy_from_slice(name);
        out[p + 18 + name.len()] = 0;
        out[p + reclen - 1] = d_type;

        written += reclen;
        idx += 1;
    }
    if written == 0 && idx < entries.len() {
        return EINVAL;
    }
    if written > 0 && frame::user::copy_to_user(dirp, &out[..written]).is_err() {
        return EFAULT;
    }
    *file.offset.lock() = idx as u64;
    written as i64
}

pub(super) fn sys_getdents64(fd: u64, dirp: u64, count: u64) -> i64 {
    let count = count as usize;
    if count < 24 {
        return EINVAL;
    }
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if file.inode.kind() != InodeKind::Directory {
        return ENOTDIR;
    }
    let entries = match file.inode.list() {
        Ok(e) => e,
        Err(e) => return e.errno(),
    };

    let mut out = [0u8; DIRENT_BUF_MAX];
    let cap = count.min(out.len());
    let mut written = 0usize;
    let mut idx = *file.offset.lock() as usize;

    while idx < entries.len() {
        let entry = &entries[idx];
        let name = entry.name.as_bytes();
        let raw = 8 + 8 + 2 + 1 + name.len() + 1;
        let reclen = (raw + 7) & !7;
        if written + reclen > cap {
            break;
        }
        let d_off = (idx + 1) as u64;
        let d_type: u8 = match entry.kind {
            InodeKind::Regular => 8,
            InodeKind::Directory => 4,
            InodeKind::CharDevice => 2,
            InodeKind::Symlink => 10,
            InodeKind::Pipe => 1,
        };

        let p = written;
        out[p..p + 8].copy_from_slice(&entry.inode_id.to_le_bytes());
        out[p + 8..p + 16].copy_from_slice(&d_off.to_le_bytes());
        out[p + 16..p + 18].copy_from_slice(&(reclen as u16).to_le_bytes());
        out[p + 18] = d_type;
        out[p + 19..p + 19 + name.len()].copy_from_slice(name);
        out[p + 19 + name.len()] = 0;

        written += reclen;
        idx += 1;
    }

    if written == 0 && idx < entries.len() {
        return EINVAL;
    }
    if written > 0 && frame::user::copy_to_user(dirp, &out[..written]).is_err() {
        return EFAULT;
    }
    *file.offset.lock() = idx as u64;
    written as i64
}

pub(super) fn sys_dup(fd: u64) -> i64 {
    sched::with_current_fds(|t| match t.get(fd as i32) {
        Some(of) => t.install(of).unwrap_or(EMFILE as i32) as i64,
        None => EBADF,
    })
}

pub(super) fn sys_dup2(oldfd: u64, newfd: u64) -> i64 {
    sched::with_current_fds(|t| match t.dup_to(oldfd as i32, newfd as i32, 0) {
        Ok(fd) => fd as i64,
        Err(e) => e as i64,
    })
}

pub(super) fn sys_dup3(oldfd: u64, newfd: u64, flags: u64) -> i64 {
    if oldfd == newfd {
        return EINVAL;
    }
    let cloexec = if (flags & 0o2_000_000) != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    sched::with_current_fds(|t| match t.dup_to(oldfd as i32, newfd as i32, cloexec) {
        Ok(fd) => fd as i64,
        Err(e) => e as i64,
    })
}

const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;
const F_GET_SEALS: u64 = 1034;
const F_ADD_SEALS: u64 = 1033;
const F_GETLK: u64 = 5;
const F_OFD_GETLK: u64 = 36;
const F_OFD_SETLK: u64 = 37;
const F_OFD_SETLKW: u64 = 38;
const F_SETLK: u64 = 6;
const F_SETLKW: u64 = 7;

pub(super) fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    let fd = fd as i32;
    sched::with_current_fds(|t| match cmd {
        F_DUPFD => match t.get(fd) {
            Some(of) => t.install_from(of, arg as i32, 0).unwrap_or(EMFILE as i32) as i64,
            None => EBADF,
        },
        F_DUPFD_CLOEXEC => match t.get(fd) {
            Some(of) => t
                .install_from(of, arg as i32, vfs::fd::FD_CLOEXEC)
                .unwrap_or(EMFILE as i32) as i64,
            None => EBADF,
        },
        F_GETFD => match t.fd_flags(fd) {
            Some(flags) => flags as i64,
            None => EBADF,
        },
        F_SETFD => match t.set_fd_flags(fd, (arg as u8) & vfs::fd::FD_CLOEXEC) {
            Ok(()) => 0,
            Err(e) => e as i64,
        },
        F_GETFL => match t.get(fd) {
            Some(of) => of.flags().bits() as i64,
            None => EBADF,
        },
        F_SETFL => match t.get(fd) {
            Some(of) => {
                let new = vfs::OpenFlags::from_bits_truncate(arg as u32);
                of.set_flags_subset(new);
                0
            }
            None => EBADF,
        },
        F_GET_SEALS => 0xf,
        F_ADD_SEALS => 0,
        F_GETLK | F_SETLK | F_SETLKW => {
            let file = match t.get(fd) {
                Some(f) => f,
                None => return EBADF,
            };
            let inode_id = file.inode.inode_id();
            let cur_offset = *file.offset.lock();
            let file_size = file.inode.stat().size;
            drop_with_current_fds_then_lock_inner(
                cmd,
                inode_id,
                arg,
                Some(cur_offset),
                Some(file_size),
            )
        }
        F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            let file = match t.get(fd) {
                Some(f) => f,
                None => return EBADF,
            };
            let inode_id = file.inode.inode_id();
            let cur_offset = *file.offset.lock();
            let file_size = file.inode.stat().size;
            let mapped = match cmd {
                F_OFD_GETLK => F_GETLK,
                F_OFD_SETLK => F_SETLK,
                F_OFD_SETLKW => F_SETLKW,
                _ => unreachable!(),
            };
            drop_with_current_fds_then_lock_inner(
                mapped,
                inode_id,
                arg,
                Some(cur_offset),
                Some(file_size),
            )
        }
        _ => EINVAL,
    })
}

fn drop_with_current_fds_then_lock_inner(
    cmd: u64,
    inode_id: u64,
    arg: u64,
    cur_offset: Option<u64>,
    file_size: Option<u64>,
) -> i64 {
    use crate::vfs::locks::posix::{
        F_RDLCK, F_UNLCK, F_WRLCK, find_conflict, try_set_lock, waiters_for,
    };

    let mut flock_buf = [0u8; 32];
    if frame::user::copy_from_user(arg, &mut flock_buf).is_err() {
        return EFAULT;
    }
    let l_type = i16::from_le_bytes(flock_buf[0..2].try_into().unwrap()) as u16;
    let l_whence = i16::from_le_bytes(flock_buf[2..4].try_into().unwrap()) as u16;
    let l_start = i64::from_le_bytes(flock_buf[8..16].try_into().unwrap());
    let l_len = i64::from_le_bytes(flock_buf[16..24].try_into().unwrap());

    let base = match l_whence {
        0 => 0i64,
        1 => cur_offset.map(|o| o as i64).unwrap_or(0),
        2 => file_size.map(|s| s as i64).unwrap_or(0),
        _ => return EINVAL,
    };
    let resolved_start = base.saturating_add(l_start);
    if resolved_start < 0 {
        return EINVAL;
    }
    let start = resolved_start as u64;
    let end = if l_len == 0 {
        u64::MAX
    } else if l_len < 0 {
        return EINVAL;
    } else {
        match start.checked_add(l_len as u64) {
            Some(e) => e,
            None => return EINVAL,
        }
    };
    let owner = sched::current_pid();

    if cmd == F_GETLK {
        match find_conflict(inode_id, l_type, start, end, owner) {
            Some(conf) => {
                flock_buf[0..2].copy_from_slice(&(conf.kind as i16).to_le_bytes());
                flock_buf[2..4].copy_from_slice(&0i16.to_le_bytes());
                flock_buf[8..16].copy_from_slice(&(conf.start as i64).to_le_bytes());
                let len_field = if conf.end == u64::MAX {
                    0i64
                } else {
                    (conf.end - conf.start) as i64
                };
                flock_buf[16..24].copy_from_slice(&len_field.to_le_bytes());
                flock_buf[24..28].copy_from_slice(&(conf.owner.raw() as i32).to_le_bytes());
            }
            None => {
                flock_buf[0..2].copy_from_slice(&(F_UNLCK as i16).to_le_bytes());
            }
        }
        if frame::user::copy_to_user(arg, &flock_buf).is_err() {
            return EFAULT;
        }
        return 0;
    }

    if l_type != F_RDLCK && l_type != F_WRLCK && l_type != F_UNLCK {
        return EINVAL;
    }

    if cmd == F_SETLK {
        return match try_set_lock(inode_id, l_type, start, end, owner) {
            Ok(()) => 0,
            Err(_) => -11,
        };
    }

    let waiters = waiters_for(inode_id);
    loop {
        match try_set_lock(inode_id, l_type, start, end, owner) {
            Ok(()) => return 0,
            Err(_) => {
                waiters.park();
                if sched::current_signal_pending() {
                    return EINTR;
                }
            }
        }
    }
}

pub(super) fn sys_pread64(fd: u64, buf: u64, count: u64, offset: u64) -> i64 {
    if count == 0 {
        return 0;
    }
    let n = (count as usize).min(READ_BUF_MAX);
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if !file.flags().is_readable() {
        return -9;
    }
    let mut tmp = alloc::vec![0u8; n];
    let read = match file.inode.read_at(offset, &mut tmp) {
        Ok(r) => r,
        Err(e) => return e.errno(),
    };
    if read > 0 && frame::user::copy_to_user(buf, &tmp[..read]).is_err() {
        return EFAULT;
    }
    read as i64
}

pub(super) fn sys_pwrite64(fd: u64, buf: u64, count: u64, offset: u64) -> i64 {
    if count == 0 {
        return 0;
    }
    let n = (count as usize).min(WRITE_BUF_MAX);
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if !file.flags().is_writable() {
        return -9;
    }
    let mut buffer = alloc::vec![0u8; n];
    if frame::user::copy_from_user(buf, &mut buffer).is_err() {
        return EFAULT;
    }
    match file.inode.write_at(offset, &buffer) {
        Ok(w) => w as i64,
        Err(e) => write_err_to_errno(e),
    }
}

const IOV_MAX: usize = 16;

fn read_iovecs(iov: u64, count: u64) -> Result<alloc::vec::Vec<(u64, usize)>, i64> {
    if count > IOV_MAX as u64 {
        return Err(EINVAL);
    }
    let mut raw = [0u8; IOV_MAX * 16];
    let bytes = (count as usize) * 16;
    if frame::user::copy_from_user(iov, &mut raw[..bytes]).is_err() {
        return Err(EFAULT);
    }
    let mut out = alloc::vec::Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let off = i * 16;
        let base = u64::from_le_bytes(raw[off..off + 8].try_into().unwrap());
        let len = u64::from_le_bytes(raw[off + 8..off + 16].try_into().unwrap()) as usize;
        out.push((base, len));
    }
    Ok(out)
}

pub(super) fn sys_readv(fd: u64, iov: u64, iovcnt: u64) -> i64 {
    let vecs = match read_iovecs(iov, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut total: i64 = 0;
    for (base, len) in vecs {
        if len == 0 {
            continue;
        }
        let r = sys_read(fd, base, len as u64);
        if r < 0 {
            return if total == 0 { r } else { total };
        }
        total += r;
        if (r as usize) < len {
            break;
        }
    }
    total
}

pub(super) fn sys_writev(fd: u64, iov: u64, iovcnt: u64) -> i64 {
    let vecs = match read_iovecs(iov, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut total: i64 = 0;
    for (base, len) in vecs {
        if len == 0 {
            continue;
        }
        let r = sys_write(fd, base, len as u64);
        if r < 0 {
            return if total == 0 { r } else { total };
        }
        total += r;
        if (r as usize) < len {
            break;
        }
    }
    total
}

const TIOCGWINSZ: u64 = 0x5413;
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TIOCSCTTY: u64 = 0x540E;

static FG_PGRP: frame::sync::SpinIrq<(u32, u32)> = frame::sync::SpinIrq::new((0, 0));

pub fn console_fg_pgrp() -> u32 {
    FG_PGRP.lock().1
}
const TIOCGPTN: u64 = 0x80045430;
const TIOCSPTLCK: u64 = 0x40045431;
const FBIOGET_VSCREENINFO: u64 = 0x4600;
const FBIOPUT_VSCREENINFO: u64 = 0x4601;
const FBIOGET_FSCREENINFO: u64 = 0x4602;
const KDGKBTYPE: u64 = 0x4B33;
const KDGKBMODE: u64 = 0x4B44;
const KDSKBMODE: u64 = 0x4B45;
const KDGETLED: u64 = 0x4B31;
const KDSETLED: u64 = 0x4B32;
const KB_101: u8 = 0x02;

const SNDCTL_DSP_RESET: u64 = 0x0000_5000;
const SNDCTL_DSP_SYNC: u64 = 0x0000_5001;
const SNDCTL_DSP_SPEED: u64 = 0xC004_5002;
const SNDCTL_DSP_STEREO: u64 = 0xC004_5003;
const SNDCTL_DSP_GETBLKSIZE: u64 = 0xC004_5004;
const SNDCTL_DSP_SETFMT: u64 = 0xC004_5005;
const SNDCTL_DSP_CHANNELS: u64 = 0xC004_5006;
const SNDCTL_DSP_GETFMTS: u64 = 0x8004_500B;
const SNDCTL_DSP_GETOSPACE: u64 = 0x8010_500C;
const SNDCTL_DSP_SETFRAGMENT: u64 = 0xC004_500A;

use crate::errno::ENOTTY;

pub(crate) const DEFAULT_TERMIOS: [u8; 36] = {
    let mut t = [0u8; 36];
    t[0] = 0x00;
    t[1] = 0x05;
    t[2] = 0x00;
    t[3] = 0x00;
    t[4] = 0x05;
    t[5] = 0x00;
    t[6] = 0x00;
    t[7] = 0x00;
    t[8] = 0xbd;
    t[9] = 0x0b;
    t[10] = 0x00;
    t[11] = 0x00;
    t[12] = 0x8b;
    t[13] = 0x00;
    t[14] = 0x00;
    t[15] = 0x00;
    t
};

static TERMIOS_STATE: frame::sync::SpinIrq<alloc::collections::BTreeMap<u64, [u8; 36]>> =
    frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new());

fn termios_get(inode_id: u64) -> [u8; 36] {
    TERMIOS_STATE
        .lock()
        .get(&inode_id)
        .copied()
        .unwrap_or(DEFAULT_TERMIOS)
}

fn termios_set(inode_id: u64, t: [u8; 36]) {
    TERMIOS_STATE.lock().insert(inode_id, t);
}

pub fn termios_get_pub(inode_id: u64) -> [u8; 36] {
    termios_get(inode_id)
}

pub(super) fn sys_ioctl(fd: u64, cmd: u64, arg: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let is_tty = file.inode.kind() == InodeKind::CharDevice;
    let cmd = cmd & 0xFFFF_FFFF;
    match cmd {
        TIOCGWINSZ => {
            if !is_tty {
                return ENOTTY;
            }
            let buf: [u8; 8] = [24, 0, 80, 0, 0, 0, 0, 0];
            if frame::user::copy_to_user(arg, &buf).is_err() {
                return EFAULT;
            }
            0
        }
        TCGETS => {
            if !is_tty {
                return ENOTTY;
            }
            let t = termios_get(file.inode.inode_id());
            if frame::user::copy_to_user(arg, &t).is_err() {
                return EFAULT;
            }
            0
        }
        TCSETS | TCSETSW | TCSETSF => {
            if !is_tty {
                return ENOTTY;
            }
            let mut buf = [0u8; 36];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            termios_set(file.inode.inode_id(), buf);
            0
        }
        TIOCGPGRP => {
            if !is_tty {
                return ENOTTY;
            }
            let my_sid = sched::current_sid().raw();
            let my_pgid_host = sched::current_pgid();
            let (sid, fg_host) = *FG_PGRP.lock();
            let host_pgid = if fg_host != 0 && sid == my_sid {
                crate::process::Pid(fg_host)
            } else {
                my_pgid_host
            };
            let pgid = sched::host_to_caller_local(host_pgid);
            if frame::user::copy_to_user(arg, &pgid.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        TIOCSPGRP => {
            if !is_tty {
                return ENOTTY;
            }
            let mut buf = [0u8; 4];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            let pgrp_local = u32::from_le_bytes(buf);
            let pgrp_host = sched::caller_local_to_host(pgrp_local)
                .map(|p| p.0)
                .unwrap_or(pgrp_local);
            let my_sid = sched::current_sid().raw();
            *FG_PGRP.lock() = (my_sid, pgrp_host);
            0
        }
        TIOCSCTTY => {
            if !is_tty {
                return ENOTTY;
            }
            0
        }
        TIOCGPTN => {
            if !is_tty {
                return ENOTTY;
            }
            let id = file.inode.inode_id();
            const MASTER_BIT: u64 = 1u64 << 62;
            if id & MASTER_BIT == 0 {
                return ENOTTY;
            }
            let n = (id & !(MASTER_BIT)) as u32;
            if frame::user::copy_to_user(arg, &n.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        TIOCSPTLCK => {
            if !is_tty {
                return ENOTTY;
            }
            0
        }
        FBIOGET_VSCREENINFO => {
            let (_ptr, _len, w, h) = match virtio::framebuffer_info() {
                Some(i) => i,
                None => return ENOTTY,
            };
            let buf = fb_var_screeninfo(w, h);
            if frame::user::copy_to_user(arg, &buf).is_err() {
                return EFAULT;
            }
            0
        }
        FBIOPUT_VSCREENINFO => {
            if virtio::framebuffer_info().is_none() {
                return ENOTTY;
            }
            0
        }
        FBIOGET_FSCREENINFO => {
            let (ptr, len, w, _h) = match virtio::framebuffer_info() {
                Some(i) => i,
                None => return ENOTTY,
            };
            let buf = fb_fix_screeninfo(ptr, len, w);
            if frame::user::copy_to_user(arg, &buf).is_err() {
                return EFAULT;
            }
            0
        }
        KDGKBTYPE => {
            if !is_tty {
                return ENOTTY;
            }
            if frame::user::copy_to_user(arg, &[KB_101]).is_err() {
                return EFAULT;
            }
            0
        }
        KDGKBMODE => {
            if !is_tty {
                return ENOTTY;
            }
            let mode = crate::console::kbd_mode_get();
            if frame::user::copy_to_user(arg, &mode.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        KDSKBMODE => {
            if !is_tty {
                return ENOTTY;
            }
            crate::console::kbd_mode_set(arg as u32);
            0
        }
        KDGETLED => {
            if !is_tty {
                return ENOTTY;
            }
            if frame::user::copy_to_user(arg, &[0u8]).is_err() {
                return EFAULT;
            }
            0
        }
        KDSETLED => {
            if !is_tty {
                return ENOTTY;
            }
            0
        }
        SNDCTL_DSP_SETFMT
        | SNDCTL_DSP_CHANNELS
        | SNDCTL_DSP_SPEED
        | SNDCTL_DSP_GETOSPACE
        | SNDCTL_DSP_GETFMTS
        | SNDCTL_DSP_GETBLKSIZE
        | SNDCTL_DSP_SETFRAGMENT
        | SNDCTL_DSP_STEREO
        | SNDCTL_DSP_SYNC
        | SNDCTL_DSP_RESET => {
            if file.inode.inode_id() & crate::fs::devfs::DSP_INODE_BIT == 0 {
                return ENOTTY;
            }
            do_dsp_ioctl(cmd, arg)
        }
        _ => ENOTTY,
    }
}

fn do_dsp_ioctl(cmd: u64, arg: u64) -> i64 {
    use crate::fs::devfs::{
        AFMT_QUERY, AFMT_S8, AFMT_S16_LE, AFMT_U8, AFMT_U16_LE, DSP_CHANNELS, DSP_FORMAT, DSP_RATE,
        nearest_supported_rate,
    };
    use core::sync::atomic::Ordering;
    match cmd {
        SNDCTL_DSP_SETFMT => {
            let mut buf = [0u8; 4];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            let req = u32::from_le_bytes(buf);
            let chosen = match req {
                AFMT_QUERY => DSP_FORMAT.load(Ordering::Relaxed),
                AFMT_S16_LE | AFMT_U16_LE | AFMT_S8 | AFMT_U8 => req,
                _ => AFMT_S16_LE,
            };
            DSP_FORMAT.store(chosen, Ordering::Relaxed);
            if frame::user::copy_to_user(arg, &chosen.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_CHANNELS => {
            let mut buf = [0u8; 4];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            let req = u32::from_le_bytes(buf);
            let chosen = if req == 1 || req == 2 { req } else { 2 };
            DSP_CHANNELS.store(chosen, Ordering::Relaxed);
            if frame::user::copy_to_user(arg, &chosen.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_STEREO => {
            let mut buf = [0u8; 4];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            let req = u32::from_le_bytes(buf);
            let channels = if req == 0 { 1 } else { 2 };
            DSP_CHANNELS.store(channels, Ordering::Relaxed);
            let echo = if channels == 1 { 0u32 } else { 1u32 };
            if frame::user::copy_to_user(arg, &echo.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_SPEED => {
            let mut buf = [0u8; 4];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            let req = u32::from_le_bytes(buf);
            let (negotiated_hz, _) = nearest_supported_rate(req);
            DSP_RATE.store(negotiated_hz, Ordering::Relaxed);
            if frame::user::copy_to_user(arg, &negotiated_hz.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_GETOSPACE => {
            let fragments: i32 = 8;
            let fragstotal: i32 = 8;
            let fragsize: i32 = 4096;
            let bytes: i32 = fragments * fragsize;
            let mut out = [0u8; 16];
            out[0..4].copy_from_slice(&fragments.to_le_bytes());
            out[4..8].copy_from_slice(&fragstotal.to_le_bytes());
            out[8..12].copy_from_slice(&fragsize.to_le_bytes());
            out[12..16].copy_from_slice(&bytes.to_le_bytes());
            if frame::user::copy_to_user(arg, &out).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_GETFMTS => {
            let mask: u32 = AFMT_S16_LE | AFMT_U16_LE | AFMT_S8 | AFMT_U8;
            if frame::user::copy_to_user(arg, &mask.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_GETBLKSIZE => {
            let blk: u32 = 4096;
            if frame::user::copy_to_user(arg, &blk.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_SETFRAGMENT => {
            0
        }
        SNDCTL_DSP_SYNC | SNDCTL_DSP_RESET => {
            0
        }
        _ => ENOTTY,
    }
}

fn fb_var_screeninfo(width: u32, height: u32) -> [u8; 160] {
    let mut out = [0u8; 160];
    let put_u32 = |out: &mut [u8; 160], off: usize, v: u32| {
        out[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    put_u32(&mut out, 0, width);
    put_u32(&mut out, 4, height);
    put_u32(&mut out, 8, width);
    put_u32(&mut out, 12, height);
    put_u32(&mut out, 16, 0);
    put_u32(&mut out, 20, 0);
    put_u32(&mut out, 24, 32);
    put_u32(&mut out, 28, 0);
    put_u32(&mut out, 32, 16);
    put_u32(&mut out, 36, 8);
    put_u32(&mut out, 40, 0);
    put_u32(&mut out, 44, 8);
    put_u32(&mut out, 48, 8);
    put_u32(&mut out, 52, 0);
    put_u32(&mut out, 56, 0);
    put_u32(&mut out, 60, 8);
    put_u32(&mut out, 64, 0);
    put_u32(&mut out, 68, 24);
    put_u32(&mut out, 72, 8);
    put_u32(&mut out, 76, 0);
    out
}

fn fb_fix_screeninfo(smem_start: u64, smem_len: usize, width: u32) -> [u8; 80] {
    let mut out = [0u8; 80];
    let id = b"cyphera-virtgpu";
    let n = id.len().min(15);
    out[..n].copy_from_slice(&id[..n]);
    out[16..24].copy_from_slice(&smem_start.to_le_bytes());
    out[24..28].copy_from_slice(&(smem_len as u32).to_le_bytes());
    out[36..40].copy_from_slice(&2u32.to_le_bytes());
    out[48..52].copy_from_slice(&(width * 4).to_le_bytes());
    out
}

pub(super) fn sys_pipe(fds_ptr: u64) -> i64 {
    sys_pipe2(fds_ptr, 0)
}

pub(super) fn sys_pipe2(fds_ptr: u64, flags: u64) -> i64 {
    let cloexec = if (flags & 0o2_000_000) != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    let pipe = vfs::pipe::Pipe::new();
    let inode_dyn: Arc<dyn Inode> = pipe;
    let read_end = Arc::new(OpenFile::new(inode_dyn.clone(), OpenFlags::RDONLY));
    let write_end = Arc::new(OpenFile::new(inode_dyn, OpenFlags::WRONLY));

    let (rfd, wfd) = sched::with_current_fds(|t| {
        let r = t.install_from(read_end, 0, cloexec);
        let w = match r {
            Ok(_) => t.install_from(write_end, 0, cloexec),
            Err(e) => Err(e),
        };
        (r, w)
    });

    let rfd = match rfd {
        Ok(f) => f,
        Err(e) => return e as i64,
    };
    let wfd = match wfd {
        Ok(f) => f,
        Err(e) => {
            sched::with_current_fds(|t| t.remove(rfd));
            return e as i64;
        }
    };

    let buf: [u8; 8] = {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&rfd.to_le_bytes());
        b[4..8].copy_from_slice(&wfd.to_le_bytes());
        b
    };
    if frame::user::copy_to_user(fds_ptr, &buf).is_err() {
        sched::with_current_fds(|t| {
            t.remove(rfd);
            t.remove(wfd);
        });
        return EFAULT;
    }
    0
}

pub(super) fn sys_mkdirat(dirfd: u64, pathname: u64, mode: u64) -> i64 {
    let mut path_buf = [0u8; PATH_MAX];
    let len = match frame::user::copy_cstr_from_user(pathname, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let path = match core::str::from_utf8(&path_buf[..len]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    if path == "/" {
        return -17;
    }
    let (parent, leaf) = match resolve_at_parent(dirfd as i64, path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match parent.create(&leaf, InodeKind::Directory) {
        Ok(i) => {
            apply_create_owner(&i);
            apply_create_mode(&i, mode as u16);
            0
        }
        Err(e) => e.errno(),
    }
}

fn apply_create_owner(inode: &alloc::sync::Arc<dyn vfs::Inode>) {
    let (euid, egid) = sched::with_current_creds(|c| (c.euid, c.egid));
    let _ = inode.set_owner(Some(euid), Some(egid));
}

fn apply_create_mode(inode: &alloc::sync::Arc<dyn vfs::Inode>, mode: u16) {
    let perm = (mode & 0o7777) & !sched::current_umask();
    let _ = inode.set_mode(perm);
}

pub(super) fn sys_unlinkat(dirfd: u64, pathname: u64, flags: u64) -> i64 {
    let mut path_buf = [0u8; PATH_MAX];
    let len = match frame::user::copy_cstr_from_user(pathname, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let path = match core::str::from_utf8(&path_buf[..len]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let normalized = match resolve_user_path(dirfd as i64, path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let ctx = vfs::path::Context::current();
    let (parent, leaf) = match vfs::path::resolve_parent(&ctx, &ctx.root, &normalized) {
        Ok(p) => p,
        Err(e) => return e.errno(),
    };
    let target = match parent.lookup(leaf) {
        Ok(t) => t,
        Err(e) => return e.errno(),
    };
    if vfs::is_mountpoint_inode(Some(&ctx.mounts), target.inode_id()) {
        return -16;
    }
    let want_dir = (flags & AT_REMOVEDIR) != 0;
    let is_dir = target.kind() == InodeKind::Directory;
    if want_dir && !is_dir {
        return ENOTDIR;
    }
    if !want_dir && is_dir {
        return -21;
    }
    if is_dir {
        match parent.rmdir(leaf) {
            Ok(()) => return 0,
            Err(e) => return e.errno(),
        }
    }
    match parent.unlink(leaf) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_renameat(olddirfd: u64, oldpath: u64, newdirfd: u64, newpath: u64) -> i64 {
    let mut buf_old = [0u8; PATH_MAX];
    let mut buf_new = [0u8; PATH_MAX];
    let lo = match frame::user::copy_cstr_from_user(oldpath, &mut buf_old) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let ln = match frame::user::copy_cstr_from_user(newpath, &mut buf_new) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let old_str = match core::str::from_utf8(&buf_old[..lo]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let new_str = match core::str::from_utf8(&buf_new[..ln]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let old_norm = match resolve_user_path(olddirfd as i64, old_str) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new_norm = match resolve_user_path(newdirfd as i64, new_str) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let ctx = vfs::path::Context::current();
    let (old_parent, old_leaf) = match vfs::path::resolve_parent(&ctx, &ctx.root, &old_norm) {
        Ok(p) => p,
        Err(e) => return e.errno(),
    };
    let (new_parent, new_leaf) = match vfs::path::resolve_parent(&ctx, &ctx.root, &new_norm) {
        Ok(p) => p,
        Err(e) => return e.errno(),
    };
    let old_leaf = old_leaf.to_string();
    let new_leaf = new_leaf.to_string();
    match old_parent.rename(&old_leaf, &new_parent, &new_leaf) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_linkat(
    olddirfd: u64,
    oldpath: u64,
    newdirfd: u64,
    newpath: u64,
    _flags: u64,
) -> i64 {
    let mut buf_old = [0u8; PATH_MAX];
    let mut buf_new = [0u8; PATH_MAX];
    let lo = match frame::user::copy_cstr_from_user(oldpath, &mut buf_old) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let ln = match frame::user::copy_cstr_from_user(newpath, &mut buf_new) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let old_str = match core::str::from_utf8(&buf_old[..lo]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let new_str = match core::str::from_utf8(&buf_new[..ln]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let old_norm = match resolve_user_path(olddirfd as i64, old_str) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new_norm = match resolve_user_path(newdirfd as i64, new_str) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let ctx = vfs::path::Context::current();
    let target = match vfs::path::resolve(&ctx, &ctx.root, &old_norm) {
        Ok(t) => t,
        Err(e) => return e.errno(),
    };
    if target.kind() == InodeKind::Directory {
        return -1;
    }
    let (new_parent, new_leaf) = match vfs::path::resolve_parent(&ctx, &ctx.root, &new_norm) {
        Ok(p) => p,
        Err(e) => return e.errno(),
    };
    match new_parent.attach(new_leaf, target) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_symlinkat(target: u64, newdirfd: u64, linkpath: u64) -> i64 {
    let mut buf_target = [0u8; PATH_MAX];
    let mut buf_link = [0u8; PATH_MAX];
    let lt = match frame::user::copy_cstr_from_user(target, &mut buf_target) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let ll = match frame::user::copy_cstr_from_user(linkpath, &mut buf_link) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let target_str = match core::str::from_utf8(&buf_target[..lt]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let link_str = match core::str::from_utf8(&buf_link[..ll]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let (parent, leaf) = match resolve_at_parent(newdirfd as i64, link_str) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match parent.symlink(&leaf, target_str) {
        Ok(i) => {
            let _ = i.set_owner(
                Some(sched::with_current_creds(|c| c.euid)),
                Some(sched::with_current_creds(|c| c.egid)),
            );
            0
        }
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_mount(source: u64, target: u64, fs_type: u64, flags: u64, _data: u64) -> i64 {
    if !sched::with_current_creds(|c| c.capable_host(crate::process::CAP_SYS_ADMIN)) {
        return EPERM;
    }
    const MS_BIND: u64 = 0x1000;
    const MS_REC: u64 = 0x4000;
    const MS_REMOUNT: u64 = 0x0020;
    const MS_SHARED: u64 = 1 << 20;
    const MS_PRIVATE: u64 = 1 << 18;
    const MS_SLAVE: u64 = 1 << 19;
    const MS_UNBINDABLE: u64 = 1 << 17;
    const MS_MOVE: u64 = 0x2000;
    const PROPAGATION_MASK: u64 = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;

    let new_mount_propagation = |_ctx: &vfs::path::Context, f: u64| -> vfs::MountPropagation {
        if f & MS_UNBINDABLE != 0 {
            vfs::MountPropagation::Unbindable
        } else if f & MS_SHARED != 0 {
            vfs::MountPropagation::Shared(vfs::PeerGroup::new_empty())
        } else {
            vfs::MountPropagation::Private
        }
    };

    if (flags & PROPAGATION_MASK) != 0 && (flags & MS_BIND) == 0 {
        let mut tbuf = [0u8; PATH_MAX];
        let tlen = match frame::user::copy_cstr_from_user(target, &mut tbuf) {
            Ok(n) => n,
            Err(_) => return ENAMETOOLONG,
        };
        let t = match core::str::from_utf8(&tbuf[..tlen]) {
            Ok(p) => p,
            Err(_) => return EINVAL,
        };
        let t_norm = match resolve_user_path(AT_FDCWD, t) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ctx = vfs::path::Context::current();
        let mut targets: alloc::vec::Vec<String> = alloc::vec::Vec::new();
        if (flags & MS_REC) != 0 {
            for (suffix, _) in ctx.collect_subtree(&t_norm) {
                let p = if suffix.is_empty() {
                    String::from(&t_norm)
                } else if t_norm == "/" {
                    suffix
                } else {
                    let mut s = String::from(&t_norm);
                    s.push_str(&suffix);
                    s
                };
                targets.push(p);
            }
            if targets.is_empty() {
                targets.push(String::from(&t_norm));
            }
        } else {
            targets.push(String::from(&t_norm));
        }
        for p in targets.iter() {
            let existing = match ctx.lookup_mount_full(p) {
                Some(e) => e,
                None => continue,
            };
            let new_prop = if flags & MS_UNBINDABLE != 0 {
                vfs::MountPropagation::Unbindable
            } else if flags & MS_PRIVATE != 0 {
                vfs::MountPropagation::Private
            } else if flags & MS_SHARED != 0 {
                match existing.propagation.clone() {
                    vfs::MountPropagation::Shared(g) => vfs::MountPropagation::Shared(g),
                    _ => vfs::MountPropagation::Shared(vfs::PeerGroup::new_empty()),
                }
            } else if flags & MS_SLAVE != 0 {
                match existing.propagation.clone() {
                    vfs::MountPropagation::Shared(g) => vfs::MountPropagation::Slave(g),
                    other => other,
                }
            } else {
                existing.propagation.clone()
            };
            ctx.set_mount_propagation(p, new_prop);
        }
        return 0;
    }
    if (flags & MS_MOVE) != 0 {
        let mut sbuf = [0u8; PATH_MAX];
        let slen = match frame::user::copy_cstr_from_user(source, &mut sbuf) {
            Ok(n) => n,
            Err(_) => return ENAMETOOLONG,
        };
        let s = match core::str::from_utf8(&sbuf[..slen]) {
            Ok(p) => p,
            Err(_) => return EINVAL,
        };
        let mut tbuf = [0u8; PATH_MAX];
        let tlen = match frame::user::copy_cstr_from_user(target, &mut tbuf) {
            Ok(n) => n,
            Err(_) => return ENAMETOOLONG,
        };
        let t = match core::str::from_utf8(&tbuf[..tlen]) {
            Ok(p) => p,
            Err(_) => return EINVAL,
        };
        let s_norm = match resolve_user_path(AT_FDCWD, s) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let t_norm = match resolve_user_path(AT_FDCWD, t) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ctx = vfs::path::Context::current();
        let entry = match ctx.lookup_mount_full(&s_norm) {
            Some(e) => e,
            None => return EINVAL,
        };
        let tgt_inode = match vfs::path::resolve(&ctx, &ctx.root, &t_norm) {
            Ok(i) => i,
            Err(e) => return e.errno(),
        };
        ctx.remove_mount(&s_norm);
        ctx.install_mount(&t_norm, tgt_inode.inode_id(), entry.root, entry.propagation);
        return 0;
    }

    if (flags & MS_REMOUNT) != 0 {
        return 0;
    }

    if (flags & MS_BIND) != 0 {
        let mut sbuf = [0u8; PATH_MAX];
        let slen = match frame::user::copy_cstr_from_user(source, &mut sbuf) {
            Ok(n) => n,
            Err(_) => return ENAMETOOLONG,
        };
        let s = match core::str::from_utf8(&sbuf[..slen]) {
            Ok(p) => p,
            Err(_) => return EINVAL,
        };
        let mut tbuf = [0u8; PATH_MAX];
        let tlen = match frame::user::copy_cstr_from_user(target, &mut tbuf) {
            Ok(n) => n,
            Err(_) => return ENAMETOOLONG,
        };
        let t = match core::str::from_utf8(&tbuf[..tlen]) {
            Ok(p) => p,
            Err(_) => return EINVAL,
        };
        let s_norm = match resolve_user_path(AT_FDCWD, s) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let t_norm = match resolve_user_path(AT_FDCWD, t) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ctx = vfs::path::Context::current();
        if let Some(containing) = ctx.containing_mount(&s_norm) {
            if containing.propagation.is_unbindable() {
                return EINVAL;
            }
        }
        let src_inode = match vfs::path::resolve(&ctx, &ctx.root, &s_norm) {
            Ok(i) => i,
            Err(e) => return e.errno(),
        };
        let tgt_inode = match vfs::path::resolve(&ctx, &ctx.root, &t_norm) {
            Ok(i) => i,
            Err(e) => return e.errno(),
        };
        let explicit = flags & PROPAGATION_MASK;
        let bind_prop = if explicit != 0 {
            new_mount_propagation(&ctx, flags)
        } else {
            let src_entry = ctx
                .lookup_mount_full(&s_norm)
                .or_else(|| ctx.containing_mount(&s_norm));
            match src_entry.map(|e| e.propagation) {
                Some(vfs::MountPropagation::Shared(g)) => vfs::MountPropagation::Shared(g),
                Some(vfs::MountPropagation::Slave(g)) => vfs::MountPropagation::Slave(g),
                _ => vfs::MountPropagation::Private,
            }
        };
        ctx.install_mount_propagating(&t_norm, tgt_inode.inode_id(), src_inode, bind_prop);
        if (flags & MS_REC) != 0 {
            for (suffix, entry) in ctx.collect_subtree(&s_norm) {
                if suffix.is_empty() {
                    continue;
                }
                let mirror_path = if t_norm == "/" {
                    suffix.clone()
                } else {
                    let mut s = String::from(t_norm.as_str());
                    s.push_str(&suffix);
                    s
                };
                if let Ok(mirror_target_inode) = vfs::path::resolve(&ctx, &ctx.root, &mirror_path) {
                    ctx.install_mount_propagating(
                        &mirror_path,
                        mirror_target_inode.inode_id(),
                        entry.root.clone(),
                        entry.propagation,
                    );
                }
            }
        }
        return 0;
    }

    let _ = source;

    let mut fst_buf = [0u8; 32];
    let fst_len = match frame::user::copy_cstr_from_user(fs_type, &mut fst_buf) {
        Ok(n) => n,
        Err(_) => return EINVAL,
    };
    let fst = match core::str::from_utf8(&fst_buf[..fst_len]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let virtual_fs = matches!(
        fst,
        "proc" | "sysfs" | "devtmpfs" | "devpts" | "mqueue" | "cgroup" | "cgroup2"
    );
    if fst != "tmpfs" && fst != "ext4" && !virtual_fs {
        return -19;
    }
    if virtual_fs {
        return 0;
    }
    let mut path_buf = [0u8; PATH_MAX];
    let plen = match frame::user::copy_cstr_from_user(target, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let path = match core::str::from_utf8(&path_buf[..plen]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let normalized = match resolve_user_path(AT_FDCWD, path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    let ctx = vfs::path::Context::current();
    let target_inode = match vfs::path::resolve(&ctx, &ctx.root, &normalized) {
        Ok(i) => i,
        Err(e) => return e.errno(),
    };
    if target_inode.kind() != vfs::InodeKind::Directory {
        return -20;
    }

    let new_root: Arc<dyn vfs::Inode> = if fst == "ext4" {
        let mut src_buf = [0u8; PATH_MAX];
        let slen = match frame::user::copy_cstr_from_user(source, &mut src_buf) {
            Ok(n) => n,
            Err(_) => return ENAMETOOLONG,
        };
        let src = match core::str::from_utf8(&src_buf[..slen]) {
            Ok(s) => s,
            Err(_) => return EINVAL,
        };
        if src != "/dev/vda" {
            return -19; // ENODEV — no such block device
        }
        let dev = match crate::fs::ext4::VirtioBlockDevice::new() {
            Some(d) => d,
            None => return -19, // ENODEV — no virtio-blk disk attached
        };
        match crate::fs::ext4::Ext4Fs::mount(dev) {
            Ok(fs) => fs.root_inode(),
            Err(_) => return -22, // EINVAL — not a mountable ext4 image
        }
    } else {
        crate::fs::tmpfs::TmpfsInode::new_dir()
    };
    let new_prop = new_mount_propagation(&ctx, flags);
    ctx.install_mount_propagating(&normalized, target_inode.inode_id(), new_root, new_prop);
    0
}

pub(super) fn sys_umount2(target: u64, flags: u64) -> i64 {
    if !sched::with_current_creds(|c| c.capable_host(crate::process::CAP_SYS_ADMIN)) {
        return EPERM;
    }
    const MNT_FORCE: u64 = 1;
    const MNT_DETACH: u64 = 2;
    const MNT_EXPIRE: u64 = 4;
    const UMOUNT_NOFOLLOW: u64 = 8;
    const EBUSY: i64 = -16;

    if (flags & MNT_EXPIRE) != 0 {
        return EINVAL;
    }

    let mut path_buf = [0u8; PATH_MAX];
    let plen = match frame::user::copy_cstr_from_user(target, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let path = match core::str::from_utf8(&path_buf[..plen]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let normalized = match resolve_user_path(AT_FDCWD, path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    let ctx = vfs::path::Context::current();

    if (flags & UMOUNT_NOFOLLOW) != 0 {
        if let Err(e) = vfs::path::resolve_no_follow(&ctx, &ctx.root, &normalized) {
            return e.errno();
        }
    }

    let skip_busy_check = (flags & (MNT_DETACH | MNT_FORCE)) != 0;
    if !skip_busy_check {
        if let Some(entry) = ctx.lookup_mount_full(&normalized) {
            if entry.in_use.refs() > 0 {
                return EBUSY;
            }
        }
    }

    if ctx.remove_mount_propagating(&normalized).is_none() {
        return -22;
    }
    0
}

pub(super) fn sys_readlinkat(dirfd: u64, pathname: u64, buf: u64, bufsize: u64) -> i64 {
    let mut path_buf = [0u8; PATH_MAX];
    let len = match frame::user::copy_cstr_from_user(pathname, &mut path_buf) {
        Ok(n) => n,
        Err(_) => return ENAMETOOLONG,
    };
    let path = match core::str::from_utf8(&path_buf[..len]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    let normalized = match resolve_user_path(dirfd as i64, path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let ctx = vfs::path::Context::current();
    let inode = match vfs::path::resolve_no_follow(&ctx, &ctx.root, &normalized) {
        Ok(i) => i,
        Err(e) => return e.errno(),
    };
    let target = match inode.read_link() {
        Ok(t) => t,
        Err(e) => return e.errno(),
    };
    let bytes = target.as_bytes();
    let n = bytes.len().min(bufsize as usize);
    if n > 0 && frame::user::copy_to_user(buf, &bytes[..n]).is_err() {
        return EFAULT;
    }
    n as i64
}

fn resolve_path(dirfd: u64, pathname: u64, follow: bool) -> Result<Arc<dyn Inode>, i64> {
    let mut path_buf = [0u8; PATH_MAX];
    let len =
        frame::user::copy_cstr_from_user(pathname, &mut path_buf).map_err(|_| ENAMETOOLONG)?;
    let path = core::str::from_utf8(&path_buf[..len]).map_err(|_| EINVAL)?;
    let normalized = resolve_user_path(dirfd as i64, path)?;
    let ctx = vfs::path::Context::current();
    if follow {
        vfs::path::resolve(&ctx, &ctx.root, &normalized).map_err(|e| e.errno())
    } else {
        vfs::path::resolve_no_follow(&ctx, &ctx.root, &normalized).map_err(|e| e.errno())
    }
}

fn copy_path(pathname: u64) -> Result<alloc::string::String, i64> {
    let mut path_buf = [0u8; PATH_MAX];
    let len =
        frame::user::copy_cstr_from_user(pathname, &mut path_buf).map_err(|_| ENAMETOOLONG)?;
    let path = core::str::from_utf8(&path_buf[..len]).map_err(|_| EINVAL)?;
    Ok(alloc::string::String::from(path))
}

fn copy_xname(name_ptr: u64) -> Result<alloc::string::String, i64> {
    let mut buf = [0u8; 256];
    let len = frame::user::copy_cstr_from_user(name_ptr, &mut buf).map_err(|_| ENAMETOOLONG)?;
    let s = core::str::from_utf8(&buf[..len]).map_err(|_| EINVAL)?;
    Ok(alloc::string::String::from(s))
}

pub(super) fn sys_stat(pathname: u64, statbuf: u64, lstat: bool) -> i64 {
    let inode = match resolve_path(AT_FDCWD as u64, pathname, !lstat) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let stat = build_stat(&inode);
    if frame::user::copy_to_user(statbuf, &stat).is_err() {
        return EFAULT;
    }
    0
}

const STATX_BASIC_STATS: u32 = 0x7ff;

pub(super) fn sys_statx(dirfd: u64, pathname: u64, flags: u64, _mask: u64, statxbuf: u64) -> i64 {
    if statxbuf == 0 {
        return EFAULT;
    }
    let inode = if (flags & AT_EMPTY_PATH) != 0 {
        let mut path_buf = [0u8; 1];
        if frame::user::copy_cstr_from_user(pathname, &mut path_buf)
            .ok()
            .map(|n| n == 0)
            .unwrap_or(false)
        {
            match sched::with_current_fds(|t| t.get(dirfd as i32)) {
                Some(f) => f.inode.clone(),
                None => return EBADF,
            }
        } else {
            match resolve_path(dirfd, pathname, true) {
                Ok(i) => i,
                Err(e) => return e,
            }
        }
    } else {
        match resolve_path(dirfd, pathname, true) {
            Ok(i) => i,
            Err(e) => return e,
        }
    };
    let st = inode.stat();
    let mut buf = [0u8; 256];
    buf[0..4].copy_from_slice(&STATX_BASIC_STATS.to_le_bytes());
    buf[4..8].copy_from_slice(&(st.blksize).to_le_bytes());
    buf[16..20].copy_from_slice(&st.nlink.to_le_bytes());
    let (vis_uid, vis_gid) = crate::sched::with_current_creds(|c| {
        (c.uid_from_kernel(st.uid), c.gid_from_kernel(st.gid))
    });
    buf[20..24].copy_from_slice(&vis_uid.to_le_bytes());
    buf[24..28].copy_from_slice(&vis_gid.to_le_bytes());
    let mode_bits: u16 = match st.kind {
        InodeKind::Regular => 0o100_000,
        InodeKind::Directory => 0o040_000,
        InodeKind::CharDevice => 0o020_000,
        InodeKind::Symlink => 0o120_000,
        InodeKind::Pipe => 0o010_000,
    };
    let mode = mode_bits | (st.mode & 0o7777);
    buf[28..30].copy_from_slice(&mode.to_le_bytes());
    buf[32..40].copy_from_slice(&st.inode_id.to_le_bytes());
    buf[40..48].copy_from_slice(&st.size.to_le_bytes());
    buf[48..56].copy_from_slice(&st.blocks.to_le_bytes());
    let put_ts = |buf: &mut [u8; 256], off: usize, ts: TimeSpec| {
        buf[off..off + 8].copy_from_slice(&ts.sec.to_le_bytes());
        buf[off + 8..off + 12].copy_from_slice(&(ts.nsec as u32).to_le_bytes());
    };
    put_ts(&mut buf, 64, st.atime);
    put_ts(&mut buf, 96, st.ctime);
    put_ts(&mut buf, 112, st.mtime);
    if frame::user::copy_to_user(statxbuf, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_faccessat(dirfd: u64, pathname: u64, mode: u64, _flags: u64) -> i64 {
    let inode = match resolve_path(dirfd, pathname, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let mode_req = (mode & 0o7) as u8;
    if mode_req == 0 {
        return 0;
    }
    let st = inode.stat();
    let ok = sched::with_current_creds(|c| {
        let mut shadow = c.clone();
        shadow.euid = c.ruid;
        shadow.egid = c.rgid;
        shadow.can_access(st.uid, st.gid, st.mode, mode_req)
    });
    if ok {
        0
    } else {
        -13
    }
}

fn chmod_permitted(file_uid: u32) -> bool {
    sched::with_current_creds(|c| c.capable_host(crate::process::CAP_FOWNER) || c.fsuid == file_uid)
}

fn chown_permitted(file_uid: u32, want_uid: Option<u32>, want_gid: Option<u32>) -> bool {
    sched::with_current_creds(|c| {
        let uid_ok = match want_uid {
            None => true,
            Some(nu) => {
                c.capable_host(crate::process::CAP_CHOWN) || (c.fsuid == file_uid && nu == file_uid)
            }
        };
        let gid_ok = match want_gid {
            None => true,
            Some(ng) => {
                c.capable_host(crate::process::CAP_CHOWN)
                    || (c.fsuid == file_uid && (c.fsgid == ng || c.is_in_group(ng)))
            }
        };
        uid_ok && gid_ok
    })
}

fn xlate_chown_ids(u: Option<u32>, g: Option<u32>) -> Result<(Option<u32>, Option<u32>), i64> {
    sched::with_current_creds(|c| {
        let ku = match u {
            None => None,
            Some(v) => Some(c.uid_into_kernel(v).ok_or(EINVAL)?),
        };
        let kg = match g {
            None => None,
            Some(v) => Some(c.gid_into_kernel(v).ok_or(EINVAL)?),
        };
        Ok((ku, kg))
    })
}

pub(super) fn sys_fchmod(fd: u64, mode: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if !chmod_permitted(file.inode.stat().uid) {
        return EPERM;
    }
    match file.inode.set_mode((mode & 0o7777) as u16) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_fchmodat(dirfd: u64, pathname: u64, mode: u64) -> i64 {
    let inode = match resolve_path(dirfd, pathname, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !chmod_permitted(inode.stat().uid) {
        return EPERM;
    }
    match inode.set_mode((mode & 0o7777) as u16) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_fchown(fd: u64, uid: u64, gid: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let u = if (uid as i32) == -1 {
        None
    } else {
        Some(uid as u32)
    };
    let g = if (gid as i32) == -1 {
        None
    } else {
        Some(gid as u32)
    };
    if u.is_none() && g.is_none() {
        return 0;
    }
    let (u, g) = match xlate_chown_ids(u, g) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if !chown_permitted(file.inode.stat().uid, u, g) {
        return EPERM;
    }
    match file.inode.set_owner(u, g) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_fchownat(dirfd: u64, pathname: u64, uid: u64, gid: u64, _flags: u64) -> i64 {
    let inode = match resolve_path(dirfd, pathname, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let u = if (uid as i32) == -1 {
        None
    } else {
        Some(uid as u32)
    };
    let g = if (gid as i32) == -1 {
        None
    } else {
        Some(gid as u32)
    };
    if u.is_none() && g.is_none() {
        return 0;
    }
    let (u, g) = match xlate_chown_ids(u, g) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if !chown_permitted(inode.stat().uid, u, g) {
        return EPERM;
    }
    match inode.set_owner(u, g) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_truncate(pathname: u64, len: u64) -> i64 {
    let inode = match resolve_path(AT_FDCWD as u64, pathname, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let st = inode.stat();
    if st.kind == InodeKind::Directory {
        return EISDIR;
    }
    if !sched::with_current_creds(|c| c.can_access(st.uid, st.gid, st.mode, 0o2)) {
        return EACCES;
    }
    match inode.truncate(len) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_ftruncate(fd: u64, len: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if !file.flags().is_writable() {
        return EINVAL;
    }
    match file.inode.truncate(len) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_renameat2(
    olddirfd: u64,
    oldpath: u64,
    newdirfd: u64,
    newpath: u64,
    _flags: u64,
) -> i64 {
    let old = match copy_path(oldpath) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let new = match copy_path(newpath) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let old_norm = match resolve_user_path(olddirfd as i64, &old) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new_norm = match resolve_user_path(newdirfd as i64, &new) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let ctx = vfs::path::Context::current();
    let (old_parent, old_name) = match vfs::path::resolve_parent(&ctx, &ctx.root, &old_norm) {
        Ok(x) => x,
        Err(e) => return e.errno(),
    };
    let (new_parent, new_name) = match vfs::path::resolve_parent(&ctx, &ctx.root, &new_norm) {
        Ok(x) => x,
        Err(e) => return e.errno(),
    };
    match old_parent.rename(old_name, &new_parent, new_name) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_mknodat(dirfd: u64, pathname: u64, mode: u64, dev: u64) -> i64 {
    let path = match copy_path(pathname) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let (parent, leaf) = match resolve_at_parent(dirfd as i64, &path) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let kind = match mode & 0o170_000 {
        0 | 0o100_000 => InodeKind::Regular,
        0o040_000 => InodeKind::Directory,
        0o020_000 => InodeKind::CharDevice,
        0o010_000 => InodeKind::Pipe,
        _ => return EINVAL,
    };
    match parent.mknod(&leaf, kind, dev) {
        Ok(i) => {
            apply_create_owner(&i);
            apply_create_mode(&i, mode as u16);
            0
        }
        Err(e) => e.errno(),
    }
}

const STATFS_SIZE: usize = 120;

pub(super) fn sys_statfs(arg: u64, statfs_ptr: u64, fd: bool) -> i64 {
    let inode = if fd {
        match sched::with_current_fds(|t| t.get(arg as i32)) {
            Some(f) => f.inode.clone(),
            None => return EBADF,
        }
    } else {
        match resolve_path(AT_FDCWD as u64, arg, true) {
            Ok(i) => i,
            Err(e) => return e,
        }
    };
    let st = inode.stat();
    let mut buf = [0u8; STATFS_SIZE];
    let magic: u64 = if (st.dev_id >> 56) == 0xe4 {
        0xef53
    } else {
        0x0102_1994
    };
    buf[0..8].copy_from_slice(&magic.to_le_bytes());
    buf[8..16].copy_from_slice(&(st.blksize as u64).to_le_bytes());
    let mem = frame::mm::frame_alloc::stats();
    let total = (mem.total * 4096) as u64 / st.blksize as u64;
    let free = ((mem.total - mem.in_use) * 4096) as u64 / st.blksize as u64;
    buf[16..24].copy_from_slice(&total.to_le_bytes());
    buf[24..32].copy_from_slice(&free.to_le_bytes());
    buf[32..40].copy_from_slice(&free.to_le_bytes());
    buf[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
    buf[48..56].copy_from_slice(&u64::MAX.to_le_bytes());
    buf[56..64].copy_from_slice(&st.dev_id.to_le_bytes());
    buf[64..72].copy_from_slice(&255u64.to_le_bytes());
    buf[72..80].copy_from_slice(&(st.blksize as u64).to_le_bytes());
    if frame::user::copy_to_user(statfs_ptr, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_chroot(pathname: u64) -> i64 {
    let allowed = sched::with_current_creds(|c| c.has_cap(crate::process::CAP_SYS_CHROOT));
    if !allowed {
        return -1;
    }
    let inode = match resolve_path(AT_FDCWD as u64, pathname, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    if inode.kind() != InodeKind::Directory {
        return ENOTDIR;
    }
    sched::set_current_fs_root(inode);
    0
}

pub(super) fn sys_fchdir(fd: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let inode = file.inode.clone();
    if inode.kind() != InodeKind::Directory {
        return ENOTDIR;
    }
    sched::set_current_cwd(inode, String::from("/"));
    0
}

pub(super) fn sys_fallocate(fd: u64, mode: u64, offset: u64, len: u64) -> i64 {
    const FALLOC_FL_KEEP_SIZE: u64 = 0x01;
    const FALLOC_FL_PUNCH_HOLE: u64 = 0x02;
    const FALLOC_FL_ZERO_RANGE: u64 = 0x10;
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let inode = file.inode.clone();
    let cur = inode.stat().size;

    if mode & FALLOC_FL_PUNCH_HOLE != 0 {
        if mode & FALLOC_FL_KEEP_SIZE == 0 {
            return EINVAL;
        }
        let end = offset.saturating_add(len).min(cur);
        if end > offset {
            let chunk = [0u8; 4096];
            let mut pos = offset;
            while pos < end {
                let n = (end - pos).min(chunk.len() as u64) as usize;
                if let Err(e) = inode.write_at(pos, &chunk[..n]) {
                    return e.errno();
                }
                pos += n as u64;
            }
        }
        return 0;
    }

    if mode & FALLOC_FL_ZERO_RANGE != 0 {
        let target = offset.saturating_add(len);
        if target > cur && (mode & FALLOC_FL_KEEP_SIZE == 0) {
            if let Err(e) = inode.truncate(target) {
                return e.errno();
            }
        }
        let end = offset.saturating_add(len);
        let chunk = [0u8; 4096];
        let mut pos = offset;
        while pos < end {
            let n = (end - pos).min(chunk.len() as u64) as usize;
            if let Err(e) = inode.write_at(pos, &chunk[..n]) {
                return e.errno();
            }
            pos += n as u64;
        }
        return 0;
    }

    let target = offset.saturating_add(len);
    if target > cur && (mode & FALLOC_FL_KEEP_SIZE == 0) {
        if let Err(e) = inode.truncate(target) {
            return e.errno();
        }
    }
    0
}

pub(super) fn sys_flock(fd: u64, op: u64) -> i64 {
    use crate::vfs::locks::bsd::{FlockOutcome, LOCK_EX, LOCK_NB, LOCK_SH, LOCK_UN};
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let op = op as u32;
    let kind = op & !LOCK_NB;
    if !matches!(kind, LOCK_SH | LOCK_EX | LOCK_UN) {
        return EINVAL;
    }
    let inode_id = file.inode.inode_id();
    let ofd_key = Arc::as_ptr(&file) as *const () as u64;
    loop {
        match crate::vfs::locks::bsd::try_op(inode_id, ofd_key, op) {
            FlockOutcome::Acquired | FlockOutcome::Released => return 0,
            FlockOutcome::Conflict => {
                if (op & LOCK_NB) != 0 {
                    return -11;
                }
                let waiters = crate::vfs::locks::bsd::waiters_for(inode_id);
                waiters.park();
                if sched::current_signal_pending() {
                    return EINTR;
                }
            }
        }
    }
}

pub(super) fn sys_fadvise64(fd: u64) -> i64 {
    let exists = sched::with_current_fds(|t| t.get(fd as i32).is_some());
    if !exists {
        return EBADF;
    }
    0
}

pub(super) fn sys_preadv(fd: u64, iov: u64, iovcnt: u64, offset_lo: u64, offset_hi: u64) -> i64 {
    let off = offset_lo | (offset_hi << 32);
    let vecs = match read_iovecs(iov, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut total: i64 = 0;
    let mut cursor = off;
    for (base, len) in vecs {
        if len == 0 {
            continue;
        }
        let r = sys_pread64(fd, base, len as u64, cursor);
        if r < 0 {
            return if total == 0 { r } else { total };
        }
        total += r;
        cursor = cursor.saturating_add(r as u64);
        if (r as usize) < len {
            break;
        }
    }
    total
}

pub(super) fn sys_pwritev(fd: u64, iov: u64, iovcnt: u64, offset_lo: u64, offset_hi: u64) -> i64 {
    let off = offset_lo | (offset_hi << 32);
    let vecs = match read_iovecs(iov, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut total: i64 = 0;
    let mut cursor = off;
    for (base, len) in vecs {
        if len == 0 {
            continue;
        }
        let r = sys_pwrite64(fd, base, len as u64, cursor);
        if r < 0 {
            return if total == 0 { r } else { total };
        }
        total += r;
        cursor = cursor.saturating_add(r as u64);
        if (r as usize) < len {
            break;
        }
    }
    total
}

pub(super) fn sys_sendfile(out_fd: u64, in_fd: u64, offset_ptr: u64, count: u64) -> i64 {
    const CHUNK: usize = 4096;
    let mut buf = [0u8; CHUNK];
    let in_file = match sched::with_current_fds(|t| t.get(in_fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let out_file = match sched::with_current_fds(|t| t.get(out_fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };

    let mut offset_buf = [0u8; 8];
    let mut have_offset = false;
    let mut offset: u64 = 0;
    if offset_ptr != 0 {
        if frame::user::copy_from_user(offset_ptr, &mut offset_buf).is_err() {
            return EFAULT;
        }
        offset = u64::from_le_bytes(offset_buf);
        have_offset = true;
    }

    let mut transferred: usize = 0;
    while (transferred as u64) < count {
        let want = ((count - transferred as u64) as usize).min(CHUNK);
        let in_inode = in_file.inode.clone();
        let r = if have_offset {
            in_inode.read_at(offset, &mut buf[..want])
        } else {
            in_file.read(&mut buf[..want])
        };
        let n = match r {
            Ok(n) => n,
            Err(e) => return e.errno(),
        };
        if n == 0 {
            break;
        }
        let w = match out_file.write(&buf[..n]) {
            Ok(w) => w,
            Err(e) => return write_err_to_errno(e),
        };
        transferred += w;
        if have_offset {
            offset = offset.saturating_add(w as u64);
        }
        if w < n {
            break;
        }
    }
    if have_offset {
        offset_buf.copy_from_slice(&offset.to_le_bytes());
        let _ = frame::user::copy_to_user(offset_ptr, &offset_buf);
    }
    transferred as i64
}

pub(super) fn sys_copy_file_range(
    fd_in: u64,
    off_in_ptr: u64,
    fd_out: u64,
    off_out_ptr: u64,
    len: u64,
    _flags: u64,
) -> i64 {
    const CHUNK: usize = 4096;
    let mut buf = [0u8; CHUNK];

    let in_file = match sched::with_current_fds(|t| t.get(fd_in as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let out_file = match sched::with_current_fds(|t| t.get(fd_out as i32)) {
        Some(f) => f,
        None => return EBADF,
    };

    let mut in_off = read_optional_off(off_in_ptr).unwrap_or(0);
    let in_use_off = off_in_ptr != 0;
    let mut out_off = read_optional_off(off_out_ptr).unwrap_or(0);
    let out_use_off = off_out_ptr != 0;

    let mut transferred: usize = 0;
    while (transferred as u64) < len {
        let want = ((len - transferred as u64) as usize).min(CHUNK);
        let n = match if in_use_off {
            in_file.inode.clone().read_at(in_off, &mut buf[..want])
        } else {
            in_file.read(&mut buf[..want])
        } {
            Ok(n) => n,
            Err(e) => return e.errno(),
        };
        if n == 0 {
            break;
        }
        let w = match if out_use_off {
            out_file.inode.clone().write_at(out_off, &buf[..n])
        } else {
            out_file.write(&buf[..n])
        } {
            Ok(w) => w,
            Err(e) => return write_err_to_errno(e),
        };
        transferred += w;
        if in_use_off {
            in_off = in_off.saturating_add(w as u64);
        }
        if out_use_off {
            out_off = out_off.saturating_add(w as u64);
        }
        if w < n {
            break;
        }
    }
    if in_use_off {
        let _ = frame::user::copy_to_user(off_in_ptr, &in_off.to_le_bytes());
    }
    if out_use_off {
        let _ = frame::user::copy_to_user(off_out_ptr, &out_off.to_le_bytes());
    }
    transferred as i64
}

fn read_optional_off(ptr: u64) -> Result<u64, i64> {
    if ptr == 0 {
        return Ok(0);
    }
    let mut b = [0u8; 8];
    if frame::user::copy_from_user(ptr, &mut b).is_err() {
        return Err(EFAULT);
    }
    Ok(u64::from_le_bytes(b))
}

pub(super) fn sys_splice(
    fd_in: u64,
    off_in_ptr: u64,
    fd_out: u64,
    off_out_ptr: u64,
    len: u64,
    _flags: u64,
) -> i64 {
    sys_copy_file_range(fd_in, off_in_ptr, fd_out, off_out_ptr, len, 0)
}

pub(super) fn sys_tee(fd_in: u64, fd_out: u64, len: u64, _flags: u64) -> i64 {
    let f_in = match sched::with_current_fds(|t| t.get(fd_in as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let f_out = match sched::with_current_fds(|t| t.get(fd_out as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let chunk = (len as usize).min(4096);
    if chunk == 0 {
        return 0;
    }
    let mut buf = [0u8; 4096];
    let n = match f_in.inode.peek_at(&mut buf[..chunk]) {
        Ok(n) => n,
        Err(crate::vfs::FsError::NotSupported) => return EINVAL,
        Err(e) => return e.errno(),
    };
    if n == 0 {
        return 0;
    }
    match f_out.write(&buf[..n]) {
        Ok(written) => written as i64,
        Err(e) => write_err_to_errno(e),
    }
}

pub(super) fn sys_vmsplice(fd: u64, iov: u64, iovcnt: u64, _flags: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if file.flags().is_writable() {
        sys_writev(fd, iov, iovcnt)
    } else {
        sys_readv(fd, iov, iovcnt)
    }
}

pub(super) fn sys_pivot_root(new_root_ptr: u64, put_old_ptr: u64) -> i64 {
    let new_root_path = match copy_path(new_root_ptr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let put_old_path = match copy_path(put_old_ptr) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let new_root = match resolve_at_inode(AT_FDCWD, &new_root_path) {
        Ok(i) => i,
        Err(e) => return e,
    };
    if new_root.kind() != InodeKind::Directory {
        return ENOTDIR;
    }
    let put_old = match resolve_at_inode(AT_FDCWD, &put_old_path) {
        Ok(i) => i,
        Err(e) => return e,
    };
    if put_old.kind() != InodeKind::Directory {
        return ENOTDIR;
    }

    let ctx = vfs::path::Context::current();
    let old_root = ctx.root.clone();

    let new_root_norm = match resolve_user_path(AT_FDCWD, &new_root_path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let put_old_norm = match resolve_user_path(AT_FDCWD, &put_old_path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let install_path = if put_old_norm == new_root_norm {
        alloc::string::String::from("/")
    } else if let Some(rest) = put_old_norm.strip_prefix(&new_root_norm) {
        if rest.starts_with('/') {
            alloc::string::String::from(rest)
        } else {
            return EINVAL;
        }
    } else {
        return EINVAL;
    };
    ctx.install_mount(
        &install_path,
        put_old.inode_id(),
        old_root,
        vfs::MountPropagation::Private,
    );
    sched::set_current_fs_root(new_root.clone());
    sched::set_current_cwd(new_root, alloc::string::String::from("/"));
    0
}

pub(super) fn sys_openat2(dirfd: u64, pathname: u64, how_ptr: u64, size: u64) -> i64 {
    if size != 24 {
        return EINVAL;
    }
    let mut how = [0u8; 24];
    if frame::user::copy_from_user(how_ptr, &mut how).is_err() {
        return EFAULT;
    }
    let mut flags = u64::from_le_bytes(how[0..8].try_into().unwrap());
    let mode = u64::from_le_bytes(how[8..16].try_into().unwrap());
    let resolve = u64::from_le_bytes(how[16..24].try_into().unwrap());
    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    const RESOLVE_IN_ROOT: u64 = 0x10;
    const RESOLVE_CACHED: u64 = 0x20;
    const ALL_RESOLVE: u64 = RESOLVE_NO_XDEV
        | RESOLVE_NO_MAGICLINKS
        | RESOLVE_NO_SYMLINKS
        | RESOLVE_BENEATH
        | RESOLVE_IN_ROOT
        | RESOLVE_CACHED;
    if resolve & !ALL_RESOLVE != 0 {
        return EINVAL;
    }
    if resolve & RESOLVE_NO_SYMLINKS != 0 {
        const O_NOFOLLOW: u64 = 0o400000;
        flags |= O_NOFOLLOW;
    }
    sys_openat(dirfd, pathname, flags, mode)
}

pub(super) fn sys_setxattrat(
    dirfd: u64,
    pathname: u64,
    _at_flags: u64,
    name: u64,
    value: u64,
    size: u64,
) -> i64 {
    sys_setxattr_inner(dirfd, pathname, name, value, size, 0, false)
}

pub(super) fn sys_getxattrat(
    dirfd: u64,
    pathname: u64,
    _at_flags: u64,
    name: u64,
    value_size: u64,
) -> i64 {
    sys_getxattr_inner(dirfd, pathname, name, 0, value_size)
}

pub(super) fn sys_listxattrat(dirfd: u64, pathname: u64, _at_flags: u64, list_size: u64) -> i64 {
    sys_listxattr_inner(dirfd, pathname, 0, list_size)
}

pub(super) fn sys_removexattrat(dirfd: u64, pathname: u64, _at_flags: u64) -> i64 {
    sys_removexattr_inner(dirfd, pathname, 0)
}

pub(super) fn sys_close_range(first: u64, last: u64, _flags: u64) -> i64 {
    if first > last {
        return EINVAL;
    }
    sched::with_current_fds(|t| {
        for fd in (first as i32)..=(last as i32) {
            let _ = t.remove(fd);
        }
    });
    0
}

const UTIME_NOW: i64 = 0x3fff_ffff;
const UTIME_OMIT: i64 = 0x3fff_fffe;

pub(super) fn sys_utimensat(dirfd: u64, pathname: u64, times_ptr: u64, _flags: u64) -> i64 {
    let inode = if pathname == 0 {
        match sched::with_current_fds(|t| t.get(dirfd as i32)) {
            Some(f) => f.inode.clone(),
            None => return EBADF,
        }
    } else {
        match resolve_path(dirfd, pathname, true) {
            Ok(i) => i,
            Err(e) => return e,
        }
    };
    let now = TimeSpec {
        sec: (frame::cpu::clock::wall_clock_nanos() / 1_000_000_000) as i64,
        nsec: (frame::cpu::clock::wall_clock_nanos() % 1_000_000_000) as i32,
    };
    let (atime, mtime) = if times_ptr == 0 {
        (Some(now), Some(now))
    } else {
        let t0 = read_timespec(times_ptr);
        let t1 = read_timespec(times_ptr + 16);
        let parse = |t: Result<TimeSpec, i64>| -> Result<Option<TimeSpec>, i64> {
            let v = t?;
            Ok(match v.nsec as i64 {
                UTIME_NOW => Some(now),
                UTIME_OMIT => None,
                _ => Some(v),
            })
        };
        let a = match parse(t0) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let m = match parse(t1) {
            Ok(v) => v,
            Err(e) => return e,
        };
        (a, m)
    };
    match inode.set_times(atime, mtime) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_setxattr(
    path: u64,
    name: u64,
    value: u64,
    size: u64,
    flags: u64,
    no_follow: bool,
) -> i64 {
    sys_setxattr_inner(AT_FDCWD as u64, path, name, value, size, flags, no_follow)
}

pub(super) fn sys_setxattr_inner(
    dirfd: u64,
    path: u64,
    name: u64,
    value: u64,
    size: u64,
    flags: u64,
    no_follow: bool,
) -> i64 {
    let _ = no_follow;
    let inode = match resolve_path(dirfd, path, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let n = match copy_xname(name) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut buf = alloc::vec![0u8; size as usize];
    if size > 0 && frame::user::copy_from_user(value, &mut buf).is_err() {
        return EFAULT;
    }
    match inode.set_xattr(&n, &buf, flags as u32) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_fsetxattr(fd: u64, name: u64, value: u64, size: u64, flags: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let n = match copy_xname(name) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut buf = alloc::vec![0u8; size as usize];
    if size > 0 && frame::user::copy_from_user(value, &mut buf).is_err() {
        return EFAULT;
    }
    match file.inode.set_xattr(&n, &buf, flags as u32) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_getxattr(path: u64, name: u64, value: u64, size: u64) -> i64 {
    sys_getxattr_inner(AT_FDCWD as u64, path, name, value, size)
}

pub(super) fn sys_getxattr_inner(dirfd: u64, path: u64, name: u64, value: u64, size: u64) -> i64 {
    let inode = match resolve_path(dirfd, path, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let n = match copy_xname(name) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut buf = alloc::vec![0u8; size as usize];
    let got = match inode.get_xattr(&n, &mut buf) {
        Ok(g) => g,
        Err(e) => return e.errno(),
    };
    if size > 0 && got <= size as usize && frame::user::copy_to_user(value, &buf[..got]).is_err() {
        return EFAULT;
    }
    got as i64
}

pub(super) fn sys_fgetxattr(fd: u64, name: u64, value: u64, size: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let n = match copy_xname(name) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let mut buf = alloc::vec![0u8; size as usize];
    let got = match file.inode.get_xattr(&n, &mut buf) {
        Ok(g) => g,
        Err(e) => return e.errno(),
    };
    if size > 0 && got <= size as usize && frame::user::copy_to_user(value, &buf[..got]).is_err() {
        return EFAULT;
    }
    got as i64
}

pub(super) fn sys_listxattr(path: u64, list: u64, size: u64) -> i64 {
    sys_listxattr_inner(AT_FDCWD as u64, path, list, size)
}

pub(super) fn sys_listxattr_inner(dirfd: u64, path: u64, list: u64, size: u64) -> i64 {
    let inode = match resolve_path(dirfd, path, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let mut buf = alloc::vec![0u8; size as usize];
    let n = match inode.list_xattr(&mut buf) {
        Ok(n) => n,
        Err(e) => return e.errno(),
    };
    if size > 0 && n <= size as usize && frame::user::copy_to_user(list, &buf[..n]).is_err() {
        return EFAULT;
    }
    n as i64
}

pub(super) fn sys_flistxattr(fd: u64, list: u64, size: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let mut buf = alloc::vec![0u8; size as usize];
    let n = match file.inode.list_xattr(&mut buf) {
        Ok(n) => n,
        Err(e) => return e.errno(),
    };
    if size > 0 && n <= size as usize && frame::user::copy_to_user(list, &buf[..n]).is_err() {
        return EFAULT;
    }
    n as i64
}

pub(super) fn sys_removexattr(path: u64, name: u64) -> i64 {
    sys_removexattr_inner(AT_FDCWD as u64, path, name)
}

pub(super) fn sys_removexattr_inner(dirfd: u64, path: u64, name: u64) -> i64 {
    let inode = match resolve_path(dirfd, path, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let n = match copy_xname(name) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match inode.remove_xattr(&n) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_fremovexattr(fd: u64, name: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let n = match copy_xname(name) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match file.inode.remove_xattr(&n) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_readahead(fd: u64, _offset: u64, _count: u64) -> i64 {
    let kind = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(of) => of.inode.kind(),
        None => return EBADF,
    };
    if !matches!(kind, crate::vfs::InodeKind::Regular) {
        return EINVAL;
    }
    0
}

pub(super) fn sys_memfd_create(name_ptr: u64, flags: u64) -> i64 {
    if sched::with_current_process(|p| p.did_memfd_exec.load(core::sync::atomic::Ordering::Acquire))
        .unwrap_or(false)
    {
        return -38;
    }
    const MFD_CLOEXEC: u64 = 0x0001;
    const MFD_ALLOW_SEALING: u64 = 0x0002;
    const MFD_HUGETLB: u64 = 0x0004;
    const MFD_NOEXEC_SEAL: u64 = 0x0008;
    const MFD_EXEC: u64 = 0x0010;

    let known = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_NOEXEC_SEAL | MFD_EXEC;
    if (flags & !known) != 0 {
        return EINVAL;
    }
    if (flags & MFD_HUGETLB) != 0 {
        return EINVAL;
    }
    let _name = match read_user_cstr(name_ptr, 249) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let inode = crate::fs::tmpfs::TmpfsInode::new_file();
    let inode_dyn: Arc<dyn Inode> = inode;
    let file = Arc::new(OpenFile::new(inode_dyn, OpenFlags::RDWR));
    let fd_flags = if (flags & MFD_CLOEXEC) != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    match sched::with_current_fds(|t| t.install_from(file, 0, fd_flags)) {
        Ok(fd) => fd as i64,
        Err(e) => e as i64,
    }
}
