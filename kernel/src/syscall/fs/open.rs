use super::*;

pub(crate) fn sys_close(fd: u64) -> i64 {
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

type ResolvedOpen = Result<(Arc<dyn vfs::Inode>, Option<vfs::MountInUseGuard>, bool), i64>;

fn resolve_or_create_regular(
    ctx: &vfs::path::Context,
    base: &Arc<dyn vfs::Inode>,
    path: &str,
    open_flags: OpenFlags,
    mode: u64,
) -> ResolvedOpen {
    match vfs::path::resolve_with_mount(ctx, base, path) {
        Ok((inode, tag)) => {
            if open_flags.contains(OpenFlags::CREAT) && open_flags.contains(OpenFlags::EXCL) {
                return Err(EEXIST);
            }
            Ok((inode, tag.map(vfs::MountInUseGuard::new), false))
        }
        Err(Errno::NOENT) if open_flags.contains(OpenFlags::CREAT) => {
            let (parent, leaf) =
                vfs::path::resolve_parent(ctx, base, path).map_err(|e| e.as_neg_i64())?;
            if ctx.parent_mount_flags(base, path) & vfs::mount::MS_RDONLY != 0 {
                return Err(crate::errno::EROFS);
            }
            let inode = parent
                .create(leaf, InodeKind::Regular)
                .map_err(|e| e.as_neg_i64())?;
            apply_create_owner(&inode);
            apply_create_mode(&inode, mode as u16);
            let tag = vfs::path::resolve_with_mount(ctx, base, path)
                .ok()
                .and_then(|(_, t)| t);
            Ok((inode, tag.map(vfs::MountInUseGuard::new), true))
        }
        Err(e) => Err(e.as_neg_i64()),
    }
}

fn check_open_access(inode: &Arc<dyn vfs::Inode>, open_flags: OpenFlags) -> Result<(), i64> {
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
            return Err(EACCES);
        }
    }
    Ok(())
}

fn finish_open(
    inode: Arc<dyn vfs::Inode>,
    open_flags: OpenFlags,
    mount_guard: Option<vfs::MountInUseGuard>,
    path: String,
) -> i64 {
    if open_flags.contains(OpenFlags::DIRECTORY) && inode.kind() != InodeKind::Directory {
        return ENOTDIR;
    }
    if inode.kind() == InodeKind::Directory
        && (open_flags.is_writable() || open_flags.contains(OpenFlags::TRUNC))
    {
        return crate::errno::EISDIR;
    }
    let mount_flags = mount_guard.as_ref().map(|g| g.flags()).unwrap_or(0);
    if mount_flags & vfs::mount::MS_RDONLY != 0
        && (open_flags.is_writable()
            || open_flags.contains(OpenFlags::TRUNC)
            || open_flags.contains(OpenFlags::CREAT))
    {
        return crate::errno::EROFS;
    }
    if mount_flags & vfs::mount::MS_NODEV != 0 && inode.kind() == InodeKind::CharDevice {
        return EACCES;
    }
    if open_flags.contains(OpenFlags::TRUNC)
        && open_flags.is_writable()
        && inode.kind() == InodeKind::Regular
    {
        if let Err(e) = inode.truncate(0) {
            return e.as_neg_i64();
        }
    }
    let file = Arc::new(OpenFile::new_with_mount(inode, open_flags, mount_guard).with_path(path));
    match sched::with_current_fds(|t| t.install(file)) {
        Ok(fd) => fd as i64,
        Err(_) => EMFILE,
    }
}

fn open_dev_pty(normalized: &str, flags: u64) -> Option<i64> {
    if normalized == "/dev/ptmx" {
        let pty = crate::device::pty::allocate_pair();
        let master: Arc<dyn vfs::Inode> = Arc::new(crate::device::pty::MasterInode(pty));
        let open_flags = OpenFlags::from_bits_truncate(flags as u32);
        let file = Arc::new(vfs::OpenFile::new(master, open_flags));
        return Some(match sched::with_current_fds(|t| t.install(file)) {
            Ok(fd) => fd as i64,
            Err(e) => e as i64,
        });
    }
    if let Some(rest) = normalized.strip_prefix("/dev/pts/") {
        if let Ok(n) = rest.parse::<u32>() {
            if let Some(pty) = crate::device::pty::lookup(n) {
                let slave: Arc<dyn vfs::Inode> = Arc::new(crate::device::pty::SlaveInode(pty));
                let open_flags = OpenFlags::from_bits_truncate(flags as u32);
                let file = Arc::new(vfs::OpenFile::new(slave, open_flags));
                return Some(match sched::with_current_fds(|t| t.install(file)) {
                    Ok(fd) => fd as i64,
                    Err(e) => e as i64,
                });
            }
        }
    }
    None
}

pub(crate) fn sys_openat(dirfd: u64, pathname: u64, flags: u64, mode: u64) -> i64 {
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
            return ENOTDIR;
        }
        let ctx = vfs::path::Context::current();
        let open_flags = OpenFlags::from_bits_truncate(flags as u32);
        let child_path = if dir_file.path.is_empty() {
            String::new()
        } else {
            vfs::path::normalize(&dir_file.path, path)
        };
        let (inode, mount_guard, created) = if child_path.is_empty() {
            match resolve_or_create_regular(&ctx, &dir_file.inode, path, open_flags, mode) {
                Ok(t) => t,
                Err(e) => return e,
            }
        } else {
            match resolve_or_create_regular(&ctx, &ctx.root, &child_path, open_flags, mode) {
                Ok(t) => t,
                Err(e) => return e,
            }
        };
        if !created {
            if let Err(e) = check_open_access(&inode, open_flags) {
                return e;
            }
        }
        return finish_open(inode, open_flags, mount_guard, child_path);
    }

    let normalized = match resolve_user_path(dirfd as i64, path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    if let Some(r) = open_dev_pty(&normalized, flags) {
        return r;
    }

    let open_flags = OpenFlags::from_bits_truncate(flags as u32);
    let ctx = vfs::path::Context::current();
    let (inode, mount_guard, created) =
        match resolve_or_create_regular(&ctx, &ctx.root, &normalized, open_flags, mode) {
            Ok(t) => t,
            Err(e) => return e,
        };
    if !created {
        if let Err(e) = check_open_access(&inode, open_flags) {
            return e;
        }
    }
    finish_open(inode, open_flags, mount_guard, normalized)
}

pub(crate) fn sys_openat2(dirfd: u64, pathname: u64, how_ptr: u64, size: u64) -> i64 {
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

pub(crate) fn sys_close_range(first: u64, last: u64, _flags: u64) -> i64 {
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

pub(crate) fn sys_memfd_create(name_ptr: u64, flags: u64) -> i64 {
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

    let allow_sealing = (flags & MFD_ALLOW_SEALING) != 0;
    let inode = crate::fs::tmpfs::TmpfsInode::new_memfd(allow_sealing);
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
