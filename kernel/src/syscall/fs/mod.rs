use alloc::string::{String, ToString};
use alloc::sync::Arc;

use cyphera_kapi::Errno;

use crate::core as sched;
use crate::errno::{
    EACCES, EAGAIN, EBADF, EBUSY, EEXIST, EFAULT, EINVAL, EIO, EISDIR, EMFILE, ENAMETOOLONG,
    ENODEV, ENOENT, ENOSYS, ENOTDIR, EPERM, ERANGE,
};
use crate::vfs::blocking::{IoAttempt, block_io};
use crate::vfs::{self, Inode, InodeKind, OpenFile, OpenFlags, Stat, TimeSpec, Whence};

use super::util::{read_timespec, read_user_cstr};
use super::{AT_FDCWD, PATH_MAX};

mod dir;
mod file_io;
mod ioctl;
mod link;
mod locks;
mod meta;
mod mount;
mod open;
mod xattr;

pub(crate) use dir::{
    sys_chdir, sys_chroot, sys_fchdir, sys_getcwd, sys_getdents, sys_getdents64, sys_mkdirat,
    sys_mknodat,
};
pub(crate) use file_io::{
    sys_copy_file_range, sys_dup, sys_dup2, sys_dup3, sys_fadvise64, sys_fallocate, sys_fsync,
    sys_ftruncate, sys_lseek, sys_pipe, sys_pipe2, sys_pread64, sys_preadv, sys_pwrite64,
    sys_pwritev, sys_read, sys_readahead, sys_readv, sys_sendfile, sys_splice, sys_sync_file_range,
    sys_tee, sys_truncate, sys_vmsplice, sys_write, sys_writev,
};
pub(crate) use ioctl::DEFAULT_TERMIOS;
pub(crate) use ioctl::sys_ioctl;
pub use ioctl::{console_fg_pgrp, termios_get_pub};
pub(crate) use link::{
    sys_linkat, sys_readlinkat, sys_renameat, sys_renameat2, sys_symlinkat, sys_unlinkat,
};
pub(crate) use locks::{sys_fcntl, sys_flock};
pub(crate) use meta::{
    sys_faccessat, sys_fchmod, sys_fchmodat, sys_fchown, sys_fchownat, sys_fstat, sys_newfstatat,
    sys_stat, sys_statfs, sys_statx, sys_utimensat,
};
pub(crate) use mount::{sys_mount, sys_pivot_root, sys_umount2};
pub(crate) use open::{sys_close, sys_close_range, sys_memfd_create, sys_openat, sys_openat2};
pub(crate) use xattr::{
    sys_fgetxattr, sys_flistxattr, sys_fremovexattr, sys_fsetxattr, sys_getxattr, sys_getxattrat,
    sys_listxattr, sys_listxattrat, sys_removexattr, sys_removexattrat, sys_setxattr,
    sys_setxattrat,
};

const AT_REMOVEDIR: u64 = 0x200;

pub(super) const WRITE_BUF_MAX: usize = 1024 * 1024;
pub(super) const READ_BUF_MAX: usize = 256 * 1024;
const DIRENT_BUF_MAX: usize = 4096;
const GETCWD_BUF_MAX: usize = 4096;

pub(crate) fn resolve_user_path(dirfd: i64, path: &str) -> Result<String, i64> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    if path.starts_with('/') {
        return Ok(vfs::path::normalize("/", path));
    }
    if dirfd != AT_FDCWD {
        let dir = match sched::with_current_fds(|t| t.get(dirfd as i32)) {
            Some(f) => f,
            None => return Err(EBADF),
        };
        if dir.path.is_empty() {
            return Err(ENOSYS);
        }
        return Ok(vfs::path::normalize(&dir.path, path));
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
        return vfs::path::resolve(&ctx, &ctx.root, path).map_err(|e| e.as_neg_i64());
    }
    let start = if dirfd == AT_FDCWD {
        sched::with_current_cwd(|c| c.inode.clone()).unwrap_or_else(|| ctx.root.clone())
    } else {
        let f = sched::with_current_fds(|t| t.get(dirfd as i32)).ok_or(EBADF)?;
        if f.inode.kind() != InodeKind::Directory {
            return Err(ENOTDIR);
        }
        f.inode.clone()
    };
    vfs::path::resolve(&ctx, &start, path).map_err(|e| e.as_neg_i64())
}

pub(super) fn resolve_at_parent(
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
            return Err(ENOTDIR);
        }
        (f.inode.clone(), path)
    };
    let (parent, leaf) =
        vfs::path::resolve_parent(&ctx, &start_inode, search_path).map_err(|e| e.as_neg_i64())?;
    if ctx.parent_mount_flags(&start_inode, search_path) & vfs::mount::MS_RDONLY != 0 {
        return Err(crate::errno::EROFS);
    }
    Ok((parent, leaf.to_string()))
}

pub(super) const IOV_MAX: usize = 1024;

pub(super) fn read_iovecs(iov: u64, count: u64) -> Result<alloc::vec::Vec<(u64, usize)>, i64> {
    if count > IOV_MAX as u64 {
        return Err(EINVAL);
    }
    if count == 0 {
        return Ok(alloc::vec::Vec::new());
    }
    let bytes = (count as usize) * 16;
    let mut raw = alloc::vec![0u8; bytes];
    if frame::user::copy_from_user(iov, &mut raw).is_err() {
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

pub(super) fn apply_create_owner(inode: &alloc::sync::Arc<dyn vfs::Inode>) {
    let (euid, egid) = sched::with_current_creds(|c| (c.euid, c.egid));
    let _ = inode.set_owner(Some(euid), Some(egid));
}

fn apply_create_mode(inode: &alloc::sync::Arc<dyn vfs::Inode>, mode: u16) {
    let perm = (mode & 0o7777) & !sched::current_umask();
    let _ = inode.set_mode(perm);
}

fn resolve_path(dirfd: u64, pathname: u64, follow: bool) -> Result<Arc<dyn Inode>, i64> {
    let mut path_buf = [0u8; PATH_MAX];
    let len =
        frame::user::copy_cstr_from_user(pathname, &mut path_buf).map_err(|_| ENAMETOOLONG)?;
    let path = core::str::from_utf8(&path_buf[..len]).map_err(|_| EINVAL)?;
    let normalized = resolve_user_path(dirfd as i64, path)?;
    let ctx = vfs::path::Context::current();
    if follow {
        vfs::path::resolve(&ctx, &ctx.root, &normalized).map_err(|e| e.as_neg_i64())
    } else {
        vfs::path::resolve_no_follow(&ctx, &ctx.root, &normalized).map_err(|e| e.as_neg_i64())
    }
}

pub(super) fn fd_mount_is_rdonly(file: &Arc<vfs::OpenFile>) -> bool {
    file._mount_guard.as_ref().map(|g| g.flags()).unwrap_or(0) & vfs::mount::MS_RDONLY != 0
}

fn resolve_path_writable(dirfd: u64, pathname: u64, follow: bool) -> Result<Arc<dyn Inode>, i64> {
    let mut path_buf = [0u8; PATH_MAX];
    let len =
        frame::user::copy_cstr_from_user(pathname, &mut path_buf).map_err(|_| ENAMETOOLONG)?;
    let path = core::str::from_utf8(&path_buf[..len]).map_err(|_| EINVAL)?;
    let normalized = resolve_user_path(dirfd as i64, path)?;
    let ctx = vfs::path::Context::current();
    let (inode, tag) = if follow {
        vfs::path::resolve_with_mount(&ctx, &ctx.root, &normalized).map_err(|e| e.as_neg_i64())?
    } else {
        vfs::path::resolve_no_follow_with_mount(&ctx, &ctx.root, &normalized)
            .map_err(|e| e.as_neg_i64())?
    };
    if tag.map(|t| t.flags()).unwrap_or(0) & vfs::mount::MS_RDONLY != 0 {
        return Err(crate::errno::EROFS);
    }
    Ok(inode)
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
