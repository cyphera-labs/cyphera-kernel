use super::*;

pub(crate) fn sys_setxattrat(
    dirfd: u64,
    pathname: u64,
    _at_flags: u64,
    name: u64,
    value: u64,
    size: u64,
) -> i64 {
    sys_setxattr_inner(dirfd, pathname, name, value, size, 0, false)
}

pub(crate) fn sys_getxattrat(
    dirfd: u64,
    pathname: u64,
    _at_flags: u64,
    name: u64,
    value_size: u64,
) -> i64 {
    sys_getxattr_inner(dirfd, pathname, name, 0, value_size)
}

pub(crate) fn sys_listxattrat(dirfd: u64, pathname: u64, _at_flags: u64, list_size: u64) -> i64 {
    sys_listxattr_inner(dirfd, pathname, 0, list_size)
}

pub(crate) fn sys_removexattrat(dirfd: u64, pathname: u64, _at_flags: u64) -> i64 {
    sys_removexattr_inner(dirfd, pathname, 0)
}

pub(crate) fn sys_setxattr(
    path: u64,
    name: u64,
    value: u64,
    size: u64,
    flags: u64,
    no_follow: bool,
) -> i64 {
    sys_setxattr_inner(AT_FDCWD as u64, path, name, value, size, flags, no_follow)
}

pub(crate) fn sys_setxattr_inner(
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
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_fsetxattr(fd: u64, name: u64, value: u64, size: u64, flags: u64) -> i64 {
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
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_getxattr(path: u64, name: u64, value: u64, size: u64) -> i64 {
    sys_getxattr_inner(AT_FDCWD as u64, path, name, value, size)
}

pub(crate) fn sys_getxattr_inner(dirfd: u64, path: u64, name: u64, value: u64, size: u64) -> i64 {
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
        Err(e) => return e.as_neg_i64(),
    };
    if size > 0 && got <= size as usize && frame::user::copy_to_user(value, &buf[..got]).is_err() {
        return EFAULT;
    }
    got as i64
}

pub(crate) fn sys_fgetxattr(fd: u64, name: u64, value: u64, size: u64) -> i64 {
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
        Err(e) => return e.as_neg_i64(),
    };
    if size > 0 && got <= size as usize && frame::user::copy_to_user(value, &buf[..got]).is_err() {
        return EFAULT;
    }
    got as i64
}

pub(crate) fn sys_listxattr(path: u64, list: u64, size: u64) -> i64 {
    sys_listxattr_inner(AT_FDCWD as u64, path, list, size)
}

pub(crate) fn sys_listxattr_inner(dirfd: u64, path: u64, list: u64, size: u64) -> i64 {
    let inode = match resolve_path(dirfd, path, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let mut buf = alloc::vec![0u8; size as usize];
    let n = match inode.list_xattr(&mut buf) {
        Ok(n) => n,
        Err(e) => return e.as_neg_i64(),
    };
    if size > 0 && n <= size as usize && frame::user::copy_to_user(list, &buf[..n]).is_err() {
        return EFAULT;
    }
    n as i64
}

pub(crate) fn sys_flistxattr(fd: u64, list: u64, size: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let mut buf = alloc::vec![0u8; size as usize];
    let n = match file.inode.list_xattr(&mut buf) {
        Ok(n) => n,
        Err(e) => return e.as_neg_i64(),
    };
    if size > 0 && n <= size as usize && frame::user::copy_to_user(list, &buf[..n]).is_err() {
        return EFAULT;
    }
    n as i64
}

pub(crate) fn sys_removexattr(path: u64, name: u64) -> i64 {
    sys_removexattr_inner(AT_FDCWD as u64, path, name)
}

pub(crate) fn sys_removexattr_inner(dirfd: u64, path: u64, name: u64) -> i64 {
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
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_fremovexattr(fd: u64, name: u64) -> i64 {
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
        Err(e) => e.as_neg_i64(),
    }
}
