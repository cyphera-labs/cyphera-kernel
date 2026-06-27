use super::*;

pub(crate) fn sys_chdir(pathname: u64) -> i64 {
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
        Err(e) => return e.as_neg_i64(),
    };
    if inode.kind() != InodeKind::Directory {
        return ENOTDIR;
    }
    sched::set_current_cwd(inode, normalized);
    0
}

pub(crate) fn sys_getcwd(buf: u64, size: u64) -> i64 {
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

pub(crate) fn sys_getdents(fd: u64, dirp: u64, count: u64) -> i64 {
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
        Err(e) => return e.as_neg_i64(),
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
            InodeKind::Socket => 12,
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

pub(crate) fn sys_getdents64(fd: u64, dirp: u64, count: u64) -> i64 {
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
        Err(e) => return e.as_neg_i64(),
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
            InodeKind::Socket => 12,
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

pub(crate) fn sys_mkdirat(dirfd: u64, pathname: u64, mode: u64) -> i64 {
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
        return EEXIST;
    }
    let (parent, leaf) = match resolve_at_parent(dirfd as i64, path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    match parent.create(&leaf, InodeKind::Directory) {
        Ok(i) => {
            apply_create_owner(&i);
            apply_create_mode(&i, mode as u16);
            if crate::fsnotify::watching() {
                crate::fsnotify::dir_event(
                    parent.as_ref(),
                    &leaf,
                    true,
                    crate::fsnotify::IN_CREATE,
                );
            }
            0
        }
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_mknodat(dirfd: u64, pathname: u64, mode: u64, dev: u64) -> i64 {
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
    if kind == InodeKind::CharDevice {
        let mnt_owner =
            sched::with_current_mount_table(|m| m.as_ref().and_then(|t| t.owner_user_ns()))
                .flatten();
        if !crate::security::capable_in(crate::process_model::CAP_MKNOD, mnt_owner.as_ref()) {
            return EPERM;
        }
    }
    match parent.mknod(&leaf, kind, dev) {
        Ok(i) => {
            apply_create_owner(&i);
            apply_create_mode(&i, mode as u16);
            0
        }
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_chroot(pathname: u64) -> i64 {
    let mnt_owner =
        sched::with_current_mount_table(|m| m.as_ref().and_then(|t| t.owner_user_ns())).flatten();
    if !crate::security::capable_in(crate::process_model::CAP_SYS_CHROOT, mnt_owner.as_ref()) {
        return EPERM;
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

pub(crate) fn sys_fchdir(fd: u64) -> i64 {
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
