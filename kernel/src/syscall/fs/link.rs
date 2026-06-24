use super::*;

pub(crate) fn sys_unlinkat(dirfd: u64, pathname: u64, flags: u64) -> i64 {
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
    if ctx.parent_mount_flags(&ctx.root, &normalized) & vfs::mount::MS_RDONLY != 0 {
        return crate::errno::EROFS;
    }
    let (parent, leaf) = match vfs::path::resolve_parent(&ctx, &ctx.root, &normalized) {
        Ok(p) => p,
        Err(e) => return e.as_neg_i64(),
    };
    let target = match parent.lookup(leaf) {
        Ok(t) => t,
        Err(e) => return e.as_neg_i64(),
    };
    if vfs::is_mountpoint_inode(Some(&ctx.mounts), target.inode_id()) {
        return EBUSY;
    }
    let want_dir = (flags & AT_REMOVEDIR) != 0;
    let is_dir = target.kind() == InodeKind::Directory;
    if want_dir && !is_dir {
        return ENOTDIR;
    }
    if !want_dir && is_dir {
        return EISDIR;
    }
    if is_dir {
        match parent.rmdir(leaf) {
            Ok(()) => return 0,
            Err(e) => return e.as_neg_i64(),
        }
    }
    match parent.unlink(leaf) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_renameat(olddirfd: u64, oldpath: u64, newdirfd: u64, newpath: u64) -> i64 {
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
    if ctx.parent_mount_flags(&ctx.root, &old_norm) & vfs::mount::MS_RDONLY != 0
        || ctx.parent_mount_flags(&ctx.root, &new_norm) & vfs::mount::MS_RDONLY != 0
    {
        return crate::errno::EROFS;
    }
    let (old_parent, old_leaf) = match vfs::path::resolve_parent(&ctx, &ctx.root, &old_norm) {
        Ok(p) => p,
        Err(e) => return e.as_neg_i64(),
    };
    let (new_parent, new_leaf) = match vfs::path::resolve_parent(&ctx, &ctx.root, &new_norm) {
        Ok(p) => p,
        Err(e) => return e.as_neg_i64(),
    };
    let old_leaf = old_leaf.to_string();
    let new_leaf = new_leaf.to_string();
    if old_parent.fs_id() != new_parent.fs_id() {
        return crate::errno::EXDEV;
    }
    if let Ok(src) = old_parent.lookup(&old_leaf) {
        if src.kind() == InodeKind::Directory
            && new_norm.len() > old_norm.len()
            && new_norm.starts_with(&old_norm)
            && new_norm.as_bytes()[old_norm.len()] == b'/'
        {
            return EINVAL;
        }
    }
    match old_parent.rename(&old_leaf, &new_parent, &new_leaf) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_linkat(
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
    if ctx.parent_mount_flags(&ctx.root, &new_norm) & vfs::mount::MS_RDONLY != 0 {
        return crate::errno::EROFS;
    }
    let target = match vfs::path::resolve(&ctx, &ctx.root, &old_norm) {
        Ok(t) => t,
        Err(e) => return e.as_neg_i64(),
    };
    if target.kind() == InodeKind::Directory {
        return EPERM;
    }
    let (new_parent, new_leaf) = match vfs::path::resolve_parent(&ctx, &ctx.root, &new_norm) {
        Ok(p) => p,
        Err(e) => return e.as_neg_i64(),
    };
    match new_parent.attach(new_leaf, target) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_symlinkat(target: u64, newdirfd: u64, linkpath: u64) -> i64 {
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
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_readlinkat(dirfd: u64, pathname: u64, buf: u64, bufsize: u64) -> i64 {
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
        Err(e) => return e.as_neg_i64(),
    };
    let target = match inode.read_link() {
        Ok(t) => t,
        Err(e) => return e.as_neg_i64(),
    };
    let bytes = target.as_bytes();
    let n = bytes.len().min(bufsize as usize);
    if n > 0 && frame::user::copy_to_user(buf, &bytes[..n]).is_err() {
        return EFAULT;
    }
    n as i64
}

pub(crate) fn sys_renameat2(
    olddirfd: u64,
    oldpath: u64,
    newdirfd: u64,
    newpath: u64,
    flags: u64,
) -> i64 {
    const RENAME_NOREPLACE: u64 = 1;
    const RENAME_EXCHANGE: u64 = 2;
    const RENAME_WHITEOUT: u64 = 4;
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
        return EINVAL;
    }
    if flags & RENAME_WHITEOUT != 0 {
        return crate::errno::EINVAL;
    }
    if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
        return EINVAL;
    }
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
    if ctx.parent_mount_flags(&ctx.root, &old_norm) & vfs::mount::MS_RDONLY != 0
        || ctx.parent_mount_flags(&ctx.root, &new_norm) & vfs::mount::MS_RDONLY != 0
    {
        return crate::errno::EROFS;
    }
    let (old_parent, old_name) = match vfs::path::resolve_parent(&ctx, &ctx.root, &old_norm) {
        Ok(x) => x,
        Err(e) => return e.as_neg_i64(),
    };
    let (new_parent, new_name) = match vfs::path::resolve_parent(&ctx, &ctx.root, &new_norm) {
        Ok(x) => x,
        Err(e) => return e.as_neg_i64(),
    };
    if old_parent.fs_id() != new_parent.fs_id() {
        return crate::errno::EXDEV;
    }
    if let Ok(src) = old_parent.lookup(old_name) {
        if src.kind() == InodeKind::Directory
            && new_norm.len() > old_norm.len()
            && new_norm.starts_with(&old_norm)
            && new_norm.as_bytes()[old_norm.len()] == b'/'
        {
            return EINVAL;
        }
    }
    if flags & RENAME_EXCHANGE != 0 {
        return match old_parent.rename_exchange(old_name, &new_parent, new_name) {
            Ok(()) => 0,
            Err(e) => e.as_neg_i64(),
        };
    }
    if flags & RENAME_NOREPLACE != 0 && new_parent.lookup(new_name).is_ok() {
        return crate::errno::EEXIST;
    }
    match old_parent.rename(old_name, &new_parent, new_name) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}
