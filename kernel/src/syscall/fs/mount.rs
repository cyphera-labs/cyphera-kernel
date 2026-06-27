use super::*;

fn canon_proc_fd(norm: alloc::string::String) -> alloc::string::String {
    let cur = sched::current_pid().0;
    let pid_prefix = alloc::format!("/proc/{cur}/fd/");
    let rest: alloc::string::String = match norm
        .strip_prefix("/proc/self/fd/")
        .or_else(|| norm.strip_prefix(pid_prefix.as_str()))
    {
        Some(r) => alloc::string::String::from(r),
        None => return norm,
    };
    let (fd_str, sub) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest.as_str(), ""),
    };
    let fd: i32 = match fd_str.parse() {
        Ok(n) => n,
        Err(_) => return norm,
    };
    match sched::with_current_fds(|t| t.get(fd)) {
        Some(f) if !f.path.is_empty() => alloc::format!("{}{}", f.path, sub),
        _ => norm,
    }
}

fn resolve_mount_path(dirfd: i64, path: &str) -> Result<alloc::string::String, i64> {
    Ok(canon_proc_fd(resolve_user_path(dirfd, path)?))
}

pub(crate) fn sys_mount(source: u64, target: u64, fs_type: u64, flags: u64, _data: u64) -> i64 {
    let mnt_owner =
        sched::with_current_mount_table(|m| m.as_ref().and_then(|t| t.owner_user_ns())).flatten();
    if !crate::security::capable_in(crate::process_model::CAP_SYS_ADMIN, mnt_owner.as_ref()) {
        return EPERM;
    }
    use vfs::mount as m;

    if (flags & m::PROPAGATION_MASK) != 0 && (flags & m::MS_BIND) == 0 {
        let mut tbuf = [0u8; PATH_MAX];
        let tlen = match frame::user::copy_cstr_from_user(target, &mut tbuf) {
            Ok(n) => n,
            Err(_) => return ENAMETOOLONG,
        };
        let t = match core::str::from_utf8(&tbuf[..tlen]) {
            Ok(p) => p,
            Err(_) => return EINVAL,
        };
        let t_norm = match resolve_mount_path(AT_FDCWD, t) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ctx = vfs::path::Context::current();
        return m::change_propagation(&ctx, &t_norm, flags);
    }

    if (flags & m::MS_MOVE) != 0 {
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
        let s_norm = match resolve_mount_path(AT_FDCWD, s) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let t_norm = match resolve_mount_path(AT_FDCWD, t) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ctx = vfs::path::Context::current();
        return m::move_mount(&ctx, &s_norm, &t_norm);
    }

    if (flags & m::MS_REMOUNT) != 0 {
        let mut tbuf = [0u8; PATH_MAX];
        let tlen = match frame::user::copy_cstr_from_user(target, &mut tbuf) {
            Ok(n) => n,
            Err(_) => return ENAMETOOLONG,
        };
        let t = match core::str::from_utf8(&tbuf[..tlen]) {
            Ok(p) => p,
            Err(_) => return EINVAL,
        };
        let t_norm = match resolve_mount_path(AT_FDCWD, t) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ctx = vfs::path::Context::current();
        let mf = flags & m::MOUNT_FLAG_MASK;
        if ctx.set_mount_flags(&t_norm, mf) {
            return 0;
        }
        if let Ok(inode) = vfs::path::resolve(&ctx, &ctx.root, &t_norm) {
            if ctx.set_mount_flags_by_inode(inode.inode_id(), mf) {
                return 0;
            }
        }
        return EINVAL;
    }

    if (flags & m::MS_BIND) != 0 {
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
        let s_norm = match resolve_mount_path(AT_FDCWD, s) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let t_norm = match resolve_mount_path(AT_FDCWD, t) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ctx = vfs::path::Context::current();
        return m::bind_mount(&ctx, &s_norm, &t_norm, flags);
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
        return ENODEV;
    }
    if virtual_fs && fst != "proc" && fst != "sysfs" {
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
    let normalized = match resolve_mount_path(AT_FDCWD, path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    let mut src_buf = [0u8; PATH_MAX];
    let src_owned = if source == 0 {
        alloc::string::String::from("none")
    } else {
        match frame::user::copy_cstr_from_user(source, &mut src_buf) {
            Ok(slen) => match core::str::from_utf8(&src_buf[..slen]) {
                Ok(s) => alloc::string::String::from(s),
                Err(_) => return EINVAL,
            },
            Err(_) => return ENAMETOOLONG,
        }
    };

    let ctx = vfs::path::Context::current();
    let target_inode = match vfs::path::resolve(&ctx, &ctx.root, &normalized) {
        Ok(i) => i,
        Err(e) => return e.as_neg_i64(),
    };
    if target_inode.kind() != vfs::InodeKind::Directory {
        return ENOTDIR;
    }

    let new_root: Arc<dyn vfs::Inode> = if fst == "ext4" {
        if src_owned != "/dev/vda" {
            return ENODEV;
        }
        if crate::fs::devfs::vda_mount_claim().is_err() {
            return EBUSY;
        }
        let dev = match crate::fs::ext4::VirtioBlockDevice::new() {
            Some(d) => d,
            None => {
                crate::fs::devfs::vda_mount_release();
                return ENODEV;
            }
        };
        match crate::fs::ext4::Ext4Fs::mount(dev) {
            Ok(fs) => fs.root_inode(),
            Err(_) => {
                crate::fs::devfs::vda_mount_release();
                return EINVAL;
            }
        }
    } else if fst == "proc" {
        crate::fs::procfs::root()
    } else if fst == "sysfs" {
        crate::fs::sysfs::root()
    } else {
        crate::fs::tmpfs::TmpfsInode::new_dir()
    };
    m::install_new(
        &ctx,
        &normalized,
        target_inode.inode_id(),
        new_root,
        flags,
        &src_owned,
        fst,
    );
    0
}

pub(crate) fn sys_umount2(target: u64, flags: u64) -> i64 {
    let mnt_owner =
        sched::with_current_mount_table(|m| m.as_ref().and_then(|t| t.owner_user_ns())).flatten();
    if !crate::security::capable_in(crate::process_model::CAP_SYS_ADMIN, mnt_owner.as_ref()) {
        return EPERM;
    }
    if (flags & vfs::mount::MNT_EXPIRE) != 0 {
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
    let normalized = match resolve_mount_path(AT_FDCWD, path) {
        Ok(p) => p,
        Err(e) => return e,
    };

    let ctx = vfs::path::Context::current();
    vfs::mount::do_umount(&ctx, &normalized, flags)
}

pub(crate) fn sys_pivot_root(new_root_ptr: u64, put_old_ptr: u64) -> i64 {
    let mnt_owner =
        sched::with_current_mount_table(|m| m.as_ref().and_then(|t| t.owner_user_ns())).flatten();
    if !crate::security::capable_in(crate::process_model::CAP_SYS_ADMIN, mnt_owner.as_ref()) {
        return EPERM;
    }
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

    let new_root_norm = match resolve_mount_path(AT_FDCWD, &new_root_path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let put_old_norm = match resolve_mount_path(AT_FDCWD, &put_old_path) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let _ = put_old;

    let new_root_real = ctx
        .mount_path_for_root_inode(new_root.inode_id())
        .unwrap_or(new_root_norm);
    let put_old_real = ctx
        .mount_path_for_root_inode(put_old.inode_id())
        .unwrap_or(put_old_norm);

    if let Err(e) = ctx.pivot_root(&new_root_real, &put_old_real) {
        return e.as_neg_i64();
    }
    sched::set_current_fs_root(new_root.clone());
    sched::set_current_cwd(new_root, alloc::string::String::from("/"));
    0
}
