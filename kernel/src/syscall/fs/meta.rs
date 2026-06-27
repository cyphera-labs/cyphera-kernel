use super::*;

const STAT_SIZE: usize = 144;
const AT_EMPTY_PATH: u64 = 0x1000;
const STATX_BASIC_STATS: u32 = 0x7ff;
const STATFS_SIZE: usize = 120;
const UTIME_NOW: i64 = 0x3fff_ffff;
const UTIME_OMIT: i64 = 0x3fff_fffe;

pub(crate) fn sys_fstat(fd: u64, statbuf: u64) -> i64 {
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

pub(crate) fn sys_newfstatat(dirfd: u64, pathname: u64, statbuf: u64, flags: u64) -> i64 {
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
        Err(e) => return e.as_neg_i64(),
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
    const S_IFSOCK: u32 = 0o140_000;

    let kind_bits = match st.kind {
        InodeKind::Regular => S_IFREG,
        InodeKind::Directory => S_IFDIR,
        InodeKind::CharDevice => S_IFCHR,
        InodeKind::Symlink => S_IFLNK,
        InodeKind::Pipe => S_IFIFO,
        InodeKind::Socket => S_IFSOCK,
    };
    let mode = kind_bits | st.mode as u32;

    let mut buf = [0u8; STAT_SIZE];
    buf[0..8].copy_from_slice(&st.dev_id.to_le_bytes());
    buf[8..16].copy_from_slice(&st.inode_id.to_le_bytes());
    buf[16..24].copy_from_slice(&(st.nlink as u64).to_le_bytes());
    buf[24..28].copy_from_slice(&mode.to_le_bytes());
    let (vis_uid, vis_gid) =
        crate::core::with_current_creds(|c| (c.uid_from_kernel(st.uid), c.gid_from_kernel(st.gid)));
    buf[28..32].copy_from_slice(&vis_uid.to_le_bytes());
    buf[32..36].copy_from_slice(&vis_gid.to_le_bytes());
    buf[40..48].copy_from_slice(&st.rdev.to_le_bytes());
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

pub(crate) fn sys_stat(pathname: u64, statbuf: u64, lstat: bool) -> i64 {
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

pub(crate) fn sys_statx(dirfd: u64, pathname: u64, flags: u64, _mask: u64, statxbuf: u64) -> i64 {
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
    let (vis_uid, vis_gid) =
        crate::core::with_current_creds(|c| (c.uid_from_kernel(st.uid), c.gid_from_kernel(st.gid)));
    buf[20..24].copy_from_slice(&vis_uid.to_le_bytes());
    buf[24..28].copy_from_slice(&vis_gid.to_le_bytes());
    let mode_bits: u16 = match st.kind {
        InodeKind::Regular => 0o100_000,
        InodeKind::Directory => 0o040_000,
        InodeKind::CharDevice => 0o020_000,
        InodeKind::Symlink => 0o120_000,
        InodeKind::Pipe => 0o010_000,
        InodeKind::Socket => 0o140_000,
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

pub(crate) fn sys_faccessat(dirfd: u64, pathname: u64, mode: u64, _flags: u64) -> i64 {
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
    if ok { 0 } else { -13 }
}

fn chmod_permitted(file_uid: u32) -> bool {
    sched::with_current_creds(|c| {
        (c.has_cap(crate::process_model::CAP_FOWNER) && c.owns_kuid(file_uid))
            || c.fsuid == file_uid
    })
}

fn chown_permitted(
    file_uid: u32,
    file_gid: u32,
    want_uid: Option<u32>,
    want_gid: Option<u32>,
) -> bool {
    sched::with_current_creds(|c| {
        let cap_chown = c.has_cap(crate::process_model::CAP_CHOWN)
            && c.owns_kuid(file_uid)
            && c.owns_kgid(file_gid);
        let uid_ok = match want_uid {
            None => true,
            Some(nu) => cap_chown || (c.fsuid == file_uid && nu == file_uid),
        };
        let gid_ok = match want_gid {
            None => true,
            Some(ng) => cap_chown || (c.fsuid == file_uid && (c.fsgid == ng || c.is_in_group(ng))),
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

pub(crate) fn sys_fchmod(fd: u64, mode: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if fd_mount_is_rdonly(&file) {
        return crate::errno::EROFS;
    }
    if !chmod_permitted(file.inode.stat().uid) {
        return EPERM;
    }
    match file.inode.set_mode((mode & 0o7777) as u16) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_fchmodat(dirfd: u64, pathname: u64, mode: u64) -> i64 {
    let inode = match resolve_path_writable(dirfd, pathname, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    if !chmod_permitted(inode.stat().uid) {
        return EPERM;
    }
    match inode.set_mode((mode & 0o7777) as u16) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_fchown(fd: u64, uid: u64, gid: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if fd_mount_is_rdonly(&file) {
        return crate::errno::EROFS;
    }
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
    let st = file.inode.stat();
    if !chown_permitted(st.uid, st.gid, u, g) {
        return EPERM;
    }
    match file.inode.set_owner(u, g) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_fchownat(dirfd: u64, pathname: u64, uid: u64, gid: u64, _flags: u64) -> i64 {
    let inode = match resolve_path_writable(dirfd, pathname, true) {
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
    let st = inode.stat();
    if !chown_permitted(st.uid, st.gid, u, g) {
        return EPERM;
    }
    match inode.set_owner(u, g) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_statfs(arg: u64, statfs_ptr: u64, fd: bool) -> i64 {
    let (inode, mut mnt_flags) = if fd {
        match sched::with_current_fds(|t| t.get(arg as i32)) {
            Some(f) => {
                let mf = f._mount_guard.as_ref().map(|g| g.flags()).unwrap_or(0);
                (f.inode.clone(), mf)
            }
            None => return EBADF,
        }
    } else {
        match resolve_path(AT_FDCWD as u64, arg, true) {
            Ok(i) => (i, 0u64),
            Err(e) => return e,
        }
    };
    let cur = sched::current_pid();
    if let Some(exe) = crate::core::process_exe_inode(cur) {
        if alloc::sync::Arc::ptr_eq(&inode, &exe) {
            mnt_flags = crate::core::process_exe_mnt_flags(cur);
        }
    }
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
    let f_flags = mnt_flags & crate::vfs::mount::MOUNT_FLAG_MASK;
    buf[80..88].copy_from_slice(&f_flags.to_le_bytes());
    if frame::user::copy_to_user(statfs_ptr, &buf).is_err() {
        return EFAULT;
    }
    0
}

fn wall_now() -> TimeSpec {
    let nanos = frame::cpu::clock::wall_clock_nanos();
    TimeSpec {
        sec: (nanos / 1_000_000_000) as i64,
        nsec: (nanos % 1_000_000_000) as i32,
    }
}

fn utimes_apply(
    dirfd: u64,
    pathname: u64,
    atime: Option<TimeSpec>,
    mtime: Option<TimeSpec>,
) -> i64 {
    let inode = if pathname == 0 {
        match sched::with_current_fds(|t| t.get(dirfd as i32)) {
            Some(f) => {
                if fd_mount_is_rdonly(&f) {
                    return crate::errno::EROFS;
                }
                f.inode.clone()
            }
            None => return EBADF,
        }
    } else {
        match resolve_path_writable(dirfd, pathname, true) {
            Ok(i) => i,
            Err(e) => return e,
        }
    };
    match inode.set_times(atime, mtime) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

fn read_timeval_as_timespec(addr: u64) -> Result<TimeSpec, i64> {
    let mut buf = [0u8; 16];
    if frame::user::copy_from_user(addr, &mut buf).is_err() {
        return Err(EFAULT);
    }
    let sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let usec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    if !(0..1_000_000).contains(&usec) {
        return Err(EINVAL);
    }
    Ok(TimeSpec {
        sec,
        nsec: (usec * 1000) as i32,
    })
}

fn timeval_pair(times_ptr: u64) -> Result<(Option<TimeSpec>, Option<TimeSpec>), i64> {
    if times_ptr == 0 {
        let now = wall_now();
        return Ok((Some(now), Some(now)));
    }
    let a = read_timeval_as_timespec(times_ptr)?;
    let m = read_timeval_as_timespec(times_ptr + 16)?;
    Ok((Some(a), Some(m)))
}

pub(crate) fn sys_utimes(pathname: u64, times_ptr: u64) -> i64 {
    let (atime, mtime) = match timeval_pair(times_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    utimes_apply(AT_FDCWD as u64, pathname, atime, mtime)
}

pub(crate) fn sys_futimesat(dirfd: u64, pathname: u64, times_ptr: u64) -> i64 {
    let (atime, mtime) = match timeval_pair(times_ptr) {
        Ok(v) => v,
        Err(e) => return e,
    };
    utimes_apply(dirfd, pathname, atime, mtime)
}

pub(crate) fn sys_utimensat(dirfd: u64, pathname: u64, times_ptr: u64, _flags: u64) -> i64 {
    let now = wall_now();
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
    utimes_apply(dirfd, pathname, atime, mtime)
}
