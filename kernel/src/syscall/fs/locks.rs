use super::*;

const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const F_DUPFD_CLOEXEC: u64 = 1030;
const F_SETPIPE_SZ: u64 = 1031;
const F_GETPIPE_SZ: u64 = 1032;
const F_GET_SEALS: u64 = 1034;
const F_ADD_SEALS: u64 = 1033;
const F_GETLK: u64 = 5;
const F_OFD_GETLK: u64 = 36;
const F_OFD_SETLK: u64 = 37;
const F_OFD_SETLKW: u64 = 38;
const F_SETLK: u64 = 6;
const F_SETLKW: u64 = 7;

pub(crate) fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    let fd = fd as i32;
    if cmd == F_GET_SEALS || cmd == F_ADD_SEALS {
        return fcntl_seals(fd, cmd, arg);
    }
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
        F_GETPIPE_SZ => match t.get(fd) {
            Some(of) => match of.inode.as_pipe() {
                Some(p) => p.get_capacity() as i64,
                None => EINVAL,
            },
            None => EBADF,
        },
        F_SETPIPE_SZ => match t.get(fd) {
            Some(of) => match of.inode.as_pipe() {
                Some(p) => match p.set_capacity(arg as usize) {
                    Some(cap) => cap as i64,
                    None => EBUSY,
                },
                None => EINVAL,
            },
            None => EBADF,
        },
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

fn fcntl_seals(fd: i32, cmd: u64, arg: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd)) {
        Some(f) => f,
        None => return EBADF,
    };
    match cmd {
        F_GET_SEALS => match file.inode.memfd_seals() {
            Some(m) => m as i64,
            None => EINVAL,
        },
        F_ADD_SEALS => {
            let add = arg as u32;
            let writable_exists = if add & vfs::F_SEAL_WRITE != 0 {
                crate::core::inode_has_shared_writable_mapping(file.inode.inode_id())
            } else {
                false
            };
            match file.inode.memfd_add_seals(add, writable_exists) {
                Ok(()) => 0,
                Err(e) => e.as_neg_i64(),
            }
        }
        _ => EINVAL,
    }
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
            Err(_) => EAGAIN,
        };
    }

    let waiters = waiters_for(inode_id);
    match block_io(
        "fcntl_setlkw",
        &waiters,
        false,
        None,
        || match try_set_lock(inode_id, l_type, start, end, owner) {
            Ok(()) => IoAttempt::Ready(()),
            Err(_) => IoAttempt::WouldBlock,
        },
    ) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_flock(fd: u64, op: u64) -> i64 {
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
    let waiters = crate::vfs::locks::bsd::waiters_for(inode_id);
    match block_io("flock", &waiters, (op & LOCK_NB) != 0, None, || {
        match crate::vfs::locks::bsd::try_op(inode_id, ofd_key, op) {
            FlockOutcome::Acquired | FlockOutcome::Released => IoAttempt::Ready(()),
            FlockOutcome::Conflict => IoAttempt::WouldBlock,
        }
    }) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}
