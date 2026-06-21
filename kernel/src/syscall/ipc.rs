use crate::errno::{EFAULT, EINVAL, ENOMEM, ENOSYS};
use crate::sched;

use super::util::{
    decode_timespec_absolute_or_relative, decode_timespec_relative_deadline, validate_futex2_flags,
};

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 3;
const FUTEX_CMP_REQUEUE: u64 = 4;
const FUTEX_WAKE_OP: u64 = 5;
const FUTEX_LOCK_PI: u64 = 6;
const FUTEX_UNLOCK_PI: u64 = 7;
const FUTEX_TRYLOCK_PI: u64 = 8;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_WAIT_REQUEUE_PI: u64 = 11;
const FUTEX_CMP_REQUEUE_PI: u64 = 12;
const FUTEX_LOCK_PI2: u64 = 13;
const FUTEX_PRIVATE_FLAG: u64 = 0x80;
const FUTEX_CLOCK_REALTIME: u64 = 0x100;
const FUTEX_OP_MASK: u64 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

pub(super) fn sys_futex(
    uaddr: u64,
    op: u64,
    val: u64,
    timeout: u64,
    uaddr2: u64,
    val3: u64,
) -> i64 {
    let raw_op = op & FUTEX_OP_MASK;
    let vmspace_id = sched::current_vmspace_id();
    match raw_op {
        FUTEX_WAIT => {
            let deadline = match decode_timespec_relative_deadline(timeout) {
                Ok(d) => d,
                Err(e) => return e,
            };
            crate::futex::wait(vmspace_id, uaddr, val as i32, deadline)
        }
        FUTEX_WAKE => crate::futex::wake(vmspace_id, uaddr, val as u32),
        FUTEX_WAIT_BITSET => {
            let deadline = match decode_timespec_relative_deadline(timeout) {
                Ok(d) => d,
                Err(e) => return e,
            };
            crate::futex::wait_bitset(vmspace_id, uaddr, val as i32, val3 as u32, deadline)
        }
        FUTEX_WAKE_BITSET => crate::futex::wake_bitset(vmspace_id, uaddr, val as u32, val3 as u32),
        FUTEX_REQUEUE => {
            crate::futex::requeue(vmspace_id, uaddr, uaddr2, val as u32, timeout as u32, None)
        }
        FUTEX_CMP_REQUEUE => crate::futex::requeue(
            vmspace_id,
            uaddr,
            uaddr2,
            val as u32,
            timeout as u32,
            Some(val3 as i32),
        ),
        FUTEX_WAKE_OP => crate::futex::wake_op(
            vmspace_id,
            uaddr,
            uaddr2,
            val as u32,
            timeout as u32,
            val3 as u32,
        ),
        FUTEX_LOCK_PI | FUTEX_LOCK_PI2 => {
            let clockid = if raw_op == FUTEX_LOCK_PI2 { 1 } else { 0 };
            let deadline = match decode_timespec_absolute_or_relative(timeout, clockid) {
                Ok(d) => d,
                Err(e) => return e,
            };
            crate::futex::lock_pi(vmspace_id, uaddr, deadline)
        }
        FUTEX_UNLOCK_PI => crate::futex::unlock_pi(vmspace_id, uaddr),
        FUTEX_TRYLOCK_PI => crate::futex::trylock_pi(vmspace_id, uaddr),
        FUTEX_WAIT_REQUEUE_PI => {
            let clockid = if op & FUTEX_CLOCK_REALTIME != 0 { 0 } else { 1 };
            let deadline = match decode_timespec_absolute_or_relative(timeout, clockid) {
                Ok(d) => d,
                Err(e) => return e,
            };
            crate::futex::wait_requeue_pi(vmspace_id, uaddr, val as i32, deadline, uaddr2)
        }
        FUTEX_CMP_REQUEUE_PI => crate::futex::cmp_requeue_pi(
            vmspace_id,
            uaddr,
            val as u32,
            timeout as u32,
            uaddr2,
            val3 as i32,
        ),
        _ => ENOSYS,
    }
}

pub(super) fn sys_futex_wake(uaddr: u64, mask: u64, nr: u64, flags: u64) -> i64 {
    if let Err(e) = validate_futex2_flags(flags as u32) {
        return e;
    }
    if mask == 0 {
        return EINVAL;
    }
    let vmspace_id = sched::current_vmspace_id();
    crate::futex::wake_bitset(vmspace_id, uaddr, nr as u32, mask as u32)
}

pub(super) fn sys_futex_wait(
    uaddr: u64,
    val: u64,
    mask: u64,
    flags: u64,
    timeout: u64,
    clockid: u64,
) -> i64 {
    if let Err(e) = validate_futex2_flags(flags as u32) {
        return e;
    }
    if mask == 0 {
        return EINVAL;
    }
    let deadline = match decode_timespec_absolute_or_relative(timeout, clockid) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let vmspace_id = sched::current_vmspace_id();
    crate::futex::wait_bitset(vmspace_id, uaddr, val as i32, mask as u32, deadline)
}

pub(super) fn sys_futex_requeue(
    waiters_ptr: u64,
    flags: u64,
    nr_wake: u64,
    nr_requeue: u64,
) -> i64 {
    if let Err(e) = validate_futex2_flags(flags as u32) {
        return e;
    }
    let mut buf = [0u8; 48];
    if frame::user::copy_from_user(waiters_ptr, &mut buf).is_err() {
        return EFAULT;
    }
    let val_src = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let uaddr_src = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let _flags_src = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let _val_dst = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let uaddr_dst = u64::from_le_bytes(buf[32..40].try_into().unwrap());
    let _flags_dst = u32::from_le_bytes(buf[40..44].try_into().unwrap());
    let vmspace_id = sched::current_vmspace_id();
    crate::futex::requeue(
        vmspace_id,
        uaddr_src,
        uaddr_dst,
        nr_wake as u32,
        nr_requeue as u32,
        Some(val_src as i32),
    )
}

pub(super) fn sys_futex_waitv(
    waiters_ptr: u64,
    nr_futexes: u64,
    flags: u64,
    timeout: u64,
    clockid: u64,
) -> i64 {
    if flags != 0 {
        return EINVAL;
    }
    if nr_futexes == 0 || nr_futexes > 128 {
        return EINVAL;
    }
    let nr = nr_futexes as usize;
    let bytes_needed = nr.saturating_mul(24);
    let mut buf = alloc::vec![0u8; bytes_needed];
    if frame::user::copy_from_user(waiters_ptr, &mut buf).is_err() {
        return EFAULT;
    }
    let vmspace_id = sched::current_vmspace_id();
    let mut entries = alloc::vec::Vec::with_capacity(nr);
    for i in 0..nr {
        let off = i * 24;
        let val = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        let uaddr = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap());
        let entry_flags = u32::from_le_bytes(buf[off + 16..off + 20].try_into().unwrap());
        if let Err(e) = validate_futex2_flags(entry_flags) {
            return e;
        }
        entries.push((vmspace_id, uaddr, val as u32, u32::MAX));
    }
    let deadline = match decode_timespec_absolute_or_relative(timeout, clockid) {
        Ok(d) => d,
        Err(e) => return e,
    };
    crate::futex::wait_multi(&entries, deadline)
}

pub(super) fn sys_keyctl(option: u64, _arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> i64 {
    const KEYCTL_GET_KEYRING_ID: u64 = 0;
    const KEYCTL_JOIN_SESSION_KEYRING: u64 = 1;
    const KEYCTL_DESCRIBE: u64 = 6;
    const FAKE_SESSION_KEYRING_ID: i64 = 1;
    const ENOKEY: i64 = -126;
    const EOPNOTSUPP: i64 = -95;
    match option {
        KEYCTL_JOIN_SESSION_KEYRING | KEYCTL_GET_KEYRING_ID => FAKE_SESSION_KEYRING_ID,
        KEYCTL_DESCRIBE => ENOKEY,
        _ => EOPNOTSUPP,
    }
}

pub(super) fn sys_shmget(key: u64, size: u64, flags: u64) -> i64 {
    crate::ipc::shm::shmget(key as i32, size as usize, flags as u32)
}

pub(super) fn sys_shmat(shmid: u64, addr: u64, flags: u64) -> i64 {
    if sched::current_is_vfork_borrower() {
        return ENOMEM;
    }
    crate::ipc::shm::shmat(shmid as i32, addr, flags as u32)
}

pub(super) fn sys_shmdt(addr: u64) -> i64 {
    if sched::current_is_vfork_borrower() {
        return EINVAL;
    }
    crate::ipc::shm::shmdt(addr)
}

pub(super) fn sys_shmctl(shmid: u64, cmd: u64, buf: u64) -> i64 {
    crate::ipc::shm::shmctl(shmid as i32, cmd as i32, buf)
}
