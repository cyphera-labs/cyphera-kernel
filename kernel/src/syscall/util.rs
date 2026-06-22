#![allow(dead_code)]

use crate::core as sched;
use crate::errno::{EFAULT, EINVAL};
use crate::vfs::{OpenFlags, TimeSpec};

pub(super) fn write_timespec(user_ptr: u64, sec: i64, nsec: i64) -> Result<(), i64> {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&sec.to_le_bytes());
    buf[8..16].copy_from_slice(&nsec.to_le_bytes());
    frame::user::copy_to_user(user_ptr, &buf).map_err(|_| EFAULT)
}

pub(super) fn split_secs_nsecs(nanos: u64) -> (i64, i64) {
    let sec = (nanos / 1_000_000_000) as i64;
    let nsec = (nanos % 1_000_000_000) as i64;
    (sec, nsec)
}

pub(super) fn read_timespec(addr: u64) -> Result<TimeSpec, i64> {
    let mut buf = [0u8; 16];
    if frame::user::copy_from_user(addr, &mut buf).is_err() {
        return Err(EFAULT);
    }
    Ok(TimeSpec {
        sec: i64::from_le_bytes(buf[0..8].try_into().unwrap()),
        nsec: i64::from_le_bytes(buf[8..16].try_into().unwrap()) as i32,
    })
}

pub(super) fn decode_timespec_relative_deadline(addr: u64) -> Result<Option<u64>, i64> {
    if addr == 0 {
        return Ok(None);
    }
    let mut buf = [0u8; 16];
    if frame::user::copy_from_user(addr, &mut buf).is_err() {
        return Err(EFAULT);
    }
    let tv_sec = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let tv_nsec = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    if tv_nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }
    let dur = tv_sec.saturating_mul(1_000_000_000).saturating_add(tv_nsec);
    let now = frame::cpu::clock::nanos_since_boot();
    Ok(Some(now.saturating_add(dur)))
}

pub(super) fn decode_timespec_absolute_or_relative(
    addr: u64,
    clockid: u64,
) -> Result<Option<u64>, i64> {
    if addr == 0 {
        return Ok(None);
    }
    if clockid != 0 && clockid != 1 {
        return Err(EINVAL);
    }
    let mut buf = [0u8; 16];
    if frame::user::copy_from_user(addr, &mut buf).is_err() {
        return Err(EFAULT);
    }
    let tv_sec = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let tv_nsec = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    if tv_nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }
    let abs = tv_sec.saturating_mul(1_000_000_000).saturating_add(tv_nsec);
    Ok(Some(abs))
}

const FUTEX2_SIZE_MASK: u32 = 0x3;
const FUTEX2_SIZE_U32: u32 = 2;

pub(super) fn validate_futex2_flags(flags: u32) -> Result<(), i64> {
    let size = flags & FUTEX2_SIZE_MASK;
    if size != FUTEX2_SIZE_U32 {
        return Err(EINVAL);
    }
    Ok(())
}

pub(super) fn caller_can_set_time() -> bool {
    sched::with_target_creds(sched::current_pid(), |c| c.euid == 0).unwrap_or(false)
}

pub(super) fn read_user_cstr(ptr: u64, max: usize) -> Result<alloc::string::String, i64> {
    if ptr == 0 {
        return Err(EFAULT);
    }
    let mut buf = alloc::vec![0u8; max + 1];
    if frame::user::copy_from_user(ptr, &mut buf).is_err() {
        return Err(EFAULT);
    }
    let n = buf.iter().position(|&b| b == 0).ok_or(EINVAL)?;
    buf.truncate(n);
    alloc::string::String::from_utf8(buf).map_err(|_| EINVAL)
}

pub(super) fn fd_is_nonblock(fd: i32) -> bool {
    sched::with_current_fds(|t| t.get(fd))
        .map(|f| f.flags().contains(OpenFlags::NONBLOCK))
        .unwrap_or(false)
}
