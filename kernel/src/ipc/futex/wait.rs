use super::*;

#[cfg(host_test)]
#[allow(unused_imports)]
use frame_host as frame;

use alloc::sync::Arc;

use crate::core::wait::WaitQueue;

pub fn wait(vmspace_id: u64, uaddr: u64, expected: i32, deadline_nanos: Option<u64>) -> i64 {
    if uaddr & 0x3 != 0 {
        return EINVAL;
    }
    let key = Key {
        vmspace_id,
        vaddr: uaddr,
    };
    let q = queue_for(key);
    let pid = crate::core::current_pid();
    q.enqueue(pid);
    let mut buf = [0u8; 4];
    if frame::user::copy_from_user(uaddr, &mut buf).is_err() {
        q.dequeue(pid);
        return EFAULT;
    }
    let val = i32::from_le_bytes(buf);
    if val != expected {
        q.dequeue(pid);
        return EAGAIN;
    }
    if let Some(deadline) = deadline_nanos {
        crate::core::timeout::register(deadline, pid);
    }
    let still_queued = || {
        q.contains(pid) && deadline_nanos.is_none_or(|d| frame::cpu::clock::nanos_since_boot() < d)
    };
    let outcome = crate::core::wait::wait_guarded("futex_wait", deadline_nanos, &still_queued);
    q.dequeue(pid);
    let _ = crate::core::timeout::unregister(pid);
    match outcome {
        crate::core::wait::WaitOutcome::Interrupted => EINTR,
        crate::core::wait::WaitOutcome::TimedOut => ETIMEDOUT,
        crate::core::wait::WaitOutcome::Woken => 0,
    }
}

pub fn wait_bitset(
    vmspace_id: u64,
    uaddr: u64,
    expected: i32,
    mask: u32,
    deadline_nanos: Option<u64>,
) -> i64 {
    if mask == 0 {
        return EINVAL;
    }
    let pid = crate::core::current_pid();
    BITSET_MASKS.lock().insert(pid, mask);
    let r = wait(vmspace_id, uaddr, expected, deadline_nanos);
    BITSET_MASKS.lock().remove(&pid);
    r
}

pub fn wait_multi(waiters: &[(u64, u64, u32, u32)], deadline_nanos: Option<u64>) -> i64 {
    if waiters.is_empty() || waiters.len() > 128 {
        return EINVAL;
    }
    let mut keys: alloc::vec::Vec<Key> = alloc::vec::Vec::with_capacity(waiters.len());
    for (vmid, uaddr, _expected, _mask) in waiters {
        if *uaddr & 0x3 != 0 {
            return EINVAL;
        }
        keys.push(Key {
            vmspace_id: *vmid,
            vaddr: *uaddr,
        });
    }
    let pid = crate::core::current_pid();
    let queues: alloc::vec::Vec<Arc<WaitQueue>> = keys.iter().map(|k| queue_for(*k)).collect();
    let any_mask: u32 = waiters
        .iter()
        .map(|(_, _, _, m)| *m)
        .fold(0u32, |a, b| a | b);
    if any_mask != 0 {
        BITSET_MASKS.lock().insert(pid, any_mask);
    }
    for q in &queues {
        q.enqueue(pid);
    }
    for (_, uaddr, expected, _) in waiters {
        let mut buf = [0u8; 4];
        let bad = frame::user::copy_from_user(*uaddr, &mut buf).is_err();
        if bad || u32::from_le_bytes(buf) != *expected {
            for q in &queues {
                q.dequeue(pid);
            }
            if any_mask != 0 {
                BITSET_MASKS.lock().remove(&pid);
            }
            return if bad { EFAULT } else { EAGAIN };
        }
    }
    if let Some(d) = deadline_nanos {
        crate::core::timeout::register(d, pid);
    }
    let still_queued = || {
        queues.iter().all(|q| q.contains(pid))
            && deadline_nanos.is_none_or(|d| frame::cpu::clock::nanos_since_boot() < d)
    };
    let outcome = crate::core::wait::wait_guarded("futex_wait", deadline_nanos, &still_queued);
    for q in &queues {
        q.dequeue(pid);
    }
    if any_mask != 0 {
        BITSET_MASKS.lock().remove(&pid);
    }
    let _ = crate::core::timeout::unregister(pid);
    match outcome {
        crate::core::wait::WaitOutcome::Interrupted => return EINTR,
        crate::core::wait::WaitOutcome::TimedOut => return ETIMEDOUT,
        crate::core::wait::WaitOutcome::Woken => {}
    }
    for (i, (_, uaddr, expected, _)) in waiters.iter().enumerate() {
        let mut buf = [0u8; 4];
        if frame::user::copy_from_user(*uaddr, &mut buf).is_ok() {
            let cur = u32::from_le_bytes(buf);
            if cur != *expected {
                return i as i64;
            }
        }
    }
    0
}
