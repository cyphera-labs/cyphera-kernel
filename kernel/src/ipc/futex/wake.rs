use super::*;

#[cfg(host_test)]
#[allow(unused_imports)]
use frame_host as frame;

pub fn wake(vmspace_id: u64, uaddr: u64, n: u32) -> i64 {
    if uaddr & 0x3 != 0 {
        return EINVAL;
    }
    let key = Key {
        vmspace_id,
        vaddr: uaddr,
    };
    let q = match FUTEXES.lock().get(&key).cloned() {
        Some(q) => q,
        None => return 0,
    };
    let waiters = q.drain();
    let mut woken = 0i64;
    for pid in waiters {
        if (woken as u32) >= n {
            q.enqueue(pid);
            continue;
        }
        if crate::core::wait::wake(pid) {
            woken += 1;
        }
    }
    woken
}

pub fn wake_bitset(vmspace_id: u64, uaddr: u64, n: u32, mask: u32) -> i64 {
    if uaddr & 0x3 != 0 {
        return EINVAL;
    }
    if mask == 0 {
        return EINVAL;
    }
    let key = Key {
        vmspace_id,
        vaddr: uaddr,
    };
    let q = match FUTEXES.lock().get(&key).cloned() {
        Some(q) => q,
        None => return 0,
    };
    let waiters = q.drain();
    let masks = BITSET_MASKS.lock().clone();
    let mut woken = 0i64;
    for pid in waiters {
        let waiter_mask = masks.get(&pid).copied().unwrap_or(u32::MAX);
        if (waiter_mask & mask) == 0 || (woken as u32) >= n {
            q.enqueue(pid);
            continue;
        }
        if crate::core::wait::wake(pid) {
            woken += 1;
        }
    }
    woken
}

pub fn requeue(
    vmspace_id: u64,
    uaddr1: u64,
    uaddr2: u64,
    n_wake: u32,
    n_requeue: u32,
    cmp: Option<i32>,
) -> i64 {
    if (uaddr1 | uaddr2) & 0x3 != 0 {
        return EINVAL;
    }

    if let Some(expected) = cmp {
        let mut buf = [0u8; 4];
        if frame::user::copy_from_user(uaddr1, &mut buf).is_err() {
            return EFAULT;
        }
        if i32::from_le_bytes(buf) != expected {
            return EAGAIN;
        }
    }

    let key1 = Key {
        vmspace_id,
        vaddr: uaddr1,
    };
    let key2 = Key {
        vmspace_id,
        vaddr: uaddr2,
    };
    let q1 = match FUTEXES.lock().get(&key1).cloned() {
        Some(q) => q,
        None => return 0,
    };
    let q2 = queue_for(key2);

    let waiters = q1.drain();
    let mut woken: u32 = 0;
    let mut requeued: u32 = 0;
    for pid in waiters {
        if woken < n_wake {
            if crate::core::wait::wake(pid) {
                woken += 1;
            }
            continue;
        }
        if requeued < n_requeue {
            q2.enqueue(pid);
            requeued += 1;
            continue;
        }
        q1.enqueue(pid);
    }
    (woken + requeued) as i64
}

pub fn wake_op(
    vmspace_id: u64,
    uaddr1: u64,
    uaddr2: u64,
    n_wake1: u32,
    n_wake2: u32,
    op: u32,
) -> i64 {
    if (uaddr1 | uaddr2) & 0x3 != 0 {
        return EINVAL;
    }

    let oparg_shift = (op >> 31) & 0x1;
    let op_kind = (op >> 28) & 0x7;
    let cmp_kind = (op >> 24) & 0xf;
    let mut op_arg = ((op >> 12) & 0xfff) as i32;
    if (op_arg & 0x800) != 0 {
        op_arg |= !0xfff;
    }
    let mut cmp_arg = (op & 0xfff) as i32;
    if (cmp_arg & 0x800) != 0 {
        cmp_arg |= !0xfff;
    }
    if oparg_shift != 0 {
        op_arg = 1i32 << (op_arg & 0x1f);
    }

    let old_val = loop {
        let mut buf = [0u8; 4];
        if frame::user::copy_from_user(uaddr2, &mut buf).is_err() {
            return EFAULT;
        }
        let old_val = i32::from_le_bytes(buf);
        let new_val = match op_kind {
            0 => op_arg,
            1 => old_val.wrapping_add(op_arg),
            2 => old_val | op_arg,
            3 => old_val & !op_arg,
            4 => old_val ^ op_arg,
            _ => return EINVAL,
        };
        match frame::user::cmpxchg_user_u32(uaddr2, old_val as u32, new_val as u32) {
            Ok(observed) if observed == old_val as u32 => break old_val,
            Ok(_) => continue,
            Err(_) => return EFAULT,
        }
    };

    let cmp_holds = match cmp_kind {
        0 => old_val == cmp_arg,
        1 => old_val != cmp_arg,
        2 => old_val < cmp_arg,
        3 => old_val <= cmp_arg,
        4 => old_val > cmp_arg,
        5 => old_val >= cmp_arg,
        _ => return EINVAL,
    };

    let woken1 = wake(vmspace_id, uaddr1, n_wake1);
    let woken2 = if cmp_holds {
        wake(vmspace_id, uaddr2, n_wake2)
    } else {
        0
    };
    if woken1 < 0 {
        return woken1;
    }
    if woken2 < 0 {
        return woken2;
    }
    woken1 + woken2
}
