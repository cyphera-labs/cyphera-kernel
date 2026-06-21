extern crate alloc;

#[cfg(host_test)]
#[allow(unused_imports)]
use frame_host as frame;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use frame::sync::SpinIrq;

use crate::wait::WaitQueue;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub vmspace_id: u64,
    pub vaddr: u64,
}

static FUTEXES: SpinIrq<BTreeMap<Key, Arc<WaitQueue>>> = SpinIrq::new(BTreeMap::new());

static BITSET_MASKS: SpinIrq<BTreeMap<crate::process::Pid, u32>> = SpinIrq::new(BTreeMap::new());

fn queue_for(key: Key) -> Arc<WaitQueue> {
    let mut t = FUTEXES.lock();
    t.entry(key)
        .or_insert_with(|| Arc::new(WaitQueue::new()))
        .clone()
}

use crate::errno::{EAGAIN, EFAULT, EINTR, EINVAL, ETIMEDOUT};

pub fn wait(vmspace_id: u64, uaddr: u64, expected: i32, deadline_nanos: Option<u64>) -> i64 {
    if uaddr & 0x3 != 0 {
        return EINVAL;
    }
    let key = Key {
        vmspace_id,
        vaddr: uaddr,
    };
    let q = queue_for(key);
    let pid = crate::sched::current_pid();
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
        crate::timeout::register(deadline, pid);
    }
    let still_queued = || {
        q.contains(pid) && deadline_nanos.is_none_or(|d| frame::cpu::clock::nanos_since_boot() < d)
    };
    let outcome = crate::wait::wait_guarded("futex_wait", deadline_nanos, &still_queued);
    q.dequeue(pid);
    let _ = crate::timeout::unregister(pid);
    match outcome {
        crate::wait::WaitOutcome::Interrupted => EINTR,
        crate::wait::WaitOutcome::TimedOut => ETIMEDOUT,
        crate::wait::WaitOutcome::Woken => 0,
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
    let pid = crate::sched::current_pid();
    BITSET_MASKS.lock().insert(pid, mask);
    let r = wait(vmspace_id, uaddr, expected, deadline_nanos);
    BITSET_MASKS.lock().remove(&pid);
    r
}

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
        if crate::sched::wake_pid(pid) {
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
        if crate::sched::wake_pid(pid) {
            woken += 1;
        }
    }
    woken
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
    let pid = crate::sched::current_pid();
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
        crate::timeout::register(d, pid);
    }
    let still_queued = || {
        queues.iter().all(|q| q.contains(pid))
            && deadline_nanos.is_none_or(|d| frame::cpu::clock::nanos_since_boot() < d)
    };
    let outcome = crate::wait::wait_guarded("futex_wait", deadline_nanos, &still_queued);
    for q in &queues {
        q.dequeue(pid);
    }
    if any_mask != 0 {
        BITSET_MASKS.lock().remove(&pid);
    }
    let _ = crate::timeout::unregister(pid);
    match outcome {
        crate::wait::WaitOutcome::Interrupted => return EINTR,
        crate::wait::WaitOutcome::TimedOut => return ETIMEDOUT,
        crate::wait::WaitOutcome::Woken => {}
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
            if crate::sched::wake_pid(pid) {
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

const FUTEX_OWNER_DIED: u32 = 0x4000_0000;

const ROBUST_LIST_LIMIT: u32 = 2048;

pub fn exit_robust_list(vmspace_id: u64, head_addr: u64) {
    if head_addr == 0 {
        return;
    }

    let mut head_buf = [0u8; 24];
    if frame::user::copy_from_user(head_addr, &mut head_buf).is_err() {
        return;
    }
    let list = u64::from_le_bytes(head_buf[0..8].try_into().unwrap());
    let futex_offset = i64::from_le_bytes(head_buf[8..16].try_into().unwrap());
    let pending = u64::from_le_bytes(head_buf[16..24].try_into().unwrap());

    if pending != 0 && pending != head_addr {
        let futex_addr = (pending as i64).wrapping_add(futex_offset) as u64;
        handle_futex_death(vmspace_id, futex_addr);
    }

    let mut entry = list;
    let mut limit = ROBUST_LIST_LIMIT;
    while entry != head_addr && entry != 0 && limit > 0 {
        let mut next_buf = [0u8; 8];
        if frame::user::copy_from_user(entry, &mut next_buf).is_err() {
            break;
        }
        let next = u64::from_le_bytes(next_buf);

        if entry != pending {
            let futex_addr = (entry as i64).wrapping_add(futex_offset) as u64;
            handle_futex_death(vmspace_id, futex_addr);
        }

        entry = next;
        limit -= 1;
    }
}

fn handle_futex_death(vmspace_id: u64, futex_addr: u64) {
    if futex_addr & 0x3 != 0 {
        return;
    }
    let mut buf = [0u8; 4];
    if frame::user::copy_from_user(futex_addr, &mut buf).is_err() {
        return;
    }
    let val = u32::from_le_bytes(buf) | FUTEX_OWNER_DIED;
    if frame::user::copy_to_user(futex_addr, &val.to_le_bytes()).is_err() {
        return;
    }
    let _ = wake(vmspace_id, futex_addr, 1);
}

pub fn clear_child_tid(vmspace_id: u64, addr: u64) {
    if addr == 0 || addr & 0x3 != 0 {
        return;
    }
    let zero: [u8; 4] = [0; 4];
    if frame::user::copy_to_user(addr, &zero).is_err() {
        return;
    }
    let _ = wake(vmspace_id, addr, 1);
}

pub fn drop_vmspace(vmspace_id: u64) {
    let mut t = FUTEXES.lock();
    t.retain(|k, _| k.vmspace_id != vmspace_id);
    #[cfg(not(host_test))]
    pi_impl::drop_vmspace_pi(vmspace_id);
}

#[cfg(not(host_test))]
mod pi_impl {
    use super::*;

    pub(super) fn drop_vmspace_pi(vmspace_id: u64) {
        PI_STATES.lock().retain(|k, _| k.vmspace_id != vmspace_id);
    }

    const FUTEX_WAITERS: u32 = 0x8000_0000;
    const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;

    const MAX_PI_CHAIN_DEPTH: usize = 16;

    use crate::errno::{EDEADLK, EPERM};

    struct PiState {
        holder: Option<crate::process::Pid>,
        waiters: BTreeMap<(u8, u32), ()>,
    }

    impl PiState {
        fn new() -> Self {
            Self {
                holder: None,
                waiters: BTreeMap::new(),
            }
        }

        fn top_waiter_prio(&self) -> Option<u8> {
            self.waiters.iter().next().map(|(&(inv, _), _)| 255 - inv)
        }

        fn pop_top(&mut self) -> Option<(crate::process::Pid, bool)> {
            let key = self.waiters.iter().next().map(|(k, _)| *k)?;
            self.waiters.remove(&key);
            Some((
                crate::process::Pid::from_raw(key.1),
                !self.waiters.is_empty(),
            ))
        }
    }

    static PI_STATES: SpinIrq<BTreeMap<Key, PiState>> = SpinIrq::new(BTreeMap::new());

    fn effective_priority(p: &crate::process::Process) -> u8 {
        use crate::process::SchedClass;
        match p.sched_class {
            SchedClass::Rt { priority, .. } => priority,
            SchedClass::Cfs | SchedClass::Deadline { .. } => 0,
        }
    }

    fn apply_boost_locked(
        holder: &mut crate::process::Process,
        target_prio: u8,
    ) -> Option<crate::process::SchedClass> {
        use crate::process::SchedClass;
        let cur_prio = effective_priority(holder);
        if cur_prio >= target_prio {
            return None;
        }
        if holder.pi_orig_class.is_none() {
            holder.pi_orig_class = Some(holder.sched_class);
        }
        let prev = holder.sched_class;
        holder.sched_class = SchedClass::Rt {
            priority: target_prio,
            round_robin: false,
        };
        Some(prev)
    }

    fn refresh_boost_locked(
        holder: &mut crate::process::Process,
    ) -> Option<crate::process::SchedClass> {
        use crate::process::SchedClass;
        let pi_states = PI_STATES.lock();
        let new_target = holder
            .pi_held
            .iter()
            .filter_map(|k| pi_states.get(k).and_then(|s| s.top_waiter_prio()))
            .max()
            .unwrap_or(0);
        drop(pi_states);

        let orig_class = holder.pi_orig_class;
        let orig_prio = orig_class
            .map(|c| match c {
                SchedClass::Rt { priority, .. } => priority,
                _ => 0,
            })
            .unwrap_or_else(|| effective_priority(holder));

        let final_prio = new_target.max(orig_prio);
        let prev = holder.sched_class;

        if final_prio == orig_prio {
            if let Some(orig) = orig_class {
                holder.sched_class = orig;
                holder.pi_orig_class = None;
                return Some(prev);
            }
            return None;
        }
        let new_class = SchedClass::Rt {
            priority: final_prio,
            round_robin: false,
        };
        if new_class != holder.sched_class {
            holder.sched_class = new_class;
            return Some(prev);
        }
        None
    }

    fn boost_chain(
        locker: crate::process::Pid,
        initial_holder: crate::process::Pid,
        target_prio: u8,
    ) -> Result<(), i64> {
        let mut current = initial_holder;
        for _depth in 0..MAX_PI_CHAIN_DEPTH {
            if current == locker {
                return Err(EDEADLK);
            }
            let (changed_to, next_blocked_on): (Option<crate::process::SchedClass>, Option<Key>) = {
                let mut g = crate::sched::global_lock();
                let proc = match g.processes.get_mut(&current) {
                    Some(p) => p,
                    None => return Ok(()),
                };
                let prev = proc.sched_class;
                let after = apply_boost_locked(proc, target_prio);
                let blocked = proc.pi_blocked_on;
                (after.map(|_| prev), blocked)
            };

            if let Some(_prev) = changed_to {
                let new_class = match crate::sched::sched_class_of_pid(current) {
                    Some(c) => c,
                    None => return Ok(()),
                };
                let _ = crate::sched::set_sched_class(current, new_class);
            }

            match next_blocked_on {
                Some(next_key) => {
                    let next_holder = {
                        let pi = PI_STATES.lock();
                        pi.get(&next_key).and_then(|s| s.holder)
                    };
                    match next_holder {
                        Some(h) if h == current => return Ok(()),
                        Some(h) => current = h,
                        None => return Ok(()),
                    }
                }
                None => return Ok(()),
            }
        }
        Err(EDEADLK)
    }

    pub fn lock_pi(vmspace_id: u64, uaddr: u64, deadline_nanos: Option<u64>) -> i64 {
        if uaddr & 0x3 != 0 {
            return EINVAL;
        }
        let key = Key {
            vmspace_id,
            vaddr: uaddr,
        };
        let q = queue_for(key);
        let me = crate::sched::current_pid();
        let my_tid = crate::sched::current_local_pid();
        if my_tid > FUTEX_TID_MASK {
            return EINVAL;
        }

        let observed = match frame::user::cmpxchg_user_u32(uaddr, 0, my_tid) {
            Ok(v) => v,
            Err(_) => return EFAULT,
        };
        if observed == 0 {
            let mut pis = PI_STATES.lock();
            let entry = pis.entry(key).or_insert_with(PiState::new);
            entry.holder = Some(me);
            drop(pis);
            let mut g = crate::sched::global_lock();
            if let Some(p) = g.processes.get_mut(&me) {
                if !p.pi_held.contains(&key) {
                    p.pi_held.push(key);
                }
            }
            return 0;
        }

        if (observed & FUTEX_TID_MASK) == my_tid {
            return EDEADLK;
        }
        let holder_tid = observed & FUTEX_TID_MASK;

        if frame::user::atomic_or_user_u32(uaddr, FUTEX_WAITERS).is_err() {
            return EFAULT;
        }

        let holder_pid = match crate::sched::caller_local_to_host(holder_tid) {
            Some(p) => p,
            None => crate::process::Pid::from_raw(holder_tid),
        };

        let my_prio = {
            let g = crate::sched::global_lock();
            g.processes
                .get(&me)
                .map(|p| effective_priority(p))
                .unwrap_or(0)
        };

        {
            let mut pis = PI_STATES.lock();
            let entry = pis.entry(key).or_insert_with(PiState::new);
            if entry.holder.is_none() {
                entry.holder = Some(holder_pid);
            }
            entry.waiters.insert((255 - my_prio, me.raw()), ());
        }
        {
            let mut g = crate::sched::global_lock();
            if let Some(p) = g.processes.get_mut(&me) {
                p.pi_blocked_on = Some(key);
            }
        }

        if let Err(e) = boost_chain(me, holder_pid, my_prio) {
            let mut pis = PI_STATES.lock();
            if let Some(s) = pis.get_mut(&key) {
                s.waiters.remove(&(255 - my_prio, me.raw()));
            }
            let mut g = crate::sched::global_lock();
            if let Some(p) = g.processes.get_mut(&me) {
                p.pi_blocked_on = None;
            }
            return e;
        }

        if let Some(deadline) = deadline_nanos {
            crate::timeout::register(deadline, me);
        }
        q.park();
        q.dequeue(me);
        let timed_out = deadline_nanos.is_some() && !crate::timeout::unregister(me);

        let acquired = {
            let pis = PI_STATES.lock();
            pis.get(&key).map(|s| s.holder == Some(me)).unwrap_or(false)
        };
        if acquired {
            let mut g = crate::sched::global_lock();
            if let Some(p) = g.processes.get_mut(&me) {
                p.pi_blocked_on = None;
                if !p.pi_held.contains(&key) {
                    p.pi_held.push(key);
                }
            }
            return 0;
        }

        {
            let mut pis = PI_STATES.lock();
            if let Some(s) = pis.get_mut(&key) {
                s.waiters.remove(&(255 - my_prio, me.raw()));
            }
        }
        {
            let mut g = crate::sched::global_lock();
            if let Some(p) = g.processes.get_mut(&me) {
                p.pi_blocked_on = None;
            }
            if let Some(h) = {
                let pis = PI_STATES.lock();
                pis.get(&key).and_then(|s| s.holder)
            } {
                if let Some(holder) = g.processes.get_mut(&h) {
                    let _ = refresh_boost_locked(holder);
                }
            }
        }
        if crate::sched::current_signal_pending() {
            return EINTR;
        }
        if timed_out {
            return ETIMEDOUT;
        }
        EAGAIN
    }

    pub fn trylock_pi(vmspace_id: u64, uaddr: u64) -> i64 {
        if uaddr & 0x3 != 0 {
            return EINVAL;
        }
        let key = Key {
            vmspace_id,
            vaddr: uaddr,
        };
        let me = crate::sched::current_pid();
        let my_tid = crate::sched::current_local_pid();
        if my_tid > FUTEX_TID_MASK {
            return EINVAL;
        }
        let observed = match frame::user::cmpxchg_user_u32(uaddr, 0, my_tid) {
            Ok(v) => v,
            Err(_) => return EFAULT,
        };
        if observed == 0 {
            let mut pis = PI_STATES.lock();
            let entry = pis.entry(key).or_insert_with(PiState::new);
            entry.holder = Some(me);
            drop(pis);
            let mut g = crate::sched::global_lock();
            if let Some(p) = g.processes.get_mut(&me) {
                if !p.pi_held.contains(&key) {
                    p.pi_held.push(key);
                }
            }
            return 0;
        }
        if (observed & FUTEX_TID_MASK) == my_tid {
            return EDEADLK;
        }
        EAGAIN
    }

    pub fn unlock_pi(vmspace_id: u64, uaddr: u64) -> i64 {
        if uaddr & 0x3 != 0 {
            return EINVAL;
        }
        let key = Key {
            vmspace_id,
            vaddr: uaddr,
        };
        let me = crate::sched::current_pid();
        let my_tid = crate::sched::current_local_pid();

        let mut buf = [0u8; 4];
        if frame::user::copy_from_user(uaddr, &mut buf).is_err() {
            return EFAULT;
        }
        let cur = u32::from_le_bytes(buf);
        if (cur & FUTEX_TID_MASK) != my_tid {
            return EPERM;
        }

        let popped = {
            let mut pis = PI_STATES.lock();
            match pis.get_mut(&key) {
                Some(s) => s.pop_top(),
                None => None,
            }
        };

        let new_word = match popped {
            Some((winner_pid, has_more)) => {
                let winner_local = crate::sched::host_to_caller_local(winner_pid);
                let mut w = winner_local & FUTEX_TID_MASK;
                if has_more {
                    w |= FUTEX_WAITERS;
                }
                {
                    let mut pis = PI_STATES.lock();
                    if let Some(s) = pis.get_mut(&key) {
                        s.holder = Some(winner_pid);
                    }
                }
                let _ = crate::sched::wake_pid(winner_pid);
                w
            }
            None => 0,
        };

        if frame::user::copy_to_user(uaddr, &new_word.to_le_bytes()).is_err() {
            return EFAULT;
        }

        {
            let mut g = crate::sched::global_lock();
            if let Some(p) = g.processes.get_mut(&me) {
                p.pi_held.retain(|k| *k != key);
                let _changed = refresh_boost_locked(p);
            }
        }
        let new_self_class =
            crate::sched::sched_class_of_pid(me).unwrap_or(crate::process::SchedClass::Cfs);
        let _ = crate::sched::set_sched_class(me, new_self_class);

        {
            let mut pis = PI_STATES.lock();
            let drop = pis
                .get(&key)
                .map(|s| s.holder.is_none() && s.waiters.is_empty())
                .unwrap_or(false);
            if drop {
                pis.remove(&key);
            }
        }
        0
    }

    pub fn pi_owner_died(vmspace_id: u64, dying_pid: crate::process::Pid) {
        use alloc::vec::Vec;
        let held: Vec<Key> = {
            let g = crate::sched::global_lock();
            g.processes
                .get(&dying_pid)
                .map(|p| p.pi_held.clone())
                .unwrap_or_default()
        };
        for key in held {
            if key.vmspace_id != vmspace_id {
                continue;
            }
            let _ = frame::user::atomic_or_user_u32(key.vaddr, FUTEX_OWNER_DIED);

            let popped = {
                let mut pis = PI_STATES.lock();
                match pis.get_mut(&key) {
                    Some(s) => {
                        s.holder = None;
                        s.pop_top()
                    }
                    None => None,
                }
            };
            if let Some((winner, has_more)) = popped {
                let winner_local = crate::sched::host_to_caller_local(winner);
                let mut w = winner_local & FUTEX_TID_MASK;
                w |= FUTEX_OWNER_DIED;
                if has_more {
                    w |= FUTEX_WAITERS;
                }
                let _ = frame::user::copy_to_user(key.vaddr, &w.to_le_bytes());
                {
                    let mut pis = PI_STATES.lock();
                    if let Some(s) = pis.get_mut(&key) {
                        s.holder = Some(winner);
                    }
                }
                let _ = crate::sched::wake_pid(winner);
            }
        }
    }

    fn self_q1_pop_one(
        q: &alloc::sync::Arc<crate::wait::WaitQueue>,
    ) -> Option<crate::process::Pid> {
        q.pop_one_no_wake()
    }

    pub fn wait_requeue_pi(
        vmspace_id: u64,
        uaddr1: u64,
        expected: i32,
        deadline_nanos: Option<u64>,
        uaddr2: u64,
    ) -> i64 {
        if uaddr1 & 0x3 != 0 || uaddr2 & 0x3 != 0 {
            return EINVAL;
        }
        let key1 = Key {
            vmspace_id,
            vaddr: uaddr1,
        };
        let key2 = Key {
            vmspace_id,
            vaddr: uaddr2,
        };
        let q1 = queue_for(key1);
        let me = crate::sched::current_pid();

        let mut buf = [0u8; 4];
        if frame::user::copy_from_user(uaddr1, &mut buf).is_err() {
            return EFAULT;
        }
        let val = i32::from_le_bytes(buf);
        if val != expected {
            return EAGAIN;
        }

        {
            let mut g = crate::sched::global_lock();
            if let Some(p) = g.processes.get_mut(&me) {
                p.pi_blocked_on = Some(key2);
            }
        }

        if let Some(deadline) = deadline_nanos {
            crate::timeout::register(deadline, me);
        }
        q1.park();
        q1.dequeue(me);
        let timed_out = deadline_nanos.is_some() && !crate::timeout::unregister(me);

        let already_owner = {
            let pis = PI_STATES.lock();
            pis.get(&key2)
                .map(|s| s.holder == Some(me))
                .unwrap_or(false)
        };
        if already_owner {
            let mut g = crate::sched::global_lock();
            if let Some(p) = g.processes.get_mut(&me) {
                p.pi_blocked_on = None;
                if !p.pi_held.contains(&key2) {
                    p.pi_held.push(key2);
                }
            }
            return 0;
        }

        let queued_on_pi = {
            let pis = PI_STATES.lock();
            pis.get(&key2)
                .map(|s| s.waiters.iter().any(|(&(_, raw), _)| raw == me.raw()))
                .unwrap_or(false)
        };
        if queued_on_pi && !timed_out && !crate::sched::current_signal_pending() {
            let q2 = queue_for(key2);
            if let Some(deadline) = deadline_nanos {
                crate::timeout::register(deadline, me);
            }
            q2.park();
            q2.dequeue(me);
            let timed_out2 = deadline_nanos.is_some() && !crate::timeout::unregister(me);
            let acquired = {
                let pis = PI_STATES.lock();
                pis.get(&key2)
                    .map(|s| s.holder == Some(me))
                    .unwrap_or(false)
            };
            if acquired {
                let mut g = crate::sched::global_lock();
                if let Some(p) = g.processes.get_mut(&me) {
                    p.pi_blocked_on = None;
                    if !p.pi_held.contains(&key2) {
                        p.pi_held.push(key2);
                    }
                }
                return 0;
            }
            {
                let mut pis = PI_STATES.lock();
                if let Some(s) = pis.get_mut(&key2) {
                    let raw = me.raw();
                    let key = s
                        .waiters
                        .iter()
                        .find_map(|(&k, _)| if k.1 == raw { Some(k) } else { None });
                    if let Some(k) = key {
                        s.waiters.remove(&k);
                    }
                }
            }
            let mut g = crate::sched::global_lock();
            if let Some(p) = g.processes.get_mut(&me) {
                p.pi_blocked_on = None;
            }
            if crate::sched::current_signal_pending() {
                return EINTR;
            }
            if timed_out2 {
                return ETIMEDOUT;
            }
            return EAGAIN;
        }

        {
            let mut g = crate::sched::global_lock();
            if let Some(p) = g.processes.get_mut(&me) {
                p.pi_blocked_on = None;
            }
        }
        if crate::sched::current_signal_pending() {
            return EINTR;
        }
        if timed_out {
            return ETIMEDOUT;
        }
        EAGAIN
    }

    pub fn cmp_requeue_pi(
        vmspace_id: u64,
        uaddr1: u64,
        n_wake: u32,
        n_requeue: u32,
        uaddr2: u64,
        val_cmp: i32,
    ) -> i64 {
        if uaddr1 & 0x3 != 0 || uaddr2 & 0x3 != 0 {
            return EINVAL;
        }
        if n_wake != 1 {
            return EINVAL;
        }
        let mut buf = [0u8; 4];
        if frame::user::copy_from_user(uaddr1, &mut buf).is_err() {
            return EFAULT;
        }
        let observed = i32::from_le_bytes(buf);
        if observed != val_cmp {
            return EAGAIN;
        }

        let key1 = Key {
            vmspace_id,
            vaddr: uaddr1,
        };
        let key2 = Key {
            vmspace_id,
            vaddr: uaddr2,
        };
        let q1 = queue_for(key1);

        let me = crate::sched::current_pid();
        let me_local = crate::sched::current_local_pid();

        let winner_pid = match q1.wake_one_pid() {
            Some(p) => p,
            None => return 0,
        };

        let winner_local = crate::sched::host_to_caller_local(winner_pid);
        let _new_word = winner_local & FUTEX_TID_MASK;
        {
            let mut pis = PI_STATES.lock();
            let entry = pis.entry(key2).or_insert_with(PiState::new);
            entry.holder = Some(winner_pid);
        }
        {
            let mut g = crate::sched::global_lock();
            if let Some(wp) = g.processes.get_mut(&winner_pid) {
                wp.pi_blocked_on = None;
                if !wp.pi_held.contains(&key2) {
                    wp.pi_held.push(key2);
                }
            }
        }

        let mut requeued = 0u32;
        for _ in 0..n_requeue {
            let cp = {
                let head = self_q1_pop_one(&q1);
                match head {
                    Some(p) => p,
                    None => break,
                }
            };
            let cp_prio = {
                let g = crate::sched::global_lock();
                g.processes
                    .get(&cp)
                    .map(|p| effective_priority(p))
                    .unwrap_or(0)
            };
            {
                let mut pis = PI_STATES.lock();
                let entry = pis.entry(key2).or_insert_with(PiState::new);
                entry.waiters.insert((255 - cp_prio, cp.raw()), ());
            }
            let _ = crate::sched::wake_pid(cp);
            requeued = requeued.saturating_add(1);
        }

        let top_waiter_prio = {
            let pis = PI_STATES.lock();
            pis.get(&key2).and_then(|s| s.top_waiter_prio())
        };
        if let Some(prio) = top_waiter_prio {
            let _ = boost_chain(me, winner_pid, prio);
        }

        if requeued > 0 {
            let mut pisbuf = [0u8; 4];
            let _ = frame::user::copy_from_user(uaddr2, &mut pisbuf);
            let prev = u32::from_le_bytes(pisbuf);
            let want = (winner_local & FUTEX_TID_MASK) | FUTEX_WAITERS;
            let _ = frame::user::cmpxchg_user_u32(uaddr2, prev, want);
        } else {
            let mut pisbuf = [0u8; 4];
            let _ = frame::user::copy_from_user(uaddr2, &mut pisbuf);
            let prev = u32::from_le_bytes(pisbuf);
            let want = winner_local & FUTEX_TID_MASK;
            let _ = frame::user::cmpxchg_user_u32(uaddr2, prev, want);
        }
        let _ = me_local;
        (1 + requeued) as i64
    }
}

#[cfg(not(host_test))]
pub use pi_impl::{cmp_requeue_pi, lock_pi, pi_owner_died, trylock_pi, unlock_pi, wait_requeue_pi};

#[cfg(host_test)]
#[cfg(test)]
mod host_tests {
    use super::*;

    fn put_user_u32(addr: u64, val: u32) {
        frame::user::register_user_buffer(addr, val.to_le_bytes().to_vec());
    }

    fn reset_globals() {
        FUTEXES.lock().clear();
        BITSET_MASKS.lock().clear();
        crate::sched::reset_for_test();
    }

    #[test]
    fn wake_no_waiters_returns_zero() {
        reset_globals();
        let n = wake(1, 0x1000, 1);
        assert_eq!(n, 0);
    }

    #[test]
    fn wake_misaligned_uaddr_rejects() {
        reset_globals();
        let n = wake(1, 0x1001, 1);
        assert_eq!(n, EINVAL);
    }

    #[test]
    fn wait_misaligned_uaddr_rejects() {
        reset_globals();
        let r = wait(1, 0x2003, 0, None);
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn wait_value_mismatch_returns_eagain() {
        reset_globals();
        let addr = 0x1000u64;
        put_user_u32(addr, 42);
        let r = wait(1, addr, 7, None);
        assert_eq!(r, EAGAIN);
    }

    #[test]
    fn wait_bad_pointer_returns_efault() {
        reset_globals();
        let r = wait(1, 0xdead_0000, 0, None);
        assert_eq!(r, EFAULT);
    }

    #[test]
    fn wake_bitset_mask_zero_rejects() {
        reset_globals();
        let r = wake_bitset(1, 0x1000, 1, 0);
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn wait_bitset_mask_zero_rejects() {
        reset_globals();
        let r = wait_bitset(1, 0x1000, 0, 0, None);
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn key_ordering_is_total_and_consistent() {
        let k1 = Key {
            vmspace_id: 1,
            vaddr: 0x1000,
        };
        let k2 = Key {
            vmspace_id: 1,
            vaddr: 0x2000,
        };
        let k3 = Key {
            vmspace_id: 2,
            vaddr: 0x500,
        };
        assert!(k1 < k2);
        assert!(k2 < k3);
        assert!(k1 < k3);
    }

    #[test]
    fn queue_for_returns_same_arc_for_repeat_key() {
        reset_globals();
        let k = Key {
            vmspace_id: 1,
            vaddr: 0x3000,
        };
        let q1 = queue_for(k);
        let q2 = queue_for(k);
        assert!(Arc::ptr_eq(&q1, &q2));
    }

    #[test]
    fn queue_for_returns_different_arcs_for_different_keys() {
        reset_globals();
        let k1 = Key {
            vmspace_id: 1,
            vaddr: 0x1000,
        };
        let k2 = Key {
            vmspace_id: 1,
            vaddr: 0x2000,
        };
        let q1 = queue_for(k1);
        let q2 = queue_for(k2);
        assert!(!Arc::ptr_eq(&q1, &q2));
    }

    #[test]
    fn queue_for_partitions_by_vmspace_id() {
        reset_globals();
        let same_vaddr = 0x4000u64;
        let q1 = queue_for(Key {
            vmspace_id: 10,
            vaddr: same_vaddr,
        });
        let q2 = queue_for(Key {
            vmspace_id: 20,
            vaddr: same_vaddr,
        });
        assert!(!Arc::ptr_eq(&q1, &q2));
    }

    #[test]
    fn drop_vmspace_sweeps_only_target_vmspace() {
        reset_globals();
        let _ = queue_for(Key {
            vmspace_id: 1,
            vaddr: 0x1000,
        });
        let _ = queue_for(Key {
            vmspace_id: 1,
            vaddr: 0x2000,
        });
        let _ = queue_for(Key {
            vmspace_id: 2,
            vaddr: 0x1000,
        });
        assert_eq!(FUTEXES.lock().len(), 3);
        drop_vmspace(1);
        let remaining = FUTEXES.lock();
        assert_eq!(remaining.len(), 1);
        assert!(remaining.contains_key(&Key {
            vmspace_id: 2,
            vaddr: 0x1000
        }));
    }

    #[test]
    fn wake_op_set_kind_writes_user_word() {
        reset_globals();
        let uaddr1 = 0x6000u64;
        let uaddr2 = 0x7000u64;
        put_user_u32(uaddr1, 0);
        put_user_u32(uaddr2, 42);
        let op_word = ((99u32 & 0xfff) << 12) | (42u32 & 0xfff);
        let r = wake_op(1, uaddr1, uaddr2, 0, 0, op_word);
        assert_eq!(r, 0);
        let buf = frame::user::take_user_buffer(uaddr2).unwrap();
        let new_val = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(new_val, 99);
    }

    fn read_user_u32(addr: u64) -> u32 {
        let buf = frame::user::take_user_buffer(addr).unwrap();
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
    }

    fn op_word(op_kind: u32, op_arg: u32) -> u32 {
        (op_kind << 28) | ((op_arg & 0xfff) << 12)
    }

    #[test]
    fn wake_op_add_through_cmpxchg_loop() {
        reset_globals();
        put_user_u32(0x6100, 0);
        put_user_u32(0x7100, 10);
        assert_eq!(wake_op(1, 0x6100, 0x7100, 0, 0, op_word(1, 5)), 0);
        assert_eq!(read_user_u32(0x7100), 15);
    }

    #[test]
    fn wake_op_or_through_cmpxchg_loop() {
        reset_globals();
        put_user_u32(0x6200, 0);
        put_user_u32(0x7200, 0x1);
        assert_eq!(wake_op(1, 0x6200, 0x7200, 0, 0, op_word(2, 0x2)), 0);
        assert_eq!(read_user_u32(0x7200), 0x3);
    }

    #[test]
    fn wake_op_andn_through_cmpxchg_loop() {
        reset_globals();
        put_user_u32(0x6300, 0);
        put_user_u32(0x7300, 0x7);
        assert_eq!(wake_op(1, 0x6300, 0x7300, 0, 0, op_word(3, 0x1)), 0);
        assert_eq!(read_user_u32(0x7300), 0x6);
    }

    #[test]
    fn wake_op_xor_through_cmpxchg_loop() {
        reset_globals();
        put_user_u32(0x6400, 0);
        put_user_u32(0x7400, 0x5);
        assert_eq!(wake_op(1, 0x6400, 0x7400, 0, 0, op_word(4, 0x3)), 0);
        assert_eq!(read_user_u32(0x7400), 0x6);
    }

    #[test]
    fn wake_op_bad_op_kind_is_einval() {
        reset_globals();
        put_user_u32(0x6500, 0);
        put_user_u32(0x7500, 0);
        assert_eq!(wake_op(1, 0x6500, 0x7500, 0, 0, 5u32 << 28), EINVAL);
    }

    #[test]
    fn wake_op_unregistered_uaddr2_is_efault() {
        reset_globals();
        put_user_u32(0x6600, 0);
        assert_eq!(wake_op(1, 0x6600, 0x7600, 0, 0, op_word(0, 99)), EFAULT);
    }

    #[test]
    fn clear_child_tid_zeros_user_word() {
        reset_globals();
        let addr = 0x8000u64;
        put_user_u32(addr, 0x1234_5678);
        clear_child_tid(1, addr);
        let buf = frame::user::take_user_buffer(addr).unwrap();
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 0);
    }

    #[test]
    fn clear_child_tid_misaligned_is_noop() {
        reset_globals();
        let addr = 0x8003u64;
        clear_child_tid(1, addr);
        assert!(frame::user::take_user_buffer(addr).is_none());
    }

    #[test]
    fn clear_child_tid_zero_addr_is_noop() {
        reset_globals();
        clear_child_tid(1, 0);
    }

    #[test]
    fn concurrent_wake_and_wait_no_data_race() {
        reset_globals();
        let addr = 0x9000u64;
        put_user_u32(addr, 0);

        let waiter = std::thread::spawn(move || {
            let r = wait(1, addr, 0, None);
            assert_eq!(r, 0);
        });

        for _ in 0..32 {
            std::thread::yield_now();
        }
        let woken = wake(1, addr, 1);
        assert!(woken == 0 || woken == 1);
        waiter.join().unwrap();
    }
}
