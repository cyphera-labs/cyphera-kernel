use super::*;

use alloc::collections::BTreeMap;

use frame::sync::SpinIrq;

pub(crate) fn drop_vmspace_pi(vmspace_id: u64) {
    PI_STATES.lock().retain(|k, _| k.vmspace_id != vmspace_id);
}

pub(crate) fn scrub_pi_waiter(vmspace_id: u64, dying_pid: crate::process_model::Pid) {
    let raw = dying_pid.raw();
    let mut pis = PI_STATES.lock();
    for (k, s) in pis.iter_mut() {
        if k.vmspace_id != vmspace_id {
            continue;
        }
        let keys: alloc::vec::Vec<(u8, u32)> = s
            .waiters
            .keys()
            .filter(|(_, r)| *r == raw)
            .copied()
            .collect();
        for key in keys {
            s.waiters.remove(&key);
        }
    }
    drop(pis);
    crate::core::clear_pi_blocked_on(dying_pid);
}

const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;

const MAX_PI_CHAIN_DEPTH: usize = 16;

const PI_LOCK_MAX_ATTEMPTS: usize = 64;

const PI_LOCK_MAX_SPINS: usize = 1 << 20;

use crate::errno::{EDEADLK, EPERM};

struct PiState {
    holder: Option<crate::process_model::Pid>,
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

    fn pop_top(&mut self) -> Option<(crate::process_model::Pid, bool)> {
        let key = self.waiters.iter().next().map(|(k, _)| *k)?;
        self.waiters.remove(&key);
        Some((
            crate::process_model::Pid::from_raw(key.1),
            !self.waiters.is_empty(),
        ))
    }
}

fn pop_live_winner(key: Key) -> Option<(crate::process_model::Pid, bool)> {
    loop {
        let popped = {
            let mut pis = PI_STATES.lock();
            match pis.get_mut(&key) {
                Some(s) => s.pop_top(),
                None => None,
            }
        };
        match popped {
            Some((pid, has_more)) => {
                if crate::core::pid_is_terminating(pid) {
                    crate::core::clear_pi_blocked_on(pid);
                    continue;
                }
                return Some((pid, has_more));
            }
            None => return None,
        }
    }
}

static PI_STATES: SpinIrq<BTreeMap<Key, PiState>> = SpinIrq::new(BTreeMap::new());

enum Word {
    Keep,
    Set(u32),
}

fn transfer_pi_ownership(
    key: Key,
    from: Option<crate::process_model::Pid>,
    to: Option<crate::process_model::Pid>,
    word: Word,
    wake_to: bool,
) -> Result<(), i64> {
    if let Word::Set(value) = word {
        if frame::user::copy_to_user(key.vaddr, &value.to_le_bytes()).is_err() {
            return Err(EFAULT);
        }
    }

    {
        let mut pis = PI_STATES.lock();
        let drop_state = match pis.get_mut(&key) {
            Some(s) => {
                s.holder = to;
                to.is_none() && s.waiters.is_empty()
            }
            None => {
                if let Some(new_holder) = to {
                    pis.entry(key).or_insert_with(PiState::new).holder = Some(new_holder);
                }
                false
            }
        };
        if drop_state {
            pis.remove(&key);
        }
    }

    if let Some(old) = from {
        crate::core::remove_pi_held(old, key);
    }
    if let Some(new_holder) = to {
        if Some(new_holder) == from {
            crate::core::add_pi_held(new_holder, key);
        } else {
            crate::core::pi_acquired(new_holder, key);
        }
        if wake_to {
            let _ = crate::core::wait::wake(new_holder);
        }
    }
    Ok(())
}

fn effective_priority(sc: crate::process_model::SchedClass) -> u8 {
    use crate::process_model::SchedClass;
    match sc {
        SchedClass::Rt { priority, .. } => priority,
        SchedClass::Cfs | SchedClass::Deadline { .. } => 0,
    }
}

fn top_waiter_prio_for(holder: crate::process_model::Pid) -> u8 {
    let held = crate::core::pi_held_keys(holder);
    let pi_states = PI_STATES.lock();
    held.iter()
        .filter_map(|k| pi_states.get(k).and_then(|s| s.top_waiter_prio()))
        .max()
        .unwrap_or(0)
}

fn boost_chain(
    locker: crate::process_model::Pid,
    initial_holder: crate::process_model::Pid,
    target_prio: u8,
) -> Result<(), i64> {
    let mut current = initial_holder;
    for _depth in 0..MAX_PI_CHAIN_DEPTH {
        if current == locker {
            return Err(EDEADLK);
        }
        crate::core::pi_boost(current, target_prio);
        match crate::core::pi_blocked_on(current) {
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
    let me = crate::core::current_pid();
    let my_tid = crate::core::current_local_pid();
    if my_tid > FUTEX_TID_MASK {
        return EINVAL;
    }

    let my_prio = crate::core::sched_class_of_pid(me)
        .map(effective_priority)
        .unwrap_or(0);

    let mut attempts = 0usize;
    let mut spins = 0usize;
    loop {
        if attempts >= PI_LOCK_MAX_ATTEMPTS || spins >= PI_LOCK_MAX_SPINS {
            return EAGAIN;
        }
        let observed = match frame::user::cmpxchg_user_u32(uaddr, 0, my_tid) {
            Ok(v) => v,
            Err(_) => return EFAULT,
        };
        if observed == 0 {
            let _ = transfer_pi_ownership(key, Some(me), Some(me), Word::Keep, false);
            return 0;
        }
        if (observed & FUTEX_TID_MASK) == my_tid {
            return EDEADLK;
        }
        let holder_tid = observed & FUTEX_TID_MASK;

        let holder_dead = match crate::core::caller_local_to_host(holder_tid) {
            None => true,
            Some(h) => crate::core::pid_is_terminating(h),
        };
        if holder_dead {
            let want = my_tid | (observed & (FUTEX_WAITERS | FUTEX_OWNER_DIED));
            match frame::user::cmpxchg_user_u32(uaddr, observed, want) {
                Ok(prev) if prev == observed => {
                    let _ = transfer_pi_ownership(key, Some(me), Some(me), Word::Keep, false);
                    return 0;
                }
                Ok(_) => {
                    spins += 1;
                    continue;
                }
                Err(_) => return EFAULT,
            }
        }

        let holder_pid = crate::core::caller_local_to_host(holder_tid)
            .unwrap_or_else(|| crate::process_model::Pid::from_raw(holder_tid));

        crate::core::set_pi_blocked_on(me, key);
        let enqueued = {
            let mut pis = PI_STATES.lock();
            match frame::user::cmpxchg_user_u32(uaddr, observed, observed | FUTEX_WAITERS) {
                Ok(prev) if prev == observed => {
                    let entry = pis.entry(key).or_insert_with(PiState::new);
                    if entry.holder.is_none() {
                        entry.holder = Some(holder_pid);
                    }
                    entry.waiters.insert((255 - my_prio, me.raw()), ());
                    true
                }
                _ => false,
            }
        };
        if !enqueued {
            crate::core::clear_pi_blocked_on(me);
            spins += 1;
            continue;
        }

        if let Err(e) = boost_chain(me, holder_pid, my_prio) {
            let mut pis = PI_STATES.lock();
            if let Some(s) = pis.get_mut(&key) {
                s.waiters.remove(&(255 - my_prio, me.raw()));
            }
            crate::core::clear_pi_blocked_on(me);
            return e;
        }

        if let Some(deadline) = deadline_nanos {
            crate::core::timeout::register(deadline, me);
        }
        crate::core::park_on_pi_wait(key);
        let timed_out = deadline_nanos.is_some() && !crate::core::timeout::unregister(me);

        let acquired = {
            let pis = PI_STATES.lock();
            pis.get(&key).map(|s| s.holder == Some(me)).unwrap_or(false)
        };
        if acquired {
            crate::core::pi_acquired(me, key);
            return 0;
        }

        {
            let mut pis = PI_STATES.lock();
            if let Some(s) = pis.get_mut(&key) {
                s.waiters.remove(&(255 - my_prio, me.raw()));
            }
        }
        crate::core::clear_pi_blocked_on(me);
        if let Some(h) = {
            let pis = PI_STATES.lock();
            pis.get(&key).and_then(|s| s.holder)
        } {
            crate::core::pi_refresh(h, top_waiter_prio_for(h));
        }
        if crate::core::current_signal_pending() {
            return EINTR;
        }
        if timed_out {
            return ETIMEDOUT;
        }
        attempts += 1;
    }
}

pub fn trylock_pi(vmspace_id: u64, uaddr: u64) -> i64 {
    if uaddr & 0x3 != 0 {
        return EINVAL;
    }
    let key = Key {
        vmspace_id,
        vaddr: uaddr,
    };
    let me = crate::core::current_pid();
    let my_tid = crate::core::current_local_pid();
    if my_tid > FUTEX_TID_MASK {
        return EINVAL;
    }
    let observed = match frame::user::cmpxchg_user_u32(uaddr, 0, my_tid) {
        Ok(v) => v,
        Err(_) => return EFAULT,
    };
    if observed == 0 {
        let _ = transfer_pi_ownership(key, Some(me), Some(me), Word::Keep, false);
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
    let me = crate::core::current_pid();
    let my_tid = crate::core::current_local_pid();

    let mut buf = [0u8; 4];
    if frame::user::copy_from_user(uaddr, &mut buf).is_err() {
        return EFAULT;
    }
    let cur = u32::from_le_bytes(buf);
    if (cur & FUTEX_TID_MASK) != my_tid {
        return EPERM;
    }

    let popped = pop_live_winner(key);

    let (new_word, winner) = match popped {
        Some((winner_pid, has_more)) => {
            let winner_local = crate::core::host_to_caller_local(winner_pid);
            let mut w = winner_local & FUTEX_TID_MASK;
            if has_more {
                w |= FUTEX_WAITERS;
            }
            (w, Some(winner_pid))
        }
        None => (0, None),
    };

    if let Err(e) = transfer_pi_ownership(key, Some(me), winner, Word::Set(new_word), true) {
        return e;
    }

    crate::core::pi_refresh(me, top_waiter_prio_for(me));
    0
}

pub fn pi_owner_died(vmspace_id: u64, dying_pid: crate::process_model::Pid) {
    use alloc::vec::Vec;
    let keys: Vec<Key> = {
        let pis = PI_STATES.lock();
        pis.iter()
            .filter(|(k, s)| k.vmspace_id == vmspace_id && s.holder == Some(dying_pid))
            .map(|(k, _)| *k)
            .collect()
    };
    for key in keys {
        let mut cur = [0u8; 4];
        let owner_died = if frame::user::copy_from_user(key.vaddr, &mut cur).is_ok() {
            u32::from_le_bytes(cur) & FUTEX_OWNER_DIED
        } else {
            0
        };
        let popped = pop_live_winner(key);
        if let Some((winner, has_more)) = popped {
            let winner_local = crate::core::host_to_caller_local(winner);
            let mut w = (winner_local & FUTEX_TID_MASK) | owner_died;
            if has_more {
                w |= FUTEX_WAITERS;
            }
            let _ = transfer_pi_ownership(key, Some(dying_pid), Some(winner), Word::Set(w), true);
        } else {
            let _ = transfer_pi_ownership(key, Some(dying_pid), None, Word::Set(owner_died), false);
        }
    }
}

fn self_q1_pop_one(
    q: &alloc::sync::Arc<crate::core::wait::WaitQueue>,
) -> Option<crate::process_model::Pid> {
    super::pop_highest_priority(q)
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
    let me = crate::core::current_pid();

    let mut buf = [0u8; 4];
    if frame::user::copy_from_user(uaddr1, &mut buf).is_err() {
        return EFAULT;
    }
    let val = i32::from_le_bytes(buf);
    if val != expected {
        return EAGAIN;
    }

    crate::core::set_pi_blocked_on(me, key2);

    if let Some(deadline) = deadline_nanos {
        crate::core::timeout::register(deadline, me);
    }
    crate::core::park_on_pi_requeue(&q1, me);
    q1.dequeue(me);
    let timed_out = deadline_nanos.is_some() && !crate::core::timeout::unregister(me);

    let already_owner = {
        let pis = PI_STATES.lock();
        pis.get(&key2)
            .map(|s| s.holder == Some(me))
            .unwrap_or(false)
    };
    if already_owner {
        crate::core::pi_acquired(me, key2);
        return 0;
    }

    let queued_on_pi = {
        let pis = PI_STATES.lock();
        pis.get(&key2)
            .map(|s| s.waiters.iter().any(|(&(_, raw), _)| raw == me.raw()))
            .unwrap_or(false)
    };
    if queued_on_pi && !timed_out && !crate::core::current_signal_pending() {
        if let Some(deadline) = deadline_nanos {
            crate::core::timeout::register(deadline, me);
        }
        crate::core::park_on_pi_wait(key2);
        let timed_out2 = deadline_nanos.is_some() && !crate::core::timeout::unregister(me);
        let acquired = {
            let pis = PI_STATES.lock();
            pis.get(&key2)
                .map(|s| s.holder == Some(me))
                .unwrap_or(false)
        };
        if acquired {
            crate::core::pi_acquired(me, key2);
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
        crate::core::clear_pi_blocked_on(me);
        if crate::core::current_signal_pending() {
            return EINTR;
        }
        if timed_out2 {
            return ETIMEDOUT;
        }
        return EAGAIN;
    }

    crate::core::clear_pi_blocked_on(me);
    if crate::core::current_signal_pending() {
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

    let me = crate::core::current_pid();
    let me_local = crate::core::current_local_pid();

    let winner_pid = match super::pop_highest_priority(&q1) {
        Some(p) => p,
        None => return 0,
    };

    let winner_local = crate::core::host_to_caller_local(winner_pid);
    let _ = transfer_pi_ownership(key2, None, Some(winner_pid), Word::Keep, true);

    let mut requeued = 0u32;
    for _ in 0..n_requeue {
        let cp = {
            let head = self_q1_pop_one(&q1);
            match head {
                Some(p) => p,
                None => break,
            }
        };
        let cp_prio = crate::core::sched_class_of_pid(cp)
            .map(effective_priority)
            .unwrap_or(0);
        {
            let mut pis = PI_STATES.lock();
            let entry = pis.entry(key2).or_insert_with(PiState::new);
            entry.waiters.insert((255 - cp_prio, cp.raw()), ());
        }
        let _ = crate::core::wait::wake(cp);
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
