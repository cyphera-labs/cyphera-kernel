#[cfg(host_test)]
#[allow(unused_imports)]
use frame_host as frame;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use frame::sync::SpinIrq;

use crate::core::wait::WaitQueue;

pub use cyphera_kapi::WaitKey as Key;

pub(crate) static FUTEXES: SpinIrq<BTreeMap<Key, Arc<WaitQueue>>> = SpinIrq::new(BTreeMap::new());

pub(crate) static BITSET_MASKS: SpinIrq<BTreeMap<crate::process_model::Pid, u32>> =
    SpinIrq::new(BTreeMap::new());

pub(crate) fn queue_for(key: Key) -> Arc<WaitQueue> {
    let mut t = FUTEXES.lock();
    t.entry(key)
        .or_insert_with(|| Arc::new(WaitQueue::new()))
        .clone()
}

pub(crate) fn order_by_priority(
    pids: alloc::vec::Vec<crate::process_model::Pid>,
) -> alloc::vec::Vec<crate::process_model::Pid> {
    let mut indexed: alloc::vec::Vec<(usize, crate::process_model::Pid)> =
        pids.into_iter().enumerate().collect();
    indexed.sort_by(|a, b| {
        crate::core::futex_wake_priority(b.1)
            .cmp(&crate::core::futex_wake_priority(a.1))
            .then(a.0.cmp(&b.0))
    });
    indexed.into_iter().map(|(_, p)| p).collect()
}

pub(crate) fn pop_highest_priority(q: &WaitQueue) -> Option<crate::process_model::Pid> {
    let drained = q.drain();
    if drained.is_empty() {
        return None;
    }
    let mut best = 0usize;
    let mut best_prio = crate::core::futex_wake_priority(drained[0]);
    for (i, pid) in drained.iter().enumerate().skip(1) {
        let p = crate::core::futex_wake_priority(*pid);
        if p > best_prio {
            best_prio = p;
            best = i;
        }
    }
    let mut winner = None;
    for (i, pid) in drained.into_iter().enumerate() {
        if i == best {
            winner = Some(pid);
        } else {
            q.enqueue(pid);
        }
    }
    winner
}

pub(crate) use crate::errno::{EAGAIN, EFAULT, EINTR, EINVAL, ETIMEDOUT};

pub(crate) const FUTEX_OWNER_DIED: u32 = 0x4000_0000;

pub fn drop_vmspace(vmspace_id: u64) {
    let mut t = FUTEXES.lock();
    t.retain(|k, _| k.vmspace_id != vmspace_id);
    #[cfg(not(host_test))]
    super::pi::drop_vmspace_pi(vmspace_id);
}

pub(crate) fn scrub_plain_waiter(vmspace_id: u64, pid: crate::process_model::Pid) {
    let queues: alloc::vec::Vec<Arc<WaitQueue>> = {
        let t = FUTEXES.lock();
        t.iter()
            .filter(|(k, _)| k.vmspace_id == vmspace_id)
            .map(|(_, q)| q.clone())
            .collect()
    };
    for q in queues {
        q.dequeue(pid);
    }
    BITSET_MASKS.lock().remove(&pid);
}

pub fn thread_death_scrub(vmspace_id: u64, pid: crate::process_model::Pid) {
    scrub_plain_waiter(vmspace_id, pid);
    #[cfg(not(host_test))]
    super::pi::scrub_pi_waiter(vmspace_id, pid);
}
