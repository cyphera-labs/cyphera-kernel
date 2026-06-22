extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::sync::SpinIrq;

use crate::core::wait::WaitQueue;

pub const LOCK_SH: u32 = 1;
pub const LOCK_EX: u32 = 2;
pub const LOCK_UN: u32 = 8;
pub const LOCK_NB: u32 = 4;

enum FlockState {
    Unlocked,
    Shared(BTreeSet<u64>),
    Exclusive(u64),
}

struct InodeEntry {
    state: FlockState,
    waiters: Arc<WaitQueue>,
}

static TABLE: SpinIrq<BTreeMap<u64, InodeEntry>> = SpinIrq::new(BTreeMap::new());
static OWNED_BY_OFD: SpinIrq<BTreeMap<u64, u64>> = SpinIrq::new(BTreeMap::new());

fn inode_with<R>(inode_id: u64, f: impl FnOnce(&mut InodeEntry) -> R) -> R {
    let mut g = TABLE.lock();
    let entry = g.entry(inode_id).or_insert_with(|| InodeEntry {
        state: FlockState::Unlocked,
        waiters: Arc::new(WaitQueue::new()),
    });
    f(entry)
}

pub enum FlockOutcome {
    Acquired,
    Conflict,
    Released,
}

pub fn try_op(inode_id: u64, ofd_key: u64, op: u32) -> FlockOutcome {
    let kind = op & !LOCK_NB;
    let blocking = (op & LOCK_NB) == 0;
    let (outcome, drained) = inode_with(inode_id, |entry| match kind {
        LOCK_UN => {
            let drained = release_in_entry(entry, ofd_key);
            OWNED_BY_OFD.lock().remove(&ofd_key);
            (FlockOutcome::Released, drained)
        }
        LOCK_SH => acquire_shared(entry, inode_id, ofd_key),
        LOCK_EX => acquire_exclusive(entry, inode_id, ofd_key, blocking),
        _ => (FlockOutcome::Conflict, Vec::new()),
    });
    for p in drained {
        let _ = crate::core::wait::wake(p);
    }
    outcome
}

fn acquire_shared(
    entry: &mut InodeEntry,
    inode_id: u64,
    ofd_key: u64,
) -> (FlockOutcome, Vec<crate::process_model::Pid>) {
    match &mut entry.state {
        FlockState::Unlocked => {
            let mut s = BTreeSet::new();
            s.insert(ofd_key);
            entry.state = FlockState::Shared(s);
            OWNED_BY_OFD.lock().insert(ofd_key, inode_id);
            (FlockOutcome::Acquired, Vec::new())
        }
        FlockState::Shared(set) => {
            set.insert(ofd_key);
            OWNED_BY_OFD.lock().insert(ofd_key, inode_id);
            (FlockOutcome::Acquired, Vec::new())
        }
        FlockState::Exclusive(holder) => {
            if *holder == ofd_key {
                let mut s = BTreeSet::new();
                s.insert(ofd_key);
                entry.state = FlockState::Shared(s);
                let drained = entry.waiters.drain();
                (FlockOutcome::Acquired, drained)
            } else {
                (FlockOutcome::Conflict, Vec::new())
            }
        }
    }
}

fn acquire_exclusive(
    entry: &mut InodeEntry,
    inode_id: u64,
    ofd_key: u64,
    blocking: bool,
) -> (FlockOutcome, Vec<crate::process_model::Pid>) {
    match &mut entry.state {
        FlockState::Unlocked => {
            entry.state = FlockState::Exclusive(ofd_key);
            OWNED_BY_OFD.lock().insert(ofd_key, inode_id);
            (FlockOutcome::Acquired, Vec::new())
        }
        FlockState::Shared(set) => {
            if set.len() == 1 && set.contains(&ofd_key) {
                entry.state = FlockState::Exclusive(ofd_key);
                (FlockOutcome::Acquired, Vec::new())
            } else if blocking && set.remove(&ofd_key) {
                OWNED_BY_OFD.lock().remove(&ofd_key);
                if set.is_empty() {
                    entry.state = FlockState::Unlocked;
                }
                (FlockOutcome::Conflict, entry.waiters.drain())
            } else {
                (FlockOutcome::Conflict, Vec::new())
            }
        }
        FlockState::Exclusive(holder) => {
            if *holder == ofd_key {
                (FlockOutcome::Acquired, Vec::new())
            } else {
                (FlockOutcome::Conflict, Vec::new())
            }
        }
    }
}

fn release_in_entry(entry: &mut InodeEntry, ofd_key: u64) -> Vec<crate::process_model::Pid> {
    let mut woke = false;
    match &mut entry.state {
        FlockState::Unlocked => {}
        FlockState::Shared(set) => {
            if set.remove(&ofd_key) {
                woke = true;
            }
            if set.is_empty() {
                entry.state = FlockState::Unlocked;
            }
        }
        FlockState::Exclusive(holder) => {
            if *holder == ofd_key {
                entry.state = FlockState::Unlocked;
                woke = true;
            }
        }
    }
    if woke {
        entry.waiters.drain()
    } else {
        Vec::new()
    }
}

pub fn drop_ofd(ofd_key: u64) {
    let inode_id = match OWNED_BY_OFD.lock().remove(&ofd_key) {
        Some(id) => id,
        None => return,
    };
    let drained = inode_with(inode_id, |entry| release_in_entry(entry, ofd_key));
    for p in drained {
        let _ = crate::core::wait::wake(p);
    }
}

pub fn waiters_for(inode_id: u64) -> Arc<WaitQueue> {
    inode_with(inode_id, |e| e.waiters.clone())
}

#[allow(dead_code)]
pub fn held_kind(ofd_key: u64) -> Option<u32> {
    let inode_id = OWNED_BY_OFD.lock().get(&ofd_key).copied()?;
    inode_with(inode_id, |entry| match &entry.state {
        FlockState::Exclusive(h) if *h == ofd_key => Some(LOCK_EX),
        FlockState::Shared(set) if set.contains(&ofd_key) => Some(LOCK_SH),
        _ => None,
    })
}
