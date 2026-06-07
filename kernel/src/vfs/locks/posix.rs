extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::sync::SpinIrq;

use crate::process::Pid;
use crate::wait::WaitQueue;

pub const F_RDLCK: u16 = 0;
pub const F_WRLCK: u16 = 1;
pub const F_UNLCK: u16 = 2;

#[derive(Copy, Clone, Debug)]
pub struct FileLock {
    pub kind: u16,
    pub start: u64,
    pub end: u64,
    pub owner: Pid,
}

impl FileLock {
    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
    fn conflicts(&self, other: &FileLock) -> bool {
        if self.owner == other.owner {
            return false;
        }
        if !self.overlaps(other.start, other.end) {
            return false;
        }
        self.kind == F_WRLCK || other.kind == F_WRLCK
    }
}

struct InodeLocks {
    locks: Vec<FileLock>,
    waiters: Arc<WaitQueue>,
}

static TABLE: SpinIrq<BTreeMap<u64, InodeLocks>> = SpinIrq::new(BTreeMap::new());

fn with_inode<R>(inode_id: u64, f: impl FnOnce(&mut InodeLocks) -> R) -> R {
    let mut g = TABLE.lock();
    let entry = g.entry(inode_id).or_insert_with(|| InodeLocks {
        locks: Vec::new(),
        waiters: Arc::new(WaitQueue::new()),
    });
    f(entry)
}

pub fn find_conflict(
    inode_id: u64,
    kind: u16,
    start: u64,
    end: u64,
    owner: Pid,
) -> Option<FileLock> {
    let probe = FileLock {
        kind,
        start,
        end,
        owner,
    };
    let g = TABLE.lock();
    let entry = g.get(&inode_id)?;
    for lk in &entry.locks {
        if lk.conflicts(&probe) {
            return Some(*lk);
        }
    }
    None
}

fn split_owner_range(locks: &mut Vec<FileLock>, start: u64, end: u64, owner: Pid) {
    let mut split = Vec::new();
    locks.retain(|lk| {
        if lk.owner != owner || !lk.overlaps(start, end) {
            return true;
        }
        if lk.start < start {
            split.push(FileLock {
                kind: lk.kind,
                start: lk.start,
                end: start,
                owner,
            });
        }
        if lk.end > end {
            split.push(FileLock {
                kind: lk.kind,
                start: end,
                end: lk.end,
                owner,
            });
        }
        false
    });
    locks.append(&mut split);
}

pub fn try_set_lock(
    inode_id: u64,
    kind: u16,
    start: u64,
    end: u64,
    owner: Pid,
) -> Result<(), FileLock> {
    if kind == F_UNLCK {
        unlock_range(inode_id, start, end, owner);
        return Ok(());
    }
    let waiters = with_inode(inode_id, |e| {
        let probe = FileLock {
            kind,
            start,
            end,
            owner,
        };
        for lk in &e.locks {
            if lk.conflicts(&probe) {
                return Err(*lk);
            }
        }
        split_owner_range(&mut e.locks, start, end, owner);
        e.locks.push(FileLock {
            kind,
            start,
            end,
            owner,
        });
        Ok(e.waiters.clone())
    })?;
    let _ = waiters;
    Ok(())
}

pub fn unlock_range(inode_id: u64, start: u64, end: u64, owner: Pid) {
    let waiters = with_inode(inode_id, |e| {
        split_owner_range(&mut e.locks, start, end, owner);
        e.waiters.clone()
    });
    waiters.wake_all();
}

pub fn waiters_for(inode_id: u64) -> Arc<WaitQueue> {
    with_inode(inode_id, |e| e.waiters.clone())
}

pub fn drop_owner_inode(pid: Pid, inode_id: u64) {
    let waiters = {
        let mut g = TABLE.lock();
        let entry = match g.get_mut(&inode_id) {
            Some(e) => e,
            None => return,
        };
        let before = entry.locks.len();
        entry.locks.retain(|lk| lk.owner != pid);
        if entry.locks.len() == before {
            return;
        }
        entry.waiters.clone()
    };
    waiters.wake_all();
}

pub fn drop_owner(pid: Pid) {
    let mut wakeup_queues: Vec<Arc<WaitQueue>> = Vec::new();
    {
        let mut g = TABLE.lock();
        for (_, e) in g.iter_mut() {
            let before = e.locks.len();
            e.locks.retain(|lk| lk.owner != pid);
            if e.locks.len() != before {
                wakeup_queues.push(e.waiters.clone());
            }
        }
    }
    for q in wakeup_queues {
        q.wake_all();
    }
}
