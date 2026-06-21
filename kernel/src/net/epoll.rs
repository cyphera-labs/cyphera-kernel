extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::sync::SpinIrq;

use crate::errno::EINTR;
use crate::vfs::{FsError, Inode, InodeKind, OpenFile, OpenFlags, PollMask, Stat};
use crate::wait::WaitQueue;

pub const EPOLLIN: u32 = 0x001;
pub const EPOLLOUT: u32 = 0x004;
pub const EPOLLERR: u32 = 0x008;
pub const EPOLLHUP: u32 = 0x010;

#[derive(Copy, Clone, Debug)]
pub struct EpollEntry {
    pub fd: i32,
    pub events: u32,
    pub user_data: u64,
}

pub struct EpollInstance {
    entries: SpinIrq<Vec<EpollEntry>>,
}

impl EpollInstance {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: SpinIrq::new(Vec::new()),
        })
    }

    pub fn ctl_add(&self, fd: i32, events: u32, user_data: u64) -> Result<(), FsError> {
        let mut e = self.entries.lock();
        if e.iter().any(|x| x.fd == fd) {
            return Err(FsError::Exists);
        }
        e.push(EpollEntry {
            fd,
            events,
            user_data,
        });
        Ok(())
    }

    pub fn ctl_mod(&self, fd: i32, events: u32, user_data: u64) -> Result<(), FsError> {
        let mut e = self.entries.lock();
        for entry in e.iter_mut() {
            if entry.fd == fd {
                entry.events = events;
                entry.user_data = user_data;
                return Ok(());
            }
        }
        Err(FsError::NotFound)
    }

    pub fn ctl_del(&self, fd: i32) -> Result<(), FsError> {
        let mut e = self.entries.lock();
        let len_before = e.len();
        e.retain(|x| x.fd != fd);
        if e.len() == len_before {
            return Err(FsError::NotFound);
        }
        Ok(())
    }

    pub fn probe<F>(&self, lookup: &F, max: usize) -> Vec<(u32, u64)>
    where
        F: Fn(i32) -> Option<Arc<OpenFile>>,
    {
        let entries = self.entries.lock().clone();
        let mut out = Vec::new();
        for entry in entries {
            if out.len() >= max {
                break;
            }
            let file = match lookup(entry.fd) {
                Some(f) => f,
                None => {
                    out.push((EPOLLERR, entry.user_data));
                    continue;
                }
            };
            let mask = file.inode.poll();
            let interesting = entry.events | EPOLLERR | EPOLLHUP;
            let delivered = mask.bits() & interesting;
            if delivered != 0 {
                out.push((delivered, entry.user_data));
            }
        }
        out
    }

    pub fn wait<F>(&self, lookup: &F, max: usize, timeout_ms: i32) -> Result<Vec<(u32, u64)>, i64>
    where
        F: Fn(i32) -> Option<Arc<OpenFile>>,
    {
        let pid = crate::sched::current_pid();
        let deadline = if timeout_ms > 0 {
            Some(
                frame::cpu::clock::nanos_since_boot()
                    .saturating_add((timeout_ms as u64).saturating_mul(1_000_000)),
            )
        } else {
            None
        };
        if let Some(d) = deadline {
            crate::timeout::register(d, pid);
        }

        loop {
            let ready = self.probe(lookup, max);
            if !ready.is_empty() || timeout_ms == 0 {
                if deadline.is_some() {
                    let _ = crate::timeout::unregister(pid);
                }
                return Ok(ready);
            }

            let snapshot: Vec<(EpollEntry, Arc<OpenFile>)> = {
                let entries = self.entries.lock().clone();
                entries
                    .into_iter()
                    .filter_map(|e| lookup(e.fd).map(|f| (e, f)))
                    .collect()
            };

            let mut queue_count = 0usize;
            for (_e, of) in &snapshot {
                of.inode.for_each_wait_queue(&mut |q: &WaitQueue| {
                    q.enqueue(pid);
                    queue_count += 1;
                });
            }

            if queue_count == 0 {
                if deadline.is_some() {
                    let _ = crate::timeout::unregister(pid);
                }
                return Ok(Vec::new());
            }

            let ready = self.probe(lookup, max);
            if !ready.is_empty() {
                for (_e, of) in &snapshot {
                    of.inode
                        .for_each_wait_queue(&mut |q: &WaitQueue| q.dequeue(pid));
                }
                if deadline.is_some() {
                    let _ = crate::timeout::unregister(pid);
                }
                return Ok(ready);
            }

            let still_queued = || {
                if let Some(d) = deadline {
                    if frame::cpu::clock::nanos_since_boot() >= d {
                        return false;
                    }
                }
                for (_e, of) in &snapshot {
                    let mut missing = false;
                    of.inode.for_each_wait_queue(&mut |q: &WaitQueue| {
                        if !q.contains(pid) {
                            missing = true;
                        }
                    });
                    if missing {
                        return false;
                    }
                }
                true
            };
            let outcome = crate::wait::wait_guarded("epoll_wait", deadline, &still_queued);

            for (_e, of) in &snapshot {
                of.inode
                    .for_each_wait_queue(&mut |q: &WaitQueue| q.dequeue(pid));
            }
            drop(snapshot);

            match outcome {
                crate::wait::WaitOutcome::Interrupted => {
                    if deadline.is_some() {
                        let _ = crate::timeout::unregister(pid);
                    }
                    return Err(EINTR);
                }
                crate::wait::WaitOutcome::TimedOut => {
                    if deadline.is_some() {
                        let _ = crate::timeout::unregister(pid);
                    }
                    return Ok(Vec::new());
                }
                crate::wait::WaitOutcome::Woken => {}
            }
        }
    }
}

impl Inode for EpollInstance {
    fn kind(&self) -> InodeKind {
        InodeKind::Pipe
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Pipe, 0, 0o600)
    }
    fn on_open(&self, _flags: OpenFlags) {}
    fn on_close(&self, _flags: OpenFlags) {}
    fn poll(&self) -> PollMask {
        PollMask::empty()
    }
}
