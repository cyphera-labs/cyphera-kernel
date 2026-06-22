extern crate alloc;

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

pub const READ_EXPIRE_NS: u64 = 500_000_000;
pub const WRITE_EXPIRE_NS: u64 = 5_000_000_000;
pub const WRITES_STARVED: u32 = 2;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoOp {
    Read,
    Write,
    Flush,
}

#[derive(Copy, Clone, Debug)]
pub struct IoRequest {
    pub id: u64,
    pub op: IoOp,
    pub lba: u64,
    pub n_sectors: u32,
    pub deadline_ns: u64,
    pub enqueued_ns: u64,
}

pub struct IoQueue {
    read_q: BTreeMap<(u64, u64), IoRequest>,
    write_q: BTreeMap<(u64, u64), IoRequest>,
    read_streak: u32,
    next_id: AtomicU64,
}

impl Default for IoQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl IoQueue {
    pub const fn new() -> Self {
        Self {
            read_q: BTreeMap::new(),
            write_q: BTreeMap::new(),
            read_streak: 0,
            next_id: AtomicU64::new(1),
        }
    }

    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn default_deadline(op: IoOp, now_ns: u64) -> u64 {
        match op {
            IoOp::Read => now_ns.saturating_add(READ_EXPIRE_NS),
            IoOp::Write | IoOp::Flush => now_ns.saturating_add(WRITE_EXPIRE_NS),
        }
    }

    pub fn build_request(&self, op: IoOp, lba: u64, n_sectors: u32, now_ns: u64) -> IoRequest {
        IoRequest {
            id: self.next_id(),
            op,
            lba,
            n_sectors,
            deadline_ns: Self::default_deadline(op, now_ns),
            enqueued_ns: now_ns,
        }
    }

    pub fn submit(&mut self, req: IoRequest) {
        let key = (req.deadline_ns, req.id);
        match req.op {
            IoOp::Read => {
                self.read_q.insert(key, req);
            }
            IoOp::Write | IoOp::Flush => {
                self.write_q.insert(key, req);
            }
        }
    }

    pub fn dispatch_next(&mut self, now_ns: u64) -> Option<IoRequest> {
        if let Some((_, &w)) = self.write_q.iter().next() {
            if w.deadline_ns <= now_ns {
                self.write_q.remove(&(w.deadline_ns, w.id));
                self.read_streak = 0;
                return Some(w);
            }
        }
        if let Some((_, &r)) = self.read_q.iter().next() {
            if r.deadline_ns <= now_ns {
                self.read_q.remove(&(r.deadline_ns, r.id));
                self.read_streak = self.read_streak.saturating_add(1);
                return Some(r);
            }
        }

        if self.read_streak >= WRITES_STARVED {
            if let Some((_, &w)) = self.write_q.iter().next() {
                self.write_q.remove(&(w.deadline_ns, w.id));
                self.read_streak = 0;
                return Some(w);
            }
        }

        if let Some((_, &r)) = self.read_q.iter().next() {
            self.read_q.remove(&(r.deadline_ns, r.id));
            self.read_streak = self.read_streak.saturating_add(1);
            return Some(r);
        }
        if let Some((_, &w)) = self.write_q.iter().next() {
            self.write_q.remove(&(w.deadline_ns, w.id));
            self.read_streak = 0;
            return Some(w);
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.read_q.is_empty() && self.write_q.is_empty()
    }

    pub fn len(&self) -> usize {
        self.read_q.len() + self.write_q.len()
    }

    pub fn counts(&self) -> (usize, usize) {
        (self.read_q.len(), self.write_q.len())
    }
}

pub trait BlockDevice {
    fn dispatch(&mut self, req: IoRequest, buf: &mut [u8]) -> KResult<()>;
    fn capacity_sectors(&self) -> u64;
}

use cyphera_kapi::{Errno, KResult};
use frame::sync::SpinIrq;

static IO_ENGINE: SpinIrq<IoQueue> = SpinIrq::new(IoQueue::new());

pub fn block_read(lba: u64, buf: &mut [u8]) -> KResult<()> {
    if buf.is_empty() || !buf.len().is_multiple_of(512) {
        return Err(Errno::INVAL);
    }
    let n_sectors = (buf.len() / 512) as u32;
    apply_io_quota(IoOp::Read, buf.len() as u64);
    let now = frame::cpu::clock::nanos_since_boot();
    let req = {
        let q = IO_ENGINE.lock();
        q.build_request(IoOp::Read, lba, n_sectors, now)
    };
    {
        let mut q = IO_ENGINE.lock();
        q.submit(req);
        let _ = q.dispatch_next(now);
    }
    ::virtio::read_block_sector(lba, buf).map_err(|_| Errno::IO)
}

pub fn block_write(lba: u64, buf: &[u8]) -> KResult<()> {
    if buf.is_empty() || !buf.len().is_multiple_of(512) {
        return Err(Errno::INVAL);
    }
    let n_sectors = (buf.len() / 512) as u32;
    apply_io_quota(IoOp::Write, buf.len() as u64);
    let now = frame::cpu::clock::nanos_since_boot();
    let req = {
        let q = IO_ENGINE.lock();
        q.build_request(IoOp::Write, lba, n_sectors, now)
    };
    {
        let mut q = IO_ENGINE.lock();
        q.submit(req);
        let _ = q.dispatch_next(now);
    }
    ::virtio::write_block_sector(lba, buf).map_err(|_| Errno::IO)
}

fn apply_io_quota(op: IoOp, bytes: u64) {
    let cg = match crate::core::current_cgroup() {
        Some(c) => c,
        None => return,
    };
    for _ in 0..2 {
        let now = frame::cpu::clock::nanos_since_boot();
        let result = {
            let mut io_ctl = cg.io.lock();
            match op {
                IoOp::Read => io_ctl.charge_read(bytes, now),
                IoOp::Write | IoOp::Flush => io_ctl.charge_write(bytes, now),
            }
        };
        match result {
            Ok(()) => return,
            Err(retry_after_ns) => {
                let deadline = now.saturating_add(retry_after_ns.max(1_000_000));
                crate::core::sleep_until(deadline);
            }
        }
    }
    let now = frame::cpu::clock::nanos_since_boot();
    let mut io_ctl = cg.io.lock();
    match op {
        IoOp::Read => {
            let _ = io_ctl.charge_read(bytes, now);
        }
        IoOp::Write | IoOp::Flush => {
            let _ = io_ctl.charge_write(bytes, now);
        }
    }
}
