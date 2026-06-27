extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use frame::sync::SpinIrq;

use crate::core::wait::{WaitOutcome, WaitQueue, wait_guarded};
use crate::vfs::{Inode, InodeKind, OpenFlags, PollMask, Stat};
use cyphera_kapi::{Errno, KResult};

pub const IN_ACCESS: u32 = 0x0000_0001;
pub const IN_MODIFY: u32 = 0x0000_0002;
pub const IN_ATTRIB: u32 = 0x0000_0004;
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub const IN_OPEN: u32 = 0x0000_0020;
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
pub const IN_MOVED_TO: u32 = 0x0000_0080;
pub const IN_CREATE: u32 = 0x0000_0100;
pub const IN_DELETE: u32 = 0x0000_0200;
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
pub const IN_MOVE_SELF: u32 = 0x0000_0800;

const IN_ISDIR: u32 = 0x4000_0000;
const IN_IGNORED: u32 = 0x0000_8000;
const IN_Q_OVERFLOW: u32 = 0x0000_4000;

const MAX_QUEUED_EVENTS: usize = 16384;

const IN_MASK_ADD: u32 = 0x2000_0000;
const IN_MASK_CREATE: u32 = 0x1000_0000;
const IN_ONLYDIR: u32 = 0x0100_0000;
const ALL_EVENTS: u32 = IN_ACCESS
    | IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE
    | IN_OPEN
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF;

pub const IN_NONBLOCK: u32 = 0o4000;
pub const IN_CLOEXEC: u32 = 0o2_000_000;

const EVENT_HDR: usize = 16;

fn name_field_len(name: &str) -> usize {
    (name.len() + 1).div_ceil(EVENT_HDR) * EVENT_HDR
}

struct QueuedEvent {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: Option<String>,
}

impl QueuedEvent {
    fn packed_len(&self) -> usize {
        EVENT_HDR + self.name.as_deref().map_or(0, name_field_len)
    }

    fn serialize(&self, out: &mut [u8]) {
        let nlen = self.name.as_deref().map_or(0, name_field_len);
        out[0..4].copy_from_slice(&self.wd.to_le_bytes());
        out[4..8].copy_from_slice(&self.mask.to_le_bytes());
        out[8..12].copy_from_slice(&self.cookie.to_le_bytes());
        out[12..16].copy_from_slice(&(nlen as u32).to_le_bytes());
        for b in &mut out[EVENT_HDR..EVENT_HDR + nlen] {
            *b = 0;
        }
        if let Some(n) = &self.name {
            out[EVENT_HDR..EVENT_HDR + n.len()].copy_from_slice(n.as_bytes());
        }
    }
}

struct Watch {
    wd: i32,
    inode: Arc<dyn Inode>,
    mask: u32,
}

pub struct InotifyInode {
    watches: SpinIrq<Vec<Watch>>,
    events: SpinIrq<VecDeque<QueuedEvent>>,
    next_wd: AtomicI32,
    wait: WaitQueue,
    inode_id: u64,
}

struct WatchRef {
    instance: Weak<InotifyInode>,
    wd: i32,
    mask: u32,
}

static REGISTRY: SpinIrq<BTreeMap<u64, Vec<WatchRef>>> = SpinIrq::new(BTreeMap::new());
static ACTIVE_WATCHES: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static NEXT_INOTIFY_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
static NEXT_COOKIE: AtomicU32 = AtomicU32::new(1);

pub fn watching() -> bool {
    ACTIVE_WATCHES.load(Ordering::Relaxed) != 0
}

impl InotifyInode {
    pub fn new() -> Arc<Self> {
        let inode_id = 0xfb00_0000_0000_0000 | NEXT_INOTIFY_ID.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self {
            watches: SpinIrq::new(Vec::new()),
            events: SpinIrq::new(VecDeque::new()),
            next_wd: AtomicI32::new(1),
            wait: WaitQueue::new(),
            inode_id,
        })
    }

    pub fn add_watch(self: &Arc<Self>, inode: Arc<dyn Inode>, raw_mask: u32) -> KResult<i32> {
        if raw_mask & ALL_EVENTS == 0 {
            return Err(Errno::INVAL);
        }
        if raw_mask & IN_ONLYDIR != 0 && !matches!(inode.kind(), InodeKind::Directory) {
            return Err(Errno::NOTDIR);
        }
        let mask = raw_mask & ALL_EVENTS;
        let target = inode.inode_id();
        let mut watches = self.watches.lock();

        if let Some(w) = watches.iter_mut().find(|w| w.inode.inode_id() == target) {
            if raw_mask & IN_MASK_CREATE != 0 {
                return Err(Errno::EXIST);
            }
            w.mask = if raw_mask & IN_MASK_ADD != 0 {
                w.mask | mask
            } else {
                mask
            };
            let wd = w.wd;
            let new_mask = w.mask;
            drop(watches);
            let mut reg = REGISTRY.lock();
            if let Some(refs) = reg.get_mut(&target) {
                if let Some(r) = refs
                    .iter_mut()
                    .find(|r| r.wd == wd && weak_is(&r.instance, self))
                {
                    r.mask = new_mask;
                }
            }
            return Ok(wd);
        }

        let wd = self.next_wd.fetch_add(1, Ordering::Relaxed);
        watches.push(Watch { wd, inode, mask });
        drop(watches);
        REGISTRY.lock().entry(target).or_default().push(WatchRef {
            instance: Arc::downgrade(self),
            wd,
            mask,
        });
        ACTIVE_WATCHES.fetch_add(1, Ordering::Relaxed);
        Ok(wd)
    }

    pub fn rm_watch(self: &Arc<Self>, wd: i32) -> KResult<()> {
        let mut watches = self.watches.lock();
        let pos = watches
            .iter()
            .position(|w| w.wd == wd)
            .ok_or(Errno::INVAL)?;
        let target = watches[pos].inode.inode_id();
        watches.remove(pos);
        drop(watches);
        registry_remove(target, wd, self);
        ACTIVE_WATCHES.fetch_sub(1, Ordering::Relaxed);
        self.queue(QueuedEvent {
            wd,
            mask: IN_IGNORED,
            cookie: 0,
            name: None,
        });
        Ok(())
    }

    fn queue(&self, ev: QueuedEvent) {
        {
            let mut q = self.events.lock();
            if let Some(back) = q.back() {
                if back.wd == ev.wd
                    && back.mask == ev.mask
                    && back.cookie == ev.cookie
                    && back.name == ev.name
                {
                    return;
                }
            }
            if q.len() >= MAX_QUEUED_EVENTS {
                let overflowed = q
                    .back()
                    .is_some_and(|b| b.wd == -1 && b.mask == IN_Q_OVERFLOW);
                if !overflowed {
                    q.push_back(QueuedEvent {
                        wd: -1,
                        mask: IN_Q_OVERFLOW,
                        cookie: 0,
                        name: None,
                    });
                } else {
                    return;
                }
            } else {
                q.push_back(ev);
            }
        }
        self.wait.wake_all();
    }
}

fn weak_is(weak: &Weak<InotifyInode>, inst: &Arc<InotifyInode>) -> bool {
    core::ptr::eq(Weak::as_ptr(weak), Arc::as_ptr(inst))
}

fn registry_remove(target: u64, wd: i32, inst: &Arc<InotifyInode>) {
    let mut reg = REGISTRY.lock();
    if let Some(refs) = reg.get_mut(&target) {
        refs.retain(|r| !(r.wd == wd && weak_is(&r.instance, inst)));
        if refs.is_empty() {
            reg.remove(&target);
        }
    }
}

impl Inode for InotifyInode {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        let mut s = Stat::fresh(InodeKind::CharDevice, 0, 0o600);
        s.inode_id = self.inode_id;
        s
    }
    fn inode_id(&self) -> u64 {
        self.inode_id
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(&self, _off: u64, buf: &mut [u8], flags: OpenFlags) -> KResult<usize> {
        let nonblock = flags.contains(OpenFlags::NONBLOCK);
        let pid = crate::core::current_pid();
        loop {
            self.wait.enqueue(pid);
            {
                let mut q = self.events.lock();
                if let Some(front) = q.front() {
                    if front.packed_len() > buf.len() {
                        self.wait.dequeue(pid);
                        return Err(Errno::INVAL);
                    }
                    let mut written = 0;
                    while let Some(ev) = q.front() {
                        let sz = ev.packed_len();
                        if written + sz > buf.len() {
                            break;
                        }
                        let ev = q.pop_front().unwrap();
                        ev.serialize(&mut buf[written..written + sz]);
                        written += sz;
                    }
                    drop(q);
                    self.wait.dequeue(pid);
                    return Ok(written);
                }
            }
            if nonblock {
                self.wait.dequeue(pid);
                return Err(Errno::AGAIN);
            }
            let still = || self.wait.contains(pid);
            let outcome = wait_guarded("inotify_read", None, &still);
            self.wait.dequeue(pid);
            if outcome == WaitOutcome::Interrupted {
                return Err(Errno::INTR);
            }
        }
    }

    fn poll(&self) -> PollMask {
        if self.events.lock().is_empty() {
            PollMask::empty()
        } else {
            PollMask::IN
        }
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&self.wait);
    }

    fn on_close(&self, _flags: OpenFlags) {
        let watches = core::mem::take(&mut *self.watches.lock());
        ACTIVE_WATCHES.fetch_sub(watches.len(), Ordering::Relaxed);
        let mut reg = REGISTRY.lock();
        for w in watches {
            let id = w.inode.inode_id();
            if let Some(refs) = reg.get_mut(&id) {
                refs.retain(|r| !core::ptr::eq(Weak::as_ptr(&r.instance), self));
                if refs.is_empty() {
                    reg.remove(&id);
                }
            }
        }
    }
}

pub fn notify(inode_id: u64, mask: u32, name: Option<&str>, cookie: u32, is_dir: bool) {
    if !watching() {
        return;
    }
    let targets: Vec<(Arc<InotifyInode>, i32)> = {
        let mut reg = REGISTRY.lock();
        let Some(refs) = reg.get_mut(&inode_id) else {
            return;
        };
        refs.retain(|r| r.instance.strong_count() > 0);
        let hits: Vec<(Arc<InotifyInode>, i32)> = refs
            .iter()
            .filter(|r| r.mask & mask != 0)
            .filter_map(|r| r.instance.upgrade().map(|i| (i, r.wd)))
            .collect();
        if refs.is_empty() {
            reg.remove(&inode_id);
        }
        hits
    };
    if targets.is_empty() {
        return;
    }
    let full = if is_dir { mask | IN_ISDIR } else { mask };
    for (inst, wd) in targets {
        inst.queue(QueuedEvent {
            wd,
            mask: full,
            cookie,
            name: name.map(String::from),
        });
    }
}

pub fn next_cookie() -> u32 {
    NEXT_COOKIE.fetch_add(1, Ordering::Relaxed)
}

pub fn dir_event(parent: &dyn Inode, name: &str, child_is_dir: bool, mask: u32) {
    notify(parent.inode_id(), mask, Some(name), 0, child_is_dir);
}

pub fn self_event(inode: &dyn Inode, mask: u32) {
    let is_dir = matches!(inode.kind(), InodeKind::Directory);
    notify(inode.inode_id(), mask, None, 0, is_dir);
}
