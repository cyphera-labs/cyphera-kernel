extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use frame::sync::SpinIrq;

use crate::process::Pid;
use crate::vfs::blocking::IoAttempt;
use crate::vfs::{FsError, Inode, InodeKind, OpenFlags, PollMask, Stat};

#[derive(Clone)]
pub enum NamespaceHandle {
    Uts(Arc<crate::process::UtsNamespace>),
    Ipc(Arc<crate::process::IpcNamespace>),
    Pid(Arc<crate::process::PidNamespace>),
    Cgroup(Arc<crate::process::CgroupNamespace>),
    Time(Arc<crate::process::TimeNamespace>),
    Net(Arc<crate::net::NetNamespace>),
}

impl NamespaceHandle {
    pub fn type_flag(&self) -> u64 {
        match self {
            NamespaceHandle::Uts(_) => 0x0400_0000,
            NamespaceHandle::Ipc(_) => 0x0800_0000,
            NamespaceHandle::Pid(_) => 0x2000_0000,
            NamespaceHandle::Cgroup(_) => 0x0200_0000,
            NamespaceHandle::Time(_) => 0x0000_0080,
            NamespaceHandle::Net(_) => 0x4000_0000,
        }
    }
}

pub struct NamespaceFdInode {
    handle: NamespaceHandle,
    inode_id: u64,
}

static NEXT_NSFD_ID: AtomicU64 = AtomicU64::new(1);

impl NamespaceFdInode {
    pub fn new(handle: NamespaceHandle) -> Arc<Self> {
        let inode_id = 0xf500_0000_0000_0000 | NEXT_NSFD_ID.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { handle, inode_id })
    }
}

impl Inode for NamespaceFdInode {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        let mut s = Stat::fresh(InodeKind::Regular, 0, 0o444);
        s.inode_id = self.inode_id;
        s
    }
    fn inode_id(&self) -> u64 {
        self.inode_id
    }
    fn as_namespace_handle(&self) -> Option<&NamespaceHandle> {
        Some(&self.handle)
    }
}

pub struct PidFdInode {
    pub target: Pid,
    inode_id: u64,
}

static NEXT_PIDFD_ID: AtomicU64 = AtomicU64::new(1);

impl PidFdInode {
    pub fn new(target: Pid) -> Arc<Self> {
        let inode_id = 0xfd00_0000_0000_0000 | NEXT_PIDFD_ID.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self { target, inode_id })
    }

    fn target_exited(&self) -> bool {
        match crate::sched::process_state(self.target) {
            Some(s) => matches!(
                s,
                crate::process::ProcessState::Zombie(_)
                    | crate::process::ProcessState::KilledByFault { .. }
                    | crate::process::ProcessState::KilledBySignal { .. }
            ),
            None => true,
        }
    }
}

impl Inode for PidFdInode {
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

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, FsError> {
        loop {
            if self.target_exited() {
                return Ok(0);
            }
            crate::sched::park_on_exit_of(self.target);
            if self.target_exited() {
                return Ok(0);
            }
            if crate::sched::current_signal_pending() {
                return Err(FsError::Interrupted);
            }
        }
    }

    fn poll(&self) -> PollMask {
        if self.target_exited() {
            PollMask::IN
        } else {
            PollMask::empty()
        }
    }
}

pub struct SignalFdInode {
    pub mask: SpinIrq<u64>,
    inode_id: u64,
}

static NEXT_SIGNALFD_ID: AtomicU64 = AtomicU64::new(1);

impl SignalFdInode {
    pub fn new(mask: u64) -> Arc<Self> {
        let inode_id = 0xfe00_0000_0000_0000 | NEXT_SIGNALFD_ID.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self {
            mask: SpinIrq::new(mask),
            inode_id,
        })
    }
    pub fn set_mask(&self, mask: u64) {
        *self.mask.lock() = mask;
    }
}

impl Inode for SignalFdInode {
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

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        const SIGINFO_SZ: usize = 128;
        if buf.len() < SIGINFO_SZ {
            return Err(FsError::InvalidArgument);
        }
        let mask = *self.mask.lock();
        let mut written = 0;
        loop {
            let candidate = crate::sched::current_pending_in_mask(mask);
            if candidate == 0 {
                if written > 0 {
                    return Ok(written);
                }
                crate::sched::park_on_signalfd_wait();
                continue;
            }
            let signum = candidate.trailing_zeros();
            let (si_code, aux) = crate::sched::consume_pending_signal(signum);

            let off = written;
            if off + SIGINFO_SZ > buf.len() {
                return Ok(written);
            }
            for b in &mut buf[off..off + SIGINFO_SZ] {
                *b = 0;
            }
            buf[off..off + 4].copy_from_slice(&signum.to_le_bytes());
            buf[off + 8..off + 12].copy_from_slice(&(si_code as u32).to_le_bytes());
            buf[off + 12..off + 16].copy_from_slice(&(aux as u32).to_le_bytes());
            written += SIGINFO_SZ;
        }
    }

    fn poll(&self) -> PollMask {
        let mask = *self.mask.lock();
        if crate::sched::current_pending_in_mask(mask) != 0 {
            PollMask::IN
        } else {
            PollMask::empty()
        }
    }
}

pub struct EventFdInode {
    pub counter: SpinIrq<u64>,
    pub semaphore: bool,
    wait: crate::wait::WaitQueue,
    inode_id: u64,
}

static NEXT_EVENTFD_ID: AtomicU64 = AtomicU64::new(1);

pub const EFD_SEMAPHORE: u32 = 1;

const EVENTFD_MAX: u64 = u64::MAX - 1;

impl EventFdInode {
    pub fn new(initval: u64, semaphore: bool) -> Arc<Self> {
        let inode_id = 0xef00_0000_0000_0000 | NEXT_EVENTFD_ID.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self {
            counter: SpinIrq::new(initval),
            semaphore,
            wait: crate::wait::WaitQueue::new(),
            inode_id,
        })
    }
}

impl Inode for EventFdInode {
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

    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        self.read_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(
        &self,
        _off: u64,
        buf: &mut [u8],
        flags: OpenFlags,
    ) -> Result<usize, FsError> {
        if buf.len() < 8 {
            return Err(FsError::InvalidArgument);
        }
        crate::vfs::blocking::block_io(
            "eventfd_read",
            &self.wait,
            flags.contains(OpenFlags::NONBLOCK),
            None,
            || {
                let mut c = self.counter.lock();
                if *c > 0 {
                    let val = if self.semaphore {
                        *c -= 1;
                        1u64
                    } else {
                        let v = *c;
                        *c = 0;
                        v
                    };
                    drop(c);
                    buf[..8].copy_from_slice(&val.to_le_bytes());
                    self.wait.wake_all();
                    IoAttempt::Ready(8)
                } else {
                    IoAttempt::WouldBlock
                }
            },
        )
    }

    fn write_at(&self, off: u64, buf: &[u8]) -> Result<usize, FsError> {
        self.write_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn write_at_with_flags(
        &self,
        _off: u64,
        buf: &[u8],
        flags: OpenFlags,
    ) -> Result<usize, FsError> {
        if buf.len() < 8 {
            return Err(FsError::InvalidArgument);
        }
        let add = u64::from_le_bytes(buf[..8].try_into().unwrap());
        if add == u64::MAX {
            return Err(FsError::InvalidArgument);
        }
        crate::vfs::blocking::block_io(
            "eventfd_write",
            &self.wait,
            flags.contains(OpenFlags::NONBLOCK),
            None,
            || {
                let mut c = self.counter.lock();
                if c.checked_add(add)
                    .map(|n| n <= EVENTFD_MAX)
                    .unwrap_or(false)
                {
                    *c += add;
                    drop(c);
                    self.wait.wake_all();
                    IoAttempt::Ready(8)
                } else {
                    IoAttempt::WouldBlock
                }
            },
        )
    }

    fn poll(&self) -> PollMask {
        let c = *self.counter.lock();
        let mut m = PollMask::empty();
        if c > 0 {
            m |= PollMask::IN;
        }
        if c < EVENTFD_MAX {
            m |= PollMask::OUT;
        }
        m
    }
}

use alloc::collections::BTreeMap;

pub struct TimerFdInode {
    pub state: SpinIrq<TimerFdState>,
    pub clock_id: u32,
    wait: crate::wait::WaitQueue,
    inode_id: u64,
}

#[derive(Copy, Clone, Default)]
pub struct TimerFdState {
    pub deadline: u64,
    pub interval_ns: u64,
    pub expirations: u64,
}

static NEXT_TIMERFD_ID: AtomicU64 = AtomicU64::new(1);

static TIMERFD_INDEX: SpinIrq<BTreeMap<u64, Arc<TimerFdInode>>> = SpinIrq::new(BTreeMap::new());

impl TimerFdInode {
    pub fn new(clock_id: u32) -> Arc<Self> {
        let inode_id = 0xfc00_0000_0000_0000 | NEXT_TIMERFD_ID.fetch_add(1, Ordering::Relaxed);
        Arc::new(Self {
            state: SpinIrq::new(TimerFdState::default()),
            clock_id,
            wait: crate::wait::WaitQueue::new(),
            inode_id,
        })
    }

    fn arc_key(self: &Arc<Self>) -> u64 {
        Arc::as_ptr(self) as *const () as u64
    }

    pub fn arm(self: &Arc<Self>, deadline_nanos: u64, interval_ns: u64) {
        {
            let mut s = self.state.lock();
            s.deadline = deadline_nanos;
            s.interval_ns = interval_ns;
            s.expirations = 0;
        }
        let key = self.arc_key();
        if deadline_nanos == 0 {
            TIMERFD_INDEX.lock().remove(&key);
            crate::timeout::cancel_callback(key);
        } else {
            TIMERFD_INDEX.lock().insert(key, self.clone());
            crate::timeout::register_callback(deadline_nanos, key, timerfd_callback);
        }
    }

    pub fn snapshot(&self) -> TimerFdState {
        *self.state.lock()
    }
}

fn timerfd_callback(key: u64) {
    let arc = match TIMERFD_INDEX.lock().get(&key).cloned() {
        Some(a) => a,
        None => return,
    };
    let now_ns = frame::cpu::clock::nanos_since_boot();
    let mut s = arc.state.lock();
    if s.interval_ns == 0 {
        s.expirations = s.expirations.saturating_add(1);
        s.deadline = 0;
        drop(s);
        TIMERFD_INDEX.lock().remove(&key);
    } else {
        let mut bumped = 1u64;
        let mut next = s.deadline.saturating_add(s.interval_ns);
        while next <= now_ns {
            bumped = bumped.saturating_add(1);
            next = next.saturating_add(s.interval_ns);
        }
        s.expirations = s.expirations.saturating_add(bumped);
        s.deadline = next;
        drop(s);
        crate::timeout::register_callback(next, key, timerfd_callback);
    }
    arc.wait.wake_all();
}

impl Inode for TimerFdInode {
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

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        if buf.len() < 8 {
            return Err(FsError::InvalidArgument);
        }
        let pid = crate::sched::current_pid();
        loop {
            self.wait.enqueue(pid);
            let ready = {
                let mut s = self.state.lock();
                if s.expirations > 0 {
                    let v = s.expirations;
                    s.expirations = 0;
                    Some(v)
                } else {
                    None
                }
            };
            if let Some(v) = ready {
                self.wait.dequeue(pid);
                buf[..8].copy_from_slice(&v.to_le_bytes());
                return Ok(8);
            }
            let still_parked = || self.wait.contains(pid);
            let outcome = crate::wait::wait_guarded("timerfd_read", None, &still_parked);
            self.wait.dequeue(pid);
            if outcome == crate::wait::WaitOutcome::Interrupted {
                return Err(FsError::Interrupted);
            }
        }
    }

    fn poll(&self) -> PollMask {
        let s = self.state.lock();
        if s.expirations > 0 {
            PollMask::IN
        } else {
            PollMask::empty()
        }
    }

    fn on_close(&self, _flags: crate::vfs::OpenFlags) {
        let key = self as *const TimerFdInode as *const () as u64;
        TIMERFD_INDEX.lock().remove(&key);
        crate::timeout::cancel_callback(key);
    }
}
