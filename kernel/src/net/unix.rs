extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;

use frame::sync::SpinIrq;

use crate::vfs::{FsError, Inode, InodeKind, OpenFlags, Stat};
use crate::wait::WaitQueue;

const UNIX_CAPACITY: usize = 64 * 1024;

struct Ring {
    buf: VecDeque<u8>,
    readers: u32,
    writers: u32,
}

struct Channel {
    ring: SpinIrq<Ring>,
    read_waiters: WaitQueue,
    write_waiters: WaitQueue,
}

pub struct UnixEnd {
    inbox: Arc<Channel>,
    peer_inbox: Arc<Channel>,
}

impl UnixEnd {
    pub fn pair() -> (Arc<Self>, Arc<Self>) {
        let a_chan = Arc::new(Channel {
            ring: SpinIrq::new(Ring {
                buf: VecDeque::with_capacity(UNIX_CAPACITY),
                readers: 0,
                writers: 0,
            }),
            read_waiters: WaitQueue::new(),
            write_waiters: WaitQueue::new(),
        });
        let b_chan = Arc::new(Channel {
            ring: SpinIrq::new(Ring {
                buf: VecDeque::with_capacity(UNIX_CAPACITY),
                readers: 0,
                writers: 0,
            }),
            read_waiters: WaitQueue::new(),
            write_waiters: WaitQueue::new(),
        });
        let a = Arc::new(Self {
            inbox: a_chan.clone(),
            peer_inbox: b_chan.clone(),
        });
        let b = Arc::new(Self {
            inbox: b_chan,
            peer_inbox: a_chan,
        });
        (a, b)
    }
}

impl Inode for UnixEnd {
    fn kind(&self) -> InodeKind {
        InodeKind::Pipe
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Pipe, 0, 0o600)
    }

    fn read_at(&self, _off: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        loop {
            {
                let mut s = self.inbox.ring.lock();
                if !s.buf.is_empty() {
                    let mut n = 0;
                    while n < buf.len() {
                        match s.buf.pop_front() {
                            Some(b) => {
                                buf[n] = b;
                                n += 1;
                            }
                            None => break,
                        }
                    }
                    drop(s);
                    self.inbox.write_waiters.wake_one();
                    return Ok(n);
                }
                if s.writers == 0 {
                    return Ok(0);
                }
            }
            self.inbox.read_waiters.park();
            if crate::sched::current_signal_pending() {
                return Err(FsError::Interrupted);
            }
        }
    }

    fn write_at(&self, _off: u64, buf: &[u8]) -> Result<usize, FsError> {
        loop {
            {
                let mut s = self.peer_inbox.ring.lock();
                if s.readers == 0 {
                    return Err(FsError::BrokenPipe);
                }
                let room = UNIX_CAPACITY.saturating_sub(s.buf.len());
                if room > 0 {
                    let n = buf.len().min(room);
                    s.buf.extend(buf[..n].iter().copied());
                    drop(s);
                    self.peer_inbox.read_waiters.wake_one();
                    return Ok(n);
                }
            }
            self.peer_inbox.write_waiters.park();
            if crate::sched::current_signal_pending() {
                return Err(FsError::Interrupted);
            }
        }
    }

    fn poll(&self) -> crate::vfs::PollMask {
        use crate::vfs::PollMask;
        let inbox = self.inbox.ring.lock();
        let peer = self.peer_inbox.ring.lock();
        let mut m = PollMask::empty();
        if !inbox.buf.is_empty() || inbox.writers == 0 {
            m |= PollMask::IN;
        }
        if peer.buf.len() < UNIX_CAPACITY || peer.readers == 0 {
            m |= PollMask::OUT;
        }
        if inbox.writers == 0 && inbox.buf.is_empty() {
            m |= PollMask::HUP;
        }
        m
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&self.inbox.read_waiters);
        f(&self.peer_inbox.write_waiters);
    }

    fn on_open(&self, flags: OpenFlags) {
        if flags.is_readable() {
            self.inbox.ring.lock().readers += 1;
        }
        if flags.is_writable() {
            self.peer_inbox.ring.lock().writers += 1;
        }
    }
    fn on_close(&self, flags: OpenFlags) {
        if flags.is_readable() {
            let mut s = self.inbox.ring.lock();
            s.readers = s.readers.saturating_sub(1);
            let last = s.readers == 0;
            drop(s);
            if last {
                self.inbox.write_waiters.wake_all();
            }
        }
        if flags.is_writable() {
            let mut s = self.peer_inbox.ring.lock();
            s.writers = s.writers.saturating_sub(1);
            let last = s.writers == 0;
            drop(s);
            if last {
                self.peer_inbox.read_waiters.wake_all();
            }
        }
    }
}
