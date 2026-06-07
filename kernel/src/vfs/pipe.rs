extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;

#[cfg(host_test)]
#[allow(unused_imports)]
use frame_host as frame;

use frame::sync::SpinIrq;

use crate::wait::WaitQueue;

#[cfg(not(host_test))]
use super::{FsError, Inode, InodeKind, OpenFlags, PollMask, Stat};

const PIPE_CAPACITY: usize = 65_536;

struct PipeState {
    buf: VecDeque<u8>,
    readers: u32,
    writers: u32,
}

pub struct Pipe {
    state: SpinIrq<PipeState>,
    read_waiters: WaitQueue,
    write_waiters: WaitQueue,
}

impl Pipe {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: SpinIrq::new(PipeState {
                buf: VecDeque::with_capacity(PIPE_CAPACITY),
                readers: 0,
                writers: 0,
            }),
            read_waiters: WaitQueue::new(),
            write_waiters: WaitQueue::new(),
        })
    }

    pub(crate) fn bump_open(&self, readable: bool, writable: bool) {
        let mut s = self.state.lock();
        if writable {
            s.writers += 1;
        }
        if readable {
            s.readers += 1;
        }
    }

    pub(crate) fn drop_close(&self, readable: bool, writable: bool) -> (bool, bool) {
        let mut wake_readers = false;
        let mut wake_writers = false;
        let mut s = self.state.lock();
        if writable {
            s.writers = s.writers.saturating_sub(1);
            if s.writers == 0 {
                wake_readers = true;
            }
        }
        if readable {
            s.readers = s.readers.saturating_sub(1);
            if s.readers == 0 {
                wake_writers = true;
            }
        }
        (wake_readers, wake_writers)
    }

    pub(crate) fn peek_inner(&self, buf: &mut [u8]) -> usize {
        let s = self.state.lock();
        let mut n = 0;
        for &b in s.buf.iter() {
            if n >= buf.len() {
                break;
            }
            buf[n] = b;
            n += 1;
        }
        n
    }

    pub(crate) fn read_step(&self, buf: &mut [u8]) -> ReadStep {
        let mut s = self.state.lock();
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
            return ReadStep::Drained(n);
        }
        if s.writers == 0 {
            return ReadStep::Eof;
        }
        ReadStep::WouldPark
    }

    pub(crate) fn write_step(&self, buf: &[u8]) -> WriteStep {
        let mut s = self.state.lock();
        if s.readers == 0 {
            return WriteStep::BrokenPipe;
        }
        let room = PIPE_CAPACITY.saturating_sub(s.buf.len());
        if room > 0 {
            let n = buf.len().min(room);
            s.buf.extend(buf[..n].iter().copied());
            return WriteStep::Wrote(n);
        }
        WriteStep::WouldPark
    }

    pub(crate) fn poll_in_out_hup(&self) -> (bool, bool, bool) {
        let s = self.state.lock();
        let mut in_ = false;
        let mut out_ = false;
        let mut hup = false;
        if !s.buf.is_empty() || s.writers == 0 {
            in_ = true;
        }
        if s.buf.len() < PIPE_CAPACITY || s.readers == 0 {
            out_ = true;
        }
        if s.writers == 0 && s.buf.is_empty() {
            hup = true;
        }
        (in_, out_, hup)
    }

    #[allow(dead_code)]
    pub(crate) fn readers(&self) -> u32 {
        self.state.lock().readers
    }
    #[allow(dead_code)]
    pub(crate) fn writers(&self) -> u32 {
        self.state.lock().writers
    }
    #[allow(dead_code)]
    pub(crate) fn buffered(&self) -> usize {
        self.state.lock().buf.len()
    }
    #[allow(dead_code)]
    pub(crate) fn capacity() -> usize {
        PIPE_CAPACITY
    }
}

pub(crate) enum ReadStep {
    Drained(usize),
    Eof,
    WouldPark,
}

pub(crate) enum WriteStep {
    Wrote(usize),
    BrokenPipe,
    WouldPark,
}

#[cfg(not(host_test))]
impl Inode for Pipe {
    fn kind(&self) -> InodeKind {
        InodeKind::Pipe
    }

    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Pipe, self.buffered() as u64, 0o600)
    }

    fn peek_at(&self, buf: &mut [u8]) -> Result<usize, FsError> {
        Ok(self.peek_inner(buf))
    }

    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let cur = crate::sched::current_pid();
        loop {
            self.read_waiters.enqueue(cur);
            match self.read_step(buf) {
                ReadStep::Drained(n) => {
                    self.read_waiters.dequeue(cur);
                    self.write_waiters.wake_one();
                    return Ok(n);
                }
                ReadStep::Eof => {
                    self.read_waiters.dequeue(cur);
                    return Ok(0);
                }
                ReadStep::WouldPark => {}
            }
            crate::sched::park_on_pre_enqueued(&self.read_waiters);
            self.read_waiters.dequeue(cur);
            if crate::sched::current_signal_pending() {
                return Err(FsError::Interrupted);
            }
        }
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        let cur = crate::sched::current_pid();
        loop {
            self.write_waiters.enqueue(cur);
            match self.write_step(buf) {
                WriteStep::Wrote(n) => {
                    self.write_waiters.dequeue(cur);
                    self.read_waiters.wake_one();
                    return Ok(n);
                }
                WriteStep::BrokenPipe => {
                    self.write_waiters.dequeue(cur);
                    return Err(FsError::BrokenPipe);
                }
                WriteStep::WouldPark => {}
            }
            crate::sched::park_on_pre_enqueued(&self.write_waiters);
            self.write_waiters.dequeue(cur);
            if crate::sched::current_signal_pending() {
                return Err(FsError::Interrupted);
            }
        }
    }

    fn on_open(&self, flags: OpenFlags) {
        self.bump_open(flags.is_readable(), flags.is_writable());
    }

    fn poll(&self) -> PollMask {
        let (in_, out_, hup) = self.poll_in_out_hup();
        let mut m = PollMask::empty();
        if in_ {
            m |= PollMask::IN;
        }
        if out_ {
            m |= PollMask::OUT;
        }
        if hup {
            m |= PollMask::HUP;
        }
        m
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&self.read_waiters);
        f(&self.write_waiters);
    }

    fn on_close(&self, flags: OpenFlags) {
        let (wake_readers, wake_writers) =
            self.drop_close(flags.is_readable(), flags.is_writable());
        if wake_readers {
            self.read_waiters.wake_all();
        }
        if wake_writers {
            self.write_waiters.wake_all();
        }
    }
}

#[cfg(host_test)]
#[cfg(test)]
mod host_tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn open_close_read_end_balanced() {
        let p = Pipe::new();
        assert_eq!((p.readers(), p.writers()), (0, 0));
        p.bump_open(true, false);
        assert_eq!((p.readers(), p.writers()), (1, 0));
        let (wake_r, wake_w) = p.drop_close(true, false);
        assert_eq!((p.readers(), p.writers()), (0, 0));
        assert_eq!((wake_r, wake_w), (false, true));
    }

    #[test]
    fn open_close_write_end_balanced() {
        let p = Pipe::new();
        p.bump_open(false, true);
        assert_eq!((p.readers(), p.writers()), (0, 1));
        let (wake_r, wake_w) = p.drop_close(false, true);
        assert_eq!((p.readers(), p.writers()), (0, 0));
        assert_eq!((wake_r, wake_w), (true, false));
    }

    #[test]
    fn open_close_rdwr_bumps_both() {
        let p = Pipe::new();
        p.bump_open(true, true);
        assert_eq!((p.readers(), p.writers()), (1, 1));
        let (wake_r, wake_w) = p.drop_close(true, true);
        assert_eq!((p.readers(), p.writers()), (0, 0));
        assert_eq!((wake_r, wake_w), (true, true));
    }

    #[test]
    fn drop_close_saturates_at_zero() {
        let p = Pipe::new();
        p.bump_open(true, false);
        let _ = p.drop_close(true, false);
        let (wake_r, wake_w) = p.drop_close(true, false);
        assert_eq!((p.readers(), p.writers()), (0, 0));
        assert_eq!((wake_r, wake_w), (false, true));
    }

    #[test]
    fn open_writers_increment_monotonically() {
        let p = Pipe::new();
        for i in 1..=32 {
            p.bump_open(false, true);
            assert_eq!(p.writers(), i);
            assert_eq!(p.readers(), 0);
        }
        for i in (1..=32).rev() {
            let (wake_r, _) = p.drop_close(false, true);
            assert_eq!(wake_r, i == 1);
        }
    }

    #[test]
    fn peek_empty_returns_zero() {
        let p = Pipe::new();
        let mut buf = [0u8; 16];
        assert_eq!(p.peek_inner(&mut buf), 0);
        assert_eq!(p.buffered(), 0);
    }

    #[test]
    fn peek_partial_buffer_does_not_consume() {
        let p = Pipe::new();
        p.bump_open(true, true);
        let _ = p.write_step(b"hello world");
        let mut buf = [0u8; 5];
        assert_eq!(p.peek_inner(&mut buf), 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(p.buffered(), 11);
    }

    #[test]
    fn peek_larger_buf_than_data_returns_data_len() {
        let p = Pipe::new();
        p.bump_open(true, true);
        let _ = p.write_step(b"abc");
        let mut buf = [0u8; 64];
        assert_eq!(p.peek_inner(&mut buf), 3);
        assert_eq!(&buf[..3], b"abc");
    }

    #[test]
    fn write_step_broken_pipe_no_readers() {
        let p = Pipe::new();
        p.bump_open(false, true);
        match p.write_step(b"x") {
            WriteStep::BrokenPipe => {}
            _ => panic!("expected BrokenPipe with readers==0"),
        }
    }

    #[test]
    fn write_step_writes_when_room() {
        let p = Pipe::new();
        p.bump_open(true, true);
        match p.write_step(b"hello") {
            WriteStep::Wrote(n) => assert_eq!(n, 5),
            _ => panic!("expected Wrote(5)"),
        }
        assert_eq!(p.buffered(), 5);
    }

    #[test]
    fn write_step_would_park_when_full() {
        let p = Pipe::new();
        p.bump_open(true, true);
        let big: Vec<u8> = vec![0u8; Pipe::capacity()];
        match p.write_step(&big) {
            WriteStep::Wrote(n) => assert_eq!(n, Pipe::capacity()),
            _ => panic!("expected full-buffer Wrote"),
        }
        match p.write_step(b"more") {
            WriteStep::WouldPark => {}
            _ => panic!("expected WouldPark when buffer full"),
        }
    }

    #[test]
    fn write_step_short_write_at_boundary() {
        let p = Pipe::new();
        p.bump_open(true, true);
        let prefill: Vec<u8> = vec![0u8; Pipe::capacity() - 3];
        let _ = p.write_step(&prefill);
        assert_eq!(p.buffered(), Pipe::capacity() - 3);
        match p.write_step(b"0123456789") {
            WriteStep::Wrote(n) => assert_eq!(n, 3),
            _ => panic!("expected Wrote(3) at near-full boundary"),
        }
        assert_eq!(p.buffered(), Pipe::capacity());
    }

    #[test]
    fn read_step_eof_no_writers_empty() {
        let p = Pipe::new();
        let mut buf = [0u8; 4];
        match p.read_step(&mut buf) {
            ReadStep::Eof => {}
            _ => panic!("expected Eof on empty pipe with no writers"),
        }
    }

    #[test]
    fn read_step_would_park_empty_with_writer() {
        let p = Pipe::new();
        p.bump_open(true, true);
        let mut buf = [0u8; 4];
        match p.read_step(&mut buf) {
            ReadStep::WouldPark => {}
            _ => panic!("expected WouldPark on empty pipe with writer"),
        }
    }

    #[test]
    fn read_step_drains_when_data_present() {
        let p = Pipe::new();
        p.bump_open(true, true);
        let _ = p.write_step(b"abcdef");
        let mut buf = [0u8; 4];
        match p.read_step(&mut buf) {
            ReadStep::Drained(n) => assert_eq!(n, 4),
            _ => panic!("expected Drained(4)"),
        }
        assert_eq!(&buf, b"abcd");
        assert_eq!(p.buffered(), 2);
    }

    #[test]
    fn read_step_drains_after_writers_close() {
        let p = Pipe::new();
        p.bump_open(true, true);
        let _ = p.write_step(b"final");
        let (wake_r, _) = p.drop_close(false, true);
        assert!(wake_r, "last-writer close should signal wake_readers");
        let mut buf = [0u8; 8];
        match p.read_step(&mut buf) {
            ReadStep::Drained(n) => assert_eq!(n, 5),
            _ => panic!("expected Drained before Eof"),
        }
        match p.read_step(&mut buf) {
            ReadStep::Eof => {}
            _ => panic!("expected Eof after drain"),
        }
    }

    #[test]
    fn poll_fresh_pipe_writers_zero_eof_in() {
        let p = Pipe::new();
        let (in_, out_, hup) = p.poll_in_out_hup();
        assert!(in_, "writers==0 → IN");
        assert!(out_, "readers==0 → OUT");
        assert!(hup, "writers==0 + empty → HUP");
    }

    #[test]
    fn poll_live_writer_empty_buf_not_in() {
        let p = Pipe::new();
        p.bump_open(true, true);
        let (in_, out_, hup) = p.poll_in_out_hup();
        assert!(!in_, "writer alive + empty buf → not IN");
        assert!(out_, "buf has room → OUT");
        assert!(!hup, "writer alive → not HUP");
    }

    #[test]
    fn poll_full_buffer_in_but_not_out() {
        let p = Pipe::new();
        p.bump_open(true, true);
        let big: Vec<u8> = vec![0u8; Pipe::capacity()];
        let _ = p.write_step(&big);
        let (in_, out_, hup) = p.poll_in_out_hup();
        assert!(in_, "buf non-empty → IN");
        assert!(!out_, "buf full + readers alive → not OUT");
        assert!(!hup, "writer alive → not HUP");
    }

    #[test]
    fn drop_pipe_no_uaf_on_outstanding_buffer() {
        let p = Pipe::new();
        for _ in 0..16 {
            p.bump_open(true, true);
            let _ = p.write_step(b"data");
            let _ = p.drop_close(true, true);
        }
        p.bump_open(true, true);
        let _ = p.write_step(b"lingering bytes never read");
        drop(p);
    }

    #[test]
    fn clone_arc_observes_same_state() {
        let p = Pipe::new();
        let q = p.clone();
        p.bump_open(false, true);
        assert_eq!(q.writers(), 1);
        let _ = q.write_step(b"");
        assert_eq!(p.writers(), 1);
        let _ = p.drop_close(false, true);
        assert_eq!(q.writers(), 0);
    }
}
