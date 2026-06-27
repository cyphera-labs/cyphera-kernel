use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use frame::sync::SpinIrq;

use cyphera_kapi::KResult;

use crate::core::wait::WaitQueue;
use crate::vfs::{Inode, InodeKind, OpenFlags, PollMask, Stat};

const RING_CAPACITY: usize = 4096;
const LINE_MAX: usize = 4096;

struct Ring {
    buf: Vec<u8>,
    head: usize,
    tail: usize,
    len: usize,
}

impl Ring {
    fn new() -> Self {
        Self {
            buf: alloc::vec![0; RING_CAPACITY],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    fn push(&mut self, b: u8) -> bool {
        if self.len == RING_CAPACITY {
            return false;
        }
        self.buf[self.tail] = b;
        self.tail = (self.tail + 1) % RING_CAPACITY;
        self.len += 1;
        true
    }

    fn pop_into(&mut self, out: &mut [u8]) -> usize {
        let n = self.len.min(out.len());
        for slot in out.iter_mut().take(n) {
            *slot = self.buf[self.head];
            self.head = (self.head + 1) % RING_CAPACITY;
        }
        self.len -= n;
        n
    }
}

pub struct Pty {
    pub n: u32,
    s_to_app: SpinIrq<Ring>,
    m_to_app: SpinIrq<Ring>,
    line: SpinIrq<Vec<u8>>,
    eof_pending_slave: SpinIrq<bool>,
    s_readers: WaitQueue,
    m_readers: WaitQueue,
    opens: AtomicUsize,
}

impl Pty {
    fn new(n: u32) -> Self {
        Self {
            n,
            s_to_app: SpinIrq::new(Ring::new()),
            m_to_app: SpinIrq::new(Ring::new()),
            line: SpinIrq::new(Vec::new()),
            eof_pending_slave: SpinIrq::new(false),
            s_readers: WaitQueue::new(),
            m_readers: WaitQueue::new(),
            opens: AtomicUsize::new(0),
        }
    }
}

static PAIRS: SpinIrq<BTreeMap<u32, Arc<Pty>>> = SpinIrq::new(BTreeMap::new());
static NEXT_PTY_N: SpinIrq<u32> = SpinIrq::new(0);

pub fn allocate_pair() -> Arc<Pty> {
    let n = {
        let mut g = NEXT_PTY_N.lock();
        let v = *g;
        *g = g.wrapping_add(1);
        v
    };
    let pty = Arc::new(Pty::new(n));
    PAIRS.lock().insert(n, pty.clone());
    pty
}

pub fn lookup(n: u32) -> Option<Arc<Pty>> {
    PAIRS.lock().get(&n).cloned()
}

fn open_pair(pty: &Pty) {
    pty.opens.fetch_add(1, Ordering::AcqRel);
}

fn close_pair(pty: &Pty) {
    if pty.opens.fetch_sub(1, Ordering::AcqRel) == 1 {
        PAIRS.lock().remove(&pty.n);
        crate::core::tty::release(crate::core::tty::TtyId::Pty(pty.n));
    }
}

fn master_hangup(pty: &Pty) {
    crate::core::tty::hangup(crate::core::tty::TtyId::Pty(pty.n));
    pty.s_readers.wake_all();
    pty.m_readers.wake_all();
}

pub fn flush_input(n: u32) {
    if let Some(pty) = lookup(n) {
        pty.line.lock().clear();
        let mut r = pty.s_to_app.lock();
        r.head = 0;
        r.tail = 0;
        r.len = 0;
        *pty.eof_pending_slave.lock() = false;
    }
}

pub fn flush_output(n: u32) {
    if let Some(pty) = lookup(n) {
        let mut r = pty.m_to_app.lock();
        r.head = 0;
        r.tail = 0;
        r.len = 0;
    }
}

pub struct MasterInode(pub Arc<Pty>);
pub struct SlaveInode(pub Arc<Pty>);

const ICRNL: u32 = 0x0100;
const ISIG: u32 = 0x0001;
const ICANON: u32 = 0x0002;
const ECHO_F: u32 = 0x0008;
const ECHOE: u32 = 0x0010;
const ECHOK: u32 = 0x0020;
const OPOST: u32 = 0x0001;
const ONLCR: u32 = 0x0004;

fn push_opost(m: &mut Ring, b: u8, t: &[u8; 36]) -> bool {
    let oflag = flag_word(t, 4);
    if (oflag & OPOST) != 0 && (oflag & ONLCR) != 0 && b == b'\n' && !m.push(b'\r') {
        return false;
    }
    m.push(b)
}

const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VSUSP: usize = 10;

fn flag_word(t: &[u8; 36], offset: usize) -> u32 {
    u32::from_le_bytes([t[offset], t[offset + 1], t[offset + 2], t[offset + 3]])
}

fn cc(t: &[u8; 36], idx: usize) -> u8 {
    t[16 + 1 + idx]
}

fn discipline_input(b: u8, t: &[u8; 36], pty: &Pty) {
    let iflag = flag_word(t, 0);
    let lflag = flag_word(t, 12);

    let b = if (iflag & ICRNL) != 0 && b == b'\r' {
        b'\n'
    } else {
        b
    };

    let intr = cc(t, VINTR);
    let quit = cc(t, VQUIT);
    let susp = cc(t, VSUSP);
    let erase = cc(t, VERASE);
    let kill = cc(t, VKILL);
    let eof = cc(t, VEOF);

    let echo_on = (lflag & ECHO_F) != 0;
    let canon = (lflag & ICANON) != 0;
    let isig = (lflag & ISIG) != 0;

    let tty = crate::core::tty::TtyId::Pty(pty.n);

    if isig && intr != 0 && b == intr {
        crate::core::tty::deliver_input_signal(tty, 0);
        pty.line.lock().clear();
        if echo_on {
            for &c in b"^C\n" {
                let _ = pty.m_to_app.lock().push(c);
            }
        }
        return;
    }
    if isig && quit != 0 && b == quit {
        crate::core::tty::deliver_input_signal(tty, 1);
        pty.line.lock().clear();
        return;
    }
    if isig && susp != 0 && b == susp {
        crate::core::tty::deliver_input_signal(tty, 2);
        return;
    }

    if !canon {
        let _ = pty.s_to_app.lock().push(b);
        if echo_on {
            let _ = pty.m_to_app.lock().push(b);
        }
        return;
    }

    if eof != 0 && b == eof {
        let mut line = pty.line.lock();
        if line.is_empty() {
            *pty.eof_pending_slave.lock() = true;
        } else {
            let mut s = pty.s_to_app.lock();
            for &c in line.iter() {
                let _ = s.push(c);
            }
            line.clear();
        }
        return;
    }
    if (erase != 0 && b == erase) || b == 0x7f {
        let popped = pty.line.lock().pop().is_some();
        if popped && (lflag & ECHOE) != 0 && echo_on {
            let mut m = pty.m_to_app.lock();
            for &c in b"\x08 \x08" {
                let _ = m.push(c);
            }
        }
        return;
    }
    if kill != 0 && b == kill {
        pty.line.lock().clear();
        if (lflag & ECHOK) != 0 && echo_on {
            let _ = pty.m_to_app.lock().push(b'\n');
        }
        return;
    }
    if b == b'\n' {
        let mut line = pty.line.lock();
        line.push(b'\n');
        let mut s = pty.s_to_app.lock();
        for &c in line.iter() {
            let _ = s.push(c);
        }
        line.clear();
        if echo_on {
            let _ = pty.m_to_app.lock().push(b'\n');
        }
        return;
    }
    let mut line = pty.line.lock();
    if line.len() < LINE_MAX {
        line.push(b);
        if echo_on {
            let _ = pty.m_to_app.lock().push(b);
        }
    }
}

fn pty_termios(pty: &Pty) -> [u8; 36] {
    let id = (pty.n as u64) | (1u64 << 63);
    crate::syscall::termios_get_pub(id)
}

pub fn pty_termios_id(pty: &Pty) -> u64 {
    (pty.n as u64) | (1u64 << 63)
}

impl Inode for MasterInode {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::CharDevice, 0, 0o666)
    }
    fn inode_id(&self) -> u64 {
        (self.0.n as u64) | (1u64 << 62)
    }

    fn on_open(&self, _flags: OpenFlags) {
        open_pair(&self.0);
    }

    fn on_close(&self, _flags: OpenFlags) {
        master_hangup(&self.0);
        close_pair(&self.0);
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_at_with_flags(offset, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(&self, _offset: u64, buf: &mut [u8], flags: OpenFlags) -> KResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        use crate::vfs::blocking::IoAttempt;
        let nonblock = flags.contains(OpenFlags::NONBLOCK);
        crate::vfs::blocking::block_io("pty_master_read", &self.0.m_readers, nonblock, None, || {
            let mut r = self.0.m_to_app.lock();
            if r.len > 0 {
                IoAttempt::Ready(r.pop_into(buf))
            } else {
                IoAttempt::WouldBlock
            }
        })
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> KResult<usize> {
        let t = pty_termios(&self.0);
        for &b in buf {
            discipline_input(b, &t, &self.0);
        }
        self.0.s_readers.wake_all();
        self.0.m_readers.wake_all();
        Ok(buf.len())
    }

    fn poll(&self) -> PollMask {
        let mut mask = PollMask::OUT;
        if self.0.m_to_app.lock().len > 0 {
            mask |= PollMask::IN;
        }
        mask
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&self.0.m_readers);
    }
}

impl Inode for SlaveInode {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::CharDevice, 0, 0o666)
    }
    fn inode_id(&self) -> u64 {
        pty_termios_id(&self.0)
    }

    fn on_open(&self, flags: OpenFlags) {
        open_pair(&self.0);
        crate::core::tty::maybe_acquire_on_open(
            crate::core::tty::TtyId::Pty(self.0.n),
            flags.contains(OpenFlags::NOCTTY),
        );
    }

    fn on_close(&self, _flags: OpenFlags) {
        close_pair(&self.0);
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_at_with_flags(offset, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(&self, _offset: u64, buf: &mut [u8], flags: OpenFlags) -> KResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        crate::core::tty::background_read_guard(self.inode_id())?;
        use crate::vfs::blocking::IoAttempt;
        let nonblock = flags.contains(OpenFlags::NONBLOCK);
        crate::vfs::blocking::block_io("pty_slave_read", &self.0.s_readers, nonblock, None, || {
            let mut r = self.0.s_to_app.lock();
            if r.len > 0 {
                return IoAttempt::Ready(r.pop_into(buf));
            }
            {
                let mut eof = self.0.eof_pending_slave.lock();
                if *eof {
                    *eof = false;
                    return IoAttempt::Ready(0);
                }
            }
            drop(r);
            IoAttempt::WouldBlock
        })
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> KResult<usize> {
        crate::core::tty::background_write_guard(self.inode_id())?;
        let t = pty_termios(&self.0);
        {
            let mut m = self.0.m_to_app.lock();
            for &b in buf {
                if !push_opost(&mut m, b, &t) {
                    break;
                }
            }
        }
        self.0.m_readers.wake_all();
        Ok(buf.len())
    }

    fn poll(&self) -> PollMask {
        let mut mask = PollMask::OUT;
        let has_data = self.0.s_to_app.lock().len > 0;
        let eof = *self.0.eof_pending_slave.lock();
        if has_data || eof {
            mask |= PollMask::IN;
        }
        mask
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&self.0.s_readers);
    }
}
