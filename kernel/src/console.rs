use alloc::vec::Vec;

use frame::sync::SpinIrq;

use crate::process::Pid;
use crate::wait::WaitQueue;

const RING_CAPACITY: usize = 4096;
const LINE_MAX: usize = 4096;

struct Ring {
    buf: [u8; RING_CAPACITY],
    head: usize,
    tail: usize,
    len: usize,
}

impl Ring {
    const fn new() -> Self {
        Self {
            buf: [0; RING_CAPACITY],
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

    fn is_empty(&self) -> bool {
        self.len == 0
    }
}

struct State {
    raw: Ring,
    cooked: Ring,
    line: Vec<u8>,
    eof_pending: bool,
    last_reader: Option<Pid>,
}

impl State {
    const fn new() -> Self {
        Self {
            raw: Ring::new(),
            cooked: Ring::new(),
            line: Vec::new(),
            eof_pending: false,
            last_reader: None,
        }
    }
}

static STATE: SpinIrq<State> = SpinIrq::new(State::new());
static READERS: WaitQueue = WaitQueue::new();

const K_XLATE: u32 = 1;
const K_MEDIUMRAW: u32 = 2;

static KBD_MODE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(K_XLATE);

pub fn kbd_mode_get() -> u32 {
    KBD_MODE.load(core::sync::atomic::Ordering::Relaxed)
}

pub fn kbd_mode_set(mode: u32) {
    KBD_MODE.store(mode, core::sync::atomic::Ordering::Relaxed);
}

const ICRNL: u32 = 0x0100;
const ISIG: u32 = 0x0001;
const ICANON: u32 = 0x0002;
const ECHO_F: u32 = 0x0008;
const ECHOE: u32 = 0x0010;
const ECHOK: u32 = 0x0020;

const VINTR: usize = 0;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;

fn live_termios() -> [u8; 36] {
    let ctx = crate::vfs::path::Context::global();
    if let Ok(inode) = crate::vfs::path::resolve(&ctx, &ctx.root, "/dev/console") {
        crate::syscall::termios_get_pub(inode.inode_id())
    } else {
        crate::syscall::DEFAULT_TERMIOS
    }
}

fn flag_word(t: &[u8; 36], offset: usize) -> u32 {
    u32::from_le_bytes([t[offset], t[offset + 1], t[offset + 2], t[offset + 3]])
}

fn cc(t: &[u8; 36], idx: usize) -> u8 {
    t[16 + 1 + idx]
}

fn echo_byte(b: u8) {
    frame::io::uart::write_bytes(&[b]);
}

fn echo_str(s: &[u8]) {
    frame::io::uart::write_bytes(s);
}

fn process_input(b: u8, t: &[u8; 36], st: &mut State) {
    let iflag = flag_word(t, 0);
    let lflag = flag_word(t, 12);

    let b = if (iflag & ICRNL) != 0 && b == b'\r' {
        b'\n'
    } else {
        b
    };

    let intr = cc(t, VINTR);
    let erase = cc(t, VERASE);
    let kill = cc(t, VKILL);
    let eof = cc(t, VEOF);

    let echo_on = (lflag & ECHO_F) != 0;
    let canon = (lflag & ICANON) != 0;
    let isig = (lflag & ISIG) != 0;

    if isig && intr != 0 && b == intr {
        if let Some(pid) = st.last_reader {
            const SIGINT: u32 = 2;
            let info = crate::signal::SigInfo::for_fault(SIGINT, 0);
            let _ = crate::sched::send_signal_with_info(pid, SIGINT, info);
        }
        st.line.clear();
        if echo_on {
            echo_str(b"^C\n");
        }
        return;
    }

    if !canon {
        if st.cooked.push(b) && echo_on {
            echo_byte(b);
        }
        return;
    }

    if eof != 0 && b == eof {
        if st.line.is_empty() {
            st.eof_pending = true;
        } else {
            for &c in &st.line {
                let _ = st.cooked.push(c);
            }
            st.line.clear();
        }
        return;
    }
    if (erase != 0 && b == erase) || (erase == 0 && b == 0x7f) {
        if st.line.pop().is_some() && (lflag & ECHOE) != 0 && echo_on {
            echo_str(b"\x08 \x08");
        }
        return;
    }
    if kill != 0 && b == kill {
        st.line.clear();
        if (lflag & ECHOK) != 0 && echo_on {
            echo_byte(b'\n');
        }
        return;
    }
    if b == b'\n' {
        st.line.push(b'\n');
        for &c in &st.line {
            let _ = st.cooked.push(c);
        }
        st.line.clear();
        if echo_on {
            echo_byte(b'\n');
        }
        return;
    }
    if st.line.len() < LINE_MAX {
        st.line.push(b);
        if echo_on {
            echo_byte(b);
        }
    }
}

pub fn poll_rx_from_tick() {
    let t = live_termios();

    let mut tmp = [0u8; 64];
    let mut n = 0usize;
    frame::io::uart::drain_rx(|b| {
        if n < tmp.len() {
            tmp[n] = b;
            n += 1;
        }
    });
    if n == 0 {
        return;
    }

    let mut woke = false;
    {
        let mut st = STATE.lock();
        for &b in &tmp[..n] {
            let cooked_before = st.cooked.len + (if st.eof_pending { 1 } else { 0 });
            process_input(b, &t, &mut st);
            let cooked_after = st.cooked.len + (if st.eof_pending { 1 } else { 0 });
            if cooked_after > cooked_before {
                woke = true;
            }
        }
        let _ = &mut st.raw;
    }
    if woke {
        let waiters = READERS.drain();
        for pid in waiters {
            let _ = crate::sched::wake_pid(pid);
        }
    }
}

pub fn read(out: &mut [u8], nonblock: bool) -> Result<usize, crate::vfs::FsError> {
    if out.is_empty() {
        return Ok(0);
    }
    if kbd_mode_get() == K_MEDIUMRAW {
        return read_kbd(out, nonblock);
    }
    loop {
        {
            let mut st = STATE.lock();
            st.last_reader = Some(crate::sched::current_pid());

            if !st.cooked.is_empty() {
                return Ok(st.cooked.pop_into(out));
            }
            if st.eof_pending {
                st.eof_pending = false;
                return Ok(0);
            }
            if nonblock {
                return Err(crate::vfs::FsError::WouldBlock);
            }
        }
        crate::sched::park_on(&READERS);
    }
}

fn read_kbd(out: &mut [u8], nonblock: bool) -> Result<usize, crate::vfs::FsError> {
    loop {
        if let Some(ev) = crate::input::pop_kbd_event() {
            let kc = (ev.keycode & 0x7f) as u8;
            out[0] = if ev.press { kc } else { kc | 0x80 };
            return Ok(1);
        }
        if nonblock {
            return Err(crate::vfs::FsError::WouldBlock);
        }
        crate::input::park_on_kbd();
    }
}

pub fn read_blocking(out: &mut [u8]) -> usize {
    read(out, false).unwrap_or(0)
}
