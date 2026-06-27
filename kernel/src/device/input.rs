use alloc::vec::Vec;

use frame::sync::SpinIrq;

use crate::core::wait::WaitQueue;

#[derive(Copy, Clone, Debug)]
pub struct StoredEvent {
    pub event_type: u16,
    pub code: u16,
    pub value: i32,
}

const EV_SYN: u16 = 0;
const EV_KEY: u16 = 1;
const EV_REL: u16 = 2;
const EV_ABS: u16 = 3;
const SYN_DROPPED: u16 = 3;

#[derive(Copy, Clone, Debug)]
pub struct KbdEvent {
    pub keycode: u16,
    pub press: bool,
}

const KBD_RING_CAPACITY: usize = 256;

struct KbdRing {
    ring: [KbdEvent; KBD_RING_CAPACITY],
    head: usize,
    tail: usize,
    len: usize,
}

impl KbdRing {
    const fn new() -> Self {
        Self {
            ring: [KbdEvent {
                keycode: 0,
                press: false,
            }; KBD_RING_CAPACITY],
            head: 0,
            tail: 0,
            len: 0,
        }
    }
    fn push(&mut self, ev: KbdEvent) -> bool {
        if self.len == KBD_RING_CAPACITY {
            return false;
        }
        self.ring[self.tail] = ev;
        self.tail = (self.tail + 1) % KBD_RING_CAPACITY;
        self.len += 1;
        true
    }
    fn pop(&mut self) -> Option<KbdEvent> {
        if self.len == 0 {
            return None;
        }
        let ev = self.ring[self.head];
        self.head = (self.head + 1) % KBD_RING_CAPACITY;
        self.len -= 1;
        Some(ev)
    }
}

static KBD_RING: SpinIrq<KbdRing> = SpinIrq::new(KbdRing::new());
static KBD_WAITERS: WaitQueue = WaitQueue::new();

pub fn pop_kbd_event() -> Option<KbdEvent> {
    KBD_RING.lock().pop()
}

pub fn read_kbd_event_blocking(nonblock: bool) -> cyphera_kapi::KResult<KbdEvent> {
    use crate::vfs::blocking::{IoAttempt, block_io};
    block_io(
        "kbd_read",
        &KBD_WAITERS,
        nonblock,
        None,
        || match KBD_RING.lock().pop() {
            Some(ev) => IoAttempt::Ready(ev),
            None => IoAttempt::WouldBlock,
        },
    )
}

pub fn kbd_has_event() -> bool {
    KBD_RING.lock().len != 0
}

pub fn for_each_kbd_wq(f: &mut dyn FnMut(&WaitQueue)) {
    f(&KBD_WAITERS);
}

const RING_CAPACITY: usize = 512;

struct DeviceState {
    ring: [StoredEvent; RING_CAPACITY],
    head: usize,
    tail: usize,
    len: usize,
    dropped: bool,
}

impl DeviceState {
    const fn new() -> Self {
        Self {
            ring: [StoredEvent {
                event_type: 0,
                code: 0,
                value: 0,
            }; RING_CAPACITY],
            head: 0,
            tail: 0,
            len: 0,
            dropped: false,
        }
    }
    fn push(&mut self, ev: StoredEvent) -> bool {
        if self.len == RING_CAPACITY {
            return false;
        }
        self.ring[self.tail] = ev;
        self.tail = (self.tail + 1) % RING_CAPACITY;
        self.len += 1;
        true
    }
    fn evict_oldest_rel(&mut self) -> bool {
        let mut scanned = 0;
        let mut write = self.head;
        let mut read = self.head;
        let mut removed = false;
        while scanned < self.len {
            let ev = self.ring[read];
            read = (read + 1) % RING_CAPACITY;
            scanned += 1;
            if !removed && ev.event_type == EV_REL {
                removed = true;
                continue;
            }
            self.ring[write] = ev;
            write = (write + 1) % RING_CAPACITY;
        }
        if removed {
            self.tail = write;
            self.len -= 1;
        }
        removed
    }
    fn push_evicting_rel(&mut self, ev: StoredEvent) -> bool {
        if self.push(ev) {
            return true;
        }
        if self.evict_oldest_rel() {
            return self.push(ev);
        }
        false
    }
    fn pending(&self) -> bool {
        self.len != 0 || self.dropped
    }
    fn drain_up_to(&mut self, max: usize) -> Vec<StoredEvent> {
        if max == 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        if self.dropped {
            self.dropped = false;
            out.push(StoredEvent {
                event_type: EV_SYN,
                code: SYN_DROPPED,
                value: 0,
            });
        }
        let take = self.len.min(max - out.len());
        for _ in 0..take {
            out.push(self.ring[self.head]);
            self.head = (self.head + 1) % RING_CAPACITY;
            self.len -= 1;
        }
        out
    }
}

const MAX_DEVS: usize = 4;
static DEVS: SpinIrq<[DeviceState; MAX_DEVS]> = SpinIrq::new([
    DeviceState::new(),
    DeviceState::new(),
    DeviceState::new(),
    DeviceState::new(),
]);
static WAITERS: [WaitQueue; MAX_DEVS] = [
    WaitQueue::new(),
    WaitQueue::new(),
    WaitQueue::new(),
    WaitQueue::new(),
];

pub fn poll_from_tick() {
    let raw = virtio::input_drain();
    if raw.is_empty() {
        return;
    }
    let mut affected = [false; MAX_DEVS];
    let mut kbd_event_arrived = false;
    let mut kbd_xlate: Vec<(u16, bool)> = Vec::new();
    {
        let mut d = DEVS.lock();
        let mut k = KBD_RING.lock();
        for (idx, ev) in raw {
            if idx >= MAX_DEVS {
                continue;
            }
            let stored = StoredEvent {
                event_type: ev.event_type,
                code: ev.code,
                value: ev.value as i32,
            };
            let pushed = if ev.event_type == EV_KEY {
                d[idx].push_evicting_rel(stored)
            } else {
                d[idx].push(stored)
            };
            if !pushed {
                d[idx].dropped = true;
            }
            affected[idx] = true;
            if ev.event_type == EV_KEY {
                let press = match ev.value {
                    0 => false,
                    1 | 2 => true,
                    _ => continue,
                };
                let _ = k.push(KbdEvent {
                    keycode: ev.code,
                    press,
                });
                kbd_event_arrived = true;
                kbd_xlate.push((ev.code, press));
            }
        }
    }
    for (idx, hit) in affected.iter().enumerate() {
        if !hit {
            continue;
        }
        WAITERS[idx].wake_all();
    }
    if kbd_event_arrived {
        KBD_WAITERS.wake_all();
    }
    for (keycode, press) in kbd_xlate {
        crate::console::feed_keycode(keycode, press);
    }
}

pub fn drain_for(idx: usize, max: usize) -> Vec<StoredEvent> {
    if idx >= MAX_DEVS {
        return Vec::new();
    }
    DEVS.lock()[idx].drain_up_to(max)
}

pub fn has_pending(idx: usize) -> bool {
    if idx >= MAX_DEVS {
        return false;
    }
    DEVS.lock()[idx].pending()
}

pub fn for_each_evdev_wq(idx: usize, f: &mut dyn FnMut(&WaitQueue)) {
    if idx >= MAX_DEVS {
        return;
    }
    f(&WAITERS[idx]);
}

pub fn read_blocking(idx: usize, buf: &mut [u8], nonblock: bool) -> cyphera_kapi::KResult<usize> {
    use crate::vfs::blocking::{IoAttempt, block_io};
    const EV_SIZE: usize = 24;
    if idx >= MAX_DEVS || buf.len() < EV_SIZE {
        return Ok(0);
    }
    block_io("evdev_read", &WAITERS[idx], nonblock, None, || {
        let max = buf.len() / EV_SIZE;
        let evs = drain_for(idx, max);
        if evs.is_empty() {
            return IoAttempt::WouldBlock;
        }
        let n = evs.len();
        for (i, ev) in evs.iter().enumerate() {
            let off = i * EV_SIZE;
            let now = frame::cpu::clock::nanos_since_boot();
            let sec = (now / 1_000_000_000) as i64;
            let usec = ((now / 1_000) % 1_000_000) as i64;
            buf[off..off + 8].copy_from_slice(&sec.to_le_bytes());
            buf[off + 8..off + 16].copy_from_slice(&usec.to_le_bytes());
            buf[off + 16..off + 18].copy_from_slice(&ev.event_type.to_le_bytes());
            buf[off + 18..off + 20].copy_from_slice(&ev.code.to_le_bytes());
            buf[off + 20..off + 24].copy_from_slice(&ev.value.to_le_bytes());
        }
        IoAttempt::Ready(n * EV_SIZE)
    })
}

#[derive(Clone)]
struct CachedCaps {
    name: Vec<u8>,
    key_bits: Vec<u8>,
    rel_bits: Vec<u8>,
    abs_bits: Vec<u8>,
}

static CAPS_CACHE: SpinIrq<[Option<CachedCaps>; MAX_DEVS]> = SpinIrq::new([None, None, None, None]);

fn caps_for(idx: usize) -> Option<CachedCaps> {
    if idx >= MAX_DEVS {
        return None;
    }
    if let Some(c) = CAPS_CACHE.lock()[idx].clone() {
        return Some(c);
    }
    let raw = virtio::input_caps(idx)?;
    let mut name = raw.name.into_bytes();
    if !name.contains(&0) {
        name.push(0);
    }
    let cached = CachedCaps {
        name,
        key_bits: raw.key_bits,
        rel_bits: raw.rel_bits,
        abs_bits: raw.abs_bits,
    };
    CAPS_CACHE.lock()[idx] = Some(cached.clone());
    Some(cached)
}

pub fn evdev_ioctl(idx: usize, cmd: u32, arg: u64) -> i64 {
    let size = ((cmd >> 16) & 0x3fff) as usize;
    let nr = cmd & 0xff;
    evdev_ioctl_inner(idx, nr, size, arg)
}

fn evdev_ioctl_inner(idx: usize, nr: u32, size: usize, arg: u64) -> i64 {
    let put = |bytes: &[u8]| -> i64 {
        let n = bytes.len().min(size);
        if n > 0 && frame::user::copy_to_user(arg, &bytes[..n]).is_err() {
            return crate::errno::EFAULT;
        }
        n as i64
    };
    let zeros = |len: usize| -> Vec<u8> { alloc::vec![0u8; len] };
    let caps = caps_for(idx);
    match nr {
        0x01 => put(&0x0001_0001u32.to_le_bytes()),
        0x02 => {
            let mut b = [0u8; 8];
            b[0..2].copy_from_slice(&6u16.to_le_bytes());
            b[2..4].copy_from_slice(&0x1af4u16.to_le_bytes());
            b[4..6].copy_from_slice(&1u16.to_le_bytes());
            b[6..8].copy_from_slice(&1u16.to_le_bytes());
            put(&b)
        }
        0x06 => match caps.as_ref().filter(|c| !c.name.is_empty()) {
            Some(c) => put(&c.name),
            None => put(b"cyphera virtio input\0"),
        },
        0x07 => put(b"virtio0/input0\0"),
        0x08 => put(b"\0"),
        0x09 => put(&zeros(size)),
        0x18..=0x1b => put(&zeros(size)),
        0x20 => {
            let mut types: u64 = 1u64 << EV_SYN;
            if let Some(c) = caps.as_ref() {
                if !c.key_bits.is_empty() {
                    types |= 1u64 << EV_KEY;
                }
                if !c.rel_bits.is_empty() {
                    types |= 1u64 << EV_REL;
                }
                if !c.abs_bits.is_empty() {
                    types |= 1u64 << EV_ABS;
                }
            }
            put(&types.to_le_bytes())
        }
        0x21 => match caps.as_ref().filter(|c| !c.key_bits.is_empty()) {
            Some(c) => {
                let mut b = zeros(size);
                let n = c.key_bits.len().min(b.len());
                b[..n].copy_from_slice(&c.key_bits[..n]);
                put(&b)
            }
            None => put(&zeros(size)),
        },
        0x22 => match caps.as_ref().filter(|c| !c.rel_bits.is_empty()) {
            Some(c) => {
                let mut b = zeros(size);
                let n = c.rel_bits.len().min(b.len());
                b[..n].copy_from_slice(&c.rel_bits[..n]);
                put(&b)
            }
            None => put(&zeros(size)),
        },
        0x23 => match caps.as_ref().filter(|c| !c.abs_bits.is_empty()) {
            Some(c) => {
                let mut b = zeros(size);
                let n = c.abs_bits.len().min(b.len());
                b[..n].copy_from_slice(&c.abs_bits[..n]);
                put(&b)
            }
            None => put(&zeros(size)),
        },
        0x34 => {
            let mut b = zeros(size);
            if !b.is_empty() {
                b[0] = 0x03;
            }
            put(&b)
        }
        0x24..=0x3f => put(&zeros(size)),
        0x40..=0x7f => put(&zeros(size)),
        0x90 => 0,
        0xa0 => 0,
        _ => crate::errno::ENOTTY,
    }
}
