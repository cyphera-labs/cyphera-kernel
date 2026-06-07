use alloc::vec::Vec;

use frame::sync::SpinIrq;

use crate::wait::WaitQueue;

#[derive(Copy, Clone, Debug)]
pub struct StoredEvent {
    pub event_type: u16,
    pub code: u16,
    pub value: i32,
}

const EV_KEY: u16 = 1;

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

pub fn park_on_kbd() {
    crate::sched::park_on(&KBD_WAITERS)
}

const RING_CAPACITY: usize = 512;

struct DeviceState {
    ring: [StoredEvent; RING_CAPACITY],
    head: usize,
    tail: usize,
    len: usize,
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
    fn drain(&mut self) -> Vec<StoredEvent> {
        let mut out = Vec::with_capacity(self.len);
        while self.len > 0 {
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
            let _ = d[idx].push(StoredEvent {
                event_type: ev.event_type,
                code: ev.code,
                value: ev.value as i32,
            });
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
        for pid in WAITERS[idx].drain() {
            let _ = crate::sched::wake_pid(pid);
        }
    }
    if kbd_event_arrived {
        for pid in KBD_WAITERS.drain() {
            let _ = crate::sched::wake_pid(pid);
        }
    }
    for (keycode, press) in kbd_xlate {
        crate::console::feed_keycode(keycode, press);
    }
}

pub fn drain_for(idx: usize) -> Vec<StoredEvent> {
    if idx >= MAX_DEVS {
        return Vec::new();
    }
    DEVS.lock()[idx].drain()
}

pub fn read_blocking(idx: usize, buf: &mut [u8]) -> usize {
    const EV_SIZE: usize = 24;
    if idx >= MAX_DEVS || buf.len() < EV_SIZE {
        return 0;
    }
    loop {
        let evs = drain_for(idx);
        if !evs.is_empty() {
            let max = buf.len() / EV_SIZE;
            let n = evs.len().min(max);
            for (i, ev) in evs.iter().take(n).enumerate() {
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
            return n * EV_SIZE;
        }
        crate::sched::park_on(&WAITERS[idx]);
    }
}
