extern crate alloc;

use alloc::vec::Vec;

use frame::sync::SpinIrq;

pub const KLOG_CAPACITY: usize = 64 * 1024;

struct KlogRing {
    buf: Vec<u8>,
    len: usize,
    head: usize,
    unread: usize,
}

impl KlogRing {
    const fn new() -> Self {
        Self {
            buf: Vec::new(),
            len: 0,
            head: 0,
            unread: 0,
        }
    }

    fn ensure_alloced(&mut self) {
        if self.buf.capacity() < KLOG_CAPACITY {
            self.buf.resize(KLOG_CAPACITY, 0);
        }
    }

    fn push_bytes(&mut self, data: &[u8]) {
        self.ensure_alloced();
        for &b in data {
            self.buf[self.head] = b;
            self.head = (self.head + 1) % KLOG_CAPACITY;
            if self.len < KLOG_CAPACITY {
                self.len += 1;
            }
        }
        self.unread = (self.unread + data.len()).min(KLOG_CAPACITY);
    }

    fn snapshot(&self) -> Vec<u8> {
        if self.len == 0 {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(self.len);
        let start = if self.len < KLOG_CAPACITY {
            0
        } else {
            self.head
        };
        for i in 0..self.len {
            let idx = (start + i) % KLOG_CAPACITY;
            out.push(self.buf[idx]);
        }
        out
    }

    fn clear(&mut self) {
        self.len = 0;
        self.head = 0;
        self.unread = 0;
    }
}

static KLOG: SpinIrq<KlogRing> = SpinIrq::new(KlogRing::new());

pub fn push_bytes(data: &[u8]) {
    KLOG.lock().push_bytes(data);
}

pub fn snapshot() -> Vec<u8> {
    KLOG.lock().snapshot()
}

pub fn unread_bytes() -> usize {
    KLOG.lock().unread
}

pub fn capacity() -> usize {
    KLOG_CAPACITY
}

pub fn clear() {
    KLOG.lock().clear();
}
