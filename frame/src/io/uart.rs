use core::fmt;

use crate::io::port::Port;
use crate::sync::SpinIrq;

const COM1: u16 = 0x3F8;

pub static UART: SpinIrq<Uart> = SpinIrq::new(Uart::new(COM1));

pub struct Uart {
    data: Port<u8>,
    int_enable: Port<u8>,
    fifo_ctrl: Port<u8>,
    line_ctrl: Port<u8>,
    modem_ctrl: Port<u8>,
    line_status: Port<u8>,
}

impl Uart {
    pub const fn new(base: u16) -> Self {
        // SAFETY: kernel owns these COM1 ports, constructed once via the
        // static UART singleton.
        unsafe {
            Self {
                data: Port::new(base),
                int_enable: Port::new(base + 1),
                fifo_ctrl: Port::new(base + 2),
                line_ctrl: Port::new(base + 3),
                modem_ctrl: Port::new(base + 4),
                line_status: Port::new(base + 5),
            }
        }
    }

    pub fn init(&mut self) {
        self.int_enable.write(0x00);
        self.line_ctrl.write(0x80);
        self.data.write(0x03);
        self.int_enable.write(0x00);
        self.line_ctrl.write(0x03);
        self.fifo_ctrl.write(0xC7);
        self.modem_ctrl.write(0x0B);
    }

    pub fn put_byte(&mut self, b: u8) {
        while self.line_status.read() & 0x20 == 0 {
            core::hint::spin_loop();
        }
        self.data.write(b);
    }

    pub fn try_read_byte(&mut self) -> Option<u8> {
        if self.line_status.read() & 0x01 == 0 {
            None
        } else {
            Some(self.data.read())
        }
    }

    pub fn write_str(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                self.put_byte(b'\r');
            }
            self.put_byte(b);
        }
        if let Some(sink) = klog_sink() {
            sink(bytes);
        }
    }
}

type KlogSink = fn(&[u8]);
static KLOG_SINK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

pub fn set_klog_sink(f: KlogSink) {
    KLOG_SINK.store(f as *mut (), core::sync::atomic::Ordering::SeqCst);
}

fn klog_sink() -> Option<KlogSink> {
    let p = KLOG_SINK.load(core::sync::atomic::Ordering::Relaxed);
    if p.is_null() {
        None
    } else {
        // SAFETY: KLOG_SINK only ever holds either null (handled above) or a
        // value produced by `f as *mut ()` in `set_klog_sink`. Transmuting that
        // exact provenance back to `KlogSink` (a plain `fn(&[u8])`, same size
        // and ABI as the pointer) reconstructs the original function pointer.
        Some(unsafe { core::mem::transmute::<*mut (), KlogSink>(p) })
    }
}

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Uart::write_str(self, s);
        Ok(())
    }
}

pub fn init() {
    UART.lock().init();
}

pub fn write_bytes(bytes: &[u8]) {
    UART.lock().write_bytes(bytes);
}

pub fn drain_rx<F: FnMut(u8)>(mut emit: F) {
    let mut u = UART.lock();
    for _ in 0..256 {
        match u.try_read_byte() {
            Some(b) => emit(b),
            None => break,
        }
    }
}
