use core::arch::asm;
use core::marker::PhantomData;

pub struct Port<T> {
    port: u16,
    _marker: PhantomData<T>,
}

impl<T> Port<T> {
    /// # Safety
    ///
    /// Caller asserts that no other Rust code is concurrently driving
    /// `port` and that doing so is appropriate for the device at this
    /// port number.
    pub const unsafe fn new(port: u16) -> Self {
        Self {
            port,
            _marker: PhantomData,
        }
    }

    pub const fn raw_port(&self) -> u16 {
        self.port
    }
}

impl Port<u8> {
    pub fn read(&self) -> u8 {
        let v: u8;
        // SAFETY: `in` from an I/O port touches no Rust-visible memory, so it
        // cannot create aliasing or invalidate references. The right to drive
        // this port number was asserted by the caller of the unsafe `Port::new`.
        unsafe {
            asm!(
                "in al, dx",
                out("al") v,
                in("dx") self.port,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }

    pub fn write(&self, v: u8) {
        // SAFETY: `out` to an I/O port touches no Rust-visible memory, so it
        // cannot create aliasing or invalidate references. The right to drive
        // this port number was asserted by the caller of the unsafe `Port::new`.
        unsafe {
            asm!(
                "out dx, al",
                in("dx") self.port,
                in("al") v,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

impl Port<u16> {
    pub fn read(&self) -> u16 {
        let v: u16;
        // SAFETY: `in` from an I/O port touches no Rust-visible memory, so it
        // cannot create aliasing or invalidate references. The right to drive
        // this port number was asserted by the caller of the unsafe `Port::new`.
        unsafe {
            asm!(
                "in ax, dx",
                out("ax") v,
                in("dx") self.port,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }

    pub fn write(&self, v: u16) {
        // SAFETY: `out` to an I/O port touches no Rust-visible memory, so it
        // cannot create aliasing or invalidate references. The right to drive
        // this port number was asserted by the caller of the unsafe `Port::new`.
        unsafe {
            asm!(
                "out dx, ax",
                in("dx") self.port,
                in("ax") v,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

impl Port<u32> {
    pub fn read(&self) -> u32 {
        let v: u32;
        // SAFETY: `in` from an I/O port touches no Rust-visible memory, so it
        // cannot create aliasing or invalidate references. The right to drive
        // this port number was asserted by the caller of the unsafe `Port::new`.
        unsafe {
            asm!(
                "in eax, dx",
                out("eax") v,
                in("dx") self.port,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }

    pub fn write(&self, v: u32) {
        // SAFETY: `out` to an I/O port touches no Rust-visible memory, so it
        // cannot create aliasing or invalidate references. The right to drive
        // this port number was asserted by the caller of the unsafe `Port::new`.
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") self.port,
                in("eax") v,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}
