use core::marker::PhantomData;
use core::ptr;

pub struct Mmio<T> {
    addr: *mut T,
    _marker: PhantomData<T>,
}

// SAFETY: `Mmio<T>` is a thin wrapper over a raw `*mut T`. The construction
// contract (`Mmio::new`) requires the caller to assert unique ownership of the
// region with no aliasing access path, so sharing/sending the handle across
// threads is sound exactly when `T: Send`/`T: Sync`.
unsafe impl<T: Send> Send for Mmio<T> {}
// SAFETY: `read`/`write` go through `read_volatile`/`write_volatile` against a
// device MMIO register, not ordinary memory. `Sync` permits two threads to each
// hold `&Mmio<T>` and `write(&self)` concurrently; that is sound here because
// these are volatile accesses to a hardware register whose concurrency contract
// is defined by the device, not the unsynchronized-write-to-Rust-memory UB that
// `Sync` normally guards. The `T: Sync` bound does NOT justify this (it only
// makes `&T` `Send`, and says nothing about mutation through `&`); soundness
// rests on the MMIO/volatile semantics plus the unique-region ownership the
// `Mmio::new` caller asserts. Callers needing serialized writes must guard the
// handle externally.
unsafe impl<T: Sync> Sync for Mmio<T> {}

impl<T> Mmio<T> {
    /// # Safety
    ///
    /// `addr` must point at a valid MMIO region for `T`. The wrapper
    /// must have unique ownership of the region (no other access
    /// path may alias), and the region must remain mapped and live
    /// for the lifetime of this `Mmio<T>`.
    pub const unsafe fn new(addr: *mut T) -> Self {
        Self {
            addr,
            _marker: PhantomData,
        }
    }

    pub fn raw(&self) -> *mut T {
        self.addr
    }
}

impl<T: Copy> Mmio<T> {
    #[inline]
    pub fn read(&self) -> T {
        // SAFETY: `addr` was asserted to be a valid, uniquely-owned, live MMIO
        // region for `T` at the unsafe `Mmio::new` call site; a `read_volatile`
        // of a `Copy` `T` from it is a well-defined device read.
        unsafe { ptr::read_volatile(self.addr) }
    }

    #[inline]
    pub fn write(&self, val: T) {
        // SAFETY: as for `read` — `addr` is a valid, uniquely-owned, live MMIO
        // region for `T` (asserted at `Mmio::new`); `write_volatile` is a
        // well-defined device write.
        unsafe { ptr::write_volatile(self.addr, val) }
    }

    pub fn modify(&self, f: impl FnOnce(T) -> T) {
        let cur = self.read();
        self.write(f(cur));
    }
}
