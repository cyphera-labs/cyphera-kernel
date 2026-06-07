use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use super::IrqGuard;

pub struct SpinIrq<T: ?Sized> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: sending the lock to another thread moves the contained `T`, so
// `Send` is sound exactly when `T: Send`. (Concurrent sharing of the
// `UnsafeCell` is the `Sync` impl's concern — see below.)
unsafe impl<T: ?Sized + Send> Send for SpinIrq<T> {}
// SAFETY: the lock serialises every access to `data`: a guard is only handed
// out after the `locked` CAS succeeds (Acquire), and Drop publishes the
// release (Release), so at most one thread ever holds a reference into the
// `UnsafeCell` at a time. That mutual exclusion turns shared `&SpinIrq<T>`
// access into the equivalent of single-threaded ownership, so `T: Send`
// (without `Sync`) is sufficient for `Sync`.
unsafe impl<T: ?Sized + Send> Sync for SpinIrq<T> {}

impl<T> SpinIrq<T> {
    pub const fn new(val: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(val),
        }
    }
}

impl<T: ?Sized> SpinIrq<T> {
    pub fn lock(&self) -> SpinIrqGuard<'_, T> {
        let irq = IrqGuard::new();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        SpinIrqGuard {
            lock: self,
            _irq: irq,
        }
    }

    pub fn try_lock(&self) -> Option<SpinIrqGuard<'_, T>> {
        let irq = IrqGuard::new();
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinIrqGuard {
                lock: self,
                _irq: irq,
            })
        } else {
            drop(irq);
            None
        }
    }
}

pub struct SpinIrqGuard<'a, T: ?Sized> {
    lock: &'a SpinIrq<T>,
    _irq: IrqGuard,
}

impl<T: ?Sized> Deref for SpinIrqGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: existence of this guard proves the `locked` CAS succeeded and
        // has not yet been released (Drop runs after the borrow ends). The
        // shared `&self` borrow keeps the returned `&T` tied to the guard's
        // lifetime; `DerefMut` requires `&mut self`, so no aliasing &mut into
        // `data` can coexist while these shared borrows are live (repeated
        // `&T` are permitted and benign).
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for SpinIrqGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard holds the lock for its whole lifetime, so this is
        // the only path to `data` while it lives. The `&mut self` receiver
        // ties the returned `&mut T` to an exclusive borrow of the guard,
        // ruling out any other concurrent reference into the `UnsafeCell`.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for SpinIrqGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

pub struct SpinNoIrq<T: ?Sized> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: like `SpinIrq`, the lock is the only way to reach `data`, so moving
// the lock (and its `T`) between threads is sound exactly when `T: Send`.
unsafe impl<T: ?Sized + Send> Send for SpinNoIrq<T> {}
// SAFETY: the `locked` CAS/Release pair serialises all access to `data`, so at
// most one guard ever references the `UnsafeCell` at once; that mutual
// exclusion means shared `&SpinNoIrq<T>` access is sound for `Sync` with only
// `T: Send`. (The "NoIrq" variant differs only in not touching IRQ state on
// acquire/release — the data-access discipline is identical.)
unsafe impl<T: ?Sized + Send> Sync for SpinNoIrq<T> {}

impl<T> SpinNoIrq<T> {
    pub const fn new(val: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(val),
        }
    }
}

impl<T: ?Sized> SpinNoIrq<T> {
    pub fn lock(&self) -> SpinNoIrqGuard<'_, T> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        SpinNoIrqGuard { lock: self }
    }
}

pub struct SpinNoIrqGuard<'a, T: ?Sized> {
    lock: &'a SpinNoIrq<T>,
}

impl<T: ?Sized> Deref for SpinNoIrqGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard only exists after the `locked` CAS succeeded and is
        // released solely in Drop. The shared `&self` borrow scopes the
        // returned `&T` to the guard; `DerefMut` requires `&mut self`, so no
        // aliasing &mut into `data` can be produced while these shared borrows
        // are live (repeated `&T` are permitted and benign).
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for SpinNoIrqGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: while this guard lives it holds the lock, so it is the only
        // path to `data`; the `&mut self` receiver scopes the returned `&mut T`
        // to an exclusive borrow of the guard, so no other reference into the
        // `UnsafeCell` can alias it.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for SpinNoIrqGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}
