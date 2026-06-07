mod spinlock;

pub use spinlock::{SpinIrq, SpinIrqGuard, SpinNoIrq, SpinNoIrqGuard};

pub struct IrqGuard {
    were_enabled: bool,
}

impl Default for IrqGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl IrqGuard {
    pub fn new() -> Self {
        let were_enabled = irq_enabled();
        if were_enabled {
            // SAFETY: `cli` clears the IF flag in RFLAGS to mask maskable
            // interrupts; it touches no Rust-visible memory (nomem) and no
            // stack (nostack). The prior IF state is captured in
            // `were_enabled` above so Drop can restore it exactly, keeping
            // the disable/restore pairing balanced.
            unsafe { core::arch::asm!("cli", options(nomem, nostack)) }
        }
        Self { were_enabled }
    }
}

impl Drop for IrqGuard {
    fn drop(&mut self) {
        if self.were_enabled {
            // SAFETY: `sti` sets the IF flag, restoring interrupt delivery.
            // It runs only when `were_enabled` recorded that IF was set
            // before this guard cleared it, so this re-enables IRQs exactly
            // when they were on entering `new` and never enables them in a
            // context that had them masked for another reason. nomem/nostack
            // hold: it touches no Rust-visible memory and no stack.
            unsafe { core::arch::asm!("sti", options(nomem, nostack)) }
        }
    }
}

#[inline]
fn irq_enabled() -> bool {
    let flags: u64;
    // SAFETY: `pushfq; pop {}` pushes RFLAGS onto the stack and pops it into
    // the `flags` register, a pure read of the current flags word. The popped
    // value initializes the `out(reg) flags` binding, so the read of `flags`
    // below is defined. `nomem` is correct because the sequence accesses no
    // memory observable through Rust-visible pointers — only a stack scratch
    // slot, written by `pushfq` and immediately reclaimed by the matching
    // `pop`, plus the output GP register. The sequence leaves RFLAGS
    // unchanged, so `preserves_flags` holds. `nostack` is intentionally
    // omitted because `pushfq` writes to the stack.
    unsafe {
        core::arch::asm!(
            "pushfq; pop {}",
            out(reg) flags,
            options(nomem, preserves_flags),
        );
    }
    (flags & (1 << 9)) != 0
}
