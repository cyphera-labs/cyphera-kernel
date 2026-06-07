use core::arch::asm;
#[cfg(coverage)]
use core::sync::atomic::{AtomicBool, Ordering};

#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum ExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit(code: ExitCode) -> ! {
    #[cfg(coverage)]
    {
        static DUMPING: AtomicBool = AtomicBool::new(false);
        if DUMPING.swap(true, Ordering::SeqCst) {
            loop {
                // SAFETY: `cli` masks maskable interrupts and `hlt` parks the
                // CPU until the next event; neither reads nor writes any
                // Rust-visible memory and neither touches the stack, matching
                // the `nomem, nostack` options. We deliberately never return
                // from this loop — the winning CPU's port write halts the VM.
                unsafe { asm!("cli; hlt", options(nomem, nostack)) }
            }
        }
        crate::coverage::dump();
    }

    // SAFETY: `out dx, eax` writes a 32-bit word to I/O port 0xf4, the fixed
    // ioport of QEMU's isa-debug-exit device. The transfer targets the I/O
    // address space only — it touches no Rust-visible memory and no stack
    // (consistent with `nomem, nostack`) and leaves flags intact
    // (`preserves_flags`). If the device is absent the write is discarded by
    // the host platform, so the operation is harmless either way.
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") 0xf4u16,
            in("eax") code as u32,
            options(nomem, nostack, preserves_flags),
        );
    }
    loop {
        // SAFETY: `cli` masks maskable interrupts and `hlt` parks the CPU
        // until the next event; neither reads nor writes any Rust-visible
        // memory and neither touches the stack, matching the `nomem, nostack`
        // options. This is the terminal halt loop reached when the
        // isa-debug-exit device is not wired up, so never returning satisfies
        // the function's `-> !` contract.
        unsafe { asm!("cli; hlt", options(nomem, nostack)) }
    }
}
