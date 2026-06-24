use core::arch::asm;

pub mod clock;
pub mod cpu_registry;
pub mod hwrng;
pub mod per_cpu;
pub mod rtc;
pub mod task;
pub mod tlb;

pub use clock::{nanos_since_boot, rdtsc, record_boot_tsc, tsc_hz, wall_clock_nanos};

pub fn halt() -> ! {
    loop {
        // SAFETY: `cli; hlt` only toggles the interrupt flag and parks the
        // core; with IRQs masked first it halts forever as intended. `nomem`
        // is correct because no Rust-visible memory is touched, and `nostack`
        // because the instructions use no stack.
        unsafe { asm!("cli; hlt", options(nomem, nostack)) }
    }
}

pub fn enable_interrupts() {
    // SAFETY: `sti` only sets the interrupt-enable flag; it touches no
    // Rust-visible memory (`nomem`) and uses no stack (`nostack`). Re-arming
    // IRQs is a deliberate, idempotent CPU-state change with no aliasing or
    // memory-ordering obligations of its own. `preserves_flags` holds because
    // `sti` leaves all other RFLAGS bits unchanged.
    unsafe { asm!("sti", options(nomem, nostack, preserves_flags)) }
}

pub fn idle_halt() {
    // SAFETY: the `sti; hlt` pair is the architecturally-defined atomic idle:
    // `sti` defers the interrupt-enable by one instruction so an IRQ arriving
    // in the gap is recognized before `hlt` parks the core, avoiding a lost
    // wakeup. Neither instruction touches Rust-visible memory (`nomem`) or the
    // stack (`nostack`); `hlt` preserves RFLAGS so `preserves_flags` is sound.
    unsafe { asm!("sti; hlt", options(nomem, nostack, preserves_flags)) }
}

#[inline]
pub fn pause() {
    core::hint::spin_loop();
}

#[inline]
pub fn disable_irqs() -> bool {
    let prev = irqs_enabled();
    if prev {
        // SAFETY: `cli` only clears the interrupt-enable flag; it touches no
        // Rust-visible memory (`nomem`) and uses no stack (`nostack`). The
        // prior IRQ state was already captured in `prev` for `restore_irqs`,
        // so masking here loses no information.
        unsafe { asm!("cli", options(nomem, nostack)) }
    }
    prev
}

#[inline]
pub fn restore_irqs(was_enabled: bool) {
    if was_enabled {
        // SAFETY: `sti` only sets the interrupt-enable flag, touching no
        // Rust-visible memory (`nomem`) and no stack (`nostack`). It is gated
        // on `was_enabled` so it only re-arms IRQs that the matching
        // `disable_irqs` actually masked, restoring the caller's prior state.
        unsafe { asm!("sti", options(nomem, nostack)) }
    }
}

#[inline]
pub fn irqs_enabled() -> bool {
    let flags: u64;
    // SAFETY: `pushfq; pop {}` reads RFLAGS into a compiler-allocated output
    // register. `nostack` is omitted because `pushfq` writes to the stack (the
    // matching `pop` only restores RSP afterward), and `nostack` would assert
    // the asm pushes nothing. `nomem` is correct because no Rust-visible memory
    // is accessed, and `preserves_flags` holds since the sequence reads RFLAGS
    // without modifying it.
    unsafe {
        asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags));
    }
    (flags & (1 << 9)) != 0
}

#[inline]
pub fn set_user_tls_base(addr: u64) {
    use x86_64::VirtAddr;
    use x86_64::registers::model_specific::FsBase;
    FsBase::write(VirtAddr::new(addr));
}

#[inline]
pub fn get_user_tls_base() -> u64 {
    use x86_64::registers::model_specific::FsBase;
    FsBase::read().as_u64()
}

pub type SecondaryEntry = extern "C" fn(cpu_id: u64) -> !;

pub fn online_mask() -> u64 {
    crate::arch::x86_64::smp::online_mask()
}

pub fn set_kernel_stack(top: u64) {
    crate::arch::x86_64::tss::set_rsp0(top);
}

pub fn bring_up_secondaries(entry: SecondaryEntry) {
    crate::arch::x86_64::smp::set_ap_main(entry);
    let bsp_apic = crate::intr::lapic::local_apic_id();
    let _ = crate::cpu::cpu_registry::register_cpu(crate::cpu::cpu_registry::ApicId(bsp_apic));
    let ids = crate::arch::x86_64::madt::parse_apic_ids(crate::boot::rsdp_paddr());
    let ap_count = ids.iter().filter(|&&a| a != bsp_apic).count();
    if ap_count > 0 {
        crate::println!("smp: bringing up {ap_count} secondary CPUs");
    }
    crate::arch::x86_64::smp::bring_up(&ids);
}

pub use clock::busy_wait_nanos;
