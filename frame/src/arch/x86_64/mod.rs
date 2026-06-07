pub mod gdt;
pub mod idt;
pub mod madt;
pub mod mcfg;
pub mod smp;
pub mod tss;

pub fn init() {
    enable_cpu_features();
    gdt::init();
    idt::init();
}

pub fn enable_cpu_features_ap() {
    enable_cpu_features();
}

fn enable_cpu_features() {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
    use x86_64::registers::model_specific::{Efer, EferFlags};
    // SAFETY: EFER/CR0/CR4 writes and CPUID touch only CPU control state,
    // never Rust-visible memory; MP+!EM+OSFXSR+OSXMMEXCPT_ENABLE merely
    // enable x87/SSE so userland's xmm moves don't #UD; SMEP is gated on
    // CPUID.07H:EBX bit 7, probed here, so it is only requested when the
    // CPU reports support. Run once on the BSP via `init` and idempotently
    // per-CPU via `enable_cpu_features_ap`, before any task runs.
    //
    // CR0.WP turns a ring-0 write through any W=0 mapping into a #PF, so
    // it REQUIRES that no kernel write targets a read-only mapping. The
    // mappings the frame writes through are created writable: the boot
    // stub's bootstrap maps (`boot.s` low PD + high PDPT[510]) carry RW,
    // and the frame's own page-table builders set the WRITABLE bit on
    // every kernel-writable mapping. NXE/SMEP add a ring-0 no-execute /
    // no-execute-USER-pages restriction that likewise REQUIRES no kernel
    // code on USER/NX pages, upheld by that same page-table construction.
    unsafe {
        Efer::update(|f| f.insert(EferFlags::NO_EXECUTE_ENABLE));
        Cr0::update(|f| {
            f.insert(Cr0Flags::WRITE_PROTECT);
            f.insert(Cr0Flags::MONITOR_COPROCESSOR);
            f.remove(Cr0Flags::EMULATE_COPROCESSOR);
            f.remove(Cr0Flags::TASK_SWITCHED);
        });
        Cr4::update(|f| {
            f.insert(Cr4Flags::OSFXSR);
            f.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
        });

        let cpuid = core::arch::x86_64::__cpuid(7);
        if cpuid.ebx & (1 << 7) != 0 {
            Cr4::update(|f| f.insert(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION));
        }
    }
}
