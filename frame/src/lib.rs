#![no_std]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]
#![allow(internal_features)]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

pub mod arch;
pub mod boot;
pub mod coverage;
pub mod cpu;
pub mod intr;
pub mod io;
pub mod mm;
pub mod panic;
pub mod sync;
pub mod user;

/// # Safety
///
/// Caller must invoke this exactly once, on the BSP, with IRQs
/// disabled, before any service runs.
pub unsafe fn init(boot_info: &boot::BootInfo) {
    arch::x86_64::init();
    cpu::per_cpu::init_bsp();
    mm::heap::init();
    mm::frame_alloc::init(boot_info);
    mm::heap::expand_to_main();
    cpu::clock::init();
    intr::init();
    intr::lapic::init();
    user::init();
    if let Some(pa) = boot_info.rsdp_paddr {
        boot::set_rsdp_paddr(pa);
        if let Some(ecam) = crate::arch::x86_64::mcfg::parse_mcfg_ecam_base(Some(pa)) {
            boot::set_ecam_base(ecam);
        }
    }
    boot::set_modules(boot_info.modules);
}
