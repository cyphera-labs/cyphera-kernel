#![no_std]
#![no_main]

use frame::{
    boot::parse_hvm_start_info,
    io::uart,
    mm::{
        VirtAddr,
        vm::{Perms, VmSpace},
    },
    println,
};

const PROC_TIMER_STORM_LEN: usize = include_bytes!(env!("PROC_TIMER_STORM_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedTimerStorm([u8; PROC_TIMER_STORM_LEN]);

static PROC_TIMER_STORM_ALIGNED: AlignedTimerStorm =
    AlignedTimerStorm(*include_bytes!(env!("PROC_TIMER_STORM_ELF_PATH")));

const PROC_TIMER_STORM_ELF: &[u8] = &PROC_TIMER_STORM_ALIGNED.0;

const STACK_VADDR: u64 = 0x6008_0000;
const STACK_PAGES: usize = 8;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] timer_storm: bringing up frame; proc_timer_storm={} bytes",
        PROC_TIMER_STORM_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_timer_storm vmspace");
    let loaded = kernel::elf::load_static(PROC_TIMER_STORM_ELF, &mut vmspace)
        .expect("load proc_timer_storm");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_timer_storm stack");
    let pid = kernel::sched::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x6010_0000,
    );

    println!(
        "[test] timer_storm: registered proc_timer_storm as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::sched::start_first()
}
