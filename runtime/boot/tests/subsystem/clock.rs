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

const PROC_CLOCK_LEN: usize = include_bytes!(env!("PROC_CLOCK_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedClock([u8; PROC_CLOCK_LEN]);

static PROC_CLOCK_ALIGNED: AlignedClock =
    AlignedClock(*include_bytes!(env!("PROC_CLOCK_ELF_PATH")));

const PROC_CLOCK_ELF: &[u8] = &PROC_CLOCK_ALIGNED.0;

const STACK_VADDR: u64 = 0x7008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] clock: bringing up frame; proc_clock={} bytes",
        PROC_CLOCK_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_clock vmspace");
    let loaded =
        kernel::loader::elf::load_static(PROC_CLOCK_ELF, &mut vmspace).expect("load proc_clock");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_clock stack");
    let pid = kernel::process_model::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x7010_0000,
    );

    println!(
        "[test] clock: registered proc_clock as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::core::start_first()
}
