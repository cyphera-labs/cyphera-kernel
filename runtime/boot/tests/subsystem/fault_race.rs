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

const PROC_FAULT_RACE_LEN: usize = include_bytes!(env!("PROC_FAULT_RACE_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedFaultRace([u8; PROC_FAULT_RACE_LEN]);

static PROC_FAULT_RACE_ALIGNED: AlignedFaultRace =
    AlignedFaultRace(*include_bytes!(env!("PROC_FAULT_RACE_ELF_PATH")));

const PROC_FAULT_RACE_ELF: &[u8] = &PROC_FAULT_RACE_ALIGNED.0;

const STACK_VADDR: u64 = 0x6008_0000;
const STACK_PAGES: usize = 8;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] fault_race: bringing up frame; proc_fault_race={} bytes",
        PROC_FAULT_RACE_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_fault_race vmspace");
    let loaded = kernel::loader::elf::load_static(PROC_FAULT_RACE_ELF, &mut vmspace)
        .expect("load proc_fault_race");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_fault_race stack");
    let pid = kernel::process_model::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x6010_0000,
    );

    println!(
        "[test] fault_race: registered proc_fault_race as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::core::start_first()
}
