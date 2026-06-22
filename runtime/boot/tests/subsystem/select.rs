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

const PROC_SELECT_LEN: usize = include_bytes!(env!("PROC_SELECT_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedSelect([u8; PROC_SELECT_LEN]);

static PROC_SELECT_ALIGNED: AlignedSelect =
    AlignedSelect(*include_bytes!(env!("PROC_SELECT_ELF_PATH")));

const PROC_SELECT_ELF: &[u8] = &PROC_SELECT_ALIGNED.0;

const STACK_VADDR: u64 = 0x6008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] select: bringing up frame; proc_select={} bytes",
        PROC_SELECT_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_select vmspace");
    let loaded =
        kernel::loader::elf::load_static(PROC_SELECT_ELF, &mut vmspace).expect("load proc_select");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_select stack");
    let pid = kernel::process_model::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x6010_0000,
    );

    println!(
        "[test] select: registered proc_select as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::core::start_first()
}
