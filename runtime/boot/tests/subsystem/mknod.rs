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

const PROC_MKNOD_LEN: usize = include_bytes!(env!("PROC_MKNOD_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedMknod([u8; PROC_MKNOD_LEN]);

static PROC_MKNOD_ALIGNED: AlignedMknod =
    AlignedMknod(*include_bytes!(env!("PROC_MKNOD_ELF_PATH")));

const PROC_MKNOD_ELF: &[u8] = &PROC_MKNOD_ALIGNED.0;

const STACK_VADDR: u64 = 0x6008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] mknod: bringing up frame; proc_mknod={} bytes",
        PROC_MKNOD_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_mknod vmspace");
    let loaded =
        kernel::loader::elf::load_static(PROC_MKNOD_ELF, &mut vmspace).expect("load proc_mknod");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_mknod stack");
    let pid = kernel::process_model::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x6010_0000,
    );

    println!(
        "[test] mknod: registered proc_mknod as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::core::start_first()
}
