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

const PROC_MISC_LEN: usize = include_bytes!(env!("PROC_MISC_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedMisc([u8; PROC_MISC_LEN]);

static PROC_MISC_ALIGNED: AlignedMisc = AlignedMisc(*include_bytes!(env!("PROC_MISC_ELF_PATH")));

const PROC_MISC_ELF: &[u8] = &PROC_MISC_ALIGNED.0;

const STACK_VADDR: u64 = 0x3008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] misc: bringing up frame; proc_misc={} bytes",
        PROC_MISC_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_misc vmspace");
    let loaded =
        kernel::loader::elf::load_static(PROC_MISC_ELF, &mut vmspace).expect("load proc_misc");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_misc stack");
    let pid = kernel::process_model::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x3010_0000,
    );

    println!(
        "[test] misc: registered proc_misc as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::core::start_first()
}
