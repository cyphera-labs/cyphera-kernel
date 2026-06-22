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

const PROC_TMPFS_LEAK_LEN: usize = include_bytes!(env!("PROC_TMPFS_LEAK_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedTmpfsLeak([u8; PROC_TMPFS_LEAK_LEN]);

static PROC_TMPFS_LEAK_ALIGNED: AlignedTmpfsLeak =
    AlignedTmpfsLeak(*include_bytes!(env!("PROC_TMPFS_LEAK_ELF_PATH")));

const PROC_TMPFS_LEAK_ELF: &[u8] = &PROC_TMPFS_LEAK_ALIGNED.0;

const STACK_VADDR: u64 = 0x6008_0000;
const STACK_PAGES: usize = 8;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] tmpfs_leak: bringing up frame; proc_tmpfs_leak={} bytes",
        PROC_TMPFS_LEAK_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_tmpfs_leak vmspace");
    let loaded = kernel::loader::elf::load_static(PROC_TMPFS_LEAK_ELF, &mut vmspace)
        .expect("load proc_tmpfs_leak");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_tmpfs_leak stack");
    let pid = kernel::process_model::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x6010_0000,
    );

    println!(
        "[test] tmpfs_leak: registered proc_tmpfs_leak as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::core::start_first()
}
