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

const PROC_SA_RESTART_LEN: usize = include_bytes!(env!("PROC_SA_RESTART_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedSaRestart([u8; PROC_SA_RESTART_LEN]);

static PROC_SA_RESTART_ALIGNED: AlignedSaRestart =
    AlignedSaRestart(*include_bytes!(env!("PROC_SA_RESTART_ELF_PATH")));

const PROC_SA_RESTART_ELF: &[u8] = &PROC_SA_RESTART_ALIGNED.0;

const STACK_VADDR: u64 = 0x6008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] sa_restart: bringing up frame; proc_sa_restart={} bytes",
        PROC_SA_RESTART_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_sa_restart vmspace");
    let loaded = kernel::loader::elf::load_static(PROC_SA_RESTART_ELF, &mut vmspace)
        .expect("load proc_sa_restart");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_sa_restart stack");
    let pid = kernel::process_model::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x6010_0000,
    );

    println!(
        "[test] sa_restart: registered proc_sa_restart as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::core::start_first()
}
