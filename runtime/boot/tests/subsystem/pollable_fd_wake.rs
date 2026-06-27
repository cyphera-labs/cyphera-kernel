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

const PROC_POLLABLE_FD_WAKE_LEN: usize =
    include_bytes!(env!("PROC_POLLABLE_FD_WAKE_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedPollable([u8; PROC_POLLABLE_FD_WAKE_LEN]);

static PROC_POLLABLE_FD_WAKE_ALIGNED: AlignedPollable =
    AlignedPollable(*include_bytes!(env!("PROC_POLLABLE_FD_WAKE_ELF_PATH")));

const PROC_POLLABLE_FD_WAKE_ELF: &[u8] = &PROC_POLLABLE_FD_WAKE_ALIGNED.0;

const STACK_VADDR: u64 = 0x6008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] pollable_fd_wake: bringing up frame; proc_pollable_fd_wake={} bytes",
        PROC_POLLABLE_FD_WAKE_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc pollable_fd_wake vmspace");
    let loaded = kernel::loader::elf::load_static(PROC_POLLABLE_FD_WAKE_ELF, &mut vmspace)
        .expect("load proc_pollable_fd_wake");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map pollable_fd_wake stack");
    let pid = kernel::process_model::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x6010_0000,
    );

    println!(
        "[test] pollable_fd_wake: registered proc_pollable_fd_wake as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::core::start_first()
}
