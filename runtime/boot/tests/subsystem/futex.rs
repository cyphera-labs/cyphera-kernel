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

const PROC_FUTEX_LEN: usize = include_bytes!(env!("PROC_FUTEX_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedFutex([u8; PROC_FUTEX_LEN]);

static PROC_FUTEX_ALIGNED: AlignedFutex =
    AlignedFutex(*include_bytes!(env!("PROC_FUTEX_ELF_PATH")));

const PROC_FUTEX_ELF: &[u8] = &PROC_FUTEX_ALIGNED.0;

const STACK_VADDR: u64 = 0x5008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] futex: bringing up frame; proc_futex={} bytes",
        PROC_FUTEX_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_futex vmspace");
    let loaded = kernel::elf::load_static(PROC_FUTEX_ELF, &mut vmspace).expect("load proc_futex");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_futex stack");
    let pid = kernel::sched::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x5010_0000,
    );

    println!(
        "[test] futex: registered proc_futex as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::sched::start_first()
}
