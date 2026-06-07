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

const ELF_LEN: usize = include_bytes!(env!("PROC_SIGNALS_DEFAULT_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedElf([u8; ELF_LEN]);

static ELF_ALIGNED: AlignedElf = AlignedElf(*include_bytes!(env!("PROC_SIGNALS_DEFAULT_ELF_PATH")));
const ELF: &[u8] = &ELF_ALIGNED.0;

const STACK_VADDR: u64 = 0x7008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] signals_default: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_signals_default vmspace");

    let loaded = kernel::elf::load_static(ELF, &mut vmspace).expect("load proc_signals_default");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map stack");

    let _pid = kernel::sched::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x7010_0000,
    );

    println!("[test] signals_default: dropping to ring 3");
    println!("------ user output ------");
    kernel::sched::start_first()
}
