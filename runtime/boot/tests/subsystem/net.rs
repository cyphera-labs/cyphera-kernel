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

const NET_LEN: usize = include_bytes!(env!("PROC_NET_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedElf([u8; NET_LEN]);

static NET_ALIGNED: AlignedElf = AlignedElf(*include_bytes!(env!("PROC_NET_ELF_PATH")));
const NET_ELF: &[u8] = &NET_ALIGNED.0;

const STACK_VADDR: u64 = 0x7008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] net: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_net vmspace");
    let loaded = kernel::elf::load_static(NET_ELF, &mut vmspace).expect("load proc_net");
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

    println!("[test] net: dropping to ring 3");
    println!("------ user output ------");
    kernel::sched::start_first()
}
