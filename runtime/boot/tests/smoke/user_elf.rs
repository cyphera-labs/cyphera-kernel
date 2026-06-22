#![no_std]
#![no_main]

use frame::{
    boot::parse_hvm_start_info,
    io::uart,
    mm::{
        VirtAddr, frame_alloc,
        vm::{Perms, VmSpace},
    },
    println,
    user::start_user_process,
};

const HELLO_LEN: usize = include_bytes!(env!("HELLO_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedHello([u8; HELLO_LEN]);

static HELLO_ALIGNED: AlignedHello = AlignedHello(*include_bytes!(env!("HELLO_ELF_PATH")));
const HELLO_ELF: &[u8] = &HELLO_ALIGNED.0;

const USER_STACK_VADDR: u64 = 0x4001_0000;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] user_elf: hello.elf is {} bytes; bringing up frame",
        HELLO_ELF.len()
    );

    let boot_info = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&boot_info) };

    kernel::syscall::install_pre_sched();

    let mut vmspace = VmSpace::current();

    let loaded = kernel::loader::elf::load_static(HELLO_ELF, &mut vmspace).expect("load_static");
    println!("[test] user_elf: loaded; entry @ {:#x}", loaded.entry);

    let _stack = vmspace
        .map_anon(
            VirtAddr::new(USER_STACK_VADDR),
            4,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map user stack");

    let _ = frame_alloc::alloc_frame();

    println!("[test] user_elf: dropping to ring 3");
    println!("------ user output ------");
    start_user_process(loaded.entry, USER_STACK_VADDR + 4 * 0x1000)
}
