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

#[rustfmt::skip]
const USER_PROG: &[u8] = &[
    0xb8, 0x3c, 0x00, 0x00, 0x00,
    0x31, 0xff,
    0x0f, 0x05,
];

const USER_CODE_VADDR: u64 = 0x4000_0000;
const USER_STACK_VADDR: u64 = 0x4001_0000;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] user_exit: bringing up frame");

    let boot_info = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&boot_info) };

    kernel::syscall::install_pre_sched();

    let code_frame = frame_alloc::alloc_frame().expect("alloc user code frame");
    unsafe {
        let dst = code_frame.start_address().as_u64() as *mut u8;
        core::ptr::copy_nonoverlapping(USER_PROG.as_ptr(), dst, USER_PROG.len());
    }

    let mut vmspace = VmSpace::current();

    let _code_region = vmspace
        .map(
            VirtAddr::new(USER_CODE_VADDR),
            code_frame,
            Perms::READ | Perms::EXECUTE | Perms::USER,
        )
        .expect("map user code");

    let _stack_region = vmspace
        .map_anon(
            VirtAddr::new(USER_STACK_VADDR),
            1,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map user stack");

    println!(
        "[test] user_exit: user code at {:#x}, stack at {:#x} (top {:#x})",
        USER_CODE_VADDR,
        USER_STACK_VADDR,
        USER_STACK_VADDR + 0x1000,
    );

    println!("[test] user_exit: dropping to ring 3");

    start_user_process(USER_CODE_VADDR, USER_STACK_VADDR + 0x1000)
}
