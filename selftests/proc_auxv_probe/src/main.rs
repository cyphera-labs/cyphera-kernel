#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const AT_NULL: u64 = 0;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_SECURE: u64 = 23;

#[unsafe(naked)]
#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp+8]",
        "call {main}",
        main = sym rust_main,
    )
}

extern "C" fn rust_main(argc: u64, argv: *const u64) -> ! {
    let mut p = unsafe { argv.add(argc as usize + 1) };
    unsafe {
        while *p != 0 {
            p = p.add(1);
        }
        p = p.add(1);
    }

    let mut at_uid: u64 = u64::MAX;
    let mut at_euid: u64 = u64::MAX;
    let mut at_secure: u64 = u64::MAX;
    unsafe {
        loop {
            let a_type = *p;
            let a_val = *p.add(1);
            if a_type == AT_NULL {
                break;
            }
            match a_type {
                AT_UID => at_uid = a_val,
                AT_EUID => at_euid = a_val,
                AT_SECURE => at_secure = a_val,
                _ => {}
            }
            p = p.add(2);
        }
    }

    let mut code = 0i32;
    if at_secure == 1 {
        code |= 1;
    }
    if at_uid == 1000 {
        code |= 2;
    }
    if at_euid == 0 {
        code |= 4;
    }
    sys_exit(code);
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
