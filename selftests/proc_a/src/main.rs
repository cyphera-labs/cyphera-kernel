#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let m1 = b"A: before yield\n";
    sys_write(1, m1.as_ptr(), m1.len());
    sys_yield();
    let m2 = b"A: after yield\n";
    sys_write(1, m2.as_ptr(), m2.len());
    sys_exit(0);
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_yield() {
    unsafe {
        asm!(
            "syscall",
            in("rax") 24u64,
            lateout("rax") _,
            out("rcx") _, out("r11") _,
            out("rdi") _, out("rsi") _, out("rdx") _, out("r10") _, out("r8") _, out("r9") _,
            options(nostack),
        );
    }
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
