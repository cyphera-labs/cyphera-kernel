#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let msg: &[u8] = b"hello from a real ELF in ring 3\n";
    let _ = sys_write(1, msg.as_ptr(), msg.len());
    sys_exit(0);
}

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 1u64,
            in("rdi") fd,
            in("rsi") buf,
            in("rdx") len,
            lateout("rax") r,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") 60u64,
            in("rdi") code as u64,
            options(noreturn, nostack),
        );
    }
}
