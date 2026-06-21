#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit_group(3);
}

const SIGKILL: u64 = 9;

fn sleep_ms(ms: i64) {
    let ts: [i64; 2] = [0, ms * 1_000_000];
    let _ = sys_nanosleep(ts.as_ptr());
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("spin_kill: starting\n");

    let child = sys_fork();
    if child < 0 {
        log("spin_kill: fork failed\n");
        sys_exit_group(1);
    }
    if child == 0 {
        loop {
            unsafe { asm!("pause", options(nomem, nostack)) };
        }
    }

    sleep_ms(50);
    sys_kill(child as u64, SIGKILL);

    let mut status: i32 = 0;
    let _ = sys_wait4(child as u64, &mut status as *mut i32, 0);

    log("SPIN_KILL_OK\n");
    sys_exit_group(0)
}

#[inline(never)]
fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_kill(pid: u64, sig: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 62u64, in("rdi") pid, in("rsi") sig,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_wait4(pid: u64, status: *mut i32, options: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid, in("rsi") status, in("rdx") options, in("r10") 0u64,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_nanosleep(req: *const i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 35u64, in("rdi") req, in("rsi") 0u64,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn sys_exit_group(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 231u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
