#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit_group(3);
}

const CLOCK_MONOTONIC: u64 = 1;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("timerfd_race: starting\n");

    let fd = sys_timerfd_create(CLOCK_MONOTONIC, 0);
    if fd < 0 {
        log("timerfd_race: timerfd_create failed\n");
        sys_exit_group(1);
    }

    let its: [i64; 4] = [0, 0, 0, 10_000_000];
    if sys_timerfd_settime(fd as u64, 0, its.as_ptr() as u64, 0) < 0 {
        log("timerfd_race: timerfd_settime failed\n");
        sys_exit_group(1);
    }

    let mut buf = [0u8; 8];
    let n = sys_read(fd as u64, buf.as_mut_ptr(), 8);
    if n != 8 {
        log("timerfd_race: short read\n");
        sys_exit_group(1);
    }
    let expirations = u64::from_le_bytes(buf);
    if expirations == 0 {
        log("timerfd_race: zero expirations\n");
        sys_exit_group(1);
    }

    log("TIMERFD_RACE_OK\n");
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
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_timerfd_create(clockid: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 283u64, in("rdi") clockid, in("rsi") flags,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_timerfd_settime(fd: u64, flags: u64, new_value: u64, old_value: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 286u64, in("rdi") fd, in("rsi") flags, in("rdx") new_value, in("r10") old_value,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn sys_exit_group(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 231u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
