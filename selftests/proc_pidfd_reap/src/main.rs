#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit_group(3);
}

fn sleep_ms(ms: i64) {
    let ts: [i64; 2] = [0, ms * 1_000_000];
    let _ = sys_nanosleep(ts.as_ptr());
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("pidfd_reap: starting\n");

    let c = sys_fork();
    if c < 0 {
        log("pidfd_reap: fork C failed\n");
        sys_exit_group(1);
    }
    if c == 0 {
        sleep_ms(120);
        sys_exit_group(0);
    }

    let o = sys_fork();
    if o < 0 {
        log("pidfd_reap: fork O failed\n");
        sys_exit_group(1);
    }
    if o == 0 {
        let pidfd = sys_pidfd_open(c as u64, 0);
        if pidfd < 0 {
            log("pidfd_reap: pidfd_open failed\n");
            sys_exit_group(1);
        }
        let mut rbuf = [0u8; 1];
        let _ = sys_read(pidfd as u64, rbuf.as_mut_ptr(), 1);
        log("PIDFD_REAP_OBSERVER_OK\n");
        sys_exit_group(0);
    }

    sleep_ms(40);
    let mut status: i32 = 0;
    let _ = sys_wait4(c as u64, &mut status as *mut i32, 0);
    let mut ostatus: i32 = 0;
    let _ = sys_wait4(o as u64, &mut ostatus as *mut i32, 0);
    log("PIDFD_REAP_OK\n");
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
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_pidfd_open(pid: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 434u64, in("rdi") pid, in("rsi") flags,
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
