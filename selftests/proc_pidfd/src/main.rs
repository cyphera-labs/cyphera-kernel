#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SIGTERM: i32 = 15;
const SIGUSR1: i32 = 10;
const ESRCH: i64 = -3;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("pidfd test starting\n");

    let bogus = sys_pidfd_open(0xfffffe, 0);
    if bogus != ESRCH {
        log("pidfd_open(bogus): expected ESRCH got ");
        log_num(bogus);
        sys_exit(1);
    }
    log("pidfd_open(bogus) -> ESRCH OK\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        loop {
            sys_sched_yield();
        }
    }
    let pidfd = sys_pidfd_open(pid as u32, 0);
    if pidfd < 0 {
        log("pidfd_open(child): ");
        log_num(pidfd);
        sys_exit(1);
    }
    let r = sys_pidfd_send_signal(pidfd as i32, SIGTERM, 0, 0);
    if r != 0 {
        log("pidfd_send_signal: ");
        log_num(r);
        sys_exit(1);
    }
    let mut sink = [0u8; 16];
    let n = sys_read(pidfd as i32, sink.as_mut_ptr(), sink.len());
    if n != 0 {
        log("pidfd read returned non-zero: ");
        log_num(n);
        sys_exit(1);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    if (st & 0x7f) != SIGTERM {
        log("child wstatus signal != SIGTERM: ");
        log_num(st as i64);
        sys_exit(1);
    }
    sys_close(pidfd as i32);
    log("pidfd_open + pidfd_send_signal(SIGTERM) + read OK\n");

    let mask: u64 = 1u64 << (SIGUSR1 as u32);
    let sfd = sys_signalfd4(-1, &mask as *const u64 as u64, 8, 0);
    if sfd < 0 {
        log("signalfd4: ");
        log_num(sfd);
        sys_exit(1);
    }
    let block = mask;
    let r = sys_rt_sigprocmask(0, &block as *const u64 as u64, 0, 8);
    if r != 0 {
        log("sigprocmask: ");
        log_num(r);
        sys_exit(1);
    }

    let parent_pid = sys_getpid();
    let pid = sys_fork();
    if pid < 0 {
        log("fork2 failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        sys_kill(parent_pid, SIGUSR1);
        sys_exit(0);
    }
    let mut sbuf = [0u8; 128];
    let n = sys_read(sfd as i32, sbuf.as_mut_ptr(), sbuf.len());
    if n != 128 {
        log("signalfd read: ");
        log_num(n);
        sys_exit(1);
    }
    let signo = u32::from_le_bytes([sbuf[0], sbuf[1], sbuf[2], sbuf[3]]);
    if signo != SIGUSR1 as u32 {
        log("signalfd ssi_signo: ");
        log_num(signo as i64);
        sys_exit(1);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    sys_close(sfd as i32);
    log("signalfd4 + kill child + read ssi_signo OK\n");

    log("all pidfd/signalfd tests OK\n");
    sys_exit(0);
}

#[inline(never)]
fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

fn log_num(n: i64) {
    let mut buf = [0u8; 24];
    let mut i = 0usize;
    let neg = n < 0;
    let mut v = if neg { (-n) as u64 } else { n as u64 };
    if v == 0 {
        buf[i] = b'0';
        i += 1;
    } else {
        let mut digits = [0u8; 24];
        let mut d = 0;
        while v > 0 {
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            d += 1;
        }
        if neg {
            buf[i] = b'-';
            i += 1;
        }
        while d > 0 {
            d -= 1;
            buf[i] = digits[d];
            i += 1;
        }
    }
    buf[i] = b'\n';
    i += 1;
    sys_write(1, buf.as_ptr(), i);
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
fn sys_read(fd: i32, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd as i64, in("rsi") buf, in("rdx") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_close(fd: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd as i64,
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
fn sys_wait4(pid: i32, status: *mut i32, options: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid as i64, in("rsi") status,
        in("rdx") options as i64, in("r10") 0u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_sched_yield() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 24u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_getpid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

#[inline(never)]
fn sys_kill(pid: i32, signal: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 62u64, in("rdi") pid as i64, in("rsi") signal as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_rt_sigprocmask(how: u32, set: u64, oldset: u64, sigsetsize: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 14u64, in("rdi") how as u64, in("rsi") set,
        in("rdx") oldset, in("r10") sigsetsize,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_pidfd_open(pid: u32, flags: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 434u64, in("rdi") pid as u64, in("rsi") flags as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_pidfd_send_signal(pidfd: i32, sig: i32, info: u64, flags: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 424u64, in("rdi") pidfd as i64,
        in("rsi") sig as i64, in("rdx") info, in("r10") flags as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_signalfd4(fd: i32, mask_ptr: u64, sigsetsize: u64, flags: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 289u64, in("rdi") fd as i64, in("rsi") mask_ptr,
        in("rdx") sigsetsize, in("r10") flags as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
