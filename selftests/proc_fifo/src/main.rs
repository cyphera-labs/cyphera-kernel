#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const S_IFIFO: u64 = 0o010000;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_NONBLOCK: u64 = 0o4000;
const AT_FDCWD: i64 = -100;
const EAGAIN: i64 = -11;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("fifo test starting\n");

    let p0 = b"/tmp/fifo0\0";
    if sys_mknodat(AT_FDCWD, p0.as_ptr(), S_IFIFO | 0o600, 0) != 0 {
        log("mknodat fifo0 failed\n");
        sys_exit(1);
    }
    let pid = sys_fork();
    if pid < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        let fd = sys_openat(AT_FDCWD, p0.as_ptr(), O_RDONLY, 0);
        if fd < 0 {
            sys_exit(50);
        }
        let mut buf = [0u8; 16];
        let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n != 4 || &buf[..4] != b"data" {
            sys_exit(51);
        }
        let n2 = sys_read(fd as u64, buf.as_mut_ptr(), buf.len());
        if n2 != 0 {
            sys_exit(52);
        }
        sys_close(fd as u64);
        sys_exit(0);
    }
    for _ in 0..5 {
        sys_sched_yield();
    }
    let fd = sys_openat(AT_FDCWD, p0.as_ptr(), O_WRONLY, 0);
    if fd < 0 {
        log("writer open failed\n");
        sys_exit(1);
    }
    if sys_write(fd as u64, b"data".as_ptr(), 4) != 4 {
        log("writer write failed\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || code != 0 {
        log("reader child failed, code=");
        log_num(code as i64);
        sys_exit(1);
    }
    log("reader-first race: reader got data, no spurious EOF OK\n");

    let prw = b"/tmp/fifo_rw\0";
    if sys_mknodat(AT_FDCWD, prw.as_ptr(), S_IFIFO | 0o600, 0) != 0 {
        log("mknodat fifo_rw failed\n");
        sys_exit(1);
    }
    let fd = sys_openat(AT_FDCWD, prw.as_ptr(), O_RDWR, 0);
    if fd < 0 {
        log("O_RDWR open failed\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("O_RDWR open returns without a peer OK\n");

    let pnb = b"/tmp/fifo_nb\0";
    if sys_mknodat(AT_FDCWD, pnb.as_ptr(), S_IFIFO | 0o600, 0) != 0 {
        log("mknodat fifo_nb failed\n");
        sys_exit(1);
    }
    let fd_r = sys_openat(AT_FDCWD, pnb.as_ptr(), O_RDONLY | O_NONBLOCK, 0);
    if fd_r < 0 {
        log("nonblock RDONLY open failed\n");
        sys_exit(1);
    }
    let fd_w = sys_openat(AT_FDCWD, pnb.as_ptr(), O_WRONLY | O_NONBLOCK, 0);
    if fd_w < 0 {
        log("nonblock WRONLY open failed\n");
        sys_exit(1);
    }
    let mut buf = [0u8; 8];
    let r = sys_read(fd_r as u64, buf.as_mut_ptr(), buf.len());
    if r != EAGAIN {
        log("nonblock read expected -EAGAIN, got ");
        log_num(r);
        sys_exit(1);
    }
    sys_close(fd_r as u64);
    sys_close(fd_w as u64);
    log("O_NONBLOCK read on empty fifo -> EAGAIN OK\n");

    log("all fifo tests OK\n");
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
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i64, p: *const u8, flags: u64, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 257u64, in("rdi") dirfd, in("rsi") p, in("rdx") flags, in("r10") mode,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_mknodat(dirfd: i64, p: *const u8, mode: u64, dev: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 259u64, in("rdi") dirfd, in("rsi") p, in("rdx") mode, in("r10") dev,
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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
