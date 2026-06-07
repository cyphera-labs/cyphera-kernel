#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const LOCK_SH: i32 = 1;
const LOCK_EX: i32 = 2;
const LOCK_UN: i32 = 8;
const LOCK_NB: i32 = 4;

const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const AT_FDCWD: i32 = -100;

const EWOULDBLOCK: i64 = -11;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("flock test starting\n");

    let path = b"/tmp/flock-test\0";
    let fd_a = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR | O_CREAT, 0o600);
    if fd_a < 0 {
        log("open A: ");
        log_num(fd_a);
        sys_exit(1);
    }

    if sys_flock(fd_a as i32, LOCK_EX) != 0 {
        log("LOCK_EX initial fail\n");
        sys_exit(1);
    }
    log("LOCK_EX initial OK\n");

    if sys_flock(fd_a as i32, LOCK_EX) != 0 {
        log("LOCK_EX re-acquire fail\n");
        sys_exit(1);
    }
    log("LOCK_EX re-acquire OK\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork fail\n");
        sys_exit(1);
    }
    if pid == 0 {
        let fd_b = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR, 0);
        if fd_b < 0 {
            sys_exit(40);
        }
        let r = sys_flock(fd_b as i32, LOCK_EX | LOCK_NB);
        if r != EWOULDBLOCK {
            sys_exit(41);
        }
        sys_close(fd_b as i32);
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("LOCK_NB child failed: ");
        log_num(exit_code as i64);
        sys_exit(1);
    }
    log("LOCK_NB|LOCK_EX -> EWOULDBLOCK OK\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork2 fail\n");
        sys_exit(1);
    }
    if pid == 0 {
        let fd_b = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR, 0);
        if fd_b < 0 {
            sys_exit(50);
        }
        if sys_flock(fd_b as i32, LOCK_EX) != 0 {
            sys_exit(51);
        }
        sys_close(fd_b as i32);
        sys_exit(0);
    }
    for _ in 0..5 {
        sys_sched_yield();
    }
    if sys_flock(fd_a as i32, LOCK_UN) != 0 {
        log("LOCK_UN fail\n");
        sys_exit(1);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("blocking LOCK_EX child failed: ");
        log_num(exit_code as i64);
        sys_exit(1);
    }
    log("blocking LOCK_EX wakes on parent's LOCK_UN OK\n");

    let fd_b = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR, 0);
    if fd_b < 0 {
        log("open B fail\n");
        sys_exit(1);
    }
    if sys_flock(fd_a as i32, LOCK_SH) != 0 {
        log("LOCK_SH A fail\n");
        sys_exit(1);
    }
    if sys_flock(fd_b as i32, LOCK_SH) != 0 {
        log("LOCK_SH B fail\n");
        sys_exit(1);
    }
    log("two LOCK_SH OK\n");

    let fd_c = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR, 0);
    if fd_c < 0 {
        log("open C fail\n");
        sys_exit(1);
    }
    let r = sys_flock(fd_c as i32, LOCK_EX | LOCK_NB);
    if r != EWOULDBLOCK {
        log("EX over SH: expected EWOULDBLOCK got ");
        log_num(r);
        sys_exit(1);
    }
    log("LOCK_NB|LOCK_EX over SH -> EWOULDBLOCK OK\n");

    sys_close(fd_a as i32);
    sys_close(fd_b as i32);
    if sys_flock(fd_c as i32, LOCK_EX) != 0 {
        log("LOCK_EX after closes fail\n");
        sys_exit(1);
    }
    log("close drops lock; EX after closes OK\n");

    let fd_dup = sys_dup(fd_c as i32);
    if fd_dup < 0 {
        log("dup fail\n");
        sys_exit(1);
    }
    if sys_flock(fd_dup as i32, LOCK_EX) != 0 {
        log("EX on dup fail\n");
        sys_exit(1);
    }
    sys_close(fd_dup as i32);
    let fd_d = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR, 0);
    let r = sys_flock(fd_d as i32, LOCK_EX | LOCK_NB);
    if r != EWOULDBLOCK {
        log("dup-close shouldn't drop lock; got ");
        log_num(r);
        sys_exit(1);
    }
    sys_close(fd_d as i32);
    sys_close(fd_c as i32);
    log("dup'd fd shares OFD/lock OK\n");

    let fd_x = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR, 0);
    let fd_y = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR, 0);
    if fd_x < 0 || fd_y < 0 {
        log("open X/Y fail\n");
        sys_exit(1);
    }
    if sys_flock(fd_x as i32, LOCK_SH) != 0 || sys_flock(fd_y as i32, LOCK_SH) != 0 {
        log("parent LOCK_SH X/Y fail\n");
        sys_exit(1);
    }
    let pid = sys_fork();
    if pid < 0 {
        log("fork3 fail\n");
        sys_exit(1);
    }
    if pid == 0 {
        let fd_z = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR, 0);
        if fd_z < 0 {
            sys_exit(90);
        }
        if sys_flock(fd_z as i32, LOCK_SH) != 0 {
            sys_exit(91);
        }
        if sys_flock(fd_z as i32, LOCK_EX) != 0 {
            sys_exit(92);
        }
        sys_close(fd_z as i32);
        sys_exit(0);
    }
    for _ in 0..5 {
        sys_sched_yield();
    }
    sys_flock(fd_x as i32, LOCK_UN);
    sys_flock(fd_y as i32, LOCK_UN);
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("multi-holder blocking upgrade child failed: ");
        log_num(exit_code as i64);
        sys_exit(1);
    }
    sys_close(fd_x as i32);
    sys_close(fd_y as i32);
    log("multi-holder blocking SH->EX upgrade serializes OK\n");

    log("all flock tests OK\n");
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
fn sys_close(fd: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 257u64, in("rdi") dirfd as i64,
        in("rsi") path, in("rdx") flags as i64, in("r10") mode as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_flock(fd: i32, op: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 73u64, in("rdi") fd as i64,
        in("rsi") op as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_dup(fd: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 32u64, in("rdi") fd as i64,
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
