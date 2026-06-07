#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const MFD_CLOEXEC: u64 = 0x0001;
const MFD_HUGETLB: u64 = 0x0004;
const SEEK_SET: i32 = 0;
const F_GETFD: u64 = 1;
const FD_CLOEXEC: i64 = 1;
const EINVAL: i64 = -22;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("memfd test starting\n");

    let name = b"my-arena\0";
    let fd = sys_memfd_create(name.as_ptr(), 0);
    if fd < 0 {
        log("memfd_create: ");
        log_num(fd);
        sys_exit(1);
    }
    log("memfd_create returned fd OK\n");

    let payload = b"hello memfd world";
    let w = sys_write(fd as u64, payload.as_ptr(), payload.len());
    if w as usize != payload.len() {
        log("write short\n");
        sys_exit(1);
    }
    let pos = sys_lseek(fd as u64, 0, SEEK_SET);
    if pos != 0 {
        log("lseek non-zero\n");
        sys_exit(1);
    }
    let mut readback = [0u8; 32];
    let r = sys_read(fd as u64, readback.as_mut_ptr(), payload.len());
    if r as usize != payload.len() {
        log("read short\n");
        sys_exit(1);
    }
    if &readback[..payload.len()] != payload.as_slice() {
        log("readback mismatch\n");
        sys_exit(1);
    }
    log("memfd write+lseek+read round-trip OK\n");

    if sys_ftruncate(fd as u64, 1024) != 0 {
        log("ftruncate up failed\n");
        sys_exit(1);
    }
    if sys_ftruncate(fd as u64, 0) != 0 {
        log("ftruncate down failed\n");
        sys_exit(1);
    }
    log("memfd ftruncate grow + shrink OK\n");
    sys_close(fd as u64);

    let fd2 = sys_memfd_create(b"cloexec\0".as_ptr(), MFD_CLOEXEC);
    if fd2 < 0 {
        log("memfd CLOEXEC: ");
        log_num(fd2);
        sys_exit(1);
    }
    let flags = sys_fcntl(fd2 as u64, F_GETFD, 0);
    if flags & FD_CLOEXEC == 0 {
        log("MFD_CLOEXEC didn't set FD_CLOEXEC\n");
        sys_exit(1);
    }
    log("MFD_CLOEXEC sets FD_CLOEXEC OK\n");
    sys_close(fd2 as u64);

    let r = sys_memfd_create(b"huge\0".as_ptr(), MFD_HUGETLB);
    if r != EINVAL {
        log("MFD_HUGETLB not rejected: ");
        log_num(r);
        sys_exit(1);
    }
    log("MFD_HUGETLB → EINVAL OK\n");

    log("all memfd tests OK\n");
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
fn sys_lseek(fd: u64, off: i64, whence: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 8u64, in("rdi") fd, in("rsi") off, in("rdx") whence as i64,
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
fn sys_ftruncate(fd: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 77u64, in("rdi") fd, in("rsi") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_memfd_create(name: *const u8, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 319u64, in("rdi") name, in("rsi") flags,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 72u64, in("rdi") fd, in("rsi") cmd, in("rdx") arg,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
