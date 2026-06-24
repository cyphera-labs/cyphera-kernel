#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const O_RDONLY: u64 = 0o0;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const AT_FDCWD: i64 = -100;

const SEEK_SET: u64 = 0;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("files test starting\n");

    let urandom_path: &[u8; 13] = b"/dev/urandom\0";
    let fd = sys_openat(AT_FDCWD, urandom_path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        log("open /dev/urandom failed\n");
        sys_exit(1);
    }
    log("/dev/urandom opened\n");

    let mut buf = [0u8; 16];
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len());
    if n != 16 {
        log("read /dev/urandom short\n");
        sys_exit(1);
    }
    log("/dev/urandom 16 bytes: ");
    let mut hex = [0u8; 33];
    for (i, b) in buf.iter().enumerate() {
        hex[i * 2] = nibble(b >> 4);
        hex[i * 2 + 1] = nibble(b & 0xf);
    }
    hex[32] = b'\n';
    sys_write(1, hex.as_ptr(), hex.len());

    if sys_close(fd as u64) != 0 {
        log("close urandom failed\n");
        sys_exit(1);
    }

    let foo_path: &[u8; 9] = b"/tmp/foo\0";
    let fd = sys_openat(
        AT_FDCWD,
        foo_path.as_ptr(),
        O_RDWR | O_CREAT | O_TRUNC,
        0o644,
    );
    if fd < 0 {
        log("open /tmp/foo failed\n");
        sys_exit(1);
    }
    log("/tmp/foo created\n");

    let payload = b"hello world";
    let w = sys_write(fd as u64, payload.as_ptr(), payload.len());
    if w != payload.len() as i64 {
        log("write /tmp/foo short\n");
        sys_exit(1);
    }
    log("/tmp/foo 11 bytes written\n");

    let pos = sys_lseek(fd as u64, 0, SEEK_SET);
    if pos != 0 {
        log("lseek failed\n");
        sys_exit(1);
    }

    let mut readback = [0u8; 11];
    let n = sys_read(fd as u64, readback.as_mut_ptr(), readback.len());
    if n != 11 {
        log("readback short\n");
        sys_exit(1);
    }
    if &readback != payload {
        log("readback mismatch\n");
        sys_exit(1);
    }
    log("/tmp/foo readback OK\n");

    if sys_close(fd as u64) != 0 {
        log("close /tmp/foo failed\n");
        sys_exit(1);
    }

    let fd2 = sys_openat(AT_FDCWD, foo_path.as_ptr(), O_RDONLY, 0);
    if fd2 < 0 {
        log("re-open /tmp/foo failed\n");
        sys_exit(1);
    }
    let mut readback2 = [0u8; 11];
    let n = sys_read(fd2 as u64, readback2.as_mut_ptr(), readback2.len());
    if n != 11 || &readback2 != payload {
        log("persistence check failed\n");
        sys_exit(1);
    }
    sys_close(fd2 as u64);
    log("/tmp/foo persisted across close\n");

    const O_EXCL: u64 = 0o200;
    const EEXIST: i64 = -17;
    let xfd = sys_openat(AT_FDCWD, foo_path.as_ptr(), O_CREAT | O_EXCL, 0o644);
    if xfd != EEXIST {
        log("O_CREAT|O_EXCL on existing file did not return EEXIST\n");
        sys_exit(1);
    }
    log("O_EXCL rejects existing file OK\n");

    const O_PATH: u64 = 0o10_000_000;
    const EBADF: i64 = -9;
    let pfd = sys_openat(AT_FDCWD, b"/tmp\0".as_ptr(), O_PATH, 0);
    if pfd < 0 {
        log("open /tmp O_PATH failed\n");
        sys_exit(1);
    }
    if sys_close(pfd as u64) != 0 {
        log("close O_PATH fd not 0\n");
        sys_exit(1);
    }
    if sys_close(pfd as u64) != EBADF {
        log("O_PATH fd slot not freed on close\n");
        sys_exit(1);
    }
    log("O_PATH close frees slot OK\n");

    log("all file syscalls OK\n");
    sys_exit(0);
}

fn nibble(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

#[inline(never)]
fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

#[inline(never)]
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

#[inline(never)]
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 3u64, in("rdi") fd,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_lseek(fd: u64, offset: i64, whence: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 8u64, in("rdi") fd, in("rsi") offset, in("rdx") whence,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i64, pathname: *const u8, flags: u64, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 257u64, in("rdi") dirfd, in("rsi") pathname,
            in("rdx") flags, in("r10") mode,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
