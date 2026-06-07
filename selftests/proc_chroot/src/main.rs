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

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("chroot test starting\n");

    if sys_mkdirat(AT_FDCWD, b"/jail\0".as_ptr(), 0o755) != 0 {
        log("mkdir /jail failed\n");
        sys_exit(1);
    }
    if sys_mkdirat(AT_FDCWD, b"/jail/sub\0".as_ptr(), 0o755) != 0 {
        log("mkdir /jail/sub failed\n");
        sys_exit(1);
    }
    let fd = sys_openat(
        AT_FDCWD,
        b"/jail/sub/marker\0".as_ptr(),
        O_CREAT | O_RDWR | O_TRUNC,
        0o644,
    );
    if fd < 0 {
        log("create /jail/sub/marker failed\n");
        sys_exit(1);
    }
    let payload = b"captured-by-chroot\n";
    sys_write(fd as u64, payload.as_ptr(), payload.len());
    sys_close(fd as u64);
    log("jail tree built\n");

    let mut buf = [0u8; 32];
    let n = read_path(b"/dev/zero\0", &mut buf);
    if n <= 0 {
        log("pre-chroot /dev/zero read failed\n");
        sys_exit(1);
    }
    log("pre-chroot world is visible\n");

    if sys_chroot(b"/jail\0".as_ptr()) != 0 {
        log("chroot /jail failed\n");
        sys_exit(1);
    }
    log("chroot returned 0\n");

    let n = read_path(b"/sub/marker\0", &mut buf);
    if n != payload.len() as i64 || &buf[..n as usize] != payload {
        log("post-chroot /sub/marker mismatch\n");
        sys_exit(1);
    }
    log("post-chroot /sub/marker readback OK\n");

    let mut throwaway = [0u8; 8];
    let r = read_path(b"/jail/sub/marker\0", &mut throwaway);
    if r >= 0 {
        log("post-chroot /jail/sub/marker still resolves (escape!)\n");
        sys_exit(1);
    }
    log("post-chroot pre-chroot path correctly invisible\n");

    let r = read_path(b"/dev/zero\0", &mut throwaway);
    if r >= 0 {
        log("post-chroot /dev/zero still resolves (escape!)\n");
        sys_exit(1);
    }
    log("post-chroot /dev/zero correctly invisible\n");

    log("all chroot tests OK\n");
    sys_exit(0);
}

fn read_path(path: &[u8], buf: &mut [u8]) -> i64 {
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len());
    sys_close(fd as u64);
    n
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

#[inline(never)]
fn sys_mkdirat(dirfd: i64, pathname: *const u8, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 258u64, in("rdi") dirfd, in("rsi") pathname, in("rdx") mode,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_chroot(pathname: *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 161u64, in("rdi") pathname,
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
