#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const AT_FDCWD: i64 = -100;
const O_RDWR: u64 = 2;
const S_IFCHR: u64 = 0o020_000;

const fn makedev(major: u64, minor: u64) -> u64 {
    (major << 8) | minor
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    report(b"mknod: _start entered\n");

    if sys_mknodat(
        AT_FDCWD,
        b"/tmp/mynull\0".as_ptr(),
        S_IFCHR | 0o666,
        makedev(1, 3),
    ) != 0
    {
        report(b"mknod null failed\n");
        sys_exit(1);
    }
    let fd = sys_openat(AT_FDCWD, b"/tmp/mynull\0".as_ptr(), O_RDWR, 0);
    if fd < 0 {
        report(b"open mynull failed\n");
        sys_exit(2);
    }
    if sys_write(fd as u64, b"hello".as_ptr(), 5) != 5 {
        report(b"write to null did not discard 5 bytes\n");
        sys_exit(3);
    }
    let mut rb = [0xAAu8; 8];
    if sys_read(fd as u64, rb.as_mut_ptr(), 8) != 0 {
        report(b"read from null was not EOF\n");
        sys_exit(4);
    }
    sys_close(fd as u64);
    report(b"mknod: /tmp/mynull routes to null (discard + EOF) ok\n");

    if sys_mknodat(
        AT_FDCWD,
        b"/tmp/myzero\0".as_ptr(),
        S_IFCHR | 0o666,
        makedev(1, 5),
    ) != 0
    {
        report(b"mknod zero failed\n");
        sys_exit(5);
    }
    let fz = sys_openat(AT_FDCWD, b"/tmp/myzero\0".as_ptr(), O_RDWR, 0);
    if fz < 0 {
        report(b"open myzero failed\n");
        sys_exit(6);
    }
    let mut zb = [0xAAu8; 8];
    if sys_read(fz as u64, zb.as_mut_ptr(), 8) != 8 {
        report(b"read from zero did not return 8\n");
        sys_exit(7);
    }
    if zb.iter().any(|&b| b != 0) {
        report(b"zero device did not return zeros\n");
        sys_exit(8);
    }
    sys_close(fz as u64);
    report(b"mknod: /tmp/myzero routes to zero (reads zeros) ok\n");

    report(b"mknod: ALL OK\n");
    sys_exit(0);
}

fn report(msg: &[u8]) {
    sys_write(1, msg.as_ptr(), msg.len());
}

fn sys_mknodat(dirfd: i64, path: *const u8, mode: u64, dev: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 259u64, in("rdi") dirfd, in("rsi") path,
            in("rdx") mode, in("r10") dev,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_openat(dirfd: i64, path: *const u8, flags: u64, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 257u64, in("rdi") dirfd, in("rsi") path,
            in("rdx") flags, in("r10") mode,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
