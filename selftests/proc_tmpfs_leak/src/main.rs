#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(3);
}

const AT_FDCWD: i64 = -100;
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;

const ROUNDS: usize = 8;
const FILE_BYTES: usize = 8 * 1024 * 1024;
const CHUNK: usize = 65536;
const TOLERANCE: u64 = 16 * 1024 * 1024;

static CHUNK_BUF: [u8; CHUNK] = [0xab; CHUNK];

fn freeram() -> u64 {
    let mut si = [0u8; 112];
    if sys_sysinfo(si.as_mut_ptr() as u64) != 0 {
        log("tmpfs_leak: sysinfo failed\n");
        sys_exit(1);
    }
    u64::from_le_bytes(si[40..48].try_into().unwrap())
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("tmpfs_leak: starting\n");
    let path = b"/tmp/leaktest\0";

    let base_free = freeram();

    for _ in 0..ROUNDS {
        let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o644);
        if fd < 0 {
            log("tmpfs_leak: open failed\n");
            sys_exit(1);
        }
        let mut written = 0;
        while written < FILE_BYTES {
            let n = sys_write(fd as u64, CHUNK_BUF.as_ptr(), CHUNK);
            if n <= 0 {
                log("tmpfs_leak: write failed (ENOSPC = leak exhausted RAM)\n");
                sys_exit(1);
            }
            written += n as usize;
        }
        if sys_ftruncate(fd as u64, 0) != 0 {
            log("tmpfs_leak: ftruncate failed\n");
            sys_exit(1);
        }
        sys_close(fd as u64);
    }
    sys_unlinkat(AT_FDCWD, path.as_ptr(), 0);

    let end_free = freeram();

    if end_free + TOLERANCE < base_free {
        log("tmpfs_leak: FRAMES LEAKED (freeram dropped past tolerance)\n");
        sys_exit(1);
    }
    log("TMPFS_LEAK_OK\n");
    sys_exit(0)
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
fn sys_openat(dirfd: i64, path: *const u8, flags: u64, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 257u64, in("rdi") dirfd, in("rsi") path, in("rdx") flags,
             in("r10") mode, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
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
fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_unlinkat(dirfd: i64, path: *const u8, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 263u64, in("rdi") dirfd, in("rsi") path, in("rdx") flags,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_sysinfo(info: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 99u64, in("rdi") info,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn sys_exit(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
