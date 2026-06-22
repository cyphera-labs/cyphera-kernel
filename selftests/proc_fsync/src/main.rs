#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const AT_FDCWD: i64 = -100;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 0x01;

const PAGE: usize = 4096;
const MARK: u8 = 0x42;
const CHECK: usize = 256;

const EBADF: i64 = -9;
const EINVAL: i64 = -22;
const ESPIPE: i64 = -29;
const MARK2: u8 = 0x55;
const OFF2: usize = 1024;
const SYNC_FILE_RANGE_WRITE: u64 = 2;
const SYNC_FILE_RANGE_WAIT_AFTER: u64 = 4;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("fsync test starting\n");

    let path = b"/tmp/fsync_test\0";
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        log("open failed\n");
        sys_exit(1);
    }
    let fd = fd as u64;

    if sys_ftruncate(fd, PAGE as u64) != 0 {
        log("ftruncate failed\n");
        sys_exit(2);
    }

    let m = sys_mmap(0, PAGE as u64, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if m < 0 {
        log("mmap MAP_SHARED failed\n");
        sys_exit(3);
    }
    let map = m as u64 as *mut u8;

    for i in 0..CHECK {
        unsafe { core::ptr::write_volatile(map.add(i), MARK) };
    }

    if sys_fsync(fd) != 0 {
        log("fsync returned nonzero\n");
        sys_exit(4);
    }

    if sys_lseek(fd, 0, 0) < 0 {
        log("lseek failed\n");
        sys_exit(5);
    }
    let mut buf = [0u8; CHECK];
    let n = sys_read(fd, buf.as_mut_ptr(), CHECK);
    if n != CHECK as i64 {
        log("short read after fsync\n");
        sys_exit(6);
    }
    for &b in buf.iter() {
        if b != MARK {
            log("fsync did not flush mmap write to backing store\n");
            sys_exit(7);
        }
    }
    log("fsync: mmap(MAP_SHARED) write flushed to backing store\n");

    if sys_fsync(999) != EBADF {
        log("fsync(badfd) not EBADF\n");
        sys_exit(8);
    }

    let mut pfds = [0i32; 2];
    if sys_pipe2(pfds.as_mut_ptr(), 0) != 0 {
        log("pipe2 failed\n");
        sys_exit(9);
    }
    if sys_fsync(pfds[0] as u64) != EINVAL {
        log("fsync(pipe) not EINVAL\n");
        sys_exit(10);
    }
    log("fsync: EBADF + EINVAL(pipe) ok\n");

    let path2 = b"/tmp/sfr_test\0";
    let fd2 = sys_openat(AT_FDCWD, path2.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd2 < 0 {
        log("open sfr file failed\n");
        sys_exit(11);
    }
    let fd2 = fd2 as u64;
    if sys_ftruncate(fd2, PAGE as u64) != 0 {
        log("ftruncate sfr failed\n");
        sys_exit(12);
    }
    let m2 = sys_mmap(0, PAGE as u64, PROT_READ | PROT_WRITE, MAP_SHARED, fd2, 0);
    if m2 < 0 {
        log("mmap sfr failed\n");
        sys_exit(13);
    }
    let map2 = m2 as u64 as *mut u8;
    for i in 0..CHECK {
        unsafe { core::ptr::write_volatile(map2.add(OFF2 + i), MARK2) };
    }
    if sys_sync_file_range(
        fd2,
        OFF2 as u64,
        CHECK as u64,
        SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER,
    ) != 0
    {
        log("sync_file_range returned nonzero\n");
        sys_exit(14);
    }
    if sys_lseek(fd2, OFF2 as i64, 0) < 0 {
        log("lseek OFF2 failed\n");
        sys_exit(15);
    }
    let mut buf2 = [0u8; CHECK];
    if sys_read(fd2, buf2.as_mut_ptr(), CHECK) != CHECK as i64 {
        log("short read after sync_file_range\n");
        sys_exit(16);
    }
    for &b in buf2.iter() {
        if b != MARK2 {
            log("sync_file_range did not flush range to backing store\n");
            sys_exit(17);
        }
    }
    log("sync_file_range: range write flushed to backing store\n");

    if sys_sync_file_range(pfds[0] as u64, 0, 0, SYNC_FILE_RANGE_WRITE) != ESPIPE {
        log("sync_file_range(pipe) not ESPIPE\n");
        sys_exit(18);
    }
    if sys_sync_file_range(fd, 0, 0, 0x100) != EINVAL {
        log("sync_file_range(bad flags) not EINVAL\n");
        sys_exit(19);
    }
    if sys_sync_file_range(999, 0, 0, SYNC_FILE_RANGE_WRITE) != EBADF {
        log("sync_file_range(badfd) not EBADF\n");
        sys_exit(20);
    }
    log("sync_file_range: ESPIPE + EINVAL + EBADF ok\n");

    log("FSYNC_OK\n");
    sys_exit(0);
}

#[inline(never)]
fn sys_sync_file_range(fd: u64, offset: u64, nbytes: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 277u64, in("rdi") fd, in("rsi") offset, in("rdx") nbytes, in("r10") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i64, path: *const u8, flags: u64, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 257u64, in("rdi") dirfd, in("rsi") path, in("rdx") flags, in("r10") mode,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_ftruncate(fd: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 77u64, in("rdi") fd, in("rsi") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 9u64, in("rdi") addr, in("rsi") len,
            in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") off,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_fsync(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 74u64, in("rdi") fd,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_lseek(fd: u64, off: i64, whence: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 8u64, in("rdi") fd, in("rsi") off, in("rdx") whence,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
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
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_pipe2(fds: *mut i32, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 293u64, in("rdi") fds, in("rsi") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
