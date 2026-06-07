#![no_std]
#![no_main]
#![allow(dead_code)]

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

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const MAP_FAILED: i64 = -1;
const EEXIST: i64 = -17;

const PAGE: u64 = 4096;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("mmap_extras test starting\n");
    let _ = MAP_SHARED;
    let _ = MAP_PRIVATE;

    let len = 64 * PAGE;
    let r = sys_mmap(
        0,
        len,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        log("mmap anonymous failed\n");
        sys_exit(1);
    }
    let base = r as u64;
    let mid = base + 32 * PAGE;
    unsafe {
        core::ptr::write_volatile(mid as *mut u64, 0xCAFEBABEDEADBEEF);
    }
    let v = unsafe { core::ptr::read_volatile(mid as *const u64) };
    if v != 0xCAFEBABEDEADBEEF {
        log("lazy fault-in: write/read mismatch\n");
        sys_exit(1);
    }
    let untouched = base + 50 * PAGE;
    let z = unsafe { core::ptr::read_volatile(untouched as *const u64) };
    if z != 0 {
        log("lazy fault-in: untouched page not zero\n");
        sys_exit(1);
    }
    log("lazy fault-in (anon) OK\n");

    let fixed_addr = 0x1000_0000_0000u64;
    let r = sys_mmap(
        fixed_addr,
        4 * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1i64 as u64,
        0,
    );
    if r as u64 != fixed_addr {
        log("MAP_FIXED: didn't get requested addr\n");
        sys_exit(1);
    }
    unsafe {
        core::ptr::write_volatile(fixed_addr as *mut u64, 0xDEAD);
    }
    let v = unsafe { core::ptr::read_volatile(fixed_addr as *const u64) };
    if v != 0xDEAD {
        log("MAP_FIXED write/read mismatch\n");
        sys_exit(1);
    }
    log("MAP_FIXED at chosen addr OK\n");

    let r = sys_mmap(
        fixed_addr,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
        -1i64 as u64,
        0,
    );
    if r != EEXIST {
        log("MAP_FIXED_NOREPLACE: expected -EEXIST on collision\n");
        sys_exit(1);
    }
    log("MAP_FIXED_NOREPLACE collision -EEXIST OK\n");

    let r = sys_mmap(
        0,
        4 * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        log("mmap for split test failed\n");
        sys_exit(1);
    }
    let base = r as u64;
    unsafe {
        core::ptr::write_volatile(base as *mut u32, 0xAAAA);
        core::ptr::write_volatile((base + 3 * PAGE) as *mut u32, 0xBBBB);
    }
    if sys_munmap(base + PAGE, 2 * PAGE) != 0 {
        log("munmap middle pages failed\n");
        sys_exit(1);
    }
    let a = unsafe { core::ptr::read_volatile(base as *const u32) };
    let b = unsafe { core::ptr::read_volatile((base + 3 * PAGE) as *const u32) };
    if a != 0xAAAA || b != 0xBBBB {
        log("split-VMA: outer pages corrupted\n");
        sys_exit(1);
    }
    log("munmap partial (split VMA) OK\n");

    let path = b"/tmp/mmap_src\0";
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
    if fd < 0 {
        log("open mmap_src failed\n");
        sys_exit(1);
    }
    let body = b"hello from a file-backed mmap\n";
    sys_write(fd as u64, body.as_ptr(), body.len());
    let r = sys_mmap(0, PAGE, PROT_READ, MAP_PRIVATE, fd as u64, 0);
    if r < 0 {
        log("mmap file-backed failed\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    let mapped = r as *const u8;
    for (i, &c) in body.iter().enumerate() {
        let got = unsafe { core::ptr::read_volatile(mapped.add(i)) };
        if got != c {
            log("file-backed mmap content mismatch\n");
            sys_exit(1);
        }
    }
    log("file-backed MAP_PRIVATE OK\n");

    const MADV_DONTNEED: u64 = 4;
    const MADV_FREE: u64 = 8;
    const EINVAL: i64 = -22;
    let base = sys_mmap(
        0,
        2 * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if base < 0 {
        log("madvise: anon mmap failed\n");
        sys_exit(1);
    }
    let base = base as u64;
    unsafe { core::ptr::write_volatile((base + PAGE) as *mut u64, 0xDEAD_BEEF) };
    if sys_madvise(base, 2 * PAGE, MADV_DONTNEED) != 0 {
        log("madvise(DONTNEED) returned error\n");
        sys_exit(1);
    }
    if unsafe { core::ptr::read_volatile((base + PAGE) as *const u64) } != 0 {
        log("MADV_DONTNEED: page not re-zeroed\n");
        sys_exit(1);
    }
    log("MADV_DONTNEED re-zeroes anon OK\n");
    unsafe { core::ptr::write_volatile((base + PAGE) as *mut u64, 0xDEAD) };
    if sys_madvise(base, 2 * PAGE, MADV_FREE) != 0 {
        log("madvise(FREE) returned error\n");
        sys_exit(1);
    }
    if unsafe { core::ptr::read_volatile((base + PAGE) as *const u64) } != 0 {
        log("MADV_FREE: page not re-zeroed\n");
        sys_exit(1);
    }
    log("MADV_FREE re-zeroes anon OK\n");
    if sys_madvise(base + 1, PAGE, MADV_DONTNEED) != EINVAL {
        log("madvise: unaligned addr not EINVAL\n");
        sys_exit(1);
    }
    if sys_madvise(base, PAGE, 0xDEAD_BEEF) != EINVAL {
        log("madvise: bad advice not EINVAL\n");
        sys_exit(1);
    }
    log("madvise input validation OK\n");
    sys_munmap(base, 2 * PAGE);

    log("all mmap_extras tests OK\n");
    let _ = MAP_FAILED;
    sys_exit(0);
}

#[inline(never)]
fn sys_madvise(addr: u64, len: u64, advice: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 28u64, in("rdi") addr, in("rsi") len, in("rdx") advice,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
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
        asm!("syscall", in("rax") 257u64, in("rdi") dirfd, in("rsi") p,
            in("rdx") flags, in("r10") mode,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 9u64, in("rdi") addr, in("rsi") len,
            in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") off,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_munmap(addr: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 11u64, in("rdi") addr, in("rsi") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
