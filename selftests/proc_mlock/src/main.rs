#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_POPULATE: u64 = 0x8000;
const PAGE: u64 = 4096;
const ENOMEM: i64 = -12;

fn map_anon(pages: u64, extra_flags: u64) -> i64 {
    sys_mmap(
        0,
        pages * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | extra_flags,
        -1i64 as u64,
        0,
    )
}

fn all_resident(addr: u64, pages: usize) -> Option<bool> {
    let mut v = [0u8; 64];
    if pages > v.len() {
        return None;
    }
    if sys_mincore(addr, (pages as u64) * PAGE, v.as_mut_ptr()) != 0 {
        return None;
    }
    Some(v[..pages].iter().all(|b| b & 1 == 1))
}

fn any_resident(addr: u64, pages: usize) -> Option<bool> {
    let mut v = [0u8; 64];
    if pages > v.len() {
        return None;
    }
    if sys_mincore(addr, (pages as u64) * PAGE, v.as_mut_ptr()) != 0 {
        return None;
    }
    Some(v[..pages].iter().any(|b| b & 1 == 1))
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("mlock test starting\n");

    let a = map_anon(1, 0);
    if a < 0 {
        log("mmap A failed\n");
        sys_exit(1);
    }
    let a = a as u64;
    if any_resident(a, 1) != Some(false) {
        log("fresh anon page already resident (not lazy?)\n");
        sys_exit(2);
    }
    if sys_mlock(a, PAGE) != 0 {
        log("mlock returned nonzero\n");
        sys_exit(3);
    }
    if all_resident(a, 1) != Some(true) {
        log("page not resident after mlock (populate missing)\n");
        sys_exit(4);
    }
    log("mlock: anon page resident after mlock\n");

    let b = map_anon(4, 0);
    if b < 0 {
        log("mmap B failed\n");
        sys_exit(5);
    }
    let b = b as u64;
    if sys_mlock(b, 4 * PAGE) != 0 {
        log("mlock 4-page returned nonzero\n");
        sys_exit(6);
    }
    if all_resident(b, 4) != Some(true) {
        log("4-page range not fully resident after mlock\n");
        sys_exit(7);
    }
    log("mlock: 4-page range resident\n");

    let c = map_anon(1, 0);
    if c < 0 {
        log("mmap C failed\n");
        sys_exit(8);
    }
    let c = c as u64;
    if sys_munmap(c, PAGE) != 0 {
        log("munmap C failed\n");
        sys_exit(9);
    }
    if sys_mlock(c, PAGE) != ENOMEM {
        log("mlock of unmapped page not ENOMEM\n");
        sys_exit(10);
    }
    log("mlock: unmapped range -> ENOMEM\n");

    let d = map_anon(2, MAP_POPULATE);
    if d < 0 {
        log("mmap D (MAP_POPULATE) failed\n");
        sys_exit(11);
    }
    let d = d as u64;
    if all_resident(d, 2) != Some(true) {
        log("MAP_POPULATE range not resident\n");
        sys_exit(12);
    }
    log("mlock: MAP_POPULATE pre-faulted\n");

    if sys_munlock(a, PAGE) != 0 {
        log("munlock returned nonzero\n");
        sys_exit(13);
    }
    if all_resident(a, 1) != Some(true) {
        log("munlock evicted the page\n");
        sys_exit(14);
    }

    const MCL_FUTURE: u64 = 2;
    if sys_mlockall(MCL_FUTURE) != 0 {
        log("mlockall(MCL_FUTURE) failed\n");
        sys_exit(15);
    }
    let e = map_anon(2, 0);
    if e < 0 {
        log("mmap E (future-locked) failed\n");
        sys_exit(16);
    }
    let e = e as u64;
    if all_resident(e, 2) != Some(true) {
        log("MCL_FUTURE mapping not resident (future-lock missing)\n");
        sys_exit(17);
    }
    log("mlock: MCL_FUTURE mapping resident without explicit mlock\n");

    if sys_munlockall() != 0 {
        log("munlockall failed\n");
        sys_exit(18);
    }
    let f = map_anon(1, 0);
    if f < 0 {
        log("mmap F (post-munlockall) failed\n");
        sys_exit(19);
    }
    if any_resident(f as u64, 1) != Some(false) {
        log("mapping after munlockall not lazy again\n");
        sys_exit(20);
    }
    log("mlock: post-munlockall mapping lazy again\n");

    log("MLOCK_OK\n");
    sys_exit(0);
}

#[inline(never)]
fn sys_mlockall(flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 151u64, in("rdi") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_munlockall() -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 152u64,
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
fn sys_munmap(addr: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 11u64, in("rdi") addr, in("rsi") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_mlock(addr: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 149u64, in("rdi") addr, in("rsi") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_munlock(addr: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 150u64, in("rdi") addr, in("rsi") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_mincore(addr: u64, len: u64, vec: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 27u64, in("rdi") addr, in("rsi") len, in("rdx") vec,
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
