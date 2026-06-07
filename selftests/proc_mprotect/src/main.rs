#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const PROT_NONE: u64 = 0;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

const ENOMEM: i64 = -12;
const SIGSEGV: i32 = 11;

const PAGE: u64 = 4096;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("mprotect test starting\n");

    let r = sys_mmap(
        0,
        2 * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        log("mmap (present) failed\n");
        sys_exit(1);
    }
    let base = r as u64;
    unsafe {
        core::ptr::write_volatile(base as *mut u64, 0x1111);
        core::ptr::write_volatile((base + PAGE) as *mut u64, 0x2222);
    }
    if sys_mprotect(base, 2 * PAGE, PROT_READ) != 0 {
        log("mprotect present->READ failed\n");
        sys_exit(1);
    }
    let v = unsafe { core::ptr::read_volatile(base as *const u64) };
    if v != 0x1111 {
        log("mprotect present: read after tighten wrong\n");
        sys_exit(1);
    }
    if sys_mprotect(base, 2 * PAGE, PROT_READ | PROT_WRITE) != 0 {
        log("mprotect present->RW failed\n");
        sys_exit(1);
    }
    unsafe {
        core::ptr::write_volatile(base as *mut u64, 0x3333);
    }
    log("present-region round-trip OK\n");

    let r = sys_mmap(
        0,
        3 * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        log("mmap (hole) failed\n");
        sys_exit(1);
    }
    let base = r as u64;
    if sys_munmap(base + PAGE, PAGE) != 0 {
        log("munmap middle failed\n");
        sys_exit(1);
    }
    let rc = sys_mprotect(base, 3 * PAGE, PROT_READ);
    if rc != ENOMEM {
        log("mprotect across a hole should return ENOMEM\n");
        sys_exit(1);
    }
    log("ENOMEM-over-hole OK\n");

    let r = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        log("mmap (lazy) failed\n");
        sys_exit(1);
    }
    let lazy = r as u64;
    if sys_mprotect(lazy, PAGE, PROT_READ) != 0 {
        log("mprotect lazy->READ failed\n");
        sys_exit(1);
    }
    let child = sys_fork();
    if child < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if child == 0 {
        unsafe {
            core::ptr::write_volatile(lazy as *mut u64, 0xDEAD);
        }
        sys_exit(42);
    }
    let mut st: i32 = 0;
    let reaped = sys_wait4(child as i32, &mut st, 0);
    if reaped != child {
        log("lazy-tighten: wait4 reaped wrong pid\n");
        sys_exit(1);
    }
    if (st & 0x7f) != SIGSEGV {
        log("lazy-tighten: child not killed by SIGSEGV (tighten didn't bind to lazy page)\n");
        sys_exit(1);
    }
    log("lazy-page tighten denies later write OK\n");

    let none = sys_mmap(
        0,
        PAGE,
        PROT_NONE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if none < 0 {
        log("mmap PROT_NONE failed\n");
        sys_exit(1);
    }
    let none_base = none as u64;
    let child = sys_fork();
    if child < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if child == 0 {
        let _ = unsafe { core::ptr::read_volatile(none_base as *const u64) };
        sys_exit(42);
    }
    let mut st: i32 = 0;
    if sys_wait4(child as i32, &mut st, 0) != child || (st & 0x7f) != SIGSEGV {
        log("PROT_NONE (lazy): read was not denied with SIGSEGV\n");
        sys_exit(1);
    }

    let r = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        log("mmap (present-then-none) failed\n");
        sys_exit(1);
    }
    let base = r as u64;
    unsafe {
        core::ptr::write_volatile(base as *mut u64, 0x1234_5678);
    }
    if sys_mprotect(base, PAGE, PROT_NONE) != 0 {
        log("mprotect present->PROT_NONE failed\n");
        sys_exit(1);
    }
    let child = sys_fork();
    if child < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if child == 0 {
        let _ = unsafe { core::ptr::read_volatile(base as *const u64) };
        sys_exit(42);
    }
    let mut st: i32 = 0;
    if sys_wait4(child as i32, &mut st, 0) != child || (st & 0x7f) != SIGSEGV {
        log("PROT_NONE (present): read was not denied with SIGSEGV\n");
        sys_exit(1);
    }
    if sys_mprotect(base, PAGE, PROT_READ | PROT_WRITE) != 0 {
        log("mprotect PROT_NONE->RW failed\n");
        sys_exit(1);
    }
    if unsafe { core::ptr::read_volatile(base as *const u64) } != 0x1234_5678 {
        log("PROT_NONE round-trip lost the page's data\n");
        sys_exit(1);
    }
    unsafe {
        core::ptr::write_volatile(base as *mut u64, 0x9abc);
    }
    log("PROT_NONE faults on access + round-trips OK\n");

    log("all mprotect tests OK\n");
    sys_exit(0);
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
fn sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 10u64, in("rdi") addr, in("rsi") len, in("rdx") prot,
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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
