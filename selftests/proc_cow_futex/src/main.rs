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

const SYS_FUTEX: u64 = 202;
const FUTEX_WAIT: u64 = 0;
const FUTEX_PRIVATE_FLAG: u64 = 0x80;
const FUTEX_LOCK_PI: u64 = 6;
const FUTEX_UNLOCK_PI: u64 = 7;

const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;

const PAGE: u64 = 4096;
const EAGAIN: i64 = -11;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("cow_futex: starting\n");

    if !test_futex_wait_cow() {
        sys_exit(1);
    }
    log("cow_futex: FUTEX_WAIT on inherited COW word OK\n");

    if !test_pi_futex_owner_died() {
        sys_exit(2);
    }
    log("cow_futex: PI-futex teardown on COW word OK\n");

    log("COW_FUTEX_OK\n");
    sys_exit(0)
}

fn test_futex_wait_cow() -> bool {
    let region = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        return false;
    }
    let word = region as u64;
    wr32(word, 5);

    let pid = sys_fork();
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        wr32(word, 7);
        let r = sys_futex(word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 999, 0, 0, 0);
        if r != EAGAIN {
            sys_exit(11);
        }
        if rd32(word) != 7 {
            sys_exit(12);
        }
        sys_exit(0);
    }

    wr32(word, 13);
    let r = sys_futex(word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 999, 0, 0, 0);
    if r != EAGAIN {
        return false;
    }
    if !wait_ok(pid) {
        return false;
    }
    let ok = rd32(word) == 13;
    sys_munmap(word, PAGE);
    ok
}

fn test_pi_futex_owner_died() -> bool {
    let region = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        return false;
    }
    let word = region as u64;
    wr32(word, 0);

    let pid = sys_fork();
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        if sys_futex(word, FUTEX_LOCK_PI, 0, 0, 0, 0) != 0 {
            sys_exit(21);
        }
        let g = sys_fork();
        if g < 0 {
            sys_exit(22);
        }
        if g == 0 {
            sys_exit(0);
        }
        let mut st = 0i32;
        sys_wait4(g as i64, &mut st as *mut i32, 0, 0);
        sys_exit(0);
    }
    if !wait_ok(pid) {
        return false;
    }

    if sys_futex(word, FUTEX_LOCK_PI, 0, 0, 0, 0) != 0 {
        return false;
    }
    let held = rd32(word);
    let my_tid = sys_gettid() as u32;
    let isolated = held & FUTEX_OWNER_DIED == 0 && (held & FUTEX_TID_MASK) == my_tid;
    sys_futex(word, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
    sys_munmap(word, PAGE);
    isolated
}

fn wait_ok(pid: i64) -> bool {
    let mut status: i32 = 0;
    if sys_wait4(pid, &mut status as *mut i32, 0, 0) < 0 {
        return false;
    }
    status & 0x7f == 0 && (status >> 8) & 0xff == 0
}

fn rd32(p: u64) -> u32 {
    unsafe { core::ptr::read_volatile(p as *const u32) }
}
fn wr32(p: u64, v: u32) {
    unsafe { core::ptr::write_volatile(p as *mut u32, v) }
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
        asm!("syscall", in("rax") 9u64, in("rdi") addr, in("rsi") len, in("rdx") prot,
             in("r10") flags, in("r8") fd, in("r9") off,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_munmap(addr: u64, length: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 11u64, in("rdi") addr, in("rsi") length,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_wait4(pid: i64, status: *mut i32, options: i32, rusage: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid, in("rsi") status,
             in("rdx") options as i64, in("r10") rusage,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_futex(uaddr: u64, op: u64, val: u64, timeout: u64, uaddr2: u64, val3: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_FUTEX, in("rdi") uaddr, in("rsi") op, in("rdx") val,
             in("r10") timeout, in("r8") uaddr2, in("r9") val3,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_gettid() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 186u64,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn sys_exit(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
