#![no_std]
#![no_main]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SYS_FUTEX: u64 = 202;
const FUTEX_LOCK_PI: u64 = 6;
const FUTEX_UNLOCK_PI: u64 = 7;
const FUTEX_TRYLOCK_PI: u64 = 8;

const EPERM: i64 = -1;
const EDEADLK: i64 = -35;
const EAGAIN: i64 = -11;

const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;

const SYS_MMAP: u64 = 9;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const PAGE: u64 = 4096;
const REGION_BYTES: u64 = 16 * PAGE;

static MUTEX: AtomicU32 = AtomicU32::new(0);

static HANDOFF_MUTEX: AtomicU32 = AtomicU32::new(0);
static CHILD_STARTED: AtomicU32 = AtomicU32::new(0);
static CHILD_LOCKED: AtomicU32 = AtomicU32::new(0);

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("pi_futex test starting\n");

    let tid = sys_gettid() as u32;
    let mu_addr = &MUTEX as *const _ as u64;

    MUTEX.store(0, Ordering::SeqCst);
    let r = sys6(SYS_FUTEX, mu_addr, FUTEX_TRYLOCK_PI, 0, 0, 0, 0);
    if r != 0 {
        log("TRYLOCK_PI on unowned: ");
        log_num(r);
        sys_exit(1);
    }
    let v = MUTEX.load(Ordering::SeqCst);
    if (v & FUTEX_TID_MASK) != tid {
        log("after TRYLOCK_PI word=");
        log_num(v as i64);
        log(" expected tid=");
        log_num(tid as i64);
        sys_exit(1);
    }
    log("TRYLOCK_PI on unowned -> 0 + word=tid OK\n");

    let r = sys6(SYS_FUTEX, mu_addr, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
    if r != 0 {
        log("UNLOCK_PI: ");
        log_num(r);
        sys_exit(1);
    }
    let v = MUTEX.load(Ordering::SeqCst);
    if v != 0 {
        log("after UNLOCK_PI word=");
        log_num(v as i64);
        sys_exit(1);
    }
    log("UNLOCK_PI -> word=0 OK\n");

    MUTEX.store(0xC0FFEE, Ordering::SeqCst);
    let r = sys6(SYS_FUTEX, mu_addr, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
    if r != EPERM {
        log("UNLOCK_PI of non-self expected -EPERM got: ");
        log_num(r);
        sys_exit(1);
    }
    log("UNLOCK_PI of non-self -> EPERM OK\n");

    MUTEX.store(0, Ordering::SeqCst);
    let r = sys6(SYS_FUTEX, mu_addr, FUTEX_LOCK_PI, 0, 0, 0, 0);
    if r != 0 {
        log("LOCK_PI on unowned: ");
        log_num(r);
        sys_exit(1);
    }
    let v = MUTEX.load(Ordering::SeqCst);
    if (v & FUTEX_TID_MASK) != tid {
        log("after LOCK_PI word=");
        log_num(v as i64);
        sys_exit(1);
    }
    log("LOCK_PI on unowned -> 0 + word=tid OK\n");

    let r = sys6(SYS_FUTEX, mu_addr, FUTEX_LOCK_PI, 0, 0, 0, 0);
    if r != EDEADLK {
        log("LOCK_PI on self-held expected -EDEADLK got: ");
        log_num(r);
        sys_exit(1);
    }
    log("LOCK_PI on self-held -> EDEADLK OK\n");

    let r = sys6(SYS_FUTEX, mu_addr, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
    if r != 0 {
        log("final UNLOCK_PI: ");
        log_num(r);
        sys_exit(1);
    }

    MUTEX.store(99, Ordering::SeqCst);
    let r = sys6(SYS_FUTEX, mu_addr, FUTEX_TRYLOCK_PI, 0, 0, 0, 0);
    if r != EAGAIN {
        log("TRYLOCK_PI on held expected -EAGAIN got: ");
        log_num(r);
        sys_exit(1);
    }
    log("TRYLOCK_PI on held -> EAGAIN OK\n");

    HANDOFF_MUTEX.store(0, Ordering::SeqCst);
    CHILD_STARTED.store(0, Ordering::SeqCst);
    CHILD_LOCKED.store(0, Ordering::SeqCst);
    let h_addr = &HANDOFF_MUTEX as *const _ as u64;

    let r = sys6(SYS_FUTEX, h_addr, FUTEX_LOCK_PI, 0, 0, 0, 0);
    if r != 0 {
        log("handoff: leader LOCK_PI: ");
        log_num(r);
        sys_exit(1);
    }

    let region = sys_mmap(
        0,
        REGION_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        log("handoff: mmap child stack failed\n");
        sys_exit(1);
    }
    let child_stack_top = region as u64 + REGION_BYTES - PAGE;
    let flags = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;

    let cr: i64;
    unsafe {
        asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "call {child_entry}",
            "mov rax, 60",
            "xor rdi, rdi",
            "syscall",
            "ud2",
            "2:",
            child_entry = sym pi_handoff_child,
            in("rdi") flags,
            in("rsi") child_stack_top,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8") 0u64,
            inout("rax") 56u64 => cr,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    if cr < 0 {
        log("handoff: clone failed: ");
        log_num(cr);
        sys_exit(1);
    }

    while CHILD_STARTED.load(Ordering::SeqCst) == 0 {
        core::hint::spin_loop();
    }
    for _ in 0..1_000_000 {
        core::hint::spin_loop();
    }

    let r = sys6(SYS_FUTEX, h_addr, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
    if r != 0 {
        log("handoff: leader UNLOCK_PI: ");
        log_num(r);
        sys_exit(1);
    }

    while CHILD_LOCKED.load(Ordering::SeqCst) == 0 {
        core::hint::spin_loop();
    }
    let locked = CHILD_LOCKED.load(Ordering::SeqCst);
    if locked != 1 {
        log("handoff: child failed to acquire, code=");
        log_num(locked as i64);
        sys_exit(1);
    }
    log("cross-thread PI handoff: waiter woke + acquired OK\n");

    log("PI_OK\n");
    sys_exit(0);
}

extern "C" fn pi_handoff_child() -> ! {
    let ctid = sys_gettid() as u32;
    let h_addr = &HANDOFF_MUTEX as *const _ as u64;

    CHILD_STARTED.store(1, Ordering::SeqCst);
    let r = sys6(SYS_FUTEX, h_addr, FUTEX_LOCK_PI, 0, 0, 0, 0);
    if r != 0 {
        CHILD_LOCKED.store(2, Ordering::SeqCst);
        sys_exit(0);
    }
    let w = HANDOFF_MUTEX.load(Ordering::SeqCst) & FUTEX_TID_MASK;
    if w != ctid {
        CHILD_LOCKED.store(3, Ordering::SeqCst);
        sys_exit(0);
    }
    CHILD_LOCKED.store(1, Ordering::SeqCst);
    let _ = sys6(SYS_FUTEX, h_addr, FUTEX_UNLOCK_PI, 0, 0, 0, 0);
    sys_exit(0);
}

#[inline(never)]
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_MMAP, in("rdi") addr, in("rsi") len,
            in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") off,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys6(num: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") num, in("rdi") a, in("rsi") b, in("rdx") c,
            in("r10") d, in("r8") e, in("r9") f,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_gettid() -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 186u64,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
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
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") 60u64, in("rdi") code as u64,
            options(noreturn, nostack),
        );
    }
}
