#![no_std]
#![no_main]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(3);
}

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;

const FUTEX_WAIT: u64 = 0;

const PAGE: u64 = 4096;
const STACK_PAGES: u64 = 16;

const WORKERS: u32 = 8;
const WAITS_PER_WORKER: u32 = 400;

static FZERO: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);

fn futex_wait_timed() {
    let ts: [i64; 2] = [0, 1_000];
    let _ = sys_futex(FZERO.as_ptr() as u64, FUTEX_WAIT, 0, ts.as_ptr() as u64);
}

extern "C" fn worker_entry() -> ! {
    let mut i = 0u32;
    while i < WAITS_PER_WORKER {
        futex_wait_timed();
        i = i.wrapping_add(1);
    }
    DONE.fetch_add(1, Ordering::AcqRel);
    sys_exit(0);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("futex_timeout: starting\n");

    let stacks = sys_mmap(
        0,
        WORKERS as u64 * STACK_PAGES * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if stacks < 0 {
        log("futex_timeout: stacks mmap failed\n");
        sys_exit(1);
    }
    for w in 0..WORKERS as u64 {
        let top = stacks as u64 + (w + 1) * STACK_PAGES * PAGE;
        if unsafe { spawn_thread(top, worker_entry) } < 0 {
            log("futex_timeout: clone failed\n");
            sys_exit(1);
        }
    }

    let mut i = 0u32;
    while i < WAITS_PER_WORKER {
        futex_wait_timed();
        i = i.wrapping_add(1);
    }
    while DONE.load(Ordering::Acquire) < WORKERS {
        futex_wait_timed();
    }

    log("FUTEX_TIMEOUT_OK\n");
    sys_exit(0)
}

unsafe fn spawn_thread(stack_top: u64, entry: extern "C" fn() -> !) -> i64 {
    let flags = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
    let rc: i64;
    unsafe {
        asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "and rsp, -16",
            "call {entry}",
            "ud2",
            "2:",
            entry = in(reg) entry,
            in("rdi") flags,
            in("rsi") stack_top,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8") 0u64,
            inout("rax") 56u64 => rc,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    rc
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
fn sys_futex(uaddr: u64, op: u64, val: u64, timeout: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 202u64, in("rdi") uaddr, in("rsi") op, in("rdx") val,
             in("r10") timeout, in("r8") 0u64, in("r9") 0u64,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn sys_exit(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
