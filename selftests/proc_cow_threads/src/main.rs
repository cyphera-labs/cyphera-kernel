#![no_std]
#![no_main]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
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

const PAGE: u64 = 4096;
const NPAGES: u64 = 32;
const NPEERS: u32 = 3;
const NTHREADS: u32 = NPEERS + 1;
const ROUNDS: u32 = 16;
const STACK_PAGES: u64 = 16;

static REGION: AtomicU64 = AtomicU64::new(0);
static GO: AtomicU32 = AtomicU32::new(0);
static DONE: AtomicU32 = AtomicU32::new(0);
static FAIL: AtomicU32 = AtomicU32::new(0);
static SPAWNED: AtomicU32 = AtomicU32::new(0);

const PAGES_PER_THREAD: u64 = NPAGES / NTHREADS as u64;

fn thread_value(tid: u32, round: u32) -> u32 {
    (tid << 24) | round
}

fn hammer(region: u64, tid: u32, round: u32) {
    let want = thread_value(tid, round);
    let base = tid as u64 * PAGES_PER_THREAD;
    let mut p = 0u64;
    while p < PAGES_PER_THREAD {
        let addr = region + (base + p) * PAGE;
        unsafe { core::ptr::write_volatile(addr as *mut u32, want) };
        let v = unsafe { core::ptr::read_volatile(addr as *const u32) };
        if v != want {
            FAIL.fetch_add(1, Ordering::Relaxed);
        }
        p += 1;
    }
}

extern "C" fn peer_entry() -> ! {
    let region = REGION.load(Ordering::Acquire);
    let tid = SPAWNED.fetch_add(1, Ordering::AcqRel) + 1;
    let mut round = 1u32;
    while round <= ROUNDS {
        while GO.load(Ordering::Acquire) < round {
            sys_sched_yield();
        }
        hammer(region, tid, round);
        DONE.fetch_add(1, Ordering::AcqRel);
        round += 1;
    }
    sys_exit(0);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("cow_threads: starting\n");

    let region = sys_mmap(
        0,
        NPAGES * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        sys_exit(1);
    }
    let region = region as u64;
    let mut p = 0u64;
    while p < NPAGES {
        unsafe { core::ptr::write_volatile((region + p * PAGE) as *mut u32, 0xFFFF_0000) };
        p += 1;
    }
    REGION.store(region, Ordering::Release);

    let holder = sys_fork();
    if holder < 0 {
        sys_exit(2);
    }
    if holder == 0 {
        let mut spins = 0u64;
        while spins < 50_000_000 {
            spins += 1;
            core::hint::spin_loop();
        }
        sys_exit(0);
    }

    let stacks = sys_mmap(
        0,
        NPEERS as u64 * STACK_PAGES * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if stacks < 0 {
        sys_exit(3);
    }
    for i in 0..NPEERS as u64 {
        let stack_top = stacks as u64 + (i + 1) * STACK_PAGES * PAGE;
        if unsafe { spawn_peer(stack_top) } < 0 {
            sys_exit(4);
        }
    }

    let mut round = 1u32;
    while round <= ROUNDS {
        DONE.store(0, Ordering::Release);
        GO.store(round, Ordering::Release);
        hammer(region, 0, round);
        DONE.fetch_add(1, Ordering::AcqRel);
        while DONE.load(Ordering::Acquire) < NTHREADS {
            sys_sched_yield();
        }
        let mut q = 0u64;
        while q < NPAGES {
            let owner = (q / PAGES_PER_THREAD) as u32;
            let want = thread_value(owner, round);
            let v = unsafe { core::ptr::read_volatile((region + q * PAGE) as *const u32) };
            if v != want {
                FAIL.fetch_add(1, Ordering::Relaxed);
            }
            q += 1;
        }
        round += 1;
    }

    sys_kill(holder as u64, 9);
    let mut st: i32 = 0;
    sys_wait4(holder, &mut st as *mut i32, 0, 0);

    if FAIL.load(Ordering::Acquire) != 0 {
        log("cow_threads: incoherent read after concurrent COW break\n");
        sys_exit(5);
    }

    log("COW_THREADS_OK\n");
    sys_exit(0)
}

unsafe fn spawn_peer(stack_top: u64) -> i64 {
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
            entry = sym peer_entry,
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
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_kill(pid: u64, sig: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 62u64, in("rdi") pid, in("rsi") sig,
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
fn sys_sched_yield() {
    unsafe {
        asm!("syscall", in("rax") 24u64, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack));
    }
}
fn sys_exit(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
