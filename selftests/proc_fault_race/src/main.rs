#![no_std]
#![no_main]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(3);
}

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const MADV_DONTNEED: u64 = 4;

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;

const PAGE: u64 = 4096;
const NPEERS: u32 = 3;
const NTHREADS: u32 = NPEERS + 1;
const NPAGES: u64 = 512;
const ROUNDS: u32 = 24;
const STACK_PAGES: u64 = 16;

static REGION: AtomicU64 = AtomicU64::new(0);
static GO: AtomicU32 = AtomicU32::new(0);
static ARRIVED: AtomicU32 = AtomicU32::new(0);
static CHECK: AtomicU64 = AtomicU64::new(0);

fn read_all(region: u64) {
    let mut sum = 0u64;
    let mut p = 0u64;
    while p < NPAGES {
        let v = unsafe { core::ptr::read_volatile((region + p * PAGE) as *const u32) };
        sum = sum.wrapping_add(v as u64);
        p += 1;
    }
    CHECK.fetch_add(sum, Ordering::Relaxed);
}

extern "C" fn peer_entry() -> ! {
    let region = REGION.load(Ordering::Acquire);
    let mut round = 1u32;
    while round <= ROUNDS {
        while GO.load(Ordering::Acquire) < round {
            sys_sched_yield();
        }
        read_all(region);
        ARRIVED.fetch_add(1, Ordering::AcqRel);
        round += 1;
    }
    sys_exit(0);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("fault_race: starting\n");

    let region = sys_mmap(
        0,
        NPAGES * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        log("fault_race: region mmap failed\n");
        sys_exit(1);
    }
    REGION.store(region as u64, Ordering::Release);

    let stacks = sys_mmap(
        0,
        NPEERS as u64 * STACK_PAGES * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if stacks < 0 {
        log("fault_race: stacks mmap failed\n");
        sys_exit(1);
    }
    for i in 0..NPEERS as u64 {
        let stack_top = stacks as u64 + (i + 1) * STACK_PAGES * PAGE;
        if unsafe { spawn_peer(stack_top) } < 0 {
            log("fault_race: clone failed\n");
            sys_exit(1);
        }
    }

    let mut round = 1u32;
    while round <= ROUNDS {
        ARRIVED.store(0, Ordering::Release);
        sys_madvise(region as u64, NPAGES * PAGE, MADV_DONTNEED);
        GO.store(round, Ordering::Release);
        read_all(region as u64);
        ARRIVED.fetch_add(1, Ordering::AcqRel);
        while ARRIVED.load(Ordering::Acquire) < NTHREADS {
            sys_sched_yield();
        }
        round += 1;
    }

    log("FAULT_RACE_OK\n");
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
fn sys_madvise(addr: u64, len: u64, advice: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 28u64, in("rdi") addr, in("rsi") len, in("rdx") advice,
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
