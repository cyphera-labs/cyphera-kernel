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
const STACK_PAGES: u64 = 16;

const HAMMER_REGION_PAGES: u64 = 16;
const FORKSTORM_ITERS: u32 = 12;
const NPEERS: u32 = 3;

const RACE_REGION_PAGES: u64 = 8;
const RACE_ITERS: u32 = 20;
const PARENT_MARK: u32 = 0xAAAA_0000;
const CHILD_MARK: u32 = 0x5555_0000;

static HAMMER_REGION: AtomicU64 = AtomicU64::new(0);
static STOP: AtomicU32 = AtomicU32::new(0);
static PEER_FAIL: AtomicU32 = AtomicU32::new(0);
static PEER_SLOT: AtomicU32 = AtomicU32::new(0);

const PEER_PAGES: u64 = 4;

static RACE_REGION: AtomicU64 = AtomicU64::new(0);
static RACE_GO: AtomicU32 = AtomicU32::new(0);

extern "C" fn hammer_peer() -> ! {
    let region = HAMMER_REGION.load(Ordering::Acquire);
    let slot = PEER_SLOT.fetch_add(1, Ordering::AcqRel) as u64;
    let base = region + slot * PEER_PAGES * PAGE;
    let mut tick = 1u32;
    while STOP.load(Ordering::Acquire) == 0 {
        let mut p = 0u64;
        while p < PEER_PAGES {
            let addr = base + p * PAGE;
            wr32(addr, tick);
            if rd32(addr) != tick {
                PEER_FAIL.fetch_add(1, Ordering::Relaxed);
            }
            p += 1;
        }
        tick = tick.wrapping_add(1);
        if tick == 0 {
            tick = 1;
        }
        sys_sched_yield();
    }
    sys_exit(0);
}

extern "C" fn mprotect_peer() -> ! {
    let region = RACE_REGION.load(Ordering::Acquire);
    while RACE_GO.load(Ordering::Acquire) == 0 {
        sys_sched_yield();
    }
    while STOP.load(Ordering::Acquire) == 0 {
        sys_mprotect(region, RACE_REGION_PAGES * PAGE, PROT_READ | PROT_WRITE);
        sys_sched_yield();
    }
    sys_exit(0);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("cow_forkrace: starting\n");

    if !forkstorm_no_deadlock() {
        log("cow_forkrace: forkstorm FAILED\n");
        sys_exit(1);
    }
    log("cow_forkrace: forkstorm (no deadlock under CLONE_VM hammer) OK\n");

    if !mprotect_fork_isolation() {
        log("cow_forkrace: mprotect/fork isolation FAILED\n");
        sys_exit(2);
    }
    log("cow_forkrace: mprotect-vs-fork isolation OK\n");

    log("COW_FORKRACE_OK\n");
    sys_exit(0)
}

fn forkstorm_no_deadlock() -> bool {
    let region = sys_mmap(
        0,
        HAMMER_REGION_PAGES * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        return false;
    }
    let region = region as u64;
    let mut p = 0u64;
    while p < HAMMER_REGION_PAGES {
        wr32(region + p * PAGE, 0xDEAD_0000);
        p += 1;
    }
    HAMMER_REGION.store(region, Ordering::Release);
    STOP.store(0, Ordering::Release);
    PEER_FAIL.store(0, Ordering::Release);
    PEER_SLOT.store(0, Ordering::Release);

    let stacks = sys_mmap(
        0,
        NPEERS as u64 * STACK_PAGES * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if stacks < 0 {
        return false;
    }
    for i in 0..NPEERS as u64 {
        let stack_top = stacks as u64 + (i + 1) * STACK_PAGES * PAGE;
        if unsafe { spawn_peer(stack_top, hammer_peer) } < 0 {
            STOP.store(1, Ordering::Release);
            return false;
        }
    }

    let mut iter = 0u32;
    let mut ok = true;
    while iter < FORKSTORM_ITERS {
        let pid = sys_fork();
        if pid < 0 {
            ok = false;
            break;
        }
        if pid == 0 {
            let mut q = 0u64;
            while q < HAMMER_REGION_PAGES {
                wr32(region + q * PAGE, 0xC0DE_0000 ^ iter);
                q += 1;
            }
            sys_exit(0);
        }
        if !wait_ok(pid) {
            ok = false;
            break;
        }
        iter += 1;
    }

    STOP.store(1, Ordering::Release);
    let mut drain = 0u32;
    while drain < 8_000 {
        sys_sched_yield();
        drain += 1;
    }

    let mut q = 0u64;
    while q < HAMMER_REGION_PAGES {
        wr32(region + q * PAGE, 0xBEEF_0000);
        if rd32(region + q * PAGE) != 0xBEEF_0000 {
            ok = false;
        }
        q += 1;
    }
    sys_munmap(region, HAMMER_REGION_PAGES * PAGE);
    sys_munmap(stacks as u64, NPEERS as u64 * STACK_PAGES * PAGE);
    ok && PEER_FAIL.load(Ordering::Acquire) == 0
}

fn mprotect_fork_isolation() -> bool {
    let region = sys_mmap(
        0,
        RACE_REGION_PAGES * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        return false;
    }
    let region = region as u64;
    RACE_REGION.store(region, Ordering::Release);
    RACE_GO.store(0, Ordering::Release);
    STOP.store(0, Ordering::Release);

    let stack = sys_mmap(
        0,
        STACK_PAGES * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if stack < 0 {
        return false;
    }
    let stack_top = stack as u64 + STACK_PAGES * PAGE;
    if unsafe { spawn_peer(stack_top, mprotect_peer) } < 0 {
        return false;
    }

    let mut ok = true;
    let mut iter = 0u32;
    while iter < RACE_ITERS {
        let parent_val = PARENT_MARK ^ iter;
        let child_val = CHILD_MARK ^ iter;
        let mut q = 0u64;
        while q < RACE_REGION_PAGES {
            wr32(region + q * PAGE, parent_val);
            q += 1;
        }
        RACE_GO.store(1, Ordering::Release);
        let pid = sys_fork();
        if pid < 0 {
            ok = false;
            break;
        }
        if pid == 0 {
            let mut c = 0u64;
            while c < RACE_REGION_PAGES {
                wr32(region + c * PAGE, child_val);
                c += 1;
            }
            let mut c = 0u64;
            while c < RACE_REGION_PAGES {
                if rd32(region + c * PAGE) != child_val {
                    sys_exit(61);
                }
                c += 1;
            }
            sys_exit(0);
        }
        RACE_GO.store(0, Ordering::Release);
        if !wait_ok(pid) {
            ok = false;
            break;
        }
        let mut c = 0u64;
        while c < RACE_REGION_PAGES {
            if rd32(region + c * PAGE) != parent_val {
                ok = false;
                break;
            }
            c += 1;
        }
        if !ok {
            break;
        }
        iter += 1;
    }

    STOP.store(1, Ordering::Release);
    RACE_GO.store(1, Ordering::Release);
    let mut drain = 0u32;
    while drain < 8_000 {
        sys_sched_yield();
        drain += 1;
    }
    sys_munmap(region, RACE_REGION_PAGES * PAGE);
    sys_munmap(stack as u64, STACK_PAGES * PAGE);
    ok
}

unsafe fn spawn_peer(stack_top: u64, entry: extern "C" fn() -> !) -> i64 {
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
fn sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 10u64, in("rdi") addr, in("rsi") len, in("rdx") prot,
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
fn sys_sched_yield() {
    unsafe {
        asm!("syscall", in("rax") 24u64, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack));
    }
}
fn sys_exit(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
