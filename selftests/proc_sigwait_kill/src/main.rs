#![no_std]
#![no_main]

use core::arch::asm;
use core::sync::atomic::{AtomicI64, Ordering};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit_group(3);
}

const SIGCHLD: u32 = 17;
const SIGKILL: u64 = 9;
const SIGSTOP: u64 = 19;
const SIG_BLOCK: u64 = 0;

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const PAGE: u64 = 4096;
const STACK_PAGES: u64 = 16;

static VICTIM: AtomicI64 = AtomicI64::new(-1);

fn sleep_ms(ms: i64) {
    let ts: [i64; 2] = [0, ms * 1_000_000];
    let _ = sys_nanosleep(ts.as_ptr());
}

extern "C" fn killer_entry() -> ! {
    sleep_ms(80);
    let v = VICTIM.load(Ordering::Acquire);
    if v > 0 {
        sys_kill(v as u64, SIGKILL);
    }
    sys_exit(0);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("sigwait_kill: starting\n");

    let victim = sys_fork();
    if victim < 0 {
        log("sigwait_kill: fork(victim) failed\n");
        sys_exit_group(1);
    }
    if victim == 0 {
        sys_kill(sys_getpid() as u64, SIGSTOP);
        sys_exit(0);
    }
    VICTIM.store(victim, Ordering::Release);

    let stack = sys_mmap(
        0,
        STACK_PAGES * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if stack < 0 || unsafe { spawn_thread(stack as u64 + STACK_PAGES * PAGE, killer_entry) } < 0 {
        log("sigwait_kill: killer thread setup failed\n");
        sys_exit_group(1);
    }

    sleep_ms(30);
    let mask: u64 = 1u64 << SIGCHLD;
    let _ = sys_rt_sigprocmask(SIG_BLOCK, &mask as *const u64 as u64, 0, 8);
    let _ = sys_rt_sigtimedwait(&mask as *const u64 as u64, 0, 0, 8);

    let mut status: i32 = 0;
    let _ = sys_wait4(victim as u64, &mut status as *mut i32, 0);

    log("SIGWAIT_KILL_OK\n");
    sys_exit_group(0)
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
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
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
fn sys_rt_sigprocmask(how: u64, set: u64, oldset: u64, size: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 14u64, in("rdi") how, in("rsi") set, in("rdx") oldset, in("r10") size,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_rt_sigtimedwait(set: u64, info: u64, timeout: u64, size: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 128u64, in("rdi") set, in("rsi") info, in("rdx") timeout, in("r10") size,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_wait4(pid: u64, status: *mut i32, options: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid, in("rsi") status, in("rdx") options, in("r10") 0u64,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_nanosleep(req: *const i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 35u64, in("rdi") req, in("rsi") 0u64,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn sys_exit(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
fn sys_exit_group(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 231u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
