#![no_std]
#![no_main]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SIGUSR1: i32 = 10;
const SA_RESTORER: u64 = 0x0400_0000;
const SIG_SETMASK: u64 = 2;
const EINTR: i64 = -4;

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

const ROUNDS: u32 = 2000;

static LEADER_TID: AtomicU32 = AtomicU32::new(0);
static CHILD_STOP: AtomicU32 = AtomicU32::new(0);
static HANDLER_HITS: AtomicU32 = AtomicU32::new(0);

#[repr(C)]
#[derive(Copy, Clone)]
struct KSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

extern "C" fn usr1_handler(_sig: i32) {
    HANDLER_HITS.fetch_add(1, Ordering::SeqCst);
}

#[unsafe(naked)]
unsafe extern "C" fn restorer() {
    core::arch::naked_asm!("mov rax, 15", "syscall");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("sigsuspend_race test starting\n");

    let act = KSigAction {
        handler: usr1_handler as *const () as u64,
        flags: SA_RESTORER,
        restorer: restorer as *const () as u64,
        mask: 0,
    };
    if sys_rt_sigaction(SIGUSR1, &act, 8) != 0 {
        log("sigaction failed\n");
        sys_exit(1);
    }

    LEADER_TID.store(sys_gettid() as u32, Ordering::SeqCst);

    let usr1: u64 = 1u64 << SIGUSR1;
    let zero: u64 = 0;
    if sys_rt_sigprocmask(SIG_SETMASK, &usr1, 8) != 0 {
        log("initial block failed\n");
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
        log("mmap child stack failed\n");
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
            child_entry = sym hammer_child,
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
        log("clone failed\n");
        sys_exit(1);
    }

    for _ in 0..ROUNDS {
        let r = sys_rt_sigsuspend(&zero, 8);
        if r != EINTR {
            log("rt_sigsuspend returned non-EINTR: ");
            log_num(r);
            sys_exit(1);
        }
        let _ = sys_rt_sigprocmask(SIG_SETMASK, &zero, 8);
        let _ = sys_rt_sigprocmask(SIG_SETMASK, &usr1, 8);
    }

    CHILD_STOP.store(1, Ordering::SeqCst);
    log("SIGSUSPEND_RACE_OK\n");
    sys_exit(0);
}

extern "C" fn hammer_child() -> ! {
    let tgid = sys_getpid();
    let mut tid = LEADER_TID.load(Ordering::SeqCst);
    while tid == 0 {
        core::hint::spin_loop();
        tid = LEADER_TID.load(Ordering::SeqCst);
    }
    while CHILD_STOP.load(Ordering::SeqCst) == 0 {
        let _ = sys_tgkill(tgid, tid as i32, SIGUSR1);
    }
    sys_exit(0);
}

#[inline(never)]
fn sys_rt_sigaction(signum: i32, act: *const KSigAction, sigsetsize: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 13u64, in("rdi") signum as i64, in("rsi") act,
            in("rdx") 0u64, in("r10") sigsetsize,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_rt_sigprocmask(how: u64, set: *const u64, sigsetsize: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 14u64, in("rdi") how, in("rsi") set,
            in("rdx") 0u64, in("r10") sigsetsize,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_rt_sigsuspend(mask: *const u64, sigsetsize: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 130u64, in("rdi") mask, in("rsi") sigsetsize,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_tgkill(tgid: i32, tid: i32, sig: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 234u64, in("rdi") tgid as i64, in("rsi") tid as i64, in("rdx") sig as i64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_gettid() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 186u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_getpid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

#[inline(never)]
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") SYS_MMAP, in("rdi") addr, in("rsi") len,
            in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") off,
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
            "syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
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
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
