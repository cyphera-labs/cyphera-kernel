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

const PAGE: u64 = 4096;
const STACK_PAGES: u64 = 16;

const AF_INET: u64 = 2;
const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;

const WNOHANG: u64 = 1;

const SPINNERS: u64 = 2;
const ROUNDS: u32 = 20;
const CHILDREN_PER_ROUND: u32 = 8;
const SPINNER_CAP: u32 = 8_000;

static STOP: AtomicU32 = AtomicU32::new(0);

extern "C" fn spinner_entry() -> ! {
    let mut i = 0u32;
    while STOP.load(Ordering::Acquire) == 0 && i < SPINNER_CAP {
        sys_sched_yield();
        i = i.wrapping_add(1);
    }
    sys_exit(0);
}

fn child_body(variant: u32) -> ! {
    let _ = sys_socket(AF_INET, SOCK_STREAM, 0);
    let _ = sys_socket(AF_UNIX, SOCK_STREAM, 0);

    match variant % 4 {
        0 => {
            let mut i = 0u32;
            while i < 50_000 {
                i = i.wrapping_add(1);
                core::hint::spin_loop();
            }
            sys_exit(0)
        }
        1 => {
            sleep_nanos(100_000);
            sys_exit(0)
        }
        2 => {
            let stack = sys_mmap(
                0,
                STACK_PAGES * PAGE,
                PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE,
                -1i64 as u64,
                0,
            );
            if stack >= 0 {
                let top = stack as u64 + STACK_PAGES * PAGE;
                unsafe { spawn_thread(top, spinner_entry) };
            }
            sys_exit_group(0)
        }
        _ => {
            let mut i = 0u32;
            while i < 8 {
                sys_sched_yield();
                i = i.wrapping_add(1);
            }
            sys_exit_group(0)
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("sched_churn: starting\n");

    let _ = sys_socket(AF_INET, SOCK_STREAM, 0);
    let _ = sys_socket(AF_UNIX, SOCK_STREAM, 0);

    let mut s = 0u64;
    while s < SPINNERS {
        let stack = sys_mmap(
            0,
            STACK_PAGES * PAGE,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1i64 as u64,
            0,
        );
        if stack < 0 {
            log("sched_churn: spinner stack mmap failed\n");
            sys_exit(1);
        }
        let top = stack as u64 + STACK_PAGES * PAGE;
        if unsafe { spawn_thread(top, spinner_entry) } < 0 {
            log("sched_churn: spinner clone failed\n");
            sys_exit(1);
        }
        s += 1;
    }

    let mut round = 0u32;
    let mut variant = 0u32;
    while round < ROUNDS {
        let mut spawned = 0u32;
        while spawned < CHILDREN_PER_ROUND {
            let pid = sys_fork();
            if pid == 0 {
                child_body(variant);
            } else if pid < 0 {
                log("sched_churn: fork failed\n");
                STOP.store(1, Ordering::Release);
                sys_exit(1);
            }
            variant = variant.wrapping_add(1);
            spawned += 1;
        }

        let mut reaped = 0u32;
        while reaped < CHILDREN_PER_ROUND {
            let mut status: i32 = 0;
            let r = sys_wait4(-1i64 as u64, &mut status as *mut i32, WNOHANG);
            if r > 0 {
                reaped += 1;
            } else if r == 0 {
                sys_sched_yield();
            } else {
                let rb = sys_wait4(-1i64 as u64, &mut status as *mut i32, 0);
                if rb > 0 {
                    reaped += 1;
                } else {
                    log("sched_churn: wait4 returned no child unexpectedly\n");
                    STOP.store(1, Ordering::Release);
                    sys_exit(1);
                }
            }
        }
        round += 1;
    }

    STOP.store(1, Ordering::Release);

    log("SCHED_CHURN_OK\n");
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

fn sleep_nanos(nanos: u64) {
    let ts: [i64; 2] = [0, nanos as i64];
    let _ = sys_nanosleep(ts.as_ptr());
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
fn sys_socket(domain: u64, ty: u64, proto: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 41u64, in("rdi") domain, in("rsi") ty, in("rdx") proto,
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
fn sys_wait4(pid: u64, status: *mut i32, options: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid, in("rsi") status, in("rdx") options,
             in("r10") 0u64,
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
#[inline(never)]
fn sys_sched_yield() {
    unsafe {
        asm!("syscall", in("rax") 24u64, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack));
    }
}
fn sys_exit(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
fn sys_exit_group(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 231u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
