#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    log("PANIC\n");
    sys_exit(1);
}

const SYS_WRITE: u64 = 1;
const SYS_FORK: u64 = 57;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;
const SYS_KILL: u64 = 62;
const SYS_GETPID: u64 = 39;
const SYS_PTRACE: u64 = 101;

const PTRACE_TRACEME: u64 = 0;
const PTRACE_CONT: u64 = 7;
const PTRACE_DETACH: u64 = 17;

const SIGSTOP: u64 = 19;
const SIGUSR1: u64 = 10;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("ptrace_orphan: starting\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        sys_ptrace_call(PTRACE_TRACEME, 0, 0, 0);
        sys_kill(sys_getpid() as u64, SIGSTOP);
        for _ in 0..4_000_000u64 {
            let _ = sys_getpid();
            core::hint::black_box(());
        }
        sys_exit(0);
    }

    let tracee = pid as u64;
    let mut status: i32 = 0;

    if sys_wait4(tracee, &mut status as *mut i32, 0) != tracee as i64 || !wifstopped(status) {
        log("parent: initial stop wait4 wrong\n");
        sys_exit(2);
    }

    sys_ptrace_call(PTRACE_CONT, tracee, 0, 0);
    sys_kill(tracee, SIGUSR1);
    for _ in 0..5_000_000u64 {
        core::hint::black_box(());
    }
    sys_ptrace_call(PTRACE_DETACH, tracee, 0, 0);

    if sys_wait4(tracee, &mut status as *mut i32, 0) != tracee as i64 {
        log("parent: final wait4 wrong\n");
        sys_exit(3);
    }

    log("PTRACE_ORPHAN_OK\n");
    sys_exit(0);
}

fn wifstopped(status: i32) -> bool {
    (status & 0xff) == 0x7f
}

#[inline(never)]
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_FORK, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_GETPID, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_kill(pid: u64, sig: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_KILL, in("rdi") pid, in("rsi") sig,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_ptrace_call(req: u64, pid: u64, addr: u64, data: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "mov r10, {data}",
            "syscall",
            data = in(reg) data,
            in("rax") SYS_PTRACE, in("rdi") req, in("rsi") pid, in("rdx") addr,
            lateout("rax") r, out("rcx") _, out("r11") _, out("r10") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_wait4(pid: u64, status: *mut i32, options: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "mov r10, {opt}",
            "syscall",
            opt = in(reg) options,
            in("rax") SYS_WAIT4, in("rdi") pid, in("rsi") status, in("rdx") 0u64,
            lateout("rax") r, out("rcx") _, out("r11") _, out("r10") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_WRITE, in("rdi") fd, in("rsi") buf, in("rdx") len,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") SYS_EXIT, in("rdi") code as u64, options(noreturn, nostack))
    }
}
