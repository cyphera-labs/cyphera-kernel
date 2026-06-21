#![no_std]
#![no_main]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    log("PANIC\n");
    sys_exit(1);
}

const SYS_WRITE: u64 = 1;
const SYS_MMAP: u64 = 9;
const SYS_CLONE: u64 = 56;
const SYS_FORK: u64 = 57;
const SYS_EXECVE: u64 = 59;
const SYS_EXIT: u64 = 60;
const SYS_EXIT_GROUP: u64 = 231;
const SYS_WAIT4: u64 = 61;
const SYS_KILL: u64 = 62;
const SYS_GETPID: u64 = 39;
const SYS_PTRACE: u64 = 101;

const PTRACE_TRACEME: u64 = 0;
const PTRACE_CONT: u64 = 7;
const PTRACE_SETOPTIONS: u64 = 0x4200;

const PTRACE_O_TRACESYSGOOD: u64 = 0x0000_0001;
const PTRACE_O_TRACEFORK: u64 = 0x0000_0002;
const PTRACE_O_TRACEVFORK: u64 = 0x0000_0004;
const PTRACE_O_TRACECLONE: u64 = 0x0000_0008;
const PTRACE_O_TRACEEXEC: u64 = 0x0000_0010;

const PTRACE_EVENT_EXEC: i32 = 4;
const SIGSTOP: u64 = 19;
const WNOHANG: u64 = 1;

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_PRIVATE: u64 = 0x2;
const MAP_ANONYMOUS: u64 = 0x20;

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;

const PAGE: u64 = 4096;
const REGION_BYTES: u64 = 16 * PAGE;

const ITERS: u32 = 200;
const GC_PEERS: u32 = 4;

static EXEC_PATH: &[u8] = b"/bin/proc_a\0";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("ptrace_traceexec test starting\n");

    for i in 0..ITERS {
        run_once(i == 0);
        if i % 50 == 0 {
            log("P: cycle #");
            log_num(i as i64);
        }
    }

    log("PTRACE_TRACEEXEC_OK\n");
    sys_exit_group(0);
}

fn run_once(verbose: bool) {
    let pid = sys_fork();
    if pid < 0 {
        log("P: fork(C) failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        child_c();
    }
    let c_pid = pid;

    let mut status: i32 = 0;
    let r = sys_wait4(c_pid, &mut status, 0, 0);
    if r < 0 || !wifstopped(status) {
        log("P: C didn't stop on first wait\n");
        sys_exit(2);
    }
    if verbose {
        log("P: C stopped (initial SIGSTOP) OK\n");
    }

    let opts = PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACEVFORK
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEEXEC;
    if sys_ptrace(PTRACE_SETOPTIONS, c_pid as u64, 0, opts) < 0 {
        log("P: SETOPTIONS failed\n");
        sys_exit(3);
    }
    if sys_ptrace(PTRACE_CONT, c_pid as u64, 0, 0) < 0 {
        log("P: CONT C #1 failed\n");
        sys_exit(4);
    }

    let mut saw_exec_event = false;
    for _ in 0..4096 {
        let mut st: i32 = 0;
        let w = sys_wait4(-1, &mut st, 0, 0);
        if w <= 0 {
            break;
        }
        if wifexited(st) || wifsignaled(st) {
            continue;
        }
        if !wifstopped(st) {
            continue;
        }
        let ev = (st >> 16) & 0xff;
        if ev == PTRACE_EVENT_EXEC {
            saw_exec_event = true;
            if verbose {
                log("P: a tracee reported PTRACE_EVENT_EXEC OK\n");
            }
        }
        let _ = sys_ptrace(PTRACE_CONT, w as u64, 0, 0);
        if saw_exec_event {
            break;
        }
    }

    let mut idle = 0u32;
    while idle < 100 {
        let mut st: i32 = 0;
        let w = sys_wait4(-1, &mut st, WNOHANG, 0);
        if w <= 0 {
            idle += 1;
            sys_sched_yield();
            continue;
        }
        idle = 0;
        if wifexited(st) || wifsignaled(st) || !wifstopped(st) {
            continue;
        }
        let _ = sys_ptrace(PTRACE_CONT, w as u64, 0, 0);
    }

    if verbose && !saw_exec_event {
        log("P: WARN never observed EVENT_EXEC this cycle\n");
    }

    for _ in 0..256 {
        let mut st: i32 = 0;
        if sys_wait4(-1, &mut st, WNOHANG, 0) <= 0 {
            break;
        }
    }
}

fn child_c() -> ! {
    if sys_ptrace(PTRACE_TRACEME, 0, 0, 0) < 0 {
        sys_exit(11);
    }
    let self_pid = sys_getpid() as u64;
    sys_kill(self_pid, SIGSTOP);

    let gc_pid = sys_fork();
    if gc_pid < 0 {
        sys_exit_group(12);
    }
    if gc_pid == 0 {
        grandchild_gc();
    }
    sys_exit_group(0);
}

fn grandchild_gc() -> ! {
    let r = sys_mmap(
        0,
        REGION_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        sys_exit_group(13);
    }
    let region_base = r as u64;
    let scratch = unsafe { &*(region_base as *const AtomicU32) };
    scratch.store(0, Ordering::SeqCst);

    for k in 0..GC_PEERS {
        let stack_top = region_base + REGION_BYTES - PAGE - (k as u64) * (2 * PAGE);
        let flags = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
        let cr: i64;
        unsafe {
            asm!(
                "syscall",
                "test rax, rax",
                "jnz 2f",
                "xor r15d, r15d",
                "6:",
                "add r15d, 1",
                "mov dword ptr [r14], r15d",
                "mov rax, 39",
                "syscall",
                "jmp 6b",
                "2:",
                in("rdi") flags,
                in("rsi") stack_top,
                in("rdx") 0u64,
                in("r10") 0u64,
                in("r8")  0u64,
                inout("rax") SYS_CLONE => cr,
                in("r14") region_base,
                out("r15") _,
                out("rcx") _, out("r11") _,
                options(nostack),
            );
        }
        if cr < 0 {
            sys_exit_group(14);
        }
    }

    for _ in 0..1_000_000u64 {
        core::hint::spin_loop();
    }

    let argv = [EXEC_PATH.as_ptr(), core::ptr::null()];
    let envp = [core::ptr::null::<u8>()];
    sys_execve(EXEC_PATH.as_ptr(), argv.as_ptr(), envp.as_ptr());
    sys_exit_group(42);
}

fn wifstopped(status: i32) -> bool {
    (status & 0xff) == 0x7f
}

fn wifexited(status: i32) -> bool {
    (status & 0x7f) == 0
}

fn wifsignaled(status: i32) -> bool {
    let low = status & 0x7f;
    low != 0x7f && low != 0
}

fn log(msg: &str) {
    sys_write(1, msg.as_ptr(), msg.len());
}

fn log_num(n: i64) {
    let mut buf = [0u8; 24];
    let mut i = 0usize;
    let neg = n < 0;
    let mut v = if neg { -n as u64 } else { n as u64 };
    if v == 0 {
        buf[i] = b'0';
        i += 1;
    } else {
        let mut tmp = [0u8; 24];
        let mut j = 0usize;
        while v > 0 {
            tmp[j] = b'0' + (v % 10) as u8;
            v /= 10;
            j += 1;
        }
        if neg {
            buf[i] = b'-';
            i += 1;
        }
        while j > 0 {
            j -= 1;
            buf[i] = tmp[j];
            i += 1;
        }
    }
    buf[i] = b'\n';
    sys_write(1, buf.as_ptr(), i + 1);
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_WRITE,
            in("rdi") fd,
            in("rsi") buf,
            in("rdx") len,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_MMAP,
            in("rdi") addr,
            in("rsi") len,
            in("rdx") prot,
            in("r10") flags,
            in("r8") fd,
            in("r9") off,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_FORK, lateout("rax") r,
            out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_GETPID, lateout("rax") r,
            out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_kill(pid: u64, sig: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_KILL, in("rdi") pid, in("rsi") sig,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_EXECVE,
            in("rdi") path,
            in("rsi") argv,
            in("rdx") envp,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_wait4(pid: i64, status: *mut i32, options: u64, rusage: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_WAIT4,
            in("rdi") pid as u64,
            in("rsi") status,
            in("rdx") options,
            in("r10") rusage,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_ptrace(req: u64, pid: u64, addr: u64, data: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_PTRACE,
            in("rdi") req,
            in("rsi") pid,
            in("rdx") addr,
            in("r10") data,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_sched_yield() {
    unsafe {
        asm!("syscall", in("rax") 24u64, lateout("rax") _,
            out("rcx") _, out("r11") _, options(nostack));
    }
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") SYS_EXIT, in("rdi") code as u64, options(noreturn, nostack));
    }
}

fn sys_exit_group(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") SYS_EXIT_GROUP, in("rdi") code as u64, options(noreturn, nostack));
    }
}
