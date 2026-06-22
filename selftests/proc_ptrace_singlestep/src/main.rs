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
const PTRACE_SINGLESTEP: u64 = 9;
const PTRACE_GETREGS: u64 = 12;

const SIGSTOP: u64 = 19;
const SIGTRAP: i32 = 5;

const STEPS: usize = 24;
const NOP_RUN: u64 = 64;

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct UserRegs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
}

#[unsafe(naked)]
unsafe extern "C" fn step_target() {
    core::arch::naked_asm!(".rept 64", "nop", ".endr", "ret",);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("ptrace_singlestep test starting\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork failed\n");
        sys_exit(2);
    }
    if pid == 0 {
        if sys_ptrace_call(PTRACE_TRACEME, 0, 0, 0) != 0 {
            log("child: TRACEME failed\n");
            sys_exit(3);
        }
        let me = sys_getpid() as u64;
        sys_kill(me, SIGSTOP);
        unsafe {
            step_target();
        }
        sys_exit(0);
    }

    let child = pid as u64;
    let mut st: i32 = 0;

    if sys_wait4(child, &mut st, 0) != pid || !wifstopped(st) || wstopsig(st) != SIGSTOP as i32 {
        log("parent: first stop not SIGSTOP\n");
        sys_exit(10);
    }

    let target = step_target as *const () as u64;
    let in_nops = |x: u64| x >= target && x < target + NOP_RUN;

    let mut regs = UserRegs::default();
    if sys_ptrace_call(PTRACE_GETREGS, child, 0, &mut regs as *mut UserRegs as u64) != 0 {
        log("parent: initial GETREGS failed\n");
        sys_exit(11);
    }
    let mut prev = regs.rip;
    let mut nop_steps = 0u32;

    for _ in 0..STEPS {
        if sys_ptrace_call(PTRACE_SINGLESTEP, child, 0, 0) != 0 {
            log("parent: SINGLESTEP failed\n");
            sys_exit(20);
        }
        if sys_wait4(child, &mut st, 0) != pid {
            log("parent: wait4 wrong pid after step\n");
            sys_exit(21);
        }
        if !wifstopped(st) || wstopsig(st) != SIGTRAP {
            log("parent: step did not trap with SIGTRAP; status=");
            log_hex(st as u64);
            sys_exit(22);
        }
        if sys_ptrace_call(PTRACE_GETREGS, child, 0, &mut regs as *mut UserRegs as u64) != 0 {
            log("parent: GETREGS after step failed\n");
            sys_exit(23);
        }
        let rip = regs.rip;
        if in_nops(prev) && in_nops(rip) {
            if rip != prev + 1 {
                log("parent: nop single-step advanced rip by != 1: ");
                log_hex(rip.wrapping_sub(prev));
                sys_exit(25);
            }
            nop_steps += 1;
        }
        prev = rip;
    }

    if nop_steps < 8 {
        log("parent: too few single-byte steps within the nop run: ");
        log_hex(nop_steps as u64);
        sys_exit(26);
    }
    log("ptrace_singlestep: per-instruction single-step OK\n");

    if sys_ptrace_call(PTRACE_CONT, child, 0, 0) != 0 {
        log("parent: final CONT failed\n");
        sys_exit(27);
    }
    if sys_wait4(child, &mut st, 0) != pid {
        log("parent: final wait4 wrong pid\n");
        sys_exit(28);
    }
    if !wifexited(st) || wexitstatus(st) != 0 {
        log("parent: child not a clean exit(0); status=");
        log_hex(st as u64);
        sys_exit(29);
    }

    log("PTRACE_SINGLESTEP_OK\n");
    sys_exit(0);
}

fn wifstopped(status: i32) -> bool {
    (status & 0xff) == 0x7f
}

fn wstopsig(status: i32) -> i32 {
    (status >> 8) & 0xff
}

fn wifexited(status: i32) -> bool {
    (status & 0x7f) == 0
}

fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
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
            lateout("rax") r, out("rcx") _, out("r11") _, out("r10") _, options(nostack),
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
            lateout("rax") r, out("rcx") _, out("r11") _, out("r10") _, options(nostack),
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

fn log_hex(v: u64) {
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nib = ((v >> ((15 - i) * 4)) & 0xf) as u8;
        buf[2 + i] = if nib < 10 {
            b'0' + nib
        } else {
            b'a' + (nib - 10)
        };
    }
    let _ = sys_write(1, buf.as_ptr(), 18);
    let _ = sys_write(1, b"\n".as_ptr(), 1);
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") SYS_EXIT, in("rdi") code as u64, options(noreturn, nostack));
    }
}
