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
const PTRACE_GETREGS: u64 = 12;
const PTRACE_DETACH: u64 = 17;
const PTRACE_CONT: u64 = 7;
const PTRACE_SYSCALL: u64 = 24;
const PTRACE_SETOPTIONS: u64 = 0x4200;

const PTRACE_O_TRACESYSGOOD: u64 = 0x0000_0001;

const SIGTRAP: i32 = 5;
const SIGSTOP: u64 = 19;
const ENOSYS_RAX: u64 = (-38i64) as u64;

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

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("ptrace test starting\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        let r = sys_ptrace_call(PTRACE_TRACEME, 0, 0, 0);
        if r != 0 {
            log("child: TRACEME failed\n");
            sys_exit(2);
        }
        let self_pid = sys_getpid() as u64;
        sys_kill(self_pid, SIGSTOP);
        unsafe {
            core::arch::asm!("int3", options(nostack));
        }
        sys_write(1, b"S\n".as_ptr(), 2);
        sys_exit(0);
    }

    let child_pid = pid as u64;

    let mut status: i32 = 0;
    let r = sys_wait4(child_pid, &mut status as *mut i32, 0);
    if r != child_pid as i64 {
        log("parent: first wait4 wrong pid: ");
        log_num(r);
        sys_exit(3);
    }
    if !wifstopped(status) {
        log("parent: first wait4 not stopped: status=");
        log_hex(status as u64);
        sys_exit(4);
    }
    let stopsig = wstopsig(status);
    if stopsig != SIGSTOP as i32 {
        log("parent: first stop not SIGSTOP: ");
        log_num(stopsig as i64);
        sys_exit(5);
    }
    log("parent: first stop OK (SIGSTOP after TRACEME)\n");

    let mut regs: UserRegs = UserRegs::default();
    let r = sys_ptrace_call(
        PTRACE_GETREGS,
        child_pid,
        0,
        &mut regs as *mut UserRegs as u64,
    );
    if r != 0 {
        log("parent: GETREGS failed: ");
        log_num(r);
        sys_exit(6);
    }
    log("parent: GETREGS at SIGSTOP OK\n");

    let r = sys_ptrace_call(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD);
    if r != 0 {
        log("parent: SETOPTIONS failed: ");
        log_num(r);
        sys_exit(8);
    }
    log("parent: SETOPTIONS TRACESYSGOOD OK\n");

    let r = sys_ptrace_call(PTRACE_CONT, child_pid, 0, 0);
    if r != 0 {
        log("parent: first PTRACE_CONT failed: ");
        log_num(r);
        sys_exit(9);
    }

    let r = sys_wait4(child_pid, &mut status as *mut i32, 0);
    if r != child_pid as i64 || !wifstopped(status) {
        log("parent: int3 wait4 failed: r=");
        log_num(r);
        sys_exit(10);
    }
    let sig = wstopsig(status);
    if sig != SIGTRAP {
        log("parent: int3 stop not SIGTRAP: ");
        log_num(sig as i64);
        sys_exit(11);
    }
    log("parent: int3 SIGTRAP stop OK\n");

    let r = sys_ptrace_call(
        PTRACE_GETREGS,
        child_pid,
        0,
        &mut regs as *mut UserRegs as u64,
    );
    if r != 0 {
        log("parent: int3 GETREGS failed: ");
        log_num(r);
        sys_exit(12);
    }
    log("parent: int3 GETREGS OK\n");

    let r = sys_ptrace_call(PTRACE_SYSCALL, child_pid, 0, 0);
    if r != 0 {
        log("parent: PTRACE_SYSCALL failed: ");
        log_num(r);
        sys_exit(13);
    }

    let r = sys_wait4(child_pid, &mut status as *mut i32, 0);
    if r != child_pid as i64 || !wifstopped(status) {
        log("parent: write-entry wait4 failed\n");
        sys_exit(14);
    }
    let sig = wstopsig(status);
    if sig != (SIGTRAP | 0x80) {
        log("parent: write-entry stop wrong sig: ");
        log_num(sig as i64);
        sys_exit(15);
    }
    let r = sys_ptrace_call(
        PTRACE_GETREGS,
        child_pid,
        0,
        &mut regs as *mut UserRegs as u64,
    );
    if r != 0 || regs.orig_rax != SYS_WRITE {
        log("parent: write-entry GETREGS wrong: orig_rax=");
        log_num(regs.orig_rax as i64);
        sys_exit(16);
    }
    if regs.rax != ENOSYS_RAX {
        log("parent: write-entry rax != -ENOSYS: ");
        log_num(regs.rax as i64);
        sys_exit(20);
    }
    log("parent: write-entry stop + GETREGS OK (rax=-ENOSYS)\n");

    let r = sys_ptrace_call(PTRACE_SYSCALL, child_pid, 0, 0);
    if r != 0 {
        log("parent: PTRACE_SYSCALL (to exit) failed: ");
        log_num(r);
        sys_exit(21);
    }
    let r = sys_wait4(child_pid, &mut status as *mut i32, 0);
    if r != child_pid as i64 || !wifstopped(status) {
        log("parent: write-exit wait4 failed\n");
        sys_exit(22);
    }
    let sig = wstopsig(status);
    if sig != (SIGTRAP | 0x80) {
        log("parent: write-exit stop wrong sig: ");
        log_num(sig as i64);
        sys_exit(23);
    }
    let r = sys_ptrace_call(
        PTRACE_GETREGS,
        child_pid,
        0,
        &mut regs as *mut UserRegs as u64,
    );
    if r != 0 || regs.orig_rax != SYS_WRITE {
        log("parent: write-exit GETREGS wrong: orig_rax=");
        log_num(regs.orig_rax as i64);
        sys_exit(24);
    }
    if regs.rax != 2 {
        log("parent: write-exit rax != 2 (return value): ");
        log_num(regs.rax as i64);
        sys_exit(25);
    }
    log("parent: write-exit stop OK (rax=2 return value)\n");

    let r = sys_ptrace_call(PTRACE_DETACH, child_pid, 0, 0);
    if r != 0 {
        log("parent: DETACH failed: ");
        log_num(r);
        sys_exit(17);
    }
    log("parent: DETACH OK\n");

    let r = sys_wait4(child_pid, &mut status as *mut i32, 0);
    if r != child_pid as i64 {
        log("parent: final wait4 wrong: ");
        log_num(r);
        sys_exit(18);
    }
    if !wifexited(status) {
        log("parent: child didn't exit cleanly: status=");
        log_hex(status as u64);
        sys_exit(19);
    }

    log("PTRACE_OK\n");
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

#[inline(never)]
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_FORK,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_GETPID,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_kill(pid: u64, sig: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_KILL, in("rdi") pid, in("rsi") sig,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
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
        asm!(
            "syscall",
            in("rax") SYS_WRITE, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
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
        asm!(
            "syscall",
            in("rax") SYS_EXIT, in("rdi") code as u64,
            options(noreturn, nostack),
        );
    }
}
