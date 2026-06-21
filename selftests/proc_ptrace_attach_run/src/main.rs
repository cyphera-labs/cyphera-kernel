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

const PTRACE_ATTACH: u64 = 16;
const PTRACE_GETREGS: u64 = 12;

const SIGKILL: u64 = 9;
const SIGSTOP_STATUS: i32 = 19;

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
    log("ptrace attach-running test starting\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        loop {
            let _ = sys_getpid();
            core::hint::black_box(());
        }
    }

    let child_pid = pid as u64;

    for _ in 0..8_000_000u64 {
        core::hint::black_box(());
    }

    let r = sys_ptrace_call(PTRACE_ATTACH, child_pid, 0, 0);
    if r != 0 {
        log("parent: ATTACH failed: ");
        log_num(r);
        sys_exit(2);
    }
    log("parent: ATTACH OK\n");

    let mut status: i32 = 0;
    let r = sys_wait4(child_pid, &mut status as *mut i32, 0);
    if r != child_pid as i64 {
        log("parent: attach-stop wait4 wrong pid: ");
        log_num(r);
        sys_exit(3);
    }
    if !wifstopped(status) {
        log("parent: attach-stop not stopped: status=");
        log_hex(status as u64);
        sys_exit(4);
    }
    let stopsig = wstopsig(status);
    if stopsig != SIGSTOP_STATUS {
        log("parent: attach-stop sig != SIGSTOP: ");
        log_num(stopsig as i64);
        sys_exit(5);
    }
    log("parent: attach-stop OK (SIGSTOP)\n");

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
    if regs.rip == 0 {
        log("parent: GETREGS incoherent (rip==0)\n");
        sys_exit(7);
    }
    log("parent: GETREGS at attach-stop OK\n");

    let r = sys_kill(child_pid, SIGKILL);
    if r != 0 {
        log("parent: kill failed: ");
        log_num(r);
        sys_exit(8);
    }

    let r = sys_wait4(child_pid, &mut status as *mut i32, 0);
    if r != child_pid as i64 {
        log("parent: reap wait4 wrong pid: ");
        log_num(r);
        sys_exit(9);
    }

    log("PTRACE_ATTACH_RUN_OK\n");
    sys_exit(0);
}

fn wifstopped(status: i32) -> bool {
    (status & 0xff) == 0x7f
}

fn wstopsig(status: i32) -> i32 {
    (status >> 8) & 0xff
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
