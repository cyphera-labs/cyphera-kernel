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
const PTRACE_PEEKDATA: u64 = 2;
const PTRACE_CONT: u64 = 7;
const PTRACE_GETREGS: u64 = 12;

const SIGSTOP: u64 = 19;
const SIGSEGV: i32 = 11;
const BAD_ADDR: u64 = 0xdead_0000;

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
unsafe extern "C" fn crash_inner() {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "mov rax, 0xdead0000",
        "mov byte ptr [rax], 1",
        "pop rbp",
        "ret",
    );
}

#[unsafe(naked)]
unsafe extern "C" fn crash_middle() {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "call {inner}",
        "pop rbp",
        "ret",
        inner = sym crash_inner,
    );
}

#[unsafe(naked)]
unsafe extern "C" fn crash_main() {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "call {middle}",
        "pop rbp",
        "ret",
        middle = sym crash_middle,
    );
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("ptrace_segv test starting\n");

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
            crash_main();
        }
        sys_exit(4);
    }

    let child = pid as u64;
    let mut st: i32 = 0;

    if sys_wait4(child, &mut st, 0) != pid || !wifstopped(st) || wstopsig(st) != SIGSTOP as i32 {
        log("parent: first stop not SIGSTOP\n");
        sys_exit(10);
    }
    if sys_ptrace_call(PTRACE_CONT, child, 0, 0) != 0 {
        log("parent: CONT failed\n");
        sys_exit(11);
    }
    if sys_wait4(child, &mut st, 0) != pid || !wifstopped(st) {
        log("parent: no second stop\n");
        sys_exit(12);
    }
    if wstopsig(st) != SIGSEGV {
        log("parent: stop signal not SIGSEGV: ");
        log_num(wstopsig(st) as i64);
        sys_exit(13);
    }
    log("ptrace_segv: caught SIGSEGV signal-delivery-stop OK\n");

    let mut regs = UserRegs::default();
    if sys_ptrace_call(PTRACE_GETREGS, child, 0, &mut regs as *mut UserRegs as u64) != 0 {
        log("parent: GETREGS failed\n");
        sys_exit(14);
    }
    let inner = crash_inner as *const () as u64;
    let middle = crash_middle as *const () as u64;
    let main_fn = crash_main as *const () as u64;
    if !in_range(regs.rip, inner) {
        log("parent: fault rip not in crash_inner: ");
        log_hex(regs.rip);
        sys_exit(15);
    }
    if regs.rax != BAD_ADDR {
        log("parent: rax not the faulting pointer: ");
        log_hex(regs.rax);
        sys_exit(16);
    }
    log("ptrace_segv: GETREGS fault frame OK (rip in inner, rax=bad ptr)\n");

    let ret0 = peek(child, regs.rbp.wrapping_add(8));
    if !in_range(ret0, middle) {
        log("parent: backtrace frame 1 not crash_middle: ");
        log_hex(ret0);
        sys_exit(17);
    }
    let saved_rbp = peek(child, regs.rbp);
    let ret1 = peek(child, saved_rbp.wrapping_add(8));
    if !in_range(ret1, main_fn) {
        log("parent: backtrace frame 2 not crash_main: ");
        log_hex(ret1);
        sys_exit(18);
    }
    log("ptrace_segv: backtrace inner->middle->main OK\n");

    if sys_ptrace_call(PTRACE_CONT, child, 0, SIGSEGV as u64) != 0 {
        log("parent: CONT-reinject failed\n");
        sys_exit(19);
    }
    if sys_wait4(child, &mut st, 0) != pid {
        log("parent: final wait4 wrong pid\n");
        sys_exit(20);
    }
    if !wifsignaled(st) || wtermsig(st) != SIGSEGV {
        log("parent: child not killed by SIGSEGV: ");
        log_hex(st as u64);
        sys_exit(21);
    }

    log("PTRACE_SEGV_OK\n");
    sys_exit(0);
}

fn in_range(addr: u64, fn_start: u64) -> bool {
    addr >= fn_start && addr < fn_start + 48
}

fn peek(child: u64, addr: u64) -> u64 {
    let mut out: u64 = 0;
    let _ = sys_ptrace_call(PTRACE_PEEKDATA, child, addr, &mut out as *mut u64 as u64);
    out
}

fn wifstopped(status: i32) -> bool {
    (status & 0xff) == 0x7f
}

fn wstopsig(status: i32) -> i32 {
    (status >> 8) & 0xff
}

fn wifsignaled(status: i32) -> bool {
    let low = status & 0x7f;
    low != 0 && low != 0x7f
}

fn wtermsig(status: i32) -> i32 {
    status & 0x7f
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
        asm!("syscall", in("rax") SYS_EXIT, in("rdi") code as u64, options(noreturn, nostack));
    }
}
