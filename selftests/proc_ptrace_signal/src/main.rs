#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
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
const PTRACE_SYSCALL: u64 = 24;

const SIGUSR1: u64 = 10;
const SIGUSR2: u64 = 12;
const SIGSTOP: u64 = 19;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("ptrace_signal test starting\n");

    let r = run(SIGUSR1, 0, 0);
    if r != 0 {
        log("scenario suppress failed; r=");
        log_num(r);
        sys_exit(1);
    }
    log("ptrace_signal: suppress (CONT data=0) -> child exit 0 OK\n");

    let r = run(SIGUSR1, SIGUSR1, SIGUSR1 as i64);
    if r != 0 {
        log("scenario re-inject failed; r=");
        log_num(r);
        sys_exit(2);
    }
    log("ptrace_signal: re-inject USR1 -> killed-by-USR1 OK\n");

    let r = run(SIGUSR2, SIGUSR1, SIGUSR1 as i64);
    if r != 0 {
        log("scenario substitute failed; r=");
        log_num(r);
        sys_exit(3);
    }
    log("ptrace_signal: substitute USR2->USR1 -> killed-by-USR1 OK\n");

    let r = run_syscall_stop_inject();
    if r != 0 {
        log("scenario syscall-stop inject failed; r=");
        log_num(r);
        sys_exit(4);
    }
    log("ptrace_signal: inject-on-syscall-stop -> forwarded + killed-by-USR1 OK\n");

    log("PTRACE_SIGNAL_OK\n");
    sys_exit(0);
}

fn run_syscall_stop_inject() -> i64 {
    let pid = sys_fork();
    if pid < 0 {
        return 500;
    }
    if pid == 0 {
        if sys_ptrace(PTRACE_TRACEME, 0, 0, 0) < 0 {
            sys_exit(11);
        }
        let me = sys_getpid() as u64;
        sys_kill(me, SIGSTOP);
        let _ = sys_getpid();
        sys_exit(42);
    }
    let mut st: i32 = 0;
    if sys_wait4(pid, &mut st, 0, 0) != pid {
        return 501;
    }
    if (st & 0xff) != 0x7f {
        return 502;
    }
    if sys_ptrace(PTRACE_SYSCALL, pid as u64, 0, 0) < 0 {
        return 503;
    }
    let mut st2: i32 = 0;
    if sys_wait4(pid, &mut st2, 0, 0) != pid {
        return 504;
    }
    if (st2 & 0xff) != 0x7f {
        return 505;
    }
    if sys_ptrace(PTRACE_CONT, pid as u64, 0, SIGUSR1) < 0 {
        return 506;
    }
    let mut st3: i32 = 0;
    if sys_wait4(pid, &mut st3, 0, 0) != pid {
        return 507;
    }
    if (st3 & 0xff) != 0x7f {
        return 508;
    }
    let stopsig = ((st3 >> 8) & 0xff) as u64;
    if stopsig != SIGUSR1 {
        return 600 + stopsig as i64;
    }
    if sys_ptrace(PTRACE_CONT, pid as u64, 0, SIGUSR1) < 0 {
        return 509;
    }
    let mut st4: i32 = 0;
    if sys_wait4(pid, &mut st4, 0, 0) != pid {
        return 510;
    }
    let termsig = (st4 & 0x7f) as i64;
    if termsig != SIGUSR1 as i64 {
        return 700 + termsig;
    }
    0
}

fn run(raised_sig: u64, cont_sig: u64, expect_termsig: i64) -> i64 {
    let pid = sys_fork();
    if pid < 0 {
        return 100;
    }
    if pid == 0 {
        if sys_ptrace(PTRACE_TRACEME, 0, 0, 0) < 0 {
            sys_exit(11);
        }
        let me = sys_getpid() as u64;
        sys_kill(me, SIGSTOP);
        sys_kill(me, raised_sig);
        sys_exit(0);
    }
    let mut st: i32 = 0;
    let r = sys_wait4(pid, &mut st, 0, 0);
    if r != pid {
        return 101;
    }
    if (st & 0xff) != 0x7f {
        return 102;
    }
    if sys_ptrace(PTRACE_CONT, pid as u64, 0, 0) < 0 {
        return 103;
    }
    let mut st: i32 = 0;
    let r = sys_wait4(pid, &mut st, 0, 0);
    if r != pid {
        return 104;
    }
    if (st & 0xff) != 0x7f {
        return 105;
    }
    let stopsig = ((st >> 8) & 0xff) as u64;
    if stopsig != raised_sig {
        return 200 + stopsig as i64;
    }
    if sys_ptrace(PTRACE_CONT, pid as u64, 0, cont_sig) < 0 {
        return 106;
    }
    let mut st2: i32 = 0;
    let r = sys_wait4(pid, &mut st2, 0, 0);
    if r != pid {
        return 107;
    }
    let termsig = (st2 & 0x7f) as i64;
    if termsig != expect_termsig {
        return 300 + termsig;
    }
    if expect_termsig == 0 {
        let exit_code = (st2 >> 8) & 0xff;
        if exit_code != 0 {
            return 400 + exit_code as i64;
        }
    }
    0
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
        asm!("syscall", in("rax") SYS_WRITE, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
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

fn sys_wait4(pid: i64, status: *mut i32, options: u64, rusage: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_WAIT4, in("rdi") pid as u64,
            in("rsi") status, in("rdx") options, in("r10") rusage,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_ptrace(req: u64, pid: u64, addr: u64, data: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_PTRACE, in("rdi") req,
            in("rsi") pid, in("rdx") addr, in("r10") data,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") SYS_EXIT, in("rdi") code as u64,
            options(noreturn, nostack));
    }
}
