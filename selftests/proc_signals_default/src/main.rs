#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(2);
}

const SIGUSR1: i32 = 10;
const SIGTERM: i32 = 15;
const SIGCHLD: i32 = 17;
const SIGCONT: i32 = 18;
const SIGSTOP: i32 = 19;
const SIGKILL: i32 = 9;

const WUNTRACED: i32 = 2;
const WCONTINUED: i32 = 8;

const EINVAL: i64 = -22;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("signals_default test starting\n");

    let child = fork_loop_child();
    sys_kill(child, SIGTERM);
    let mut st: i32 = 0;
    let reaped = sys_wait4(child, &mut st, 0);
    if reaped != child as i64 {
        log("SIGTERM: wait4 wrong pid\n");
        sys_exit(1);
    }
    let term_sig = st & 0x7f;
    if term_sig != SIGTERM {
        log("SIGTERM: child not terminated by SIGTERM\n");
        sys_exit(1);
    }
    log("SIGTERM default Term OK\n");

    let child = fork_loop_child();
    sys_kill(child, SIGUSR1);
    let mut st: i32 = 0;
    sys_wait4(child, &mut st, 0);
    if (st & 0x7f) != SIGUSR1 {
        log("SIGUSR1: child not terminated by SIGUSR1\n");
        sys_exit(1);
    }
    log("SIGUSR1 default Term OK\n");

    let child = fork_loop_child();
    sys_kill(child, SIGCHLD);
    let mut st: i32 = 0;
    let r = sys_wait4(child, &mut st, 1);
    if r != 0 {
        log("SIGCHLD: child should still be alive\n");
        sys_exit(1);
    }
    sys_kill(child, SIGTERM);
    sys_wait4(child, &mut st, 0);
    if (st & 0x7f) != SIGTERM {
        log("SIGCHLD: follow-up SIGTERM didn't terminate child\n");
        sys_exit(1);
    }
    log("SIGCHLD default Ignore OK\n");

    let child = fork_loop_child();
    sys_kill(child, SIGSTOP);
    let mut st: i32 = 0;
    let r = sys_wait4(child, &mut st, WUNTRACED);
    if r != child as i64 {
        log("SIGSTOP: wait4(WUNTRACED) didn't reap stop\n");
        sys_exit(1);
    }
    if (st & 0xff) != 0x7f {
        log("SIGSTOP: status bits don't indicate stopped\n");
        sys_exit(1);
    }
    log("SIGSTOP stopped child OK\n");

    sys_kill(child, SIGCONT);
    let _ = WCONTINUED;
    sys_kill(child, SIGTERM);
    sys_wait4(child, &mut st, 0);
    if (st & 0x7f) != SIGTERM {
        log("SIGCONT/SIGTERM: child not terminated by SIGTERM after CONT\n");
        sys_exit(1);
    }
    log("SIGCONT resumed + SIGTERM terminated OK\n");

    let mut act = [0u8; 32];
    act[0..8].copy_from_slice(&0xdead_beef_u64.to_le_bytes());
    let r = sys_rt_sigaction(SIGKILL, act.as_ptr(), core::ptr::null_mut(), 8);
    if r != EINVAL {
        log("rt_sigaction(SIGKILL): expected -EINVAL\n");
        sys_exit(1);
    }
    let r = sys_rt_sigaction(SIGSTOP, act.as_ptr(), core::ptr::null_mut(), 8);
    if r != EINVAL {
        log("rt_sigaction(SIGSTOP): expected -EINVAL\n");
        sys_exit(1);
    }
    log("rt_sigaction(SIGKILL/SIGSTOP) -EINVAL OK\n");

    let child = fork_loop_child();
    sys_kill(child, SIGSTOP);
    let mut st: i32 = 0;
    let r = sys_wait4(child, &mut st, WUNTRACED);
    if r != child as i64 || (st & 0xff) != 0x7f {
        log("SIGKILL-stopped: child didn't stop\n");
        sys_exit(1);
    }
    sys_kill(child, SIGKILL);
    let mut st: i32 = 0;
    let reaped = sys_wait4(child, &mut st, 0);
    if reaped != child as i64 {
        log("SIGKILL-stopped: wait4 reaped wrong pid\n");
        sys_exit(1);
    }
    if (st & 0x7f) != SIGKILL {
        log("SIGKILL-stopped: not WIFSIGNALED SIGKILL\n");
        sys_exit(1);
    }
    log("SIGKILL of a stopped child -> WIFSIGNALED SIGKILL OK\n");

    let mut i = 0;
    while i < 32 {
        let child = fork_loop_child();
        sys_sched_yield();
        sys_sched_yield();
        sys_sched_yield();
        sys_kill(child, SIGKILL);
        let mut st: i32 = 0;
        let reaped = sys_wait4(child, &mut st, 0);
        if reaped != child as i64 {
            log("SIGKILL-running: wait4 reaped wrong pid\n");
            sys_exit(1);
        }
        if (st & 0x7f) != SIGKILL {
            log("SIGKILL-running: child not terminated by SIGKILL\n");
            sys_exit(1);
        }
        i += 1;
    }
    log("SIGKILL of running/runnable children (cross-CPU x32) OK\n");

    log("all signals_default tests OK\n");
    sys_exit(0);
}

fn fork_loop_child() -> i32 {
    let r = sys_fork();
    if r < 0 {
        log("fork failed\n");
        sys_exit(3);
    }
    if r == 0 {
        loop {
            sys_sched_yield();
        }
    }
    r as i32
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
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_kill(pid: i32, signal: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 62u64, in("rdi") pid as i64, in("rsi") signal as i64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_wait4(pid: i32, status: *mut i32, options: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid as i64, in("rsi") status,
            in("rdx") options as i64, in("r10") 0u64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_sched_yield() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 24u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_rt_sigaction(signum: i32, new_act: *const u8, old_act: *mut u8, sigsetsize: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 13u64, in("rdi") signum as i64, in("rsi") new_act,
            in("rdx") old_act, in("r10") sigsetsize,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
