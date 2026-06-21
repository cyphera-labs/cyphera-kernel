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
const SYS_SCHED_YIELD: u64 = 24;

const PTRACE_TRACEME: u64 = 0;
const PTRACE_CONT: u64 = 7;
const PTRACE_DETACH: u64 = 17;
const PTRACE_SETOPTIONS: u64 = 0x4200;
const PTRACE_GETEVENTMSG: u64 = 0x4201;

const PTRACE_O_TRACESYSGOOD: u64 = 0x0000_0001;
const PTRACE_O_TRACEFORK: u64 = 0x0000_0002;

const PTRACE_EVENT_FORK: i32 = 1;
const SIGSTOP: u64 = 19;

const GC_SPIN: u64 = 40_000_000;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("ptrace_traceexit test starting\n");

    let pid = sys_fork();
    if pid < 0 {
        log("P: fork(C) failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        if sys_ptrace(PTRACE_TRACEME, 0, 0, 0) < 0 {
            sys_exit(11);
        }
        let self_pid = sys_getpid() as u64;
        sys_kill(self_pid, SIGSTOP);
        let gc_pid = sys_fork();
        if gc_pid < 0 {
            sys_exit(12);
        }
        if gc_pid == 0 {
            let _ = sys_getpid();
            spin(GC_SPIN);
            sys_exit(0);
        }
        sys_exit(0);
    }

    let c_pid = pid;
    let mut status: i32 = 0;

    if sys_wait4(c_pid, &mut status, 0, 0) < 0 || !wifstopped(status) {
        log("P: C didn't stop on first wait\n");
        sys_exit(2);
    }
    log("P: C stopped (initial SIGSTOP) OK\n");

    let opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK;
    if sys_ptrace(PTRACE_SETOPTIONS, c_pid as u64, 0, opts) < 0 {
        log("P: SETOPTIONS failed\n");
        sys_exit(3);
    }
    if sys_ptrace(PTRACE_CONT, c_pid as u64, 0, 0) < 0 {
        log("P: CONT(C) failed\n");
        sys_exit(4);
    }

    if sys_wait4(c_pid, &mut status, 0, 0) != c_pid || !wifstopped(status) {
        log("P: C didn't stop at fork event\n");
        sys_exit(5);
    }
    if ((status >> 16) & 0xff) != PTRACE_EVENT_FORK {
        log("P: C's stop wasn't PTRACE_EVENT_FORK\n");
        sys_exit(6);
    }
    let mut msg: u64 = 0;
    if sys_ptrace(
        PTRACE_GETEVENTMSG,
        c_pid as u64,
        0,
        (&mut msg) as *mut u64 as u64,
    ) < 0
        || msg == 0
    {
        log("P: GETEVENTMSG(C) didn't return GC pid\n");
        sys_exit(7);
    }
    let gc_pid = msg as i64;
    log("P: GETEVENTMSG(C) = GC pid OK\n");

    let mut gst: i32 = 0;
    if sys_wait4(gc_pid, &mut gst, 0, 0) != gc_pid || !wifstopped(gst) {
        log("P: GC didn't reach its auto-attach syscall-stop\n");
        sys_exit(8);
    }
    log("P: GC auto-attached + stopped OK\n");

    if sys_ptrace(PTRACE_CONT, gc_pid as u64, 0, 0) < 0 {
        log("P: CONT(GC) failed\n");
        sys_exit(9);
    }

    let mut xst: i32 = 0;
    let r = sys_wait4(gc_pid, &mut xst, 0, 0);
    if r != gc_pid {
        log("P: blocking wait4(GC-exit) returned wrong pid\n");
        sys_exit(10);
    }
    if !wifexited(xst) {
        log("P: GC's reported status wasn't an exit\n");
        sys_exit(13);
    }
    log("P: blocking wait4 saw GC exit (tracer woken) OK\n");

    let _ = sys_ptrace(PTRACE_DETACH, c_pid as u64, 0, 0);
    for _ in 0..400 {
        let mut st: i32 = 0;
        if sys_wait4(-1, &mut st, 1, 0) <= 0 {
            sys_sched_yield();
        }
    }

    log("PTRACE_TRACEEXIT_OK\n");
    sys_exit(0);
}

fn wifstopped(status: i32) -> bool {
    (status & 0xff) == 0x7f
}

fn wifexited(status: i32) -> bool {
    (status & 0x7f) == 0
}

#[inline(never)]
fn spin(iters: u64) {
    let mut i = 0u64;
    while i < iters {
        unsafe {
            asm!("pause", options(nomem, nostack, preserves_flags));
        }
        i = i.wrapping_add(1);
    }
}

fn log(msg: &str) {
    sys_write(1, msg.as_ptr(), msg.len());
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
        asm!("syscall", in("rax") SYS_SCHED_YIELD, lateout("rax") _,
            out("rcx") _, out("r11") _, options(nostack));
    }
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") SYS_EXIT, in("rdi") code as u64, options(noreturn, nostack));
    }
}
