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
const PTRACE_SETOPTIONS: u64 = 0x4200;
const PTRACE_GETEVENTMSG: u64 = 0x4201;

const PTRACE_O_TRACESYSGOOD: u64 = 0x0000_0001;
const PTRACE_O_TRACEFORK: u64 = 0x0000_0002;

const PTRACE_EVENT_FORK: i32 = 1;
const SIGSTOP: u64 = 19;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("ptrace_tracefork test starting\n");

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
            sys_exit(0);
        }
        sys_exit(0);
    }

    let c_pid = pid;
    let mut status: i32 = 0;
    let r = sys_wait4(c_pid, &mut status, 0, 0);
    if r < 0 {
        log("P: wait4(C) #1 failed\n");
        sys_exit(2);
    }
    if !wifstopped(status) {
        log("P: C didn't stop on first wait\n");
        sys_exit(3);
    }
    log("P: C stopped (initial SIGSTOP) OK\n");

    let opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK;
    if sys_ptrace(PTRACE_SETOPTIONS, c_pid as u64, 0, opts) < 0 {
        log("P: SETOPTIONS failed\n");
        sys_exit(4);
    }
    if sys_ptrace(PTRACE_CONT, c_pid as u64, 0, 0) < 0 {
        log("P: CONT #1 failed\n");
        sys_exit(5);
    }

    let r = sys_wait4(c_pid, &mut status, 0, 0);
    if r != c_pid {
        log("P: wait4(C) for fork-event failed\n");
        sys_exit(6);
    }
    if !wifstopped(status) {
        log("P: C didn't stop at the fork event\n");
        sys_exit(7);
    }
    let event = (status >> 16) & 0xff;
    if event != PTRACE_EVENT_FORK {
        log("P: C's stop wasn't PTRACE_EVENT_FORK; event=");
        log_num(event as i64);
        sys_exit(8);
    }
    log("P: C stopped at PTRACE_EVENT_FORK OK\n");

    let mut msg: u64 = 0;
    let r = sys_ptrace(
        PTRACE_GETEVENTMSG,
        c_pid as u64,
        0,
        (&mut msg) as *mut u64 as u64,
    );
    if r < 0 || msg == 0 {
        log("P: GETEVENTMSG(C) didn't return GC pid\n");
        sys_exit(9);
    }
    let gc_pid = msg as i64;
    log("P: GETEVENTMSG(C) = GC pid OK\n");

    let mut gst: i32 = 0;
    let r = sys_wait4(gc_pid, &mut gst, 0, 0);
    if r != gc_pid || !wifstopped(gst) {
        log("P: GC wait4 r=");
        log_num(r);
        log("   gc_pid=");
        log_num(gc_pid);
        log("   status=");
        log_num(gst as i64);
        sys_exit(10);
    }
    log("P: GC auto-attached + stopped OK\n");
    let _ = sys_ptrace(PTRACE_DETACH, gc_pid as u64, 0, 0);

    let _ = sys_ptrace(PTRACE_DETACH, c_pid as u64, 0, 0);
    for _ in 0..400 {
        let mut st: i32 = 0;
        if sys_wait4(-1, &mut st, 1, 0) <= 0 {
            sys_sched_yield();
        }
    }

    log("PTRACE_TRACEFORK_OK\n");
    sys_exit(0);
}

fn wifstopped(status: i32) -> bool {
    (status & 0xff) == 0x7f
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
        asm!("syscall", in("rax") 24u64, lateout("rax") _,
            out("rcx") _, out("r11") _, options(nostack));
    }
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") SYS_EXIT, in("rdi") code as u64, options(noreturn, nostack));
    }
}
