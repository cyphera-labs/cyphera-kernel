#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SIGURG: i32 = 23;
const SIGKILL: i32 = 9;
const SA_RESTORER: u64 = 0x0400_0000;
const EINTR: i64 = -4;

const EPOLL_CTL_ADD: u64 = 1;
const EPOLLIN: u32 = 0x001;

const WAIT_TIMEOUT_MS: i32 = 5000;
const ROUNDS: u32 = 2000;

#[repr(C)]
#[derive(Copy, Clone)]
struct KSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

extern "C" fn urg_handler(_sig: i32) {}

#[unsafe(naked)]
unsafe extern "C" fn restorer() {
    core::arch::naked_asm!("mov rax, 15", "syscall");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("epoll_signal_eintr (cross-process) test starting\n");

    let act = KSigAction {
        handler: urg_handler as *const () as u64,
        flags: SA_RESTORER,
        restorer: restorer as *const () as u64,
        mask: 0,
    };
    if sys_rt_sigaction(SIGURG, &act, 8) != 0 {
        log("sigaction failed\n");
        sys_exit(1);
    }

    let mut fds = [0i32; 2];
    if sys_pipe2(fds.as_mut_ptr() as u64, 0) != 0 {
        log("pipe2 failed\n");
        sys_exit(1);
    }
    let rd = fds[0] as u64;
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        log("epoll_create1 failed\n");
        sys_exit(1);
    }
    let mut ev = [0u8; 12];
    ev[0..4].copy_from_slice(&EPOLLIN.to_le_bytes());
    ev[4..12].copy_from_slice(&0xfeed_face_u64.to_le_bytes());
    if sys_epoll_ctl(epfd as u64, EPOLL_CTL_ADD, rd, ev.as_ptr()) != 0 {
        log("epoll_ctl ADD failed\n");
        sys_exit(1);
    }

    let pid = sys_fork();
    if pid < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        let ppid = sys_getppid();
        loop {
            let _ = sys_kill(ppid, SIGURG);
        }
    }

    let mut events = [0u8; 12];
    for _ in 0..ROUNDS {
        let r = sys_epoll_wait(epfd as u64, events.as_mut_ptr(), 1, WAIT_TIMEOUT_MS);
        if r != EINTR {
            log("epoll_wait returned non-EINTR (lost wakeup): ");
            log_num(r);
            let _ = sys_kill(pid as i32, SIGKILL);
            sys_exit(1);
        }
    }

    let _ = sys_kill(pid as i32, SIGKILL);
    log("EPOLL_SIGNAL_EINTR_OK\n");
    sys_exit(0);
}

#[inline(never)]
fn sys_rt_sigaction(signum: i32, act: *const KSigAction, sigsetsize: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 13u64, in("rdi") signum as i64, in("rsi") act,
            in("rdx") 0u64, in("r10") sigsetsize,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_pipe2(fds: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 293u64, in("rdi") fds, in("rsi") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_epoll_create1(flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 291u64, in("rdi") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_epoll_ctl(epfd: u64, op: u64, fd: u64, ev: *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 233u64, in("rdi") epfd, in("rsi") op, in("rdx") fd, in("r10") ev,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_epoll_wait(epfd: u64, events: *mut u8, max: u64, timeout: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 232u64, in("rdi") epfd, in("rsi") events, in("rdx") max,
            in("r10") timeout as i64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
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
fn sys_getppid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 110u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

#[inline(never)]
fn sys_kill(pid: i32, sig: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 62u64, in("rdi") pid as i64, in("rsi") sig as i64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
