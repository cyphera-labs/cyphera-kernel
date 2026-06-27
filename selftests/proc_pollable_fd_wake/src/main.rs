#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const EPOLL_CTL_ADD: u64 = 1;
const EPOLLIN: u32 = 0x001;
const POLLIN: u16 = 0x0001;
const SIG_BLOCK: u64 = 0;
const SIGUSR1: u64 = 10;
const SIGUSR2: u64 = 12;
const SA_RESTORER: u64 = 0x0400_0000;
const WAIT_MS: i32 = 5000;
const TFD_NSEC: u64 = 80_000_000;
const CHILD_DELAY_NSEC: u64 = 60_000_000;

#[repr(C)]
#[derive(Copy, Clone)]
struct KSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

static mut HANDLER_RAN: i32 = 0;

extern "C" fn usr2_handler(_signum: i32) {
    unsafe {
        let r = core::ptr::read_volatile(&raw const HANDLER_RAN);
        core::ptr::write_volatile(&raw mut HANDLER_RAN, r + 1);
    }
}

#[unsafe(naked)]
unsafe extern "C" fn signal_restorer() {
    core::arch::naked_asm!("mov rax, 15", "syscall");
}

fn report(msg: &[u8]) {
    sys_write(1, msg.as_ptr(), msg.len());
}

fn fail(msg: &[u8]) -> ! {
    report(b"POLLWAKE_FAIL: ");
    report(msg);
    sys_exit(1);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    report(b"pollable_fd_wake: start\n");
    eventfd_case();
    timerfd_case();
    signalfd_case();
    signalfd_theft_case();
    report(b"POLLWAKE_OK\n");
    sys_exit(0);
}

fn eventfd_case() {
    let efd = sys_eventfd2(0, 0);
    if efd < 0 {
        fail(b"eventfd2\n");
    }
    let efd = efd as i32;

    let mut ev = [0u8; 12];
    ev[0..4].copy_from_slice(&EPOLLIN.to_le_bytes());
    ev[4..12].copy_from_slice(&0xe0u64.to_le_bytes());
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        fail(b"epoll_create1\n");
    }
    if sys_epoll_ctl(epfd as u64, EPOLL_CTL_ADD, efd as u64, ev.as_ptr()) != 0 {
        fail(b"epoll_ctl eventfd\n");
    }

    let pid = sys_fork();
    if pid < 0 {
        fail(b"fork eventfd\n");
    }
    if pid == 0 {
        sleep_nsec(CHILD_DELAY_NSEC);
        let one = 1u64.to_le_bytes();
        let _ = sys_write(efd as u64, one.as_ptr(), 8);
        sys_exit(0);
    }

    let mut out = [0u8; 12];
    let r = sys_epoll_wait(epfd as u64, out.as_mut_ptr(), 1, WAIT_MS);
    if r != 1 {
        fail(b"epoll_wait eventfd (not woken by write)\n");
    }
    let got = u32::from_le_bytes(out[0..4].try_into().unwrap());
    if got & EPOLLIN == 0 {
        fail(b"epoll_wait eventfd missing EPOLLIN\n");
    }
    report(b"  eventfd epoll woken by write OK\n");

    let mut rb = [0u8; 8];
    let rd = sys_read(efd as u64, rb.as_mut_ptr(), 8);
    if rd != 8 || u64::from_le_bytes(rb) != 1 {
        fail(b"eventfd blocking read\n");
    }
    report(b"  eventfd blocking read OK\n");

    reap(pid);
    let _ = sys_close(epfd as u64);
    let _ = sys_close(efd as u64);
}

fn timerfd_case() {
    let tfd = sys_timerfd_create(1, 0);
    if tfd < 0 {
        fail(b"timerfd_create\n");
    }
    let tfd = tfd as i32;

    let spec = [0u64, 0u64, 0u64, TFD_NSEC];
    if sys_timerfd_settime(tfd as u64, 0, spec.as_ptr(), core::ptr::null_mut()) != 0 {
        fail(b"timerfd_settime\n");
    }

    let mut ev = [0u8; 12];
    ev[0..4].copy_from_slice(&EPOLLIN.to_le_bytes());
    ev[4..12].copy_from_slice(&0x71u64.to_le_bytes());
    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        fail(b"epoll_create1 timerfd\n");
    }
    if sys_epoll_ctl(epfd as u64, EPOLL_CTL_ADD, tfd as u64, ev.as_ptr()) != 0 {
        fail(b"epoll_ctl timerfd\n");
    }

    let mut out = [0u8; 12];
    let r = sys_epoll_wait(epfd as u64, out.as_mut_ptr(), 1, WAIT_MS);
    if r != 1 {
        fail(b"epoll_wait timerfd (not woken by expiry)\n");
    }
    let got = u32::from_le_bytes(out[0..4].try_into().unwrap());
    if got & EPOLLIN == 0 {
        fail(b"epoll_wait timerfd missing EPOLLIN\n");
    }
    report(b"  timerfd epoll woken by expiry OK\n");

    let mut rb = [0u8; 8];
    let rd = sys_read(tfd as u64, rb.as_mut_ptr(), 8);
    if rd != 8 || u64::from_le_bytes(rb) == 0 {
        fail(b"timerfd blocking read\n");
    }
    report(b"  timerfd blocking read OK\n");

    let _ = sys_close(epfd as u64);
    let _ = sys_close(tfd as u64);
}

fn signalfd_case() {
    let blk: u64 = 1 << SIGUSR1;
    sys_rt_sigprocmask(SIG_BLOCK, &blk, core::ptr::null_mut(), 8);

    let sfd = sys_signalfd4(-1i64 as u64, &blk, 8, 0);
    if sfd < 0 {
        fail(b"signalfd4\n");
    }
    let sfd = sfd as i32;

    let parent = sys_getpid();
    let pid = sys_fork();
    if pid < 0 {
        fail(b"fork signalfd\n");
    }
    if pid == 0 {
        sleep_nsec(CHILD_DELAY_NSEC);
        let _ = sys_kill(parent, SIGUSR1 as i64);
        sys_exit(0);
    }

    let mut pfd = [0u8; 8];
    pfd[0..4].copy_from_slice(&sfd.to_le_bytes());
    pfd[4..6].copy_from_slice(&POLLIN.to_le_bytes());
    let r = sys_poll(pfd.as_mut_ptr(), 1, WAIT_MS as i64);
    if r != 1 {
        fail(b"poll signalfd (not woken by signal)\n");
    }
    let revents = u16::from_le_bytes(pfd[6..8].try_into().unwrap());
    if revents & POLLIN == 0 {
        fail(b"poll signalfd missing POLLIN\n");
    }
    report(b"  signalfd poll woken by signal OK\n");

    let mut rb = [0u8; 128];
    let rd = sys_read(sfd as u64, rb.as_mut_ptr(), 128);
    if rd != 128 {
        fail(b"signalfd blocking read\n");
    }
    let signo = u32::from_le_bytes(rb[0..4].try_into().unwrap());
    if signo as u64 != SIGUSR1 {
        fail(b"signalfd wrong signo\n");
    }
    report(b"  signalfd blocking read OK\n");

    reap(pid);
    let _ = sys_close(sfd as u64);
}

fn signalfd_theft_case() {
    let act = KSigAction {
        handler: usr2_handler as *const () as u64,
        flags: SA_RESTORER,
        restorer: signal_restorer as *const () as u64,
        mask: 0,
    };
    if sys_rt_sigaction(SIGUSR2 as i32, &act, core::ptr::null_mut(), 8) != 0 {
        fail(b"sigaction SIGUSR2\n");
    }

    let blk: u64 = 1 << SIGUSR1;
    sys_rt_sigprocmask(SIG_BLOCK, &blk, core::ptr::null_mut(), 8);

    let watch: u64 = (1 << SIGUSR1) | (1 << SIGUSR2);
    let sfd = sys_signalfd4(-1i64 as u64, &watch, 8, 0);
    if sfd < 0 {
        fail(b"signalfd4 theft\n");
    }
    let sfd = sfd as i32;

    let parent = sys_getpid();
    let pid = sys_fork();
    if pid < 0 {
        fail(b"fork theft\n");
    }
    if pid == 0 {
        sleep_nsec(CHILD_DELAY_NSEC);
        let _ = sys_kill(parent, SIGUSR2 as i64);
        sleep_nsec(CHILD_DELAY_NSEC);
        let _ = sys_kill(parent, SIGUSR1 as i64);
        sys_exit(0);
    }

    let mut rb = [0u8; 128];
    let signo = loop {
        let rd = sys_read(sfd as u64, rb.as_mut_ptr(), 128);
        if rd == -4 {
            continue;
        }
        if rd != 128 {
            fail(b"signalfd theft read\n");
        }
        break u32::from_le_bytes(rb[0..4].try_into().unwrap());
    };
    if signo as u64 != SIGUSR1 {
        fail(b"signalfd stole unblocked signal\n");
    }
    let ran = unsafe { core::ptr::read_volatile(&raw const HANDLER_RAN) };
    if ran != 1 {
        fail(b"unblocked signal handler did not run\n");
    }
    report(b"  signalfd does not steal unblocked signal OK\n");

    reap(pid);
    let _ = sys_close(sfd as u64);
}

fn reap(pid: i64) {
    let mut status = 0i32;
    let _ = sys_wait4(pid, &mut status, 0, 0);
}

fn sleep_nsec(nsec: u64) {
    let ts = [0u64, nsec];
    let _ = sys_nanosleep(ts.as_ptr(), core::ptr::null_mut());
}

fn sys_eventfd2(initval: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 290u64, in("rdi") initval, in("rsi") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_timerfd_create(clockid: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 283u64, in("rdi") clockid, in("rsi") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_timerfd_settime(fd: u64, flags: u64, new: *const u64, old: *mut u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 286u64, in("rdi") fd, in("rsi") flags, in("rdx") new, in("r10") old,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_signalfd4(fd: u64, mask: *const u64, sz: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 289u64, in("rdi") fd, in("rsi") mask, in("rdx") sz, in("r10") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_epoll_create1(flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 291u64, in("rdi") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_epoll_ctl(epfd: u64, op: u64, fd: u64, ev: *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 233u64, in("rdi") epfd, in("rsi") op, in("rdx") fd, in("r10") ev,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_epoll_wait(epfd: u64, events: *mut u8, max: u64, timeout: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 232u64, in("rdi") epfd, in("rsi") events, in("rdx") max,
            in("r10") timeout as i64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_poll(fds: *mut u8, nfds: u64, timeout_ms: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 7u64, in("rdi") fds, in("rsi") nfds, in("rdx") timeout_ms,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_rt_sigprocmask(how: u64, set: *const u64, oldset: *mut u64, sz: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 14u64, in("rdi") how, in("rsi") set, in("rdx") oldset, in("r10") sz,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_rt_sigaction(signum: i32, act: *const KSigAction, old: *mut KSigAction, sz: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 13u64, in("rdi") signum as i64, in("rsi") act, in("rdx") old, in("r10") sz,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_kill(pid: i64, sig: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 62u64, in("rdi") pid, in("rsi") sig,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_wait4(pid: i64, status: *mut i32, options: u64, rusage: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid, in("rsi") status, in("rdx") options, in("r10") rusage,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_nanosleep(req: *const u64, rem: *mut u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 35u64, in("rdi") req, in("rsi") rem,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as i64, options(noreturn, nostack));
    }
}
