#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const CLOCK_MONOTONIC: u32 = 1;

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_PRIVATE_FLAG: u64 = 0x80;

const ETIMEDOUT: i64 = -110;
const EAGAIN: i64 = -11;

const EPOLL_CTL_ADD: u64 = 1;
const EPOLLIN: u32 = 0x001;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("timeouts test starting\n");

    let mut t1 = [0u8; 16];
    if sys_clock_gettime(CLOCK_MONOTONIC, t1.as_mut_ptr()) != 0 {
        log("clock_gettime #1 failed\n");
        sys_exit(1);
    }
    let req = encode_timespec(0, 50_000_000);
    if sys_nanosleep(req.as_ptr(), core::ptr::null_mut()) != 0 {
        log("nanosleep returned non-zero\n");
        sys_exit(1);
    }
    let mut t2 = [0u8; 16];
    if sys_clock_gettime(CLOCK_MONOTONIC, t2.as_mut_ptr()) != 0 {
        log("clock_gettime #2 failed\n");
        sys_exit(1);
    }
    let elapsed_ns = nanos_diff(&t1, &t2);
    if elapsed_ns < 40_000_000 {
        log("nanosleep elapsed too short (busy-wait?)\n");
        sys_exit(1);
    }
    if elapsed_ns > 500_000_000 {
        log("nanosleep elapsed too long\n");
        sys_exit(1);
    }
    log("nanosleep(50ms) wake-on-time OK\n");

    let futex_word: u32 = 0xDEADBEEF;
    let timeout = encode_timespec(0, 30_000_000);
    let r = sys_futex(
        &futex_word as *const u32 as u64,
        FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        futex_word as u64,
        timeout.as_ptr() as u64,
        0,
        0,
    );
    if r != ETIMEDOUT {
        log("futex WAIT timeout: expected -ETIMEDOUT\n");
        sys_exit(1);
    }
    log("futex WAIT timeout returned -ETIMEDOUT OK\n");

    let r = sys_futex(
        &futex_word as *const u32 as u64,
        FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        0xCAFEBABE,
        0,
        0,
        0,
    );
    if r != EAGAIN {
        log("futex WAIT mismatch: expected -EAGAIN\n");
        sys_exit(1);
    }
    log("futex WAIT value-mismatch fast path OK\n");

    let r = sys_futex(
        &futex_word as *const u32 as u64,
        FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
        1,
        0,
        0,
        0,
    );
    if r != 0 {
        log("futex WAKE empty: expected 0\n");
        sys_exit(1);
    }
    log("futex WAKE empty queue returned 0 OK\n");

    let mut fds = [0i32; 2];
    if sys_pipe2(fds.as_mut_ptr() as u64, 0) != 0 {
        log("pipe2 failed\n");
        sys_exit(1);
    }
    let rd = fds[0] as u64;
    let wr = fds[1] as u64;
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
    let mut t3 = [0u8; 16];
    sys_clock_gettime(CLOCK_MONOTONIC, t3.as_mut_ptr());
    let mut events = [0u8; 12];
    let n = sys_epoll_wait(epfd as u64, events.as_mut_ptr(), 1, 50);
    let mut t4 = [0u8; 16];
    sys_clock_gettime(CLOCK_MONOTONIC, t4.as_mut_ptr());
    if n != 0 {
        log("epoll_wait(50ms) on quiet fd should return 0\n");
        sys_exit(1);
    }
    let waited = nanos_diff(&t3, &t4);
    if waited < 40_000_000 {
        log("epoll_wait(50ms) returned too early (ignored timeout?)\n");
        sys_exit(1);
    }
    if waited > 500_000_000 {
        log("epoll_wait(50ms) waited too long\n");
        sys_exit(1);
    }
    log("epoll_wait(50ms) quiet-fd timeout OK\n");

    if sys_write(wr, b"x".as_ptr(), 1) != 1 {
        log("pipe write failed\n");
        sys_exit(1);
    }
    let mut t5 = [0u8; 16];
    sys_clock_gettime(CLOCK_MONOTONIC, t5.as_mut_ptr());
    let n = sys_epoll_wait(epfd as u64, events.as_mut_ptr(), 1, 1000);
    let mut t6 = [0u8; 16];
    sys_clock_gettime(CLOCK_MONOTONIC, t6.as_mut_ptr());
    if n != 1 {
        log("epoll_wait should see the readable pipe before the deadline\n");
        sys_exit(1);
    }
    let got_data = u64::from_le_bytes([
        events[4], events[5], events[6], events[7], events[8], events[9], events[10], events[11],
    ]);
    if got_data != 0xfeed_face {
        log("epoll_wait wrong user_data\n");
        sys_exit(1);
    }
    if nanos_diff(&t5, &t6) > 500_000_000 {
        log("epoll_wait(ready) took too long\n");
        sys_exit(1);
    }
    sys_close(epfd as u64);
    sys_close(rd);
    sys_close(wr);
    log("epoll_wait ready-before-deadline OK\n");

    const CLOCK_REALTIME: u32 = 0;
    const TFD_TIMER_ABSTIME: u64 = 1;
    let wall = encode_timespec(1_700_000_000, 0);
    if sys_clock_settime(CLOCK_REALTIME, wall.as_ptr()) != 0 {
        log("clock_settime(REALTIME) failed\n");
        sys_exit(1);
    }
    let tfd = sys_timerfd_create(CLOCK_REALTIME, 0);
    if tfd < 0 {
        log("timerfd_create failed\n");
        sys_exit(1);
    }
    let mut rt = [0u8; 16];
    if sys_clock_gettime(CLOCK_REALTIME, rt.as_mut_ptr()) != 0 {
        log("clock_gettime(REALTIME) failed\n");
        sys_exit(1);
    }
    let now_ns = decode_total_ns(&rt);
    let its = encode_itimerspec(now_ns + 80_000_000);
    if sys_timerfd_settime(tfd as u64, TFD_TIMER_ABSTIME, its.as_ptr(), core::ptr::null_mut()) != 0 {
        log("timerfd_settime(ABSTIME) failed\n");
        sys_exit(1);
    }
    let mut exp = [0u8; 8];
    if sys_read(tfd as u64, exp.as_mut_ptr(), 8) != 8 {
        log("timerfd read did not return 8 (never fired?)\n");
        sys_exit(1);
    }
    if u64::from_le_bytes(exp) < 1 {
        log("timerfd expiration count < 1\n");
        sys_exit(1);
    }
    log("timerfd CLOCK_REALTIME ABSTIME fired OK\n");

    let its_past = encode_itimerspec(now_ns.saturating_sub(1_000_000_000));
    if sys_timerfd_settime(tfd as u64, TFD_TIMER_ABSTIME, its_past.as_ptr(), core::ptr::null_mut())
        != 0
    {
        log("timerfd_settime(past) failed\n");
        sys_exit(1);
    }
    if sys_read(tfd as u64, exp.as_mut_ptr(), 8) != 8 {
        log("timerfd past-deadline did not fire\n");
        sys_exit(1);
    }
    sys_close(tfd as u64);
    log("timerfd CLOCK_REALTIME past-ABSTIME fires promptly OK\n");

    log("all timeout tests OK\n");
    sys_exit(0);
}

fn decode_total_ns(ts: &[u8; 16]) -> u64 {
    let sec = i64::from_le_bytes(ts[0..8].try_into().unwrap()) as u64;
    let nsec = i64::from_le_bytes(ts[8..16].try_into().unwrap()) as u64;
    sec.saturating_mul(1_000_000_000).saturating_add(nsec)
}

fn encode_itimerspec(total_ns: u64) -> [u8; 32] {
    let mut b = [0u8; 32];
    let sec = (total_ns / 1_000_000_000) as i64;
    let nsec = (total_ns % 1_000_000_000) as i64;
    b[16..24].copy_from_slice(&sec.to_le_bytes());
    b[24..32].copy_from_slice(&nsec.to_le_bytes());
    b
}

#[inline(never)]
fn sys_clock_settime(clk: u32, ts: *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 227u64, in("rdi") clk as u64, in("rsi") ts,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_timerfd_create(clk: u32, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 283u64, in("rdi") clk as u64, in("rsi") flags,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_timerfd_settime(fd: u64, flags: u64, new_value: *const u8, old_value: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 286u64, in("rdi") fd, in("rsi") flags, in("rdx") new_value, in("r10") old_value,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn encode_timespec(secs: u64, nanos: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&secs.to_le_bytes());
    out[8..16].copy_from_slice(&nanos.to_le_bytes());
    out
}

fn nanos_diff(a: &[u8; 16], b: &[u8; 16]) -> u64 {
    let a_s = u64::from_le_bytes(a[0..8].try_into().unwrap());
    let a_n = u64::from_le_bytes(a[8..16].try_into().unwrap());
    let b_s = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let b_n = u64::from_le_bytes(b[8..16].try_into().unwrap());
    let total_a = a_s.saturating_mul(1_000_000_000).saturating_add(a_n);
    let total_b = b_s.saturating_mul(1_000_000_000).saturating_add(b_n);
    total_b.saturating_sub(total_a)
}

#[inline(never)]
fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_clock_gettime(clk: u32, ts: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 228u64, in("rdi") clk as u64, in("rsi") ts,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_nanosleep(req: *const u8, rem: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 35u64, in("rdi") req, in("rsi") rem,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_futex(uaddr: u64, op: u64, val: u64, timeout: u64, uaddr2: u64, val3: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 202u64, in("rdi") uaddr, in("rsi") op,
            in("rdx") val, in("r10") timeout,
            in("r8") uaddr2, in("r9") val3,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_pipe2(fds: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 293u64, in("rdi") fds, in("rsi") flags,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 3u64, in("rdi") fd,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_epoll_create1(flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 291u64, in("rdi") flags,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_epoll_ctl(epfd: u64, op: u64, fd: u64, ev: *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 233u64, in("rdi") epfd, in("rsi") op, in("rdx") fd, in("r10") ev,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_epoll_wait(epfd: u64, events: *mut u8, max: u64, timeout: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 232u64, in("rdi") epfd, in("rsi") events, in("rdx") max,
            in("r10") timeout as i64,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
