#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

fn report(msg: &[u8]) {
    sys_write(1, msg.as_ptr(), msg.len());
}

fn fail(msg: &[u8]) -> ! {
    report(b"SELECT_FAIL: ");
    report(msg);
    sys_exit(1);
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_pipe2(fds: *mut i32, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 293u64, in("rdi") fds, in("rsi") flags,
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

fn sys_ppoll(fds: *mut u8, nfds: u64, ts: *const u64, sig: *const u64, sigsz: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 271u64, in("rdi") fds, in("rsi") nfds, in("rdx") ts,
            in("r10") sig, in("r8") sigsz,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_select(nfds: u64, rfds: *mut u8, wfds: *mut u8, efds: *mut u8, tv: *const u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 23u64, in("rdi") nfds, in("rsi") rfds, in("rdx") wfds,
            in("r10") efds, in("r8") tv,
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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as i64, options(noreturn, nostack));
    }
}

const POLLIN: u16 = 0x0001;
const EINTR: i64 = -4;
const EINVAL: i64 = -22;
const SIG_BLOCK: u64 = 0;
const SIGUSR1: u64 = 10;

fn set_pollfd(buf: &mut [u8], idx: usize, fd: i32, events: u16) {
    let o = idx * 8;
    buf[o..o + 4].copy_from_slice(&fd.to_le_bytes());
    buf[o + 4..o + 6].copy_from_slice(&events.to_le_bytes());
    buf[o + 6..o + 8].copy_from_slice(&0u16.to_le_bytes());
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    report(b"select: start\n");

    let mut a = [0i32; 2];
    let mut b = [0i32; 2];
    if sys_pipe2(a.as_mut_ptr(), 0) != 0 || sys_pipe2(b.as_mut_ptr(), 0) != 0 {
        fail(b"pipe2\n");
    }
    let byte = [0x41u8];
    sys_write(a[1] as u64, byte.as_ptr(), 1);

    let mut pa = [0u8; 8];
    set_pollfd(&mut pa, 0, a[0], POLLIN);
    if sys_poll(pa.as_mut_ptr(), 1, 200) != 1 {
        fail(b"poll-readiness\n");
    }
    report(b"  poll readiness OK\n");

    let mut pb = [0u8; 8];
    set_pollfd(&mut pb, 0, b[0], POLLIN);
    if sys_poll(pb.as_mut_ptr(), 1, 50) != 0 {
        fail(b"poll-timeout\n");
    }
    report(b"  poll timeout OK\n");

    let blk: u64 = 1 << SIGUSR1;
    sys_rt_sigprocmask(SIG_BLOCK, &blk, core::ptr::null_mut(), 8);
    sys_kill(sys_getpid(), SIGUSR1 as i64);
    let ts_1s = [1u64, 0u64];
    let empty_mask: u64 = 0;
    set_pollfd(&mut pb, 0, b[0], POLLIN);
    if sys_ppoll(pb.as_mut_ptr(), 1, ts_1s.as_ptr(), &empty_mask, 8) != EINTR {
        fail(b"ppoll-sigmask-unblock\n");
    }
    report(b"  ppoll sigmask atomic-unblock OK (EINTR)\n");

    let ts_50ms = [0u64, 50_000_000u64];
    set_pollfd(&mut pb, 0, b[0], POLLIN);
    if sys_ppoll(pb.as_mut_ptr(), 1, ts_50ms.as_ptr(), core::ptr::null(), 0) != 0 {
        fail(b"ppoll-null-mask\n");
    }
    report(b"  ppoll NULL-mask leaves signal blocked OK\n");

    let mut big = [0u8; 100 * 8];
    for i in 0..100 {
        set_pollfd(&mut big, i, a[0], POLLIN);
    }
    if sys_poll(big.as_mut_ptr(), 100, 200) < 1 {
        fail(b"poll-100fds\n");
    }
    report(b"  poll 100 fds OK (>64 cap lifted)\n");

    let bad_tv = [0u64, 2_000_000u64];
    if sys_select(
        0,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        bad_tv.as_ptr(),
    ) != EINVAL
    {
        fail(b"select-einval\n");
    }
    report(b"  select EINVAL on out-of-range timeval OK\n");

    report(b"SELECT_OK\n");
    sys_exit(0);
}
