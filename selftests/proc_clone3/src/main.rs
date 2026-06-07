#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SIGCHLD: u64 = 17;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CloneArgsV1 {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}
const SIZE_V1: usize = 88;
const SIZE_V0: usize = 64;

const EINVAL: i64 = -22;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("clone3 test starting\n");

    let mut ptid: i32 = -1;
    let mut args = CloneArgsV1::default();
    args.flags = CLONE_PARENT_SETTID;
    args.parent_tid = &mut ptid as *mut i32 as u64;
    args.exit_signal = SIGCHLD;
    let r = sys_clone3(&args as *const CloneArgsV1 as u64, SIZE_V1 as u64);
    if r < 0 {
        log("clone3: ");
        log_num(r);
        sys_exit(1);
    }
    if r == 0 {
        sys_exit(42);
    }
    let child_pid = r as i32;
    if ptid != child_pid {
        log("ptid != child_pid\n");
        sys_exit(1);
    }
    let mut st: i32 = 0;
    let reaped = sys_wait4(child_pid, &mut st, 0);
    if reaped != child_pid as i64 || ((st >> 8) & 0xff) != 42 {
        log("wait4 wrong\n");
        sys_exit(1);
    }
    log("clone3 fork-shape + CLONE_PARENT_SETTID OK\n");

    let mut args = CloneArgsV1::default();
    args.exit_signal = SIGCHLD;
    let r = sys_clone3(&args as *const CloneArgsV1 as u64, SIZE_V0 as u64);
    if r < 0 {
        log("clone3 v0: ");
        log_num(r);
        sys_exit(1);
    }
    if r == 0 {
        sys_exit(7);
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    if ((st >> 8) & 0xff) != 7 {
        log("clone3 v0 child bad exit\n");
        sys_exit(1);
    }
    log("clone3 SIZE_VER0 (64-byte struct) OK\n");

    let mut args = CloneArgsV1::default();
    args.flags = CLONE_INTO_CGROUP;
    args.exit_signal = SIGCHLD;
    let r = sys_clone3(&args as *const CloneArgsV1 as u64, SIZE_V1 as u64);
    if r != EINVAL {
        log("clone3 CLONE_INTO_CGROUP not rejected: ");
        log_num(r);
        sys_exit(1);
    }
    log("clone3 CLONE_INTO_CGROUP → EINVAL OK\n");

    let mut args = CloneArgsV1::default();
    args.exit_signal = SIGCHLD;
    args.set_tid = 1;
    args.set_tid_size = 1;
    let r = sys_clone3(&args as *const CloneArgsV1 as u64, SIZE_V1 as u64);
    if r != EINVAL {
        log("clone3 set_tid not rejected: ");
        log_num(r);
        sys_exit(1);
    }
    log("clone3 set_tid → EINVAL OK\n");

    let args = CloneArgsV1::default();
    let r = sys_clone3(&args as *const CloneArgsV1 as u64, 32);
    if r != EINVAL {
        log("clone3 short size not rejected: ");
        log_num(r);
        sys_exit(1);
    }
    log("clone3 short-size → EINVAL OK\n");

    const CLONE_PIDFD: u64 = 0x1000;
    let mut pidfd: i32 = -1;
    let mut args = CloneArgsV1::default();
    args.flags = CLONE_PIDFD;
    args.pidfd = &mut pidfd as *mut i32 as u64;
    args.exit_signal = SIGCHLD;
    let r = sys_clone3(&args as *const CloneArgsV1 as u64, SIZE_V1 as u64);
    if r < 0 {
        log("clone3 CLONE_PIDFD: ");
        log_num(r);
        sys_exit(1);
    }
    if r == 0 {
        sys_exit(9);
    }
    if pidfd < 0 {
        log("clone3 CLONE_PIDFD: no fd written\n");
        sys_exit(1);
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    if ((st >> 8) & 0xff) != 9 {
        log("clone3 CLONE_PIDFD child bad exit\n");
        sys_exit(1);
    }
    sys_close(pidfd);
    log("clone3 CLONE_PIDFD installs a pidfd OK\n");

    let mut args = CloneArgsV1::default();
    args.flags = CLONE_PIDFD;
    args.pidfd = 0;
    args.exit_signal = SIGCHLD;
    let r = sys_clone3(&args as *const CloneArgsV1 as u64, SIZE_V1 as u64);
    if r != EINVAL {
        log("clone3 CLONE_PIDFD null ptr not rejected: ");
        log_num(r);
        sys_exit(1);
    }
    log("clone3 CLONE_PIDFD null-ptr → EINVAL OK\n");

    log("all clone3 tests OK\n");
    sys_exit(0);
}

#[inline(never)]
fn sys_close(fd: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
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
fn sys_clone3(args: u64, size: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 435u64, in("rdi") args, in("rsi") size,
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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
