#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const AT_FDCWD: i32 = -100;

const SIGUSR1: i32 = 10;

const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_VM: u64 = 0x0000_0100;
const CLONE_VFORK: u64 = 0x0000_4000;
const SIGCHLD: u64 = 17;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("clone test starting\n");

    let path = b"/tmp/clone-fds\0";
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR | O_CREAT, 0o600);
    if fd < 0 {
        log("open: ");
        log_num(fd);
        sys_exit(1);
    }
    let pid = sys_fork();
    if pid < 0 {
        log("fork: ");
        log_num(pid);
        sys_exit(1);
    }
    if pid == 0 {
        sys_close(fd as i32);
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let n = sys_write(fd as u64, b"x".as_ptr(), 1);
    if n != 1 {
        log("parent fd lost: ");
        log_num(n);
        sys_exit(1);
    }
    sys_close(fd as i32);
    log("fork: fds NOT shared OK\n");

    set_handler(SIGUSR1, 1);
    let pid = sys_fork();
    if pid < 0 {
        log("fork sigact: ");
        log_num(pid);
        sys_exit(1);
    }
    if pid == 0 {
        set_handler(SIGUSR1, 0);
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let h = get_handler(SIGUSR1);
    if h != 1 {
        log("parent handler clobbered: ");
        log_num(h as i64);
        sys_exit(1);
    }
    set_handler(SIGUSR1, 0);
    log("fork: sigactions NOT shared OK\n");

    let mut ptid: i32 = -1;
    let r = sys_clone_raw(
        CLONE_PARENT_SETTID | SIGCHLD,
        0,
        &mut ptid as *mut i32 as u64,
        0,
        0,
    );
    if r < 0 {
        log("clone PARENT_SETTID: ");
        log_num(r);
        sys_exit(1);
    }
    if r == 0 {
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    if ptid != r as i32 {
        log("PARENT_SETTID wrong ptid: ");
        log_num(ptid as i64);
        log("expected ");
        log_num(r as i64);
        sys_exit(1);
    }
    log("CLONE_PARENT_SETTID writes child pid to ptid OK\n");

    let pid = sys_vfork();
    if pid < 0 {
        log("vfork: ");
        log_num(pid);
        sys_exit(1);
    }
    if pid == 0 {
        sys_exit(0);
    }
    let mut st: i32 = 0;
    let r = sys_wait4(pid as i32, &mut st, 0);
    if r < 0 {
        log("wait4 after vfork: ");
        log_num(r);
        sys_exit(1);
    }
    let exit_code = (st >> 8) & 0xff;
    if exit_code != 0 {
        log("vfork child exit: ");
        log_num(exit_code as i64);
        sys_exit(1);
    }
    log("vfork barrier + child exit OK\n");

    log("all clone tests OK\n");
    sys_exit(0);
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

fn set_handler(sig: i32, handler: u64) {
    let act = SigAction {
        handler,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    let r = sys_rt_sigaction(sig, &act as *const SigAction as u64, 0);
    if r != 0 {
        log("rt_sigaction: ");
        log_num(r);
        sys_exit(1);
    }
}

fn get_handler(sig: i32) -> u64 {
    let mut old = SigAction {
        handler: 0,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    let r = sys_rt_sigaction_get(sig, &mut old as *mut SigAction as u64);
    if r != 0 {
        return u64::MAX;
    }
    old.handler
}

fn sys_rt_sigaction(sig: i32, new_act: u64, old_act: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 13u64, in("rdi") sig as i64,
        in("rsi") new_act, in("rdx") old_act, in("r10") 8u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_rt_sigaction_get(sig: i32, old_act: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 13u64, in("rdi") sig as i64,
        in("rsi") 0u64, in("rdx") old_act, in("r10") 8u64,
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
fn sys_close(fd: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 257u64, in("rdi") dirfd as i64,
        in("rsi") path, in("rdx") flags as i64, in("r10") mode as u64,
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
fn sys_vfork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 58u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_clone_raw(flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 56u64, in("rdi") flags, in("rsi") stack,
        in("rdx") ptid, in("r10") ctid, in("r8") tls,
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
