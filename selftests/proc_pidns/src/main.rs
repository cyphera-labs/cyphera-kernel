#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const CLONE_NEWPID: u64 = 0x2000_0000;
const O_RDONLY: u64 = 0o0;
const AT_FDCWD: i64 = -100;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("pidns test starting\n");

    let parent_pid_before = sys_getpid();
    let r = sys_fork();
    if r < 0 {
        log("fork: failed\n");
        sys_exit(1);
    }
    if r == 0 {
        let my_pid = sys_getpid();
        if my_pid == parent_pid_before {
            sys_exit(10);
        }
        let pp = sys_getppid();
        if pp != parent_pid_before {
            sys_exit(11);
        }
        sys_exit(0);
    }
    let child_pid = r as i32;
    let mut st: i32 = 0;
    let reaped = sys_wait4(child_pid, &mut st, 0);
    if reaped != child_pid as i64 {
        log("plain fork: wait4 wrong pid\n");
        sys_exit(1);
    }
    if (st & 0x7f) != 0 || ((st >> 8) & 0xff) != 0 {
        log("plain fork: child bad exit\n");
        sys_exit(1);
    }
    log("plain fork: parent/child pids consistent OK\n");

    let pid_before = sys_getpid();
    if sys_unshare(CLONE_NEWPID) != 0 {
        log("unshare(NEWPID) failed\n");
        sys_exit(1);
    }
    let pid_after = sys_getpid();
    if pid_before != pid_after {
        log("unshare(NEWPID) changed caller's pid\n");
        sys_exit(1);
    }
    log("unshare(NEWPID) leaves caller in old ns OK\n");

    let r = sys_fork();
    if r < 0 {
        log("fork after unshare: failed\n");
        sys_exit(1);
    }
    if r == 0 {
        let my_pid = sys_getpid();
        if my_pid != 1 {
            sys_exit(20);
        }
        let my_tid = sys_gettid();
        if my_tid != 1 {
            sys_exit(21);
        }
        let pp = sys_getppid();
        if pp != 0 {
            sys_exit(22);
        }
        let mut buf = [0u8; 256];
        let n = read_path(b"/proc/self/stat\0", &mut buf);
        if n <= 0 {
            sys_exit(23);
        }
        if parse_leading_u32(&buf[..n as usize]) != Some(1) {
            sys_exit(24);
        }
        let fd = sys_openat(AT_FDCWD, b"/proc/2/stat\0".as_ptr(), O_RDONLY, 0);
        if fd >= 0 {
            sys_close(fd as u64);
            sys_exit(25);
        }
        sys_exit(0);
    }
    let child_in_parent_ns = r as i32;
    if child_in_parent_ns == 1 {
        log("parent saw child as pid 1 (wrong; child is in NESTED ns)\n");
        sys_exit(1);
    }
    let mut st: i32 = 0;
    let reaped = sys_wait4(child_in_parent_ns, &mut st, 0);
    if reaped != child_in_parent_ns as i64 {
        log("ns child: wait4 wrong pid\n");
        sys_exit(1);
    }
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("ns child bad exit: ");
        log_num(exit_code as i64);
        sys_exit(1);
    }
    log("CLONE_NEWPID: child sees getpid()==1, getppid()==0; parent reaps via host-pid view OK\n");

    log("all pidns tests OK\n");
    sys_exit(0);
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

fn read_path(path: &[u8], buf: &mut [u8]) -> i64 {
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let mut total = 0usize;
    loop {
        let n = sys_read(
            fd as u64,
            unsafe { buf.as_mut_ptr().add(total) },
            buf.len() - total,
        );
        if n <= 0 {
            break;
        }
        total += n as usize;
        if total >= buf.len() {
            break;
        }
    }
    sys_close(fd as u64);
    total as i64
}

fn parse_leading_u32(s: &[u8]) -> Option<u32> {
    let mut v: u32 = 0;
    let mut any = false;
    for &c in s {
        if c.is_ascii_digit() {
            v = v.wrapping_mul(10).wrapping_add((c - b'0') as u32);
            any = true;
        } else {
            break;
        }
    }
    if any { Some(v) } else { None }
}

#[inline(never)]
fn sys_openat(dirfd: i64, path: *const u8, flags: u64, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 257u64, in("rdi") dirfd, in("rsi") path,
        in("rdx") flags, in("r10") mode,
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

#[inline(never)]
fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
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
fn sys_getpid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
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
fn sys_gettid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 186u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

#[inline(never)]
fn sys_unshare(flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 272u64, in("rdi") flags,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
