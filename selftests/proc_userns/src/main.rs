#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const CLONE_NEWUSER: u64 = 0x1000_0000;

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const EPERM: i64 = -1;

const AT_FDCWD: i32 = -100;
const O_WRONLY: i32 = 1;

const OVERFLOW_UID: u64 = 65534;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("userns test starting\n");

    let pid = sys_fork();
    if pid < 0 {
        sys_exit(1);
    }
    if pid == 0 {
        child();
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("userns child failed: ");
        log_num(exit_code as i64);
        sys_exit(1);
    }
    log("all userns tests OK\n");
    sys_exit(0);
}

fn child() -> ! {
    if sys_setresuid(1000, 1000, 1000) != 0 {
        sys_exit(20);
    }
    let (eff_pre, _, _) = capget_self();
    if eff_pre != 0 {
        sys_exit(21);
    }
    if sys_chroot(b"/tmp\0".as_ptr()) != EPERM {
        sys_exit(22);
    }

    if sys_unshare(CLONE_NEWUSER) != 0 {
        sys_exit(30);
    }
    let (eff, _, _) = capget_self();
    if eff == 0 {
        sys_exit(31);
    }

    let s = sys_socket(AF_INET, SOCK_STREAM, 0);
    if s < 0 {
        sys_exit(32);
    }
    let mut addr = [0u8; 16];
    addr[0] = AF_INET as u8;
    addr[3] = 80;
    if sys_bind(s as i32, addr.as_ptr(), 16) >= 0 {
        sys_exit(33);
    }
    sys_close(s as i32);

    if sys_getuid() != OVERFLOW_UID || sys_geteuid() != OVERFLOW_UID {
        sys_exit(40);
    }

    let fd = sys_openat(AT_FDCWD, b"/proc/self/uid_map\0".as_ptr(), O_WRONLY, 0);
    if fd < 0 {
        sys_exit(50);
    }
    let bad = b"0 0 1\n";
    if sys_write(fd as u64, bad.as_ptr(), bad.len()) >= 0 {
        sys_exit(51);
    }
    let good = b"0 1000 1\n";
    if sys_write(fd as u64, good.as_ptr(), good.len()) != good.len() as i64 {
        sys_exit(52);
    }
    sys_close(fd as i32);

    if sys_getuid() != 0 {
        sys_exit(60);
    }
    if sys_setresuid(0, 0, 0) != 0 {
        sys_exit(61);
    }
    if sys_getuid() != 0 {
        sys_exit(62);
    }
    if sys_setresuid(5, u32::MAX, u32::MAX) == 0 {
        sys_exit(63);
    }

    sys_exit(0);
}

fn capget_self() -> (u64, u64, u64) {
    let mut hdr: [u32; 2] = [LINUX_CAPABILITY_VERSION_3, 0];
    let mut data: [u32; 6] = [0; 6];
    let r = sys_capget(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64);
    if r != 0 {
        return (0, 0, 0);
    }
    let eff = ((data[3] as u64) << 32) | (data[0] as u64);
    let perm = ((data[4] as u64) << 32) | (data[1] as u64);
    let inh = ((data[5] as u64) << 32) | (data[2] as u64);
    (eff, perm, inh)
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
fn sys_capget(hdr: u64, data: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 125u64, in("rdi") hdr, in("rsi") data,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_setresuid(r: u32, e: u32, s: u32) -> i64 {
    let ret: i64;
    unsafe {
        asm!("syscall", in("rax") 117u64, in("rdi") r as u64, in("rsi") e as u64, in("rdx") s as u64,
        lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

#[inline(never)]
fn sys_getuid() -> u64 {
    let r: u64;
    unsafe {
        asm!("syscall", in("rax") 102u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_geteuid() -> u64 {
    let r: u64;
    unsafe {
        asm!("syscall", in("rax") 107u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
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

#[inline(never)]
fn sys_chroot(path: *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 161u64, in("rdi") path,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_socket(domain: i32, ty: i32, proto: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 41u64, in("rdi") domain as i64,
        in("rsi") ty as i64, in("rdx") proto as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_bind(fd: i32, addr: *const u8, addrlen: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 49u64, in("rdi") fd as i64,
        in("rsi") addr, in("rdx") addrlen as u64,
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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
