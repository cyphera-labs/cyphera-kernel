#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const CAPABILITY_VERSION_3: u32 = 0x20080522;

const CAP_SYS_CHROOT: u32 = 18;
const CAP_NET_BIND_SERVICE: u32 = 10;

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const EPERM: i64 = -1;
const EACCES: i64 = -13;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("caps test starting\n");

    let (eff, perm, _inh) = capget_self();
    if eff == 0 || perm == 0 {
        log("root caps zero?? eff=");
        log_hex(eff);
        sys_exit(1);
    }
    if (eff & (1u64 << CAP_SYS_CHROOT)) == 0 {
        log("root missing CAP_SYS_CHROOT\n");
        sys_exit(1);
    }
    if (eff & (1u64 << CAP_NET_BIND_SERVICE)) == 0 {
        log("root missing CAP_NET_BIND_SERVICE\n");
        sys_exit(1);
    }
    log("capget root: all caps OK\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork: ");
        log_num(pid);
        sys_exit(1);
    }
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(20);
        }
        let (eff2, perm2, _) = capget_self();
        if eff2 != 0 || perm2 != 0 {
            sys_exit(21);
        }
        if sys_chroot(b"/tmp\0".as_ptr()) != EPERM {
            sys_exit(22);
        }
        let s = sys_socket(AF_INET, SOCK_STREAM, 0);
        if s < 0 {
            sys_exit(23);
        }
        let mut addr = [0u8; 16];
        addr[0] = 2;
        addr[1] = 0;
        addr[2] = 0;
        addr[3] = 80;
        let r = sys_bind(s as i32, addr.as_ptr(), 16);
        if r != EACCES {
            sys_exit(24);
        }
        sys_close(s as i32);
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("uid-drop child failed: ");
        log_num(exit_code as i64);
        sys_exit(1);
    }
    log("uid-drop -> caps clear, chroot/bind blocked OK\n");

    let (e0, p0, i0) = capget_self();
    let new_eff = e0 & !(1u64 << CAP_SYS_CHROOT);
    if capset_self(new_eff, p0, i0) != 0 {
        log("capset drop SYS_CHROOT: failed\n");
        sys_exit(1);
    }
    let (e1, p1, _) = capget_self();
    if (e1 & (1u64 << CAP_SYS_CHROOT)) != 0 {
        log("CAP_SYS_CHROOT still in eff after capset\n");
        sys_exit(1);
    }
    if (p1 & (1u64 << CAP_SYS_CHROOT)) == 0 {
        log("CAP_SYS_CHROOT lost from perm — should still be there\n");
        sys_exit(1);
    }
    if capset_self(e0, p0, i0) != 0 {
        log("capset restore: failed\n");
        sys_exit(1);
    }
    log("capset eff-only drop preserves perm OK\n");

    log("all caps tests OK\n");
    sys_exit(0);
}

fn capget_self() -> (u64, u64, u64) {
    let mut hdr: [u32; 2] = [CAPABILITY_VERSION_3, 0];
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

fn capset_self(eff: u64, perm: u64, inh: u64) -> i64 {
    let mut hdr: [u32; 2] = [CAPABILITY_VERSION_3, 0];
    let data: [u32; 6] = [
        eff as u32,
        perm as u32,
        inh as u32,
        (eff >> 32) as u32,
        (perm >> 32) as u32,
        (inh >> 32) as u32,
    ];
    sys_capset(hdr.as_mut_ptr() as u64, data.as_ptr() as u64)
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

fn log_hex(n: u64) {
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let nib = ((n >> ((15 - i) * 4)) & 0xf) as u8;
        buf[2 + i] = if nib < 10 {
            b'0' + nib
        } else {
            b'a' + (nib - 10)
        };
    }
    sys_write(1, buf.as_ptr(), 18);
    sys_write(1, b"\n".as_ptr(), 1);
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
fn sys_capget(hdr: u64, data: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 125u64, in("rdi") hdr, in("rsi") data,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_capset(hdr: u64, data: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 126u64, in("rdi") hdr, in("rsi") data,
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
