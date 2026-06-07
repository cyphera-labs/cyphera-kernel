#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SIGTERM: i32 = 15;
const EPERM: i64 = -1;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("creds test starting\n");

    if sys_getuid() != 0 || sys_geteuid() != 0 || sys_getgid() != 0 || sys_getegid() != 0 {
        log("boot creds: not root\n");
        sys_exit(1);
    }
    log("boot creds (uid=0) OK\n");

    let r = sys_fork();
    if r < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if r == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(20);
        }
        if sys_getuid() != 1000 || sys_geteuid() != 1000 {
            sys_exit(21);
        }
        let mut r: u32 = 0;
        let mut e: u32 = 0;
        let mut s: u32 = 0;
        sys_getresuid(&mut r, &mut e, &mut s);
        if r != 1000 || e != 1000 || s != 1000 {
            sys_exit(22);
        }
        if sys_setresuid(0, 0, 0) != EPERM {
            sys_exit(23);
        }
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(24);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("uid-drop / promote-deny / no-op-permit: child exit ");
        log_num(exit_code as i64);
        sys_exit(1);
    }
    log("setresuid drop + EPERM-on-promote + no-op-permit OK\n");

    let r = sys_fork();
    if r < 0 {
        log("fork sg failed\n");
        sys_exit(1);
    }
    if r == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(30);
        }
        let groups: [u32; 1] = [4242];
        if sys_setgroups(1, groups.as_ptr() as u64) != EPERM {
            sys_exit(31);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    if (st & 0x7f) != 0 || (st >> 8) & 0xff != 0 {
        log("setgroups EPERM check failed\n");
        sys_exit(1);
    }
    log("setgroups from non-root → -EPERM OK\n");

    let rb = sys_fork();
    if rb < 0 {
        log("fork rb failed\n");
        sys_exit(1);
    }
    if rb == 0 {
        if sys_setresuid(2000, 2000, 2000) != 0 {
            sys_exit(40);
        }
        loop {
            sys_sched_yield();
        }
    }
    let pid_b = rb as i32;

    let ra = sys_fork();
    if ra < 0 {
        log("fork ra failed\n");
        sys_exit(1);
    }
    if ra == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(50);
        }
        if sys_kill(pid_b, SIGTERM) != EPERM {
            sys_exit(51);
        }
        if sys_kill(sys_getpid(), 18) != 0 {
            sys_exit(52);
        }
        sys_exit(0);
    }
    let mut st_a: i32 = 0;
    sys_wait4(ra as i32, &mut st_a, 0);
    let exit_code_a = (st_a >> 8) & 0xff;
    if (st_a & 0x7f) != 0 || exit_code_a != 0 {
        log("A child unexpected exit code: ");
        log_num(exit_code_a as i64);
        sys_exit(1);
    }
    sys_kill(pid_b, SIGTERM);
    let mut st_b: i32 = 0;
    sys_wait4(pid_b, &mut st_b, 0);
    if (st_b & 0x7f) != SIGTERM {
        log("B not signal-killed by root\n");
        sys_exit(1);
    }
    log("kill cred check (cross-uid -> EPERM; root override) OK\n");

    let r = sys_fork();
    if r < 0 {
        log("fork setuid failed\n");
        sys_exit(1);
    }
    if r == 0 {
        if sys_setuid(1000) != 0 {
            sys_exit(60);
        }
        let mut r: u32 = 0;
        let mut e: u32 = 0;
        let mut s: u32 = 0;
        sys_getresuid(&mut r, &mut e, &mut s);
        if r != 1000 || e != 1000 || s != 1000 {
            sys_exit(61);
        }
        if sys_setuid(0) != EPERM {
            sys_exit(62);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    if (st & 0x7f) != 0 || (st >> 8) & 0xff != 0 {
        log("setuid full-drop test failed\n");
        sys_exit(1);
    }
    log("setuid(uid) full-drop + post-drop EPERM OK\n");

    log("all creds tests OK\n");
    sys_exit(0);
}

#[inline(never)]
fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

fn log_num(n: i64) {
    let mut buf = [0u8; 16];
    let mut i = 0usize;
    let neg = n < 0;
    let mut v = if neg { (-n) as u64 } else { n as u64 };
    if v == 0 {
        buf[i] = b'0';
        i += 1;
    } else {
        let mut digits = [0u8; 16];
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
fn sys_sched_yield() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 24u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
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
fn sys_kill(pid: i32, signal: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 62u64, in("rdi") pid as i64, in("rsi") signal as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_getuid() -> u32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 102u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as u32
}
#[inline(never)]
fn sys_geteuid() -> u32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 107u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as u32
}
#[inline(never)]
fn sys_getgid() -> u32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 104u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as u32
}
#[inline(never)]
fn sys_getegid() -> u32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 108u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as u32
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
fn sys_getresuid(r: *mut u32, e: *mut u32, s: *mut u32) -> i64 {
    let ret: i64;
    unsafe {
        asm!("syscall", in("rax") 118u64, in("rdi") r, in("rsi") e, in("rdx") s,
        lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

#[inline(never)]
fn sys_setuid(uid: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 105u64, in("rdi") uid as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_setgroups(size: u64, list: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 116u64, in("rdi") size, in("rsi") list,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
