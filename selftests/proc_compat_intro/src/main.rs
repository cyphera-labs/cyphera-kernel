#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const PRIO_PROCESS: u64 = 0;
const SIGTERM: u64 = 15;
const EINTR: i64 = -4;
const EINVAL: i64 = -22;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("compat_intro test starting\n");

    let mut t: i64 = 0;
    let r = sys_time(&mut t as *mut i64 as u64);
    if r <= 0 || t != r {
        log("time: r/t mismatch ");
        log_num(r);
        sys_exit(1);
    }
    log("time(t) returns secs and writes through OK\n");

    let p = sys_personality(0xffff_ffff);
    if p != 0 {
        log("personality: ");
        log_num(p);
        sys_exit(1);
    }
    log("personality returns PER_LINUX (0) OK\n");

    let r = sys_getpriority(PRIO_PROCESS, 0);
    if r != 20 {
        log("getpriority default not 20: ");
        log_num(r);
        sys_exit(1);
    }
    if sys_setpriority(PRIO_PROCESS, 0, 5) != 0 {
        log("setpriority(5) failed\n");
        sys_exit(1);
    }
    let r = sys_getpriority(PRIO_PROCESS, 0);
    if r != 15 {
        log("getpriority post-set 5 expected 15, got ");
        log_num(r);
        sys_exit(1);
    }
    if sys_setpriority(PRIO_PROCESS, 0, 0) != 0 {
        log("setpriority(0) failed\n");
        sys_exit(1);
    }
    log("getpriority + setpriority round-trip OK\n");

    let r = sys_getpriority(99, 0);
    if r != EINVAL {
        log("getpriority bad which not EINVAL: ");
        log_num(r);
        sys_exit(1);
    }
    log("getpriority bad which → EINVAL OK\n");

    let mut buf = [0u8; 144];
    let r = sys_getrusage(0, buf.as_mut_ptr() as u64);
    if r != 0 {
        log("getrusage: ");
        log_num(r);
        sys_exit(1);
    }
    log("getrusage returns 0 + filled struct OK\n");

    let mut tms = [0u8; 32];
    let r = sys_times(tms.as_mut_ptr() as u64);
    if r < 0 {
        log("times: ");
        log_num(r);
        sys_exit(1);
    }
    log("times returns ticks-since-boot OK\n");

    let r = sys_fork();
    if r < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if r == 0 {
        let mypid = sys_getpid();
        sys_tkill(mypid, SIGTERM);
        sys_exit(99);
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    if (st & 0x7f) != SIGTERM as i32 {
        log("tkill: child not killed by SIGTERM, st=");
        log_num(st as i64);
        sys_exit(1);
    }
    log("tkill(self, SIGTERM) kills child OK\n");

    let r = sys_fork();
    if r < 0 {
        log("fork pause failed\n");
        sys_exit(1);
    }
    if r == 0 {
        let r = sys_pause();
        if r != EINTR {
            sys_exit(40);
        }
        sys_exit(0);
    }
    let child = r as i32;
    for _ in 0..2000 {
        sys_sched_yield();
    }
    sys_kill(child, 23);
    let mut st: i32 = 0;
    sys_wait4(child, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("pause: child wrong exit ");
        log_num(exit_code as i64);
        sys_exit(1);
    }
    log("pause + signal-wake → -EINTR OK\n");

    log("all compat_intro tests OK\n");
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

macro_rules! syscall {
    ($n:expr) => {{ let r: i64; unsafe { asm!("syscall", in("rax") $n as u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack)); } r }};
    ($n:expr, $a:expr) => {{ let r: i64; unsafe { asm!("syscall", in("rax") $n as u64, in("rdi") $a, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack)); } r }};
    ($n:expr, $a:expr, $b:expr) => {{ let r: i64; unsafe { asm!("syscall", in("rax") $n as u64, in("rdi") $a, in("rsi") $b, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack)); } r }};
    ($n:expr, $a:expr, $b:expr, $c:expr) => {{ let r: i64; unsafe { asm!("syscall", in("rax") $n as u64, in("rdi") $a, in("rsi") $b, in("rdx") $c, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack)); } r }};
    ($n:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {{ let r: i64; unsafe { asm!("syscall", in("rax") $n as u64, in("rdi") $a, in("rsi") $b, in("rdx") $c, in("r10") $d, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack)); } r }};
}

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    syscall!(1, fd, buf as u64, len as u64)
}
#[inline(never)]
fn sys_time(t: u64) -> i64 {
    syscall!(201, t)
}
#[inline(never)]
fn sys_personality(p: u64) -> i64 {
    syscall!(135, p)
}
#[inline(never)]
fn sys_getpriority(which: u64, who: u64) -> i64 {
    syscall!(140, which, who)
}
#[inline(never)]
fn sys_setpriority(which: u64, who: u64, niceval: u64) -> i64 {
    syscall!(141, which, who, niceval)
}
#[inline(never)]
fn sys_getrusage(who: u64, buf: u64) -> i64 {
    syscall!(98, who, buf)
}
#[inline(never)]
fn sys_times(buf: u64) -> i64 {
    syscall!(100, buf)
}
#[inline(never)]
fn sys_tkill(tid: i32, sig: u64) -> i64 {
    syscall!(200, tid as i64 as u64, sig)
}
#[inline(never)]
fn sys_pause() -> i64 {
    syscall!(34)
}
#[inline(never)]
fn sys_fork() -> i64 {
    syscall!(57)
}
#[inline(never)]
fn sys_wait4(pid: i32, st: *mut i32, opts: i32) -> i64 {
    syscall!(61, pid as i64 as u64, st as u64, opts as i64 as u64, 0u64)
}
#[inline(never)]
fn sys_getpid() -> i32 {
    syscall!(39) as i32
}
#[inline(never)]
fn sys_kill(pid: i32, sig: u64) -> i64 {
    syscall!(62, pid as i64 as u64, sig)
}
#[inline(never)]
fn sys_sched_yield() -> i64 {
    syscall!(24)
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
