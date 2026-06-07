#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SYS_SCHED_GETSCHEDULER: u64 = 145;
const SYS_SCHED_SETSCHEDULER: u64 = 144;
const SYS_SCHED_SETATTR: u64 = 314;
const SYS_SCHED_GETATTR: u64 = 315;

const SCHED_OTHER: u32 = 0;
const SCHED_DEADLINE: i64 = 6;

const EINVAL: i64 = -22;
const EBUSY: i64 = -16;

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct SchedAttr {
    size: u32,
    sched_policy: u32,
    sched_flags: u64,
    sched_nice: i32,
    sched_priority: u32,
    sched_runtime: u64,
    sched_deadline: u64,
    sched_period: u64,
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("dl test starting\n");

    let mut attr = SchedAttr {
        size: 48,
        sched_policy: 6,
        sched_runtime: 10_000_000,
        sched_deadline: 100_000_000,
        sched_period: 100_000_000,
        ..Default::default()
    };
    let r = sys3(SYS_SCHED_SETATTR, 0, &attr as *const _ as u64, 0);
    if r != 0 {
        log("setattr DEADLINE failed: ");
        log_num(r);
        sys_exit(1);
    }
    log("setattr DEADLINE 10ms/100ms OK\n");

    let pol = sys3(SYS_SCHED_GETSCHEDULER, 0, 0, 0);
    if pol != SCHED_DEADLINE {
        log("getscheduler != SCHED_DEADLINE: ");
        log_num(pol);
        sys_exit(1);
    }
    log("getscheduler = SCHED_DEADLINE OK\n");

    let mut got: SchedAttr = Default::default();
    let r = sys4(SYS_SCHED_GETATTR, 0, &mut got as *mut _ as u64, 48, 0);
    if r != 0 {
        log("getattr failed: ");
        log_num(r);
        sys_exit(1);
    }
    if got.sched_policy != 6
        || got.sched_runtime != 10_000_000
        || got.sched_deadline != 100_000_000
        || got.sched_period != 100_000_000
    {
        log("getattr round-trip wrong: pol=");
        log_num(got.sched_policy as i64);
        log(" rt=");
        log_num(got.sched_runtime as i64);
        log(" dl=");
        log_num(got.sched_deadline as i64);
        log(" pe=");
        log_num(got.sched_period as i64);
        sys_exit(1);
    }
    log("getattr round-trip OK\n");

    let mut bad = attr;
    bad.sched_runtime = 200_000_000;
    let r = sys3(SYS_SCHED_SETATTR, 0, &bad as *const _ as u64, 0);
    if r != EINVAL {
        log("setattr runtime>deadline expected -EINVAL got: ");
        log_num(r);
        sys_exit(1);
    }
    log("runtime>deadline -> EINVAL OK\n");

    let mut greedy = attr;
    greedy.sched_runtime = 96_000_000;
    greedy.sched_deadline = 100_000_000;
    greedy.sched_period = 100_000_000;
    let r = sys3(SYS_SCHED_SETATTR, 0, &greedy as *const _ as u64, 0);
    if r != 0 && r != EBUSY {
        log("greedy setattr unexpected return: ");
        log_num(r);
        sys_exit(1);
    }
    log("96% bandwidth (single-task) admit path tested\n");

    let zero: i32 = 0;
    let r = sys3(
        SYS_SCHED_SETSCHEDULER,
        0,
        SCHED_OTHER as u64,
        &zero as *const i32 as u64,
    );
    if r != 0 {
        log("back to OTHER failed: ");
        log_num(r);
        sys_exit(1);
    }
    let pol2 = sys3(SYS_SCHED_GETSCHEDULER, 0, 0, 0);
    if pol2 != 0 {
        log("not back to OTHER: ");
        log_num(pol2);
        sys_exit(1);
    }
    log("back to SCHED_OTHER OK (DL bandwidth released)\n");

    attr.sched_runtime = 50_000_000;
    let r = sys3(SYS_SCHED_SETATTR, 0, &attr as *const _ as u64, 0);
    if r != 0 {
        log("re-enter DL after release failed: ");
        log_num(r);
        sys_exit(1);
    }
    log("re-enter DL after release OK\n");

    let r = sys3(
        SYS_SCHED_SETSCHEDULER,
        0,
        SCHED_OTHER as u64,
        &zero as *const i32 as u64,
    );
    if r != 0 {
        log("final back-to-OTHER failed: ");
        log_num(r);
        sys_exit(1);
    }

    log("DL_OK\n");
    sys_exit(0);
}

#[inline(never)]
fn sys3(num: u64, a: u64, b: u64, c: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") num, in("rdi") a, in("rsi") b, in("rdx") c,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys4(num: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") num, in("rdi") a, in("rsi") b, in("rdx") c,
            in("r10") d,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") 60u64, in("rdi") code as u64,
            options(noreturn, nostack),
        );
    }
}
