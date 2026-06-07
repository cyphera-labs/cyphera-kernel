#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SYS_SCHED_SETATTR: u64 = 314;
const SYS_SCHED_SETSCHEDULER: u64 = 144;
const SYS_CLOCK_GETTIME: u64 = 228;
const CLOCK_MONOTONIC: u64 = 1;

const SCHED_OTHER: u32 = 0;

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

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

fn now_ns() -> u64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_CLOCK_GETTIME,
            in("rdi") CLOCK_MONOTONIC,
            in("rsi") &mut ts as *mut _,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    if r != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("dl_overrun test starting\n");

    let base_start = now_ns();
    let base_target = base_start + 100_000_000;
    let mut units: u64 = 0;
    while now_ns() < base_target {
        do_work_unit();
        units += 1;
    }
    let baseline_wall = now_ns() - base_start;
    if units == 0 || baseline_wall == 0 {
        log("baseline produced no work\n");
        sys_exit(1);
    }

    let attr = SchedAttr {
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
    log("entered SCHED_DEADLINE 10ms/100ms\n");

    let work_start = now_ns();
    for _ in 0..units {
        do_work_unit();
    }
    let work_wall = now_ns() - work_start;

    let zero: i32 = 0;
    let _ = sys3(
        SYS_SCHED_SETSCHEDULER,
        0,
        SCHED_OTHER as u64,
        &zero as *const i32 as u64,
    );

    log("baseline ");
    log_num((baseline_wall / 1_000_000) as i64);
    log(" ms vs throttled ");
    log_num((work_wall / 1_000_000) as i64);
    log(" ms for ");
    log_num(units as i64);
    log(" units\n");
    if work_wall < baseline_wall.saturating_mul(3) {
        log("DL throttled work not stretched >=3x: budget not enforced\n");
        sys_exit(1);
    }

    log("DL_THROTTLE_OK\n");
    sys_exit(0);
}

#[inline(never)]
fn do_work_unit() {
    for _ in 0..200 {
        unsafe { core::arch::asm!("pause", options(nostack, nomem)) };
    }
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
