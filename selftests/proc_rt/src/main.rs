#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SCHED_OTHER: i32 = 0;
const SCHED_FIFO: i32 = 1;
const SCHED_RR: i32 = 2;

const SYS_SCHED_SETPARAM: u64 = 142;
const SYS_SCHED_GETPARAM: u64 = 143;
const SYS_SCHED_SETSCHEDULER: u64 = 144;
const SYS_SCHED_GETSCHEDULER: u64 = 145;
const SYS_SCHED_GET_PRIORITY_MAX: u64 = 146;
const SYS_SCHED_GET_PRIORITY_MIN: u64 = 147;
const SYS_SCHED_RR_GET_INTERVAL: u64 = 148;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("rt test starting\n");

    let max_fifo = sys3(SYS_SCHED_GET_PRIORITY_MAX, SCHED_FIFO as u64, 0, 0);
    let min_fifo = sys3(SYS_SCHED_GET_PRIORITY_MIN, SCHED_FIFO as u64, 0, 0);
    let max_other = sys3(SYS_SCHED_GET_PRIORITY_MAX, SCHED_OTHER as u64, 0, 0);
    if max_fifo != 99 || min_fifo != 1 || max_other != 0 {
        log("priority_min/max wrong\n");
        log_num(max_fifo);
        log_num(min_fifo);
        log_num(max_other);
        sys_exit(1);
    }
    log("priority_min/max OK\n");

    let pol = sys3(SYS_SCHED_GETSCHEDULER, 0, 0, 0);
    if pol != SCHED_OTHER as i64 {
        log("default policy not OTHER: ");
        log_num(pol);
        sys_exit(1);
    }
    log("default policy = SCHED_OTHER OK\n");

    let prio: i32 = 50;
    let r = sys3(
        SYS_SCHED_SETSCHEDULER,
        0,
        SCHED_FIFO as u64,
        &prio as *const i32 as u64,
    );
    if r != 0 {
        log("setscheduler FIFO 50 failed: ");
        log_num(r);
        sys_exit(1);
    }
    let pol2 = sys3(SYS_SCHED_GETSCHEDULER, 0, 0, 0);
    if pol2 != SCHED_FIFO as i64 {
        log("getscheduler != FIFO after setsched: ");
        log_num(pol2);
        sys_exit(1);
    }
    log("set/getscheduler FIFO 50 OK\n");

    let mut got: i32 = 0;
    let r = sys3(SYS_SCHED_GETPARAM, 0, &mut got as *mut i32 as u64, 0);
    if r != 0 || got != 50 {
        log("getparam wrong: r=");
        log_num(r);
        log("got=");
        log_num(got as i64);
        sys_exit(1);
    }
    log("getparam = 50 OK\n");

    let prio60: i32 = 60;
    let r = sys3(SYS_SCHED_SETPARAM, 0, &prio60 as *const i32 as u64, 0);
    if r != 0 {
        log("setparam 60 failed\n");
        sys_exit(1);
    }
    let pol3 = sys3(SYS_SCHED_GETSCHEDULER, 0, 0, 0);
    let mut got2: i32 = 0;
    sys3(SYS_SCHED_GETPARAM, 0, &mut got2 as *mut i32 as u64, 0);
    if pol3 != SCHED_FIFO as i64 || got2 != 60 {
        log("setparam round-trip wrong\n");
        sys_exit(1);
    }
    log("setparam priority change OK\n");

    let bad: i32 = 100;
    let r = sys3(
        SYS_SCHED_SETSCHEDULER,
        0,
        SCHED_FIFO as u64,
        &bad as *const i32 as u64,
    );
    if r != -22 {
        log("bad prio expected EINVAL got: ");
        log_num(r);
        sys_exit(1);
    }
    log("bad prio -> EINVAL OK\n");

    let mut ts = [0i64; 2];
    let r = sys3(SYS_SCHED_RR_GET_INTERVAL, 0, ts.as_mut_ptr() as u64, 0);
    if r != 0 || ts[0] != 0 || ts[1] != 0 {
        log("rr_get_interval for FIFO not 0\n");
        sys_exit(1);
    }
    let prio_rr: i32 = 30;
    let r = sys3(
        SYS_SCHED_SETSCHEDULER,
        0,
        SCHED_RR as u64,
        &prio_rr as *const i32 as u64,
    );
    if r != 0 {
        log("setscheduler RR failed\n");
        sys_exit(1);
    }
    let mut ts = [0i64; 2];
    let r = sys3(SYS_SCHED_RR_GET_INTERVAL, 0, ts.as_mut_ptr() as u64, 0);
    if r != 0 || (ts[0] == 0 && ts[1] == 0) {
        log("rr_get_interval for RR was zero\n");
        sys_exit(1);
    }
    log("rr_get_interval OK\n");

    let zero: i32 = 0;
    let r = sys3(
        SYS_SCHED_SETSCHEDULER,
        0,
        SCHED_OTHER as u64,
        &zero as *const i32 as u64,
    );
    if r != 0 {
        log("setscheduler back to OTHER failed: ");
        log_num(r);
        sys_exit(1);
    }
    let pol4 = sys3(SYS_SCHED_GETSCHEDULER, 0, 0, 0);
    if pol4 != SCHED_OTHER as i64 {
        log("not back to OTHER: ");
        log_num(pol4);
        sys_exit(1);
    }
    log("back to SCHED_OTHER OK\n");

    log("RT_OK\n");
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
