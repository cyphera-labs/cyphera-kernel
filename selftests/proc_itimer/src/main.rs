#![no_std]
#![no_main]

use core::arch::asm;
use core::hint::black_box;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct KSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

const SIGVTALRM: i32 = 26;
const SIGPROF: i32 = 27;
const SA_RESTORER: u64 = 0x0400_0000;

const ITIMER_VIRTUAL: u64 = 1;
const ITIMER_PROF: u64 = 2;

const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;

const PERIOD_USEC: i64 = 50_000;
const BUDGET_NS: u64 = 1_000_000_000;

static mut VTALRM_RAN: i32 = 0;
static mut PROF_RAN: i32 = 0;

extern "C" fn vtalrm_handler(_sig: i32) {
    unsafe {
        let r = core::ptr::read_volatile(&raw const VTALRM_RAN);
        core::ptr::write_volatile(&raw mut VTALRM_RAN, r + 1);
    }
}

extern "C" fn prof_handler(_sig: i32) {
    unsafe {
        let r = core::ptr::read_volatile(&raw const PROF_RAN);
        core::ptr::write_volatile(&raw mut PROF_RAN, r + 1);
    }
}

#[unsafe(naked)]
unsafe extern "C" fn signal_restorer() {
    core::arch::naked_asm!("mov rax, 15", "syscall");
}

fn install(signo: i32, handler: extern "C" fn(i32)) -> bool {
    let act = KSigAction {
        handler: handler as *const () as u64,
        flags: SA_RESTORER,
        restorer: signal_restorer as *const () as u64,
        mask: 0,
    };
    sys_rt_sigaction(signo, &act) == 0
}

fn itimerval(interval_usec: i64, value_usec: i64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[8..16].copy_from_slice(&interval_usec.to_ne_bytes());
    buf[24..32].copy_from_slice(&value_usec.to_ne_bytes());
    buf
}

fn value_usec(buf: &[u8; 32]) -> i64 {
    i64::from_ne_bytes(buf[24..32].try_into().unwrap())
}

fn interval_usec(buf: &[u8; 32]) -> i64 {
    i64::from_ne_bytes(buf[8..16].try_into().unwrap())
}

fn process_cpu_ns() -> u64 {
    let mut ts = [0u8; 16];
    if sys_clock_gettime(CLOCK_PROCESS_CPUTIME_ID, ts.as_mut_ptr()) != 0 {
        return 0;
    }
    let sec = i64::from_ne_bytes(ts[0..8].try_into().unwrap()) as u64;
    let nsec = i64::from_ne_bytes(ts[8..16].try_into().unwrap()) as u64;
    sec.wrapping_mul(1_000_000_000).wrapping_add(nsec)
}

fn burn_until(flag: *const i32) -> bool {
    let start = process_cpu_ns();
    let mut acc: u64 = 0;
    loop {
        for i in 0..2_000_000u64 {
            acc = acc.wrapping_add(black_box(i));
        }
        black_box(acc);
        if unsafe { core::ptr::read_volatile(flag) } != 0 {
            return true;
        }
        if process_cpu_ns().wrapping_sub(start) > BUDGET_NS {
            return false;
        }
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("itimer test starting\n");

    if !install(SIGVTALRM, vtalrm_handler) {
        log("rt_sigaction SIGVTALRM failed\n");
        sys_exit(1);
    }
    if !install(SIGPROF, prof_handler) {
        log("rt_sigaction SIGPROF failed\n");
        sys_exit(2);
    }

    let mut cur = [0u8; 32];
    if sys_getitimer(ITIMER_VIRTUAL, cur.as_mut_ptr()) != 0 {
        log("getitimer(VIRTUAL) disarmed failed\n");
        sys_exit(3);
    }
    if value_usec(&cur) != 0 || interval_usec(&cur) != 0 {
        log("getitimer(VIRTUAL) not zero while disarmed\n");
        sys_exit(4);
    }

    let arm = itimerval(PERIOD_USEC, PERIOD_USEC);
    if sys_setitimer(ITIMER_VIRTUAL, arm.as_ptr(), core::ptr::null_mut()) != 0 {
        log("setitimer(VIRTUAL) failed\n");
        sys_exit(5);
    }
    let mut back = [0u8; 32];
    if sys_getitimer(ITIMER_VIRTUAL, back.as_mut_ptr()) != 0 {
        log("getitimer(VIRTUAL) armed failed\n");
        sys_exit(6);
    }
    if interval_usec(&back) != PERIOD_USEC {
        log("getitimer(VIRTUAL) interval mismatch\n");
        sys_exit(7);
    }
    let rem = value_usec(&back);
    if rem <= 0 || rem > PERIOD_USEC {
        log("getitimer(VIRTUAL) remaining out of range\n");
        sys_exit(8);
    }
    if !burn_until(&raw const VTALRM_RAN) {
        log("SIGVTALRM never fired within CPU budget\n");
        sys_exit(9);
    }
    let disarm = itimerval(0, 0);
    let _ = sys_setitimer(ITIMER_VIRTUAL, disarm.as_ptr(), core::ptr::null_mut());
    log("itimer: ITIMER_VIRTUAL fired SIGVTALRM\n");

    let arm = itimerval(PERIOD_USEC, PERIOD_USEC);
    if sys_setitimer(ITIMER_PROF, arm.as_ptr(), core::ptr::null_mut()) != 0 {
        log("setitimer(PROF) failed\n");
        sys_exit(10);
    }
    if !burn_until(&raw const PROF_RAN) {
        log("SIGPROF never fired within CPU budget\n");
        sys_exit(11);
    }
    let _ = sys_setitimer(ITIMER_PROF, disarm.as_ptr(), core::ptr::null_mut());
    log("itimer: ITIMER_PROF fired SIGPROF\n");

    log("ITIMER_OK\n");
    sys_exit(0);
}

#[inline(never)]
fn sys_rt_sigaction(signo: i32, act: *const KSigAction) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 13u64, in("rdi") signo as u64, in("rsi") act,
            in("rdx") 0u64, in("r10") 8u64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_setitimer(which: u64, new: *const u8, old: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 38u64, in("rdi") which, in("rsi") new, in("rdx") old,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_getitimer(which: u64, curr: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 36u64, in("rdi") which, in("rsi") curr,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_clock_gettime(clock: u64, ts: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 228u64, in("rdi") clock, in("rsi") ts,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
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
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
