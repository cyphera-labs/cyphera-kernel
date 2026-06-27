#![no_std]
#![no_main]

use core::arch::asm;

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

const SIGRT: i32 = 34;
const SA_RESTORER: u64 = 0x0400_0000;
const SA_SIGINFO: u64 = 0x0000_0004;

const CLOCK_MONOTONIC: u64 = 1;
const SIGEV_SIGNAL: i32 = 0;

const PERIOD_NS: i64 = 50_000_000;

static mut FIRES: i32 = 0;

extern "C" fn rt_handler(_sig: i32, _info: *mut u8, _ctx: *mut u8) {
    unsafe {
        let r = core::ptr::read_volatile(&raw const FIRES);
        core::ptr::write_volatile(&raw mut FIRES, r + 1);
    }
}

#[unsafe(naked)]
unsafe extern "C" fn signal_restorer() {
    core::arch::naked_asm!("mov rax, 15", "syscall");
}

fn install(signo: i32) -> bool {
    let act = KSigAction {
        handler: rt_handler as *const () as u64,
        flags: SA_RESTORER | SA_SIGINFO,
        restorer: signal_restorer as *const () as u64,
        mask: 0,
    };
    sys_rt_sigaction(signo, &act) == 0
}

fn sigevent(notify: i32, signo: i32, value: u64) -> [u8; 64] {
    let mut buf = [0u8; 64];
    buf[0..8].copy_from_slice(&value.to_ne_bytes());
    buf[8..12].copy_from_slice(&signo.to_ne_bytes());
    buf[12..16].copy_from_slice(&notify.to_ne_bytes());
    buf
}

fn itimerspec(interval_ns: i64, value_ns: i64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[0..8].copy_from_slice(&(interval_ns / 1_000_000_000).to_ne_bytes());
    buf[8..16].copy_from_slice(&(interval_ns % 1_000_000_000).to_ne_bytes());
    buf[16..24].copy_from_slice(&(value_ns / 1_000_000_000).to_ne_bytes());
    buf[24..32].copy_from_slice(&(value_ns % 1_000_000_000).to_ne_bytes());
    buf
}

fn its_value_ns(buf: &[u8; 32]) -> i64 {
    let sec = i64::from_ne_bytes(buf[16..24].try_into().unwrap());
    let nsec = i64::from_ne_bytes(buf[24..32].try_into().unwrap());
    sec * 1_000_000_000 + nsec
}

fn its_interval_ns(buf: &[u8; 32]) -> i64 {
    let sec = i64::from_ne_bytes(buf[0..8].try_into().unwrap());
    let nsec = i64::from_ne_bytes(buf[8..16].try_into().unwrap());
    sec * 1_000_000_000 + nsec
}

fn sleep_ms(ms: i64) {
    let ts = [(ms / 1000) as u64, ((ms % 1000) * 1_000_000) as u64];
    let _ = sys_nanosleep(ts.as_ptr() as *const u8, core::ptr::null_mut());
}

fn wait_for(target: i32, budget_ms: i64) -> bool {
    let mut waited = 0;
    while waited < budget_ms {
        if unsafe { core::ptr::read_volatile(&raw const FIRES) } >= target {
            return true;
        }
        sleep_ms(10);
        waited += 10;
    }
    let fires = unsafe { core::ptr::read_volatile(&raw const FIRES) };
    fires >= target
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("posix_timer test starting\n");

    if !install(SIGRT) {
        log("rt_sigaction failed\n");
        sys_exit(1);
    }

    let mut timer_id: i32 = -1;
    let sev = sigevent(SIGEV_SIGNAL, SIGRT, 0xdead_beef);
    if sys_timer_create(CLOCK_MONOTONIC, sev.as_ptr(), &mut timer_id) != 0 {
        log("timer_create failed\n");
        sys_exit(2);
    }

    let mut its = [0u8; 32];
    if sys_timer_gettime(timer_id as u64, its.as_mut_ptr()) != 0 {
        log("timer_gettime disarmed failed\n");
        sys_exit(3);
    }
    if its_value_ns(&its) != 0 || its_interval_ns(&its) != 0 {
        log("timer not zero while disarmed\n");
        sys_exit(4);
    }

    let arm = itimerspec(PERIOD_NS, PERIOD_NS);
    if sys_timer_settime(timer_id as u64, 0, arm.as_ptr(), core::ptr::null_mut()) != 0 {
        log("timer_settime failed\n");
        sys_exit(5);
    }

    let mut back = [0u8; 32];
    if sys_timer_gettime(timer_id as u64, back.as_mut_ptr()) != 0 {
        log("timer_gettime armed failed\n");
        sys_exit(6);
    }
    if its_interval_ns(&back) != PERIOD_NS {
        log("timer_gettime interval mismatch\n");
        sys_exit(7);
    }
    let rem = its_value_ns(&back);
    if rem <= 0 || rem > PERIOD_NS {
        log("timer_gettime remaining out of range\n");
        sys_exit(8);
    }

    if !wait_for(1, 2000) {
        log("timer signal never fired\n");
        sys_exit(9);
    }
    log("posix_timer: SIGEV_SIGNAL fired\n");

    if !wait_for(3, 2000) {
        log("timer interval did not re-arm\n");
        sys_exit(10);
    }
    log("posix_timer: interval re-armed\n");

    if sys_timer_delete(timer_id as u64) != 0 {
        log("timer_delete failed\n");
        sys_exit(11);
    }

    let snapshot = unsafe { core::ptr::read_volatile(&raw const FIRES) };
    sleep_ms(300);
    let after = unsafe { core::ptr::read_volatile(&raw const FIRES) };
    if after != snapshot {
        log("timer fired after delete\n");
        sys_exit(12);
    }
    log("posix_timer: delete stopped it\n");

    if sys_timer_gettime(timer_id as u64, back.as_mut_ptr()) == 0 {
        log("timer_gettime succeeded on deleted timer\n");
        sys_exit(13);
    }

    log("POSIX_TIMER_OK\n");
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
fn sys_timer_create(clockid: u64, sevp: *const u8, timer_id: *mut i32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 222u64, in("rdi") clockid, in("rsi") sevp, in("rdx") timer_id,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_timer_settime(timer_id: u64, flags: u64, new: *const u8, old: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 223u64, in("rdi") timer_id, in("rsi") flags, in("rdx") new,
            in("r10") old,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_timer_gettime(timer_id: u64, curr: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 224u64, in("rdi") timer_id, in("rsi") curr,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_timer_delete(timer_id: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 226u64, in("rdi") timer_id,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_nanosleep(req: *const u8, rem: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 35u64, in("rdi") req, in("rsi") rem,
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
