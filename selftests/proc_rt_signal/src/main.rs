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

#[repr(C)]
#[derive(Copy, Clone)]
struct Rlimit {
    cur: u64,
    max: u64,
}

const SIGRT: i32 = 34;
const SIGUSR1: i32 = 10;
const SA_SIGINFO: u64 = 0x0000_0004;
const SA_RESTORER: u64 = 0x0400_0000;
const SIG_BLOCK: u64 = 0;
const SIG_SETMASK: u64 = 2;
const SI_QUEUE: i32 = -1;
const RLIMIT_SIGPENDING: u64 = 11;
const EAGAIN: i64 = -11;

static mut RT_COUNT: usize = 0;
static mut RT_VALUES: [u64; 8] = [0; 8];
static mut STD_COUNT: i32 = 0;

extern "C" fn rt_handler(_sig: i32, info: *const u8, _ctx: *const u8) {
    unsafe {
        let val = core::ptr::read_volatile(info.add(24) as *const u64);
        let n = core::ptr::read_volatile(&raw const RT_COUNT);
        if n < 8 {
            core::ptr::write_volatile((&raw mut RT_VALUES).cast::<u64>().add(n), val);
        }
        core::ptr::write_volatile(&raw mut RT_COUNT, n + 1);
    }
}

extern "C" fn std_handler(_sig: i32) {
    unsafe {
        let n = core::ptr::read_volatile(&raw const STD_COUNT);
        core::ptr::write_volatile(&raw mut STD_COUNT, n + 1);
    }
}

#[unsafe(naked)]
unsafe extern "C" fn signal_restorer() {
    core::arch::naked_asm!("mov rax, 15", "syscall");
}

fn queue_rt(pid: i32, sig: i32, sival: u64) -> i64 {
    let mut si = [0u8; 128];
    si[0..4].copy_from_slice(&sig.to_le_bytes());
    si[8..12].copy_from_slice(&SI_QUEUE.to_le_bytes());
    si[16..20].copy_from_slice(&pid.to_le_bytes());
    si[24..32].copy_from_slice(&sival.to_le_bytes());
    sys_rt_sigqueueinfo(pid, sig, si.as_ptr())
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    report(b"rt_signal: _start entered\n");
    let pid = sys_getpid();

    let rt_act = KSigAction {
        handler: rt_handler as *const () as u64,
        flags: SA_SIGINFO | SA_RESTORER,
        restorer: signal_restorer as *const () as u64,
        mask: 0,
    };
    if sys_rt_sigaction(SIGRT, &rt_act, core::ptr::null_mut(), 8) != 0 {
        report(b"rt sigaction failed\n");
        sys_exit(1);
    }

    let block: u64 = 1u64 << SIGRT;
    let mut old: u64 = 0;
    if sys_rt_sigprocmask(SIG_BLOCK, &block, &mut old, 8) != 0 {
        report(b"rt block failed\n");
        sys_exit(2);
    }
    for v in 1..=5u64 {
        if queue_rt(pid, SIGRT, v) != 0 {
            report(b"rt sigqueue (under default cap) failed\n");
            sys_exit(3);
        }
    }
    if sys_rt_sigprocmask(SIG_SETMASK, &old, core::ptr::null_mut(), 8) != 0 {
        report(b"rt unblock failed\n");
        sys_exit(4);
    }
    let mut spins = 0;
    while unsafe { core::ptr::read_volatile(&raw const RT_COUNT) } < 5 && spins < 64 {
        let _ = sys_getpid();
        spins += 1;
    }
    let count = unsafe { core::ptr::read_volatile(&raw const RT_COUNT) };
    if count != 5 {
        report(b"rt queue did not deliver all 5 instances\n");
        sys_exit(5);
    }
    for i in 0..5usize {
        let got = unsafe { core::ptr::read_volatile((&raw const RT_VALUES).cast::<u64>().add(i)) };
        if got != (i as u64 + 1) {
            report(b"rt queue out of FIFO order\n");
            sys_exit(6);
        }
    }
    report(b"rt_signal: 5 instances queued + delivered in FIFO order\n");

    let std_act = KSigAction {
        handler: std_handler as *const () as u64,
        flags: SA_RESTORER,
        restorer: signal_restorer as *const () as u64,
        mask: 0,
    };
    if sys_rt_sigaction(SIGUSR1, &std_act, core::ptr::null_mut(), 8) != 0 {
        report(b"std sigaction failed\n");
        sys_exit(7);
    }
    let block_std: u64 = 1u64 << SIGUSR1;
    if sys_rt_sigprocmask(SIG_BLOCK, &block_std, &mut old, 8) != 0 {
        report(b"std block failed\n");
        sys_exit(8);
    }
    if sys_kill(pid, SIGUSR1) != 0 || sys_kill(pid, SIGUSR1) != 0 {
        report(b"std kill failed\n");
        sys_exit(9);
    }
    if sys_rt_sigprocmask(SIG_SETMASK, &old, core::ptr::null_mut(), 8) != 0 {
        report(b"std unblock failed\n");
        sys_exit(10);
    }
    if unsafe { core::ptr::read_volatile(&raw const STD_COUNT) } != 1 {
        report(b"standard signal did not coalesce to 1\n");
        sys_exit(11);
    }
    report(b"rt_signal: standard signal coalesced to 1 (unchanged)\n");

    let lim = Rlimit { cur: 3, max: 3 };
    if sys_prlimit64(0, RLIMIT_SIGPENDING, &lim, core::ptr::null_mut()) != 0 {
        report(b"prlimit64 set SIGPENDING failed\n");
        sys_exit(12);
    }
    if sys_rt_sigprocmask(SIG_BLOCK, &block, &mut old, 8) != 0 {
        report(b"rt re-block failed\n");
        sys_exit(13);
    }
    for v in 1..=3u64 {
        if queue_rt(pid, SIGRT, v) != 0 {
            report(b"rt sigqueue within cap failed\n");
            sys_exit(14);
        }
    }
    if queue_rt(pid, SIGRT, 4) != EAGAIN {
        report(b"rt sigqueue over cap did not return EAGAIN\n");
        sys_exit(15);
    }
    report(b"rt_signal: RLIMIT_SIGPENDING enforced (EAGAIN at cap)\n");

    report(b"rt_signal: ALL OK\n");
    sys_exit(0);
}

fn report(msg: &[u8]) {
    sys_write(1, msg.as_ptr(), msg.len());
}

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

fn sys_rt_sigaction(
    signum: i32,
    act: *const KSigAction,
    old: *mut KSigAction,
    sigsetsize: u64,
) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 13u64, in("rdi") signum as i64, in("rsi") act,
            in("rdx") old, in("r10") sigsetsize,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_rt_sigprocmask(how: u64, set: *const u64, oldset: *mut u64, sigsetsize: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 14u64, in("rdi") how, in("rsi") set,
            in("rdx") oldset, in("r10") sigsetsize,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_getpid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64, lateout("rax") r,
             out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

fn sys_rt_sigqueueinfo(pid: i32, sig: i32, info: *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 129u64, in("rdi") pid as i64, in("rsi") sig as i64,
            in("rdx") info,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_prlimit64(pid: i32, resource: u64, new_rlim: *const Rlimit, old_rlim: *mut Rlimit) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 302u64, in("rdi") pid as i64, in("rsi") resource,
            in("rdx") new_rlim, in("r10") old_rlim,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_kill(pid: i32, sig: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 62u64, in("rdi") pid as i64, in("rsi") sig as i64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
