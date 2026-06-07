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

const SIGUSR1: i32 = 10;
const SA_RESTORER: u64 = 0x0400_0000;
const SIG_BLOCK: u64 = 0;
const SIG_SETMASK: u64 = 2;

static mut HANDLER_RAN: i32 = 0;
static mut SIGNUM_SEEN: i32 = -1;

static mut SIGINFO_RAN: i32 = 0;
static mut SI_CODE_SEEN: i32 = 0;
static mut SI_VALUE_SEEN: u64 = 0;

extern "C" fn signal_handler(signum: i32) {
    unsafe {
        let r = core::ptr::read_volatile(&raw const HANDLER_RAN);
        core::ptr::write_volatile(&raw mut HANDLER_RAN, r + 1);
        core::ptr::write_volatile(&raw mut SIGNUM_SEEN, signum);
    }
}

extern "C" fn siginfo_handler(_sig: i32, info: *const u8, _ctx: *const u8) {
    unsafe {
        let code = core::ptr::read_volatile(info.add(8) as *const i32);
        let val = core::ptr::read_volatile(info.add(24) as *const u64);
        core::ptr::write_volatile(&raw mut SI_CODE_SEEN, code);
        core::ptr::write_volatile(&raw mut SI_VALUE_SEEN, val);
        let r = core::ptr::read_volatile(&raw const SIGINFO_RAN);
        core::ptr::write_volatile(&raw mut SIGINFO_RAN, r + 1);
    }
}

#[unsafe(naked)]
unsafe extern "C" fn signal_restorer() {
    core::arch::naked_asm!("mov rax, 15", "syscall");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    report(b"signal: _start entered\n");

    let act = KSigAction {
        handler: signal_handler as *const () as u64,
        flags: SA_RESTORER,
        restorer: signal_restorer as *const () as u64,
        mask: 0,
    };
    if sys_rt_sigaction(SIGUSR1, &act, core::ptr::null_mut(), 8) != 0 {
        report(b"sigaction failed\n");
        sys_exit(1);
    }
    report(b"signal: sigaction registered\n");

    let pid = sys_getpid();
    if sys_kill(pid, SIGUSR1) != 0 {
        report(b"kill #1 failed\n");
        sys_exit(2);
    }
    report(b"signal: returned from kill\n");

    let ran = unsafe { core::ptr::read_volatile(&raw const HANDLER_RAN) };
    if ran != 1 {
        report(b"handler did not run\n");
        sys_exit(3);
    }
    let signum = unsafe { core::ptr::read_volatile(&raw const SIGNUM_SEEN) };
    if signum != SIGUSR1 {
        report(b"handler got wrong signum\n");
        sys_exit(4);
    }
    report(b"signal: handler + sigreturn ok\n");

    let block_set: u64 = 1u64 << SIGUSR1;
    let mut old: u64 = 0;
    if sys_rt_sigprocmask(SIG_BLOCK, &block_set, &mut old, 8) != 0 {
        report(b"sigprocmask block failed\n");
        sys_exit(5);
    }
    if sys_kill(pid, SIGUSR1) != 0 {
        report(b"kill #2 failed\n");
        sys_exit(6);
    }
    let still_one = unsafe { core::ptr::read_volatile(&raw const HANDLER_RAN) };
    if still_one != 1 {
        report(b"handler ran while blocked\n");
        sys_exit(7);
    }
    report(b"signal: block-then-kill: pending ok\n");

    if sys_rt_sigprocmask(SIG_SETMASK, &old, core::ptr::null_mut(), 8) != 0 {
        report(b"sigprocmask unblock failed\n");
        sys_exit(8);
    }
    let two = unsafe { core::ptr::read_volatile(&raw const HANDLER_RAN) };
    if two != 2 {
        report(b"handler did not run after unblock\n");
        sys_exit(9);
    }
    report(b"signal: unblock delivered pending ok\n");

    const SIGUSR2: i32 = 12;
    const SA_SIGINFO: u64 = 0x0000_0004;
    const SI_QUEUE: i32 = -1;
    const SENTINEL: u64 = 0xABCD_1234_5678_9ABC;
    let act2 = KSigAction {
        handler: siginfo_handler as *const () as u64,
        flags: SA_SIGINFO | SA_RESTORER,
        restorer: signal_restorer as *const () as u64,
        mask: 0,
    };
    if sys_rt_sigaction(SIGUSR2, &act2, core::ptr::null_mut(), 8) != 0 {
        report(b"SA_SIGINFO sigaction failed\n");
        sys_exit(20);
    }
    let mut si = [0u8; 128];
    si[0..4].copy_from_slice(&SIGUSR2.to_le_bytes());
    si[8..12].copy_from_slice(&SI_QUEUE.to_le_bytes());
    si[16..20].copy_from_slice(&pid.to_le_bytes());
    si[24..32].copy_from_slice(&SENTINEL.to_le_bytes());
    if sys_rt_sigqueueinfo(pid, SIGUSR2, si.as_ptr()) != 0 {
        report(b"rt_sigqueueinfo failed\n");
        sys_exit(21);
    }
    if unsafe { core::ptr::read_volatile(&raw const SIGINFO_RAN) } != 1 {
        report(b"SA_SIGINFO handler did not run\n");
        sys_exit(22);
    }
    if unsafe { core::ptr::read_volatile(&raw const SI_CODE_SEEN) } != SI_QUEUE {
        report(b"si_code not SI_QUEUE\n");
        sys_exit(23);
    }
    if unsafe { core::ptr::read_volatile(&raw const SI_VALUE_SEEN) } != SENTINEL {
        report(b"si_value not preserved\n");
        sys_exit(24);
    }
    report(b"signal: rt_sigqueueinfo si_code+si_value preserved ok\n");

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
