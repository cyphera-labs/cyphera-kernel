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

const SA_RESTORER: u64 = 0x0400_0000;
const SIG_SETMASK: u64 = 2;

const SIGCHLD: u32 = 17;
const SIGCONT: u32 = 18;
const SIGURG: u32 = 23;
const SIGRT: u32 = 34;

static mut HANDLER_RAN: i32 = 0;

extern "C" fn handler(_sig: i32) {
    unsafe {
        let r = core::ptr::read_volatile(&raw const HANDLER_RAN);
        core::ptr::write_volatile(&raw mut HANDLER_RAN, r + 1);
    }
}

#[unsafe(naked)]
unsafe extern "C" fn signal_restorer() {
    core::arch::naked_asm!("mov rax, 15", "syscall");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    report(b"signal_drain: starting\n");

    let act = KSigAction {
        handler: handler as *const () as u64,
        flags: SA_RESTORER,
        restorer: signal_restorer as *const () as u64,
        mask: 0,
    };
    if sys_rt_sigaction(SIGRT, &act) != 0 {
        report(b"sigaction(SIGRT) failed\n");
        sys_exit(1);
    }

    let set: u64 = (1u64 << SIGCHLD) | (1u64 << SIGCONT) | (1u64 << SIGURG) | (1u64 << SIGRT);
    let mut old: u64 = 0;
    if sys_rt_sigprocmask(SIG_SETMASK, &set, &mut old) != 0 {
        report(b"sigprocmask block failed\n");
        sys_exit(2);
    }

    let pid = sys_getpid();
    for sig in [SIGCHLD, SIGCONT, SIGURG, SIGRT] {
        if sys_kill(pid, sig) != 0 {
            report(b"kill failed\n");
            sys_exit(3);
        }
    }

    if unsafe { core::ptr::read_volatile(&raw const HANDLER_RAN) } != 0 {
        report(b"handler ran while blocked\n");
        sys_exit(4);
    }

    if sys_rt_sigprocmask(SIG_SETMASK, &old, core::ptr::null_mut()) != 0 {
        report(b"sigprocmask unblock failed\n");
        sys_exit(5);
    }

    let ran = unsafe { core::ptr::read_volatile(&raw const HANDLER_RAN) };
    if ran != 1 {
        report(b"handler not delivered on the unblock crossing (drain missing)\n");
        sys_exit(6);
    }

    report(b"SIGNAL_DRAIN_OK\n");
    sys_exit(0);
}

#[inline(never)]
fn sys_rt_sigaction(signo: u32, act: *const KSigAction) -> i64 {
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
fn sys_rt_sigprocmask(how: u64, set: *const u64, old: *mut u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 14u64, in("rdi") how, in("rsi") set, in("rdx") old, in("r10") 8u64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_kill(pid: i64, sig: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 62u64, in("rdi") pid, in("rsi") sig as u64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn report(s: &[u8]) {
    unsafe {
        asm!(
            "syscall",
            in("rax") 1u64, in("rdi") 1u64, in("rsi") s.as_ptr(), in("rdx") s.len(),
            out("rcx") _, out("r11") _, lateout("rax") _, options(nostack),
        );
    }
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
