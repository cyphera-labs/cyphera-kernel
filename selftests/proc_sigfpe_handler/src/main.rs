#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SYS_WRITE: u64 = 1;
const SYS_RT_SIGACTION: u64 = 13;
const SYS_FORK: u64 = 57;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;

const SA_SIGINFO: u64 = 0x0000_0004;
const SA_RESTORER: u64 = 0x0400_0000;
const SIGFPE: u64 = 8;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct KSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

static mut HANDLER_SIG: i32 = 0;

extern "C" fn fpe_handler(sig: i32, _info: *const u8, _ctx: *const u8) {
    unsafe {
        core::ptr::write_volatile(&raw mut HANDLER_SIG, sig);
    }
    if sig == SIGFPE as i32 {
        sys_exit(0);
    }
    sys_exit(72);
}

#[unsafe(naked)]
unsafe extern "C" fn signal_restorer() {
    core::arch::naked_asm!("mov rax, 15", "syscall");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("sigfpe_handler test starting\n");
    let pid = sys_fork();
    if pid < 0 {
        log("fork failed\n");
        sys_exit(60);
    }
    if pid == 0 {
        child();
    }

    let mut status: i32 = 0;
    let r = sys_wait4(pid as u64, &mut status as *mut i32, 0);
    if r != pid {
        log("parent: wait4 wrong pid\n");
        sys_exit(61);
    }
    if !wifexited(status) {
        log("parent: child did not exit cleanly (handler did not catch SIGFPE)\n");
        sys_exit(62);
    }
    if wexitstatus(status) != 0 {
        log("parent: child exit nonzero: ");
        log_num(wexitstatus(status) as i64);
        sys_exit(63);
    }
    log("SIGFPE_HANDLER_OK\n");
    sys_exit(0);
}

fn child() -> ! {
    let act = KSigAction {
        handler: fpe_handler as *const () as u64,
        flags: SA_SIGINFO | SA_RESTORER,
        restorer: signal_restorer as *const () as u64,
        mask: 0,
    };
    if sys_rt_sigaction(SIGFPE, &act) != 0 {
        sys_exit(65);
    }

    unsafe {
        asm!(
            "xor edx, edx",
            "mov eax, 1",
            "xor ecx, ecx",
            "div ecx",
            out("eax") _,
            out("edx") _,
            out("ecx") _,
            options(nostack),
        );
    }
    sys_exit(73);
}

fn wifexited(status: i32) -> bool {
    (status & 0x7f) == 0
}

fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
}

#[inline(never)]
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_FORK, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_rt_sigaction(signo: u64, act: *const KSigAction) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "mov r10, 8",
            "syscall",
            in("rax") SYS_RT_SIGACTION, in("rdi") signo, in("rsi") act, in("rdx") 0u64,
            lateout("rax") r, out("rcx") _, out("r11") _, out("r10") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_wait4(pid: u64, status: *mut i32, options: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "mov r10, {opt}",
            "syscall",
            opt = in(reg) options,
            in("rax") SYS_WAIT4, in("rdi") pid, in("rsi") status, in("rdx") 0u64,
            lateout("rax") r, out("rcx") _, out("r11") _, out("r10") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_WRITE, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
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
        asm!("syscall", in("rax") SYS_EXIT, in("rdi") code as u64, options(noreturn, nostack));
    }
}
