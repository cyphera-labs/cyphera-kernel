#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SYS_WRITE: u64 = 1;
const SYS_MMAP: u64 = 9;
const SYS_MPROTECT: u64 = 10;
const SYS_RT_SIGACTION: u64 = 13;
const SYS_FORK: u64 = 57;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;

const PROT_NONE: u64 = 0;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const SA_SIGINFO: u64 = 0x0000_0004;
const SA_RESTORER: u64 = 0x0400_0000;
const SIGSEGV: u64 = 11;
const PAGE: u64 = 4096;
const MARKER: u64 = 0xCAFE_BABE_DEAD_BEEF;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct KSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

static mut FAULT_PAGE: u64 = 0;
static mut SI_ADDR_SEEN: u64 = 0;
static mut HANDLER_RAN: i32 = 0;

extern "C" fn segv_handler(_sig: i32, info: *const u8, _ctx: *const u8) {
    let si_addr = unsafe { core::ptr::read_volatile(info.add(16) as *const u64) };
    let page = unsafe { core::ptr::read_volatile(&raw const FAULT_PAGE) };
    unsafe {
        core::ptr::write_volatile(&raw mut SI_ADDR_SEEN, si_addr);
    }
    if si_addr >= page && si_addr < page + PAGE {
        let _ = sys_mprotect(page, PAGE, PROT_READ | PROT_WRITE);
        unsafe {
            core::ptr::write_volatile(&raw mut HANDLER_RAN, 1);
        }
    } else {
        sys_exit(70);
    }
}

#[unsafe(naked)]
unsafe extern "C" fn signal_restorer() {
    core::arch::naked_asm!("mov rax, 15", "syscall");
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("segv_handler test starting\n");
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
        log("parent: child did not exit cleanly (handler did not catch SIGSEGV)\n");
        sys_exit(62);
    }
    if wexitstatus(status) != 0 {
        log("parent: child exit nonzero: ");
        log_num(wexitstatus(status) as i64);
        sys_exit(63);
    }
    log("SEGV_HANDLER_OK\n");
    sys_exit(0);
}

fn child() -> ! {
    let page = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        u64::MAX,
        0,
    );
    if page < 0 {
        sys_exit(64);
    }
    let page = page as u64;
    unsafe {
        core::ptr::write_volatile(&raw mut FAULT_PAGE, page);
    }

    let act = KSigAction {
        handler: segv_handler as *const () as u64,
        flags: SA_SIGINFO | SA_RESTORER,
        restorer: signal_restorer as *const () as u64,
        mask: 0,
    };
    if sys_rt_sigaction(SIGSEGV, &act) != 0 {
        sys_exit(65);
    }

    if sys_mprotect(page, PAGE, PROT_NONE) != 0 {
        sys_exit(66);
    }

    unsafe {
        core::ptr::write_volatile(page as *mut u64, MARKER);
    }

    let ran = unsafe { core::ptr::read_volatile(&raw const HANDLER_RAN) };
    let seen = unsafe { core::ptr::read_volatile(&raw const SI_ADDR_SEEN) };
    let back = unsafe { core::ptr::read_volatile(page as *const u64) };
    if ran != 1 {
        sys_exit(67);
    }
    if seen != page {
        sys_exit(68);
    }
    if back != MARKER {
        sys_exit(69);
    }
    sys_exit(0);
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
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_MMAP, in("rdi") addr, in("rsi") len,
            in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") off,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_MPROTECT, in("rdi") addr, in("rsi") len, in("rdx") prot,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
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
