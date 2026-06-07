#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const PR_SET_NAME: u64 = 15;
const PR_SET_NO_NEW_PRIVS: u64 = 38;
const PR_GET_NO_NEW_PRIVS: u64 = 39;

const SECCOMP_SET_MODE_FILTER: u64 = 1;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_ERRNO: u32 = 0x00050000;
const SECCOMP_RET_TRAP: u32 = 0x00030000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

const SIGSYS: i32 = 31;
const SA_SIGINFO: u64 = 0x0000_0004;
const SA_RESTORER: u64 = 0x0400_0000;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const TRAP_DATA: u32 = 42;
const SYS_GETPPID: u32 = 110;

const SYS_GETPRIORITY: i32 = 140;

#[repr(C)]
#[derive(Copy, Clone)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    _pad: [u8; 6],
    filter: *const SockFilter,
}

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x05 | 0x10;
const BPF_RET_K: u16 = 0x06;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct KSigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

static mut HANDLER_RAN: i32 = 0;
static mut SEEN_SIGNO: i32 = -1;
static mut SEEN_CODE: i32 = 0;
static mut SEEN_ERRNO: i32 = 0;
static mut SEEN_SYSCALL: i32 = 0;
static mut SEEN_ARCH: u32 = 0;

extern "C" fn sigsys_handler(signum: i32, info: *const u8, _ctx: *const u8) {
    unsafe {
        core::ptr::write_volatile(&raw mut SEEN_SIGNO, signum);
        core::ptr::write_volatile(&raw mut SEEN_ERRNO, core::ptr::read_volatile(info.add(4) as *const i32));
        core::ptr::write_volatile(&raw mut SEEN_CODE, core::ptr::read_volatile(info.add(8) as *const i32));
        core::ptr::write_volatile(&raw mut SEEN_SYSCALL, core::ptr::read_volatile(info.add(24) as *const i32));
        core::ptr::write_volatile(&raw mut SEEN_ARCH, core::ptr::read_volatile(info.add(28) as *const u32));
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
    log("seccomp test starting\n");

    if sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0) != 0 {
        log("PR_SET_NO_NEW_PRIVS: failed\n");
        sys_exit(1);
    }
    if sys_prctl(PR_GET_NO_NEW_PRIVS, 0, 0) != 1 {
        log("PR_GET_NO_NEW_PRIVS: not 1\n");
        sys_exit(1);
    }
    log("PR_SET/GET_NO_NEW_PRIVS OK\n");

    let filter: [SockFilter; 4] = [
        SockFilter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        SockFilter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: SYS_GETPRIORITY as u32,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | 13,
        },
        SockFilter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];
    let prog = SockFprog {
        len: 4,
        _pad: [0; 6],
        filter: filter.as_ptr(),
    };
    let r = sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog as *const SockFprog as u64);
    if r != 0 {
        log("seccomp install: ");
        log_num(r);
        sys_exit(1);
    }
    log("seccomp install filter OK\n");

    let r = sys_getpriority(0, 0);
    if r != -13 {
        log("getpriority: expected -13 got ");
        log_num(r);
        sys_exit(1);
    }
    log("getpriority -> -EACCES via seccomp ERRNO OK\n");

    let pid = sys_getpid();
    if pid <= 0 {
        log("getpid broken: ");
        log_num(pid as i64);
        sys_exit(1);
    }
    log("getpid still works through filter OK\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork: ");
        log_num(pid);
        sys_exit(1);
    }
    if pid == 0 {
        let kill_filter: [SockFilter; 4] = [
            SockFilter {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: 110,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: 0x00000000,
            },
            SockFilter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            },
        ];
        let kp = SockFprog {
            len: 4,
            _pad: [0; 6],
            filter: kill_filter.as_ptr(),
        };
        if sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, &kp as *const SockFprog as u64) != 0 {
            sys_exit(40);
        }
        let _ = sys_getppid();
        sys_exit(41);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let signaled = (st & 0x7f) != 0;
    if !signaled {
        log("KILL_PROCESS child not signaled: ");
        log_num(st as i64);
        sys_exit(1);
    }
    log("seccomp KILL_PROCESS via filter OK\n");

    let pid = sys_fork();
    if pid < 0 {
        log("trap fork: ");
        log_num(pid);
        sys_exit(1);
    }
    if pid == 0 {
        let act = KSigAction {
            handler: sigsys_handler as *const () as u64,
            flags: SA_SIGINFO | SA_RESTORER,
            restorer: signal_restorer as *const () as u64,
            mask: 0,
        };
        if sys_rt_sigaction(SIGSYS, &act, core::ptr::null_mut(), 8) != 0 {
            sys_exit(50);
        }
        let trap_filter: [SockFilter; 4] = [
            SockFilter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 0 },
            SockFilter { code: BPF_JMP_JEQ_K, jt: 0, jf: 1, k: SYS_GETPPID },
            SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_TRAP | TRAP_DATA },
            SockFilter { code: BPF_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW },
        ];
        let tp = SockFprog {
            len: 4,
            _pad: [0; 6],
            filter: trap_filter.as_ptr(),
        };
        if sys_seccomp(SECCOMP_SET_MODE_FILTER, 0, &tp as *const SockFprog as u64) != 0 {
            sys_exit(51);
        }
        let r = sys_getppid();
        if r != -38 {
            sys_exit(52);
        }
        unsafe {
            if core::ptr::read_volatile(&raw const HANDLER_RAN) != 1 {
                sys_exit(53);
            }
            if core::ptr::read_volatile(&raw const SEEN_SIGNO) != SIGSYS {
                sys_exit(54);
            }
            if core::ptr::read_volatile(&raw const SEEN_CODE) != 1 {
                sys_exit(55);
            }
            if core::ptr::read_volatile(&raw const SEEN_ERRNO) != TRAP_DATA as i32 {
                sys_exit(56);
            }
            if core::ptr::read_volatile(&raw const SEEN_SYSCALL) != SYS_GETPPID as i32 {
                sys_exit(57);
            }
            if core::ptr::read_volatile(&raw const SEEN_ARCH) != AUDIT_ARCH_X86_64 {
                sys_exit(58);
            }
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    if (st & 0x7f) != 0 {
        log("RET_TRAP child was signaled, not a clean exit: ");
        log_num(st as i64);
        sys_exit(1);
    }
    if ((st >> 8) & 0xff) != 0 {
        log("RET_TRAP child exit nonzero: ");
        log_num(((st >> 8) & 0xff) as i64);
        sys_exit(1);
    }
    log("seccomp RET_TRAP -> synchronous SIGSYS OK\n");

    log("all seccomp tests OK\n");
    sys_exit(0);
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

#[inline(never)]
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

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_prctl(opt: u64, a2: u64, a3: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 157u64, in("rdi") opt, in("rsi") a2, in("rdx") a3,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_seccomp(op: u64, flags: u64, args: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 317u64, in("rdi") op, in("rsi") flags, in("rdx") args,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_getpriority(which: i32, who: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 140u64, in("rdi") which as i64, in("rsi") who as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_getpid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

#[inline(never)]
fn sys_getppid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 110u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

#[inline(never)]
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_wait4(pid: i32, status: *mut i32, options: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid as i64, in("rsi") status,
        in("rdx") options as i64, in("r10") 0u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}

#[allow(dead_code)]
const _UNUSED: u64 = PR_SET_NAME;
