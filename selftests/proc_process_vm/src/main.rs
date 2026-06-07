#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const SYS_WRITE: u64 = 1;
const SYS_FORK: u64 = 57;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;
const SYS_GETPID: u64 = 39;
const SYS_PROCESS_VM_READV: u64 = 310;
const SYS_PROCESS_VM_WRITEV: u64 = 311;
const SYS_SETRESUID: u64 = 117;

const EPERM: i64 = -1;

#[repr(C)]
#[derive(Copy, Clone)]
struct Iovec {
    base: u64,
    len: u64,
}

static mut PARENT_SRC: [u8; 64] = [0u8; 64];
static mut PARENT_DST: [u8; 64] = [0u8; 64];
static mut HANDSHAKE: [u32; 4] = [0u32; 4];

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("process_vm test starting\n");

    unsafe {
        for i in 0..64 {
            PARENT_SRC[i] = i as u8 ^ 0xA5;
        }
    }
    let parent_pid = sys_getpid();
    let parent_src_addr = core::ptr::addr_of!(PARENT_SRC) as u64;
    let parent_dst_addr = core::ptr::addr_of_mut!(PARENT_DST) as u64;
    let handshake_addr = core::ptr::addr_of_mut!(HANDSHAKE) as u64;

    let pid = sys_fork();
    if pid < 0 {
        log("fork #1 failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        let mut local: [u8; 64] = [0u8; 64];
        let liov = Iovec {
            base: local.as_mut_ptr() as u64,
            len: 64,
        };
        let riov = Iovec {
            base: parent_src_addr,
            len: 64,
        };
        let n = sys_process_vm_readv(parent_pid as u64, &liov, 1, &riov, 1, 0);
        if n != 64 {
            sys_exit(11);
        }
        for i in 0..64 {
            if local[i] != ((i as u8) ^ 0xA5) {
                sys_exit(12);
            }
        }
        for i in 0..64 {
            local[i] = (i as u8).wrapping_mul(7);
        }
        let liov_w = Iovec {
            base: local.as_ptr() as u64,
            len: 64,
        };
        let riov_w = Iovec {
            base: parent_dst_addr,
            len: 64,
        };
        let n = sys_process_vm_writev(parent_pid as u64, &liov_w, 1, &riov_w, 1, 0);
        if n != 64 {
            sys_exit(13);
        }
        let one: u32 = 1;
        let liov_h = Iovec {
            base: &one as *const u32 as u64,
            len: 4,
        };
        let riov_h = Iovec {
            base: handshake_addr,
            len: 4,
        };
        let _ = sys_process_vm_writev(parent_pid as u64, &liov_h, 1, &riov_h, 1, 0);
        sys_exit(0);
    }
    let mut st: i32 = 0;
    let r = sys_wait4(pid, &mut st, 0, 0);
    if r != pid || (st & 0xff) != 0 {
        log("child #1 didn't exit cleanly; st=");
        log_num(st as i64);
        sys_exit(2);
    }
    unsafe {
        for i in 0..64 {
            if PARENT_DST[i] != (i as u8).wrapping_mul(7) {
                log("PARENT_DST mismatch at i=");
                log_num(i as i64);
                sys_exit(3);
            }
        }
    }
    log("process_vm: readv + writev round-trip OK\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork #2 failed\n");
        sys_exit(4);
    }
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(21);
        }
        let mut local: [u8; 64] = [0u8; 64];
        let liov = Iovec {
            base: local.as_mut_ptr() as u64,
            len: 64,
        };
        let riov = Iovec {
            base: parent_src_addr,
            len: 64,
        };
        let r = sys_process_vm_readv(parent_pid as u64, &liov, 1, &riov, 1, 0);
        if r != EPERM {
            sys_exit(22);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    let r = sys_wait4(pid, &mut st, 0, 0);
    if r != pid || (st & 0xff) != 0 {
        log("child #2 (perm) didn't exit cleanly; st=");
        log_num(st as i64);
        sys_exit(5);
    }
    log("process_vm: non-root readv -> EPERM OK\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork #3 failed\n");
        sys_exit(6);
    }
    if pid == 0 {
        let mut local_a: [u8; 32] = [0u8; 32];
        let mut local_b: [u8; 32] = [0u8; 32];
        let liov: [Iovec; 2] = [
            Iovec {
                base: local_a.as_mut_ptr() as u64,
                len: 32,
            },
            Iovec {
                base: local_b.as_mut_ptr() as u64,
                len: 32,
            },
        ];
        let riov = Iovec {
            base: parent_src_addr,
            len: 16,
        };
        let n = sys_process_vm_readv(parent_pid as u64, liov.as_ptr(), 2, &riov, 1, 0);
        if n != 16 {
            sys_exit(31);
        }
        for i in 0..16 {
            if local_a[i] != ((i as u8) ^ 0xA5) {
                sys_exit(32);
            }
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    let r = sys_wait4(pid, &mut st, 0, 0);
    if r != pid || (st & 0xff) != 0 {
        log("child #3 (partial) didn't exit cleanly; st=");
        log_num(st as i64);
        sys_exit(7);
    }
    log("process_vm: iovec partial coverage OK\n");

    log("PROCESS_VM_OK\n");
    sys_exit(0);
}

fn log(msg: &str) {
    sys_write(1, msg.as_ptr(), msg.len());
}

fn log_num(n: i64) {
    let mut buf = [0u8; 24];
    let mut i = 0usize;
    let neg = n < 0;
    let mut v = if neg { -n as u64 } else { n as u64 };
    if v == 0 {
        buf[i] = b'0';
        i += 1;
    } else {
        let mut tmp = [0u8; 24];
        let mut j = 0usize;
        while v > 0 {
            tmp[j] = b'0' + (v % 10) as u8;
            v /= 10;
            j += 1;
        }
        if neg {
            buf[i] = b'-';
            i += 1;
        }
        while j > 0 {
            j -= 1;
            buf[i] = tmp[j];
            i += 1;
        }
    }
    buf[i] = b'\n';
    sys_write(1, buf.as_ptr(), i + 1);
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_WRITE, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_FORK, lateout("rax") r,
            out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_GETPID, lateout("rax") r,
            out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_wait4(pid: i64, status: *mut i32, options: u64, rusage: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_WAIT4, in("rdi") pid as u64, in("rsi") status,
            in("rdx") options, in("r10") rusage, lateout("rax") r,
            out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_setresuid(r: u32, e: u32, s: u32) -> i64 {
    let ret: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_SETRESUID, in("rdi") r as u64,
            in("rsi") e as u64, in("rdx") s as u64,
            lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

fn sys_process_vm_readv(
    pid: u64,
    liov: *const Iovec,
    liovcnt: u64,
    riov: *const Iovec,
    riovcnt: u64,
    flags: u64,
) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall",
            in("rax") SYS_PROCESS_VM_READV,
            in("rdi") pid, in("rsi") liov, in("rdx") liovcnt,
            in("r10") riov, in("r8") riovcnt, in("r9") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_process_vm_writev(
    pid: u64,
    liov: *const Iovec,
    liovcnt: u64,
    riov: *const Iovec,
    riovcnt: u64,
    flags: u64,
) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall",
            in("rax") SYS_PROCESS_VM_WRITEV,
            in("rdi") pid, in("rsi") liov, in("rdx") liovcnt,
            in("r10") riov, in("r8") riovcnt, in("r9") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") SYS_EXIT, in("rdi") code as u64,
            options(noreturn, nostack));
    }
}
