#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Rlimit {
    cur: u64,
    max: u64,
}

const SIGRT: i32 = 34;
const SIG_BLOCK: u64 = 0;
const SI_QUEUE: i32 = -1;
const RLIMIT_SIGPENDING: u64 = 11;
const EAGAIN: i64 = -11;

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
    let lim = Rlimit { cur: 2, max: 2 };
    if sys_prlimit64(0, RLIMIT_SIGPENDING, &lim, core::ptr::null_mut()) != 0 {
        report(b"prlimit64 failed\n");
        sys_exit(1);
    }
    let block: u64 = 1u64 << SIGRT;
    let mut old: u64 = 0;
    if sys_rt_sigprocmask(SIG_BLOCK, &block, &mut old, 8) != 0 {
        report(b"sigprocmask failed\n");
        sys_exit(2);
    }

    let me = sys_getpid();
    if queue_rt(me, SIGRT, 1) != 0 || queue_rt(me, SIGRT, 2) != 0 {
        report(b"self queue under cap failed\n");
        sys_exit(3);
    }
    if queue_rt(me, SIGRT, 3) != EAGAIN {
        report(b"self queue at cap did not EAGAIN\n");
        sys_exit(4);
    }

    let pid = sys_fork();
    if pid < 0 {
        report(b"fork failed\n");
        sys_exit(5);
    }
    if pid == 0 {
        let clim = Rlimit { cur: 2, max: 2 };
        sys_prlimit64(0, RLIMIT_SIGPENDING, &clim, core::ptr::null_mut());
        let cself = sys_getpid();
        if queue_rt(cself, SIGRT, 4) == EAGAIN {
            sys_exit(0);
        }
        sys_exit(50);
    }

    let mut status: i32 = 0;
    if sys_wait4(pid as i32, &mut status, 0) != pid {
        report(b"wait4 wrong pid\n");
        sys_exit(6);
    }
    if (status & 0x7f) != 0 {
        report(b"child killed, not exited\n");
        sys_exit(7);
    }
    let code = (status >> 8) & 0xff;
    if code != 0 {
        report(b"per-uid not enforced: child queued despite uid at cap\n");
        sys_exit(8);
    }
    report(b"uid_sigpending: RLIMIT_SIGPENDING enforced per real-uid OK\n");
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

fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64, lateout("rax") r,
             out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_wait4(pid: i32, status: *mut i32, options: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 61u64, in("rdi") pid as i64, in("rsi") status,
            in("rdx") options, in("r10") 0u64,
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
