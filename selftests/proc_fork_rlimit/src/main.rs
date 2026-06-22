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

const RLIMIT_NOFILE: u64 = 7;
const CUR: u64 = 64;
const MAX: u64 = 256;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let set = Rlimit { cur: CUR, max: MAX };
    if sys_prlimit64(0, RLIMIT_NOFILE, &set, core::ptr::null_mut()) != 0 {
        report(b"prlimit64 set failed\n");
        sys_exit(1);
    }

    let pid = sys_fork();
    if pid < 0 {
        report(b"fork failed\n");
        sys_exit(2);
    }
    if pid == 0 {
        let mut got = Rlimit { cur: 0, max: 0 };
        if sys_prlimit64(0, RLIMIT_NOFILE, core::ptr::null(), &mut got) != 0 {
            sys_exit(40);
        }
        if got.cur == CUR && got.max == MAX {
            sys_exit(0);
        }
        sys_exit(41);
    }

    let mut status: i32 = 0;
    if sys_wait4(pid as i32, &mut status, 0) != pid {
        report(b"wait4 wrong pid\n");
        sys_exit(3);
    }
    if (status & 0x7f) != 0 {
        report(b"child killed\n");
        sys_exit(4);
    }
    if ((status >> 8) & 0xff) != 0 {
        report(b"fork did not inherit rlimits (child saw defaults)\n");
        sys_exit(5);
    }
    report(b"fork_rlimit: child inherited the parent's rlimits OK\n");
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
