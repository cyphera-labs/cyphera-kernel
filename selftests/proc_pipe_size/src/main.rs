#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const O_NONBLOCK: u64 = 0o4000;
const F_SETPIPE_SZ: u64 = 1031;
const F_GETPIPE_SZ: u64 = 1032;
const DEFAULT_CAP: i64 = 65_536;
const EINVAL: i64 = -22;
const EBUSY: i64 = -16;

static SRC: [u8; 70_000] = [0u8; 70_000];

#[no_mangle]
pub extern "C" fn _start() -> ! {
    report(b"pipe_size: _start entered\n");

    let mut fds = [0i32; 2];
    if sys_pipe2(fds.as_mut_ptr(), O_NONBLOCK) != 0 {
        report(b"pipe2 failed\n");
        sys_exit(1);
    }
    let w = fds[1] as u64;

    if sys_fcntl(w, F_GETPIPE_SZ, 0) != DEFAULT_CAP {
        report(b"default F_GETPIPE_SZ != 65536\n");
        sys_exit(2);
    }
    let nc = sys_fcntl(w, F_SETPIPE_SZ, 131_072);
    if nc != 131_072 {
        report(b"F_SETPIPE_SZ(131072) did not return 131072\n");
        sys_exit(3);
    }
    if sys_fcntl(w, F_GETPIPE_SZ, 0) != 131_072 {
        report(b"F_GETPIPE_SZ after set != 131072\n");
        sys_exit(4);
    }

    let wrote = sys_write(w, SRC.as_ptr(), SRC.len());
    if wrote != SRC.len() as i64 {
        report(b"write of 70000 did not fit the resized pipe\n");
        sys_exit(5);
    }

    if sys_fcntl(w, F_SETPIPE_SZ, 4096) != EBUSY {
        report(b"shrink below buffered did not return EBUSY\n");
        sys_exit(6);
    }

    if sys_fcntl(1, F_GETPIPE_SZ, 0) != EINVAL {
        report(b"F_GETPIPE_SZ on a non-pipe did not return EINVAL\n");
        sys_exit(7);
    }

    report(b"pipe_size: ALL OK\n");
    sys_exit(0);
}

fn report(msg: &[u8]) {
    sys_write(1, msg.as_ptr(), msg.len());
}

fn sys_pipe2(fds: *mut i32, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 293u64, in("rdi") fds, in("rsi") flags,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 72u64, in("rdi") fd, in("rsi") cmd, in("rdx") arg,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
