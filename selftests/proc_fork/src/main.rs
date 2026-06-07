#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(2);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let pre = b"parent: pre-fork\n";
    sys_write(1, pre.as_ptr(), pre.len());

    let r = sys_fork();
    if r < 0 {
        let m = b"fork failed\n";
        sys_write(1, m.as_ptr(), m.len());
        sys_exit(1);
    }
    if r == 0 {
        let mut buf = [0u8; 32];
        let n = format_line(&mut buf, b"child: getpid=", sys_getpid() as i64);
        sys_write(1, buf.as_ptr(), n);
        let m = b"child: exiting\n";
        sys_write(1, m.as_ptr(), m.len());
        sys_exit(0);
    } else {
        let mut buf = [0u8; 32];
        let n = format_line(&mut buf, b"parent: fork returned pid=", r);
        sys_write(1, buf.as_ptr(), n);
        let m = b"parent: exiting\n";
        sys_write(1, m.as_ptr(), m.len());
        sys_exit(0);
    }
}

fn format_line(buf: &mut [u8], prefix: &[u8], n: i64) -> usize {
    let mut i = 0;
    for &b in prefix {
        buf[i] = b;
        i += 1;
    }
    let mut digits = [0u8; 16];
    let mut d = 0;
    let mut v = if n < 0 {
        buf[i] = b'-';
        i += 1;
        (-n) as u64
    } else {
        n as u64
    };
    if v == 0 {
        digits[0] = b'0';
        d = 1;
    } else {
        while v > 0 {
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            d += 1;
        }
    }
    while d > 0 {
        d -= 1;
        buf[i] = digits[d];
        i += 1;
    }
    buf[i] = b'\n';
    i += 1;
    i
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 57u64,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 39u64,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
