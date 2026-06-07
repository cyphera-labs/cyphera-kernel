#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(2);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut storm = 0i32;
    while storm < 200 {
        let c = sys_fork();
        if c < 0 {
            let m = b"storm: fork failed\n";
            sys_write(1, m.as_ptr(), m.len());
            sys_exit(10);
        }
        if c == 0 {
            sys_exit(storm & 0x7f);
        }
        let mut st: i32 = 0;
        let reaped = sys_wait4(-1, &mut st as *mut i32, 0, core::ptr::null_mut());
        if reaped != c as i64 {
            let m = b"storm: wait4 reaped wrong pid\n";
            sys_write(1, m.as_ptr(), m.len());
            sys_exit(11);
        }
        if (st & 0x7f) != 0 || ((st >> 8) & 0xff) != (storm & 0x7f) {
            let m = b"storm: wrong child exit status\n";
            sys_write(1, m.as_ptr(), m.len());
            sys_exit(12);
        }
        storm += 1;
    }
    {
        let m = b"wait4 storm (200x fork+park+reap) OK\n";
        sys_write(1, m.as_ptr(), m.len());
    }

    let r = sys_fork();
    if r < 0 {
        let m = b"fork failed\n";
        sys_write(1, m.as_ptr(), m.len());
        sys_exit(1);
    }
    if r == 0 {
        let m = b"child: exiting 42\n";
        sys_write(1, m.as_ptr(), m.len());
        sys_exit(42);
    }

    let child = r as i32;
    let mut buf = [0u8; 64];
    let n = format_kv(&mut buf, b"parent: forked child=", child as i64);
    sys_write(1, buf.as_ptr(), n);

    let mut status: i32 = 0;
    let reaped = sys_wait4(-1, &mut status as *mut i32, 0, core::ptr::null_mut());
    if reaped < 0 {
        let m = b"parent: wait4 returned negative\n";
        sys_write(1, m.as_ptr(), m.len());
        sys_exit(3);
    }
    let normal_exit = (status & 0x7f) == 0;
    let exit_code = (status >> 8) & 0xff;
    let mut buf2 = [0u8; 96];
    let n2 = format_kv(&mut buf2, b"parent: wait4 reaped=", reaped as i64);
    sys_write(1, buf2.as_ptr(), n2);
    let mut buf3 = [0u8; 96];
    let n3 = format_kv(&mut buf3, b"parent: exit_status=", exit_code as i64);
    sys_write(1, buf3.as_ptr(), n3);
    if !normal_exit {
        let m = b"parent: child terminated by signal, expected normal exit\n";
        sys_write(1, m.as_ptr(), m.len());
        sys_exit(4);
    }

    let m = b"parent: exiting\n";
    sys_write(1, m.as_ptr(), m.len());
    sys_exit(0);
}

fn format_kv(buf: &mut [u8], prefix: &[u8], n: i64) -> usize {
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

fn sys_wait4(pid: i32, status: *mut i32, options: i32, rusage: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 61u64,
            in("rdi") pid as i64,
            in("rsi") status,
            in("rdx") options as i64,
            in("r10") rusage,
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
