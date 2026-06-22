#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const SIGKILL: i32 = 9;
const CHUNK: u64 = 16 * 1024 * 1024;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let pid = sys_fork();
    if pid < 0 {
        report(b"fork failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        loop {
            let p = sys_mmap(
                0,
                CHUNK,
                PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE,
                u64::MAX,
                0,
            );
            if p < 0 {
                loop {
                    core::hint::spin_loop();
                }
            }
            let base = p as u64;
            let mut off = 0u64;
            while off < CHUNK {
                unsafe {
                    core::ptr::write_volatile((base + off) as *mut u8, 0x41);
                }
                off += 4096;
            }
        }
    }

    let mut status: i32 = 0;
    if sys_wait4(pid as i32, &mut status, 0) != pid {
        report(b"wait4 wrong pid\n");
        sys_exit(2);
    }
    let signaled = {
        let low = status & 0x7f;
        low != 0 && low != 0x7f
    };
    let termsig = status & 0x7f;
    if signaled && termsig == SIGKILL {
        report(b"oom: faulting task OOM-killed with SIGKILL OK\n");
        sys_exit(0);
    }
    report(b"oom: child not SIGKILL'd; termsig=");
    report_num(termsig as i64);
    sys_exit(3);
}

fn report(msg: &[u8]) {
    sys_write(1, msg.as_ptr(), msg.len());
}

fn report_num(n: i64) {
    let mut buf = [0u8; 8];
    let mut v = if n < 0 { (-n) as u64 } else { n as u64 };
    let mut i = 0;
    if v == 0 {
        buf[0] = b'0';
        i = 1;
    } else {
        let mut d = [0u8; 8];
        let mut k = 0;
        while v > 0 {
            d[k] = b'0' + (v % 10) as u8;
            v /= 10;
            k += 1;
        }
        while k > 0 {
            k -= 1;
            buf[i] = d[k];
            i += 1;
        }
    }
    sys_write(1, buf.as_ptr(), i);
    sys_write(1, b"\n".as_ptr(), 1);
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 9u64, in("rdi") addr, in("rsi") len,
            in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") off,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
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
