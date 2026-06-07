#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("syscalls test starting\n");

    let cur = sys_brk(0);
    if cur == 0 {
        log("brk(0) returned 0\n");
        sys_exit(1);
    }
    log("brk(0) OK\n");

    let new_brk = sys_brk(cur + 0x2000);
    if new_brk < cur + 0x2000 {
        log("brk grow failed\n");
        sys_exit(1);
    }
    log("brk grow OK\n");

    unsafe {
        core::ptr::write_volatile(cur as *mut u8, 0x42);
        if core::ptr::read_volatile(cur as *const u8) != 0x42 {
            log("heap rw failed\n");
            sys_exit(1);
        }
    }
    log("heap rw OK\n");

    let mmap_addr = sys_mmap(0, 0x1000, 0x3, 0x22, !0u64, 0);
    if (mmap_addr as i64) < 0 {
        log("mmap failed\n");
        sys_exit(1);
    }
    log("mmap OK\n");

    unsafe {
        core::ptr::write_volatile(mmap_addr as *mut u32, 0xDEAD_BEEF);
        if core::ptr::read_volatile(mmap_addr as *const u32) != 0xDEAD_BEEF {
            log("mmap rw failed\n");
            sys_exit(1);
        }
    }
    log("mmap rw OK\n");

    let r = sys_munmap(mmap_addr, 0x1000);
    if r != 0 {
        log("munmap failed\n");
        sys_exit(1);
    }
    log("munmap OK\n");

    let req: [u64; 2] = [0, 1_000_000];
    let r = sys_nanosleep(req.as_ptr() as u64, 0);
    if r != 0 {
        log("nanosleep failed\n");
        sys_exit(1);
    }
    log("nanosleep OK\n");

    const ENOSYS: i64 = -38;
    const EPERM: i64 = -1;
    let enosys_nrs: [u64; 12] = [
        156,
        134,
        174,
        178,
        183,
        181,
        175,
        176,
        205,
        211,
        154,
        214,
    ];
    for &nr in enosys_nrs.iter() {
        if raw_syscall0(nr) != ENOSYS {
            log("legacy syscall did not return -ENOSYS: nr=");
            log_num(nr as i64);
            sys_exit(1);
        }
    }
    let eperm_nrs: [u64; 4] = [
        172,
        173,
        246,
        320,
    ];
    for &nr in eperm_nrs.iter() {
        if raw_syscall0(nr) != EPERM {
            log("privileged-refusal syscall did not return -EPERM: nr=");
            log_num(nr as i64);
            sys_exit(1);
        }
    }
    log("refused syscalls return correct errno OK\n");

    log("all syscalls OK\n");
    sys_exit(0);
}

#[inline(never)]
fn raw_syscall0(nr: u64) -> i64 {
    let r: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => r,
            out("rdi") _, out("rsi") _, out("rdx") _,
            out("r10") _, out("r8") _, out("r9") _,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn log_num(n: i64) {
    let mut buf = [0u8; 24];
    let mut i = 0usize;
    let neg = n < 0;
    let mut v = if neg { (-n) as u64 } else { n as u64 };
    if v == 0 {
        buf[i] = b'0';
        i += 1;
    } else {
        let mut d = [0u8; 24];
        let mut k = 0;
        while v > 0 {
            d[k] = b'0' + (v % 10) as u8;
            v /= 10;
            k += 1;
        }
        if neg {
            buf[i] = b'-';
            i += 1;
        }
        while k > 0 {
            k -= 1;
            buf[i] = d[k];
            i += 1;
        }
    }
    buf[i] = b'\n';
    i += 1;
    sys_write(1, buf.as_ptr(), i);
}

#[inline(never)]
fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

#[inline(never)]
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

#[inline(never)]
fn sys_brk(addr: u64) -> u64 {
    let r: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 12u64, in("rdi") addr,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> u64 {
    let r: u64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 9u64, in("rdi") addr, in("rsi") len, in("rdx") prot,
            in("r10") flags, in("r8") fd, in("r9") off,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_munmap(addr: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 11u64, in("rdi") addr, in("rsi") len,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_nanosleep(req: u64, rem: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 35u64, in("rdi") req, in("rsi") rem,
            lateout("rax") r, out("rcx") _, out("r11") _,
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
