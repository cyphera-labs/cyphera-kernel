#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SYS_CLOCK_GETTIME: u64 = 228;
const CLOCK_MONOTONIC: u64 = 1;
const O_WRONLY: i32 = 1;
const AT_FDCWD: i32 = -100;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

fn now_ns() -> u64 {
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_CLOCK_GETTIME,
            in("rdi") CLOCK_MONOTONIC,
            in("rsi") &mut ts as *mut _,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    if r != 0 {
        return 0;
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn write_file(path: &[u8], data: &[u8]) -> i64 {
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_WRONLY, 0);
    if fd < 0 {
        return fd;
    }
    let n = sys_write(fd as u64, data.as_ptr(), data.len());
    let _ = sys_close(fd as i32);
    if n != data.len() as i64 { -1 } else { 0 }
}

fn format_pid(pid: i32, buf: &mut [u8]) -> usize {
    if pid == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 16];
    let mut d = 0;
    let mut v = pid as u32;
    while v > 0 {
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
        d += 1;
    }
    for i in 0..d {
        buf[i] = digits[d - 1 - i];
    }
    d
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("cpu_throttle test starting\n");

    let r = sys_mkdir(b"/sys/fs/cgroup/cputest\0".as_ptr(), 0o755);
    if r != 0 {
        log("mkdir failed: ");
        log_num(r);
        sys_exit(1);
    }

    if write_file(b"/sys/fs/cgroup/cputest/cpu.max\0", b"10000 100000") < 0 {
        log("cpu.max write failed\n");
        sys_exit(1);
    }
    log("cpu.max = 10ms/100ms (10%)\n");

    let base_start = now_ns();
    let base_target = base_start + 100_000_000;
    let mut units: u64 = 0;
    while now_ns() < base_target {
        do_work_unit();
        units += 1;
    }
    let baseline_wall = now_ns() - base_start;
    if units == 0 || baseline_wall == 0 {
        log("baseline produced no work\n");
        sys_exit(1);
    }

    let pid = sys_getpid();
    let mut buf = [0u8; 16];
    let n = format_pid(pid, &mut buf);
    if write_file(b"/sys/fs/cgroup/cputest/cgroup.procs\0", &buf[..n]) < 0 {
        log("migrate failed\n");
        sys_exit(1);
    }
    log("migrated into cputest\n");

    let work_start = now_ns();
    for _ in 0..units {
        do_work_unit();
    }
    let work_wall = now_ns() - work_start;

    let _ = write_file(b"/sys/fs/cgroup/cgroup.procs\0", &buf[..n]);

    log("baseline ");
    log_num((baseline_wall / 1_000_000) as i64);
    log(" ms vs throttled ");
    log_num((work_wall / 1_000_000) as i64);
    log(" ms for ");
    log_num(units as i64);
    log(" units\n");
    if work_wall < baseline_wall.saturating_mul(3) {
        log("throttled work not stretched >=3x: cpu.max did not limit CPU\n");
        sys_exit(1);
    }

    log("CPU_THROTTLE_OK\n");
    sys_exit(0);
}

#[inline(never)]
fn do_work_unit() {
    for _ in 0..200 {
        unsafe { core::arch::asm!("pause", options(nostack, nomem)) };
    }
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
fn sys_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 257u64, in("rdi") dirfd as i64,
            in("rsi") path, in("rdx") flags as i64, in("r10") mode as u64,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_close(fd: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 3u64, in("rdi") fd as i64,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_mkdir(path: *const u8, mode: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 258u64, in("rdi") AT_FDCWD as i64,
            in("rsi") path, in("rdx") mode as u64,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_getpid() -> i32 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 39u64, lateout("rax") r,
            out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r as i32
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
    sys_write(1, buf.as_ptr(), i);
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") 60u64, in("rdi") code as u64,
            options(noreturn, nostack),
        );
    }
}
