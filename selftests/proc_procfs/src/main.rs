#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const O_RDONLY: u64 = 0o0;
const AT_FDCWD: i64 = -100;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("procfs test starting\n");

    let mut buf = [0u8; 1024];
    let n = read_path(b"/proc/cpuinfo\0", &mut buf);
    if n <= 0 {
        log("read /proc/cpuinfo failed\n");
        sys_exit(1);
    }
    if find(&buf[..n as usize], b"vendor_id").is_none() {
        log("/proc/cpuinfo missing vendor_id\n");
        sys_exit(1);
    }
    if find(&buf[..n as usize], b"CypheraVM").is_none() {
        log("/proc/cpuinfo missing CypheraVM\n");
        sys_exit(1);
    }
    log("/proc/cpuinfo OK\n");

    let n = read_path(b"/proc/meminfo\0", &mut buf);
    if n <= 0 {
        log("read /proc/meminfo failed\n");
        sys_exit(1);
    }
    if find(&buf[..n as usize], b"MemTotal:").is_none() {
        log("/proc/meminfo missing MemTotal\n");
        sys_exit(1);
    }
    if find(&buf[..n as usize], b"MemFree:").is_none() {
        log("/proc/meminfo missing MemFree\n");
        sys_exit(1);
    }
    log("/proc/meminfo OK\n");

    let n = read_path(b"/proc/uptime\0", &mut buf);
    if n <= 0 {
        log("read /proc/uptime failed\n");
        sys_exit(1);
    }
    if find(&buf[..n as usize], b".").is_none() {
        log("/proc/uptime not a float\n");
        sys_exit(1);
    }
    log("/proc/uptime OK\n");

    let n = read_path(b"/proc/self/stat\0", &mut buf);
    if n <= 0 {
        log("read /proc/self/stat failed\n");
        sys_exit(1);
    }
    if find(&buf[..n as usize], b"(proc_procfs)").is_none() {
        log("/proc/self/stat missing comm\n");
        sys_exit(1);
    }
    if find(&buf[..n as usize], b" R ").is_none() {
        log("/proc/self/stat state != R\n");
        sys_exit(1);
    }
    log("/proc/self/stat OK\n");

    let mut u1 = [0u8; 64];
    if read_path(b"/proc/sys/kernel/random/uuid\0", &mut u1) < 37 {
        log("read uuid #1 failed\n");
        sys_exit(1);
    }
    let mut u2 = [0u8; 64];
    if read_path(b"/proc/sys/kernel/random/uuid\0", &mut u2) < 37 {
        log("read uuid #2 failed\n");
        sys_exit(1);
    }
    if !uuid_shape_ok(&u1[..36]) || !uuid_shape_ok(&u2[..36]) {
        log("uuid not canonical v4 shape\n");
        sys_exit(1);
    }
    if u1[..36] == u2[..36] {
        log("uuid is constant across opens\n");
        sys_exit(1);
    }
    log("/proc/sys/kernel/random/uuid OK\n");

    log("all procfs reads OK\n");
    sys_exit(0);
}

fn uuid_shape_ok(s: &[u8]) -> bool {
    if s.len() != 36 {
        return false;
    }
    for (i, &c) in s.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            14 => {
                if c != b'4' {
                    return false;
                }
            }
            19 => {
                if !matches!(c, b'8' | b'9' | b'a' | b'b') {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn read_path(path: &[u8], buf: &mut [u8]) -> i64 {
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let mut total = 0usize;
    loop {
        let n = sys_read(
            fd as u64,
            unsafe { buf.as_mut_ptr().add(total) },
            buf.len() - total,
        );
        if n < 0 {
            sys_close(fd as u64);
            return n;
        }
        if n == 0 {
            break;
        }
        total += n as usize;
        if total >= buf.len() {
            break;
        }
    }
    sys_close(fd as u64);
    total as i64
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
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
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 3u64, in("rdi") fd,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i64, pathname: *const u8, flags: u64, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 257u64, in("rdi") dirfd, in("rsi") pathname,
            in("rdx") flags, in("r10") mode,
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
