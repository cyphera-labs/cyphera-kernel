#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const O_RDONLY: u64 = 0o0;
const O_WRONLY: u64 = 0o1;
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
    let blocks = count_occurrences(&buf[..n as usize], b"processor\t");
    let online = affinity_popcount();
    if online == 0 || blocks != online {
        log("/proc/cpuinfo processor-block count != online CPUs\n");
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

    let mut b1 = [0u8; 64];
    if read_path(b"/proc/sys/kernel/random/boot_id\0", &mut b1) < 37 {
        log("read boot_id #1 failed\n");
        sys_exit(1);
    }
    let mut b2 = [0u8; 64];
    if read_path(b"/proc/sys/kernel/random/boot_id\0", &mut b2) < 37 {
        log("read boot_id #2 failed\n");
        sys_exit(1);
    }
    if !uuid_shape_ok(&b1[..36]) {
        log("boot_id not canonical v4 shape\n");
        sys_exit(1);
    }
    if b1[..36] != b2[..36] {
        log("boot_id not stable across opens\n");
        sys_exit(1);
    }
    if &b1[..36] == b"00000000-0000-0000-0000-000000000001" {
        log("boot_id is the old hardcoded placeholder\n");
        sys_exit(1);
    }
    log("/proc/sys/kernel/random/boot_id stable + random OK\n");

    let mut lb = [0u8; 16];
    let n = read_path(b"/proc/self/loginuid\0", &mut lb);
    if n <= 0 || &lb[..n as usize] != b"4294967295\n" {
        log("/proc/self/loginuid default not unset\n");
        sys_exit(1);
    }
    if write_path(b"/proc/self/loginuid\0", b"1000") < 0 {
        log("/proc/self/loginuid write failed\n");
        sys_exit(1);
    }
    let n = read_path(b"/proc/self/loginuid\0", &mut lb);
    if n <= 0 || &lb[..n as usize] != b"1000\n" {
        log("/proc/self/loginuid did not persist write\n");
        sys_exit(1);
    }
    let pid = sys_fork();
    if pid < 0 {
        log("loginuid fork failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        let mut cb = [0u8; 16];
        let cn = read_path(b"/proc/self/loginuid\0", &mut cb);
        if cn > 0 && &cb[..cn as usize] == b"1000\n" {
            sys_exit(0);
        }
        sys_exit(42);
    }
    let mut status: i32 = 0;
    if sys_wait4(pid, &mut status as *mut i32, 0) != pid {
        log("loginuid wait4 failed\n");
        sys_exit(1);
    }
    if (status & 0x7f) != 0 || ((status >> 8) & 0xff) != 0 {
        log("/proc/self/loginuid not inherited by child\n");
        sys_exit(1);
    }
    log("/proc/self/loginuid set + persist + inherit OK\n");

    const RLIMIT_NOFILE: u64 = 7;
    let set = Rlimit { cur: 128, max: 128 };
    if sys_prlimit64(0, RLIMIT_NOFILE, &set as *const Rlimit as u64, 0) != 0 {
        log("prlimit64 RLIMIT_NOFILE failed\n");
        sys_exit(1);
    }
    let mut st = [0u8; 2048];
    let n = read_path(b"/proc/self/status\0", &mut st);
    if n <= 0 {
        log("read /proc/self/status failed\n");
        sys_exit(1);
    }
    let st = &st[..n as usize];
    let pos = match find(st, b"FDSize:\t") {
        Some(p) => p + b"FDSize:\t".len(),
        None => {
            log("/proc/self/status missing FDSize\n");
            sys_exit(1);
        }
    };
    let mut val: u64 = 0;
    let mut saw = false;
    let mut i = pos;
    while i < st.len() && st[i].is_ascii_digit() {
        val = val * 10 + (st[i] - b'0') as u64;
        saw = true;
        i += 1;
    }
    if !saw || val != 128 {
        log("/proc/self/status FDSize != RLIMIT_NOFILE soft cap\n");
        sys_exit(1);
    }
    log("/proc/self/status FDSize reflects RLIMIT_NOFILE OK\n");

    log("all procfs reads OK\n");
    sys_exit(0);
}

fn write_path(path: &[u8], data: &[u8]) -> i64 {
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_WRONLY, 0);
    if fd < 0 {
        return fd;
    }
    let r = sys_write(fd as u64, data.as_ptr(), data.len());
    sys_close(fd as u64);
    r
}

#[inline(never)]
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_wait4(pid: i64, status: *mut i32, options: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 61u64, in("rdi") pid, in("rsi") status,
            in("rdx") options, in("r10") 0u64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
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

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> u32 {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    let mut n = 0u32;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            n += 1;
            i += needle.len();
        } else {
            i += 1;
        }
    }
    n
}

fn affinity_popcount() -> u32 {
    let mut mask = [0u8; 128];
    let r = sys_sched_getaffinity(0, mask.len() as u64, mask.as_mut_ptr());
    if r <= 0 {
        return 0;
    }
    let mut bits = 0u32;
    for b in mask.iter().take(r as usize) {
        bits += b.count_ones();
    }
    bits
}

fn sys_sched_getaffinity(pid: u64, len: u64, mask: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 204u64, in("rdi") pid, in("rsi") len, in("rdx") mask,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
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

#[repr(C)]
struct Rlimit {
    cur: u64,
    max: u64,
}

#[inline(never)]
fn sys_prlimit64(pid: u64, resource: u64, new_rlim: u64, old_rlim: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 302u64, in("rdi") pid, in("rsi") resource,
            in("rdx") new_rlim, in("r10") old_rlim,
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
