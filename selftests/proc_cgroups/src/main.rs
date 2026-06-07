#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const AT_FDCWD: i32 = -100;

const ENOTEMPTY: i64 = -39;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("cgroups test starting\n");

    let controllers = read_file(b"/sys/fs/cgroup/cgroup.controllers\0".as_ptr());
    if !contains(&controllers, b"memory") || !contains(&controllers, b"pids") {
        log("controllers wrong: ");
        sys_write(1, controllers.as_ptr(), controllers.len());
        sys_exit(1);
    }
    log("cgroup.controllers OK\n");

    let my_pid = sys_getpid();
    let procs_root_before = read_file(b"/sys/fs/cgroup/cgroup.procs\0".as_ptr());
    if !contains_pid(&procs_root_before, my_pid) {
        log("self pid not in root cgroup.procs\n");
        sys_exit(1);
    }
    log("self pid in root cgroup.procs OK\n");

    let r = sys_mkdir(b"/sys/fs/cgroup/test1\0".as_ptr(), 0o755);
    if r != 0 {
        log("mkdir /sys/fs/cgroup/test1: ");
        log_num(r);
        sys_exit(1);
    }
    log("mkdir /sys/fs/cgroup/test1 OK\n");

    let mmax = read_file(b"/sys/fs/cgroup/test1/memory.max\0".as_ptr());
    if !starts_with(&mmax, b"max") {
        log("default memory.max not 'max'\n");
        sys_exit(1);
    }
    log("default memory.max = max OK\n");

    if write_file(b"/sys/fs/cgroup/test1/memory.max\0".as_ptr(), b"1048576") < 0 {
        log("write memory.max failed\n");
        sys_exit(1);
    }

    let mmax2 = read_file(b"/sys/fs/cgroup/test1/memory.max\0".as_ptr());
    if !starts_with(&mmax2, b"1048576") {
        log("memory.max read-back wrong: ");
        sys_write(1, mmax2.as_ptr(), mmax2.len());
        sys_exit(1);
    }
    log("memory.max set+get = 1048576 OK\n");

    let mut buf = [0u8; 16];
    let n = format_pid(my_pid, &mut buf);
    if write_file_n(b"/sys/fs/cgroup/test1/cgroup.procs\0".as_ptr(), &buf[..n]) < 0 {
        log("migrate self failed\n");
        sys_exit(1);
    }

    let procs_test1 = read_file(b"/sys/fs/cgroup/test1/cgroup.procs\0".as_ptr());
    if !contains_pid(&procs_test1, my_pid) {
        log("self not in test1 procs after migrate\n");
        sys_exit(1);
    }
    let procs_root_after = read_file(b"/sys/fs/cgroup/cgroup.procs\0".as_ptr());
    if contains_pid(&procs_root_after, my_pid) {
        log("self still in root after migrate\n");
        sys_exit(1);
    }
    log("migrate self into /sys/fs/cgroup/test1 OK\n");

    let r = sys_rmdir(b"/sys/fs/cgroup/test1\0".as_ptr());
    if r != ENOTEMPTY {
        log("rmdir non-empty: expected ENOTEMPTY got ");
        log_num(r);
        sys_exit(1);
    }
    log("rmdir non-empty -> ENOTEMPTY OK\n");

    let mut buf = [0u8; 16];
    let n = format_pid(my_pid, &mut buf);
    if write_file_n(b"/sys/fs/cgroup/cgroup.procs\0".as_ptr(), &buf[..n]) < 0 {
        log("migrate back failed\n");
        sys_exit(1);
    }
    let r = sys_rmdir(b"/sys/fs/cgroup/test1\0".as_ptr());
    if r != 0 {
        log("rmdir empty: ");
        log_num(r);
        sys_exit(1);
    }
    log("rmdir empty cgroup OK\n");

    let r = sys_mkdir(b"/sys/fs/cgroup/oomtest\0".as_ptr(), 0o755);
    if r != 0 {
        log("mkdir oomtest: ");
        log_num(r);
        sys_exit(1);
    }
    if write_file(b"/sys/fs/cgroup/oomtest/memory.max\0".as_ptr(), b"65536") < 0 {
        log("write oomtest memory.max\n");
        sys_exit(1);
    }
    let pid = sys_fork();
    if pid < 0 {
        log("oom fork fail\n");
        sys_exit(1);
    }
    if pid == 0 {
        let mut buf = [0u8; 16];
        let n = format_pid(sys_getpid(), &mut buf);
        let r = write_file_n(b"/sys/fs/cgroup/oomtest/cgroup.procs\0".as_ptr(), &buf[..n]);
        if r < 0 {
            sys_exit(80);
        }
        let map = sys_mmap(
            0,
            1024 * 1024,
            3,
            0x22,
            -1,
            0,
        );
        if map < 0 {
            sys_exit(81);
        }
        let p = map as *mut u8;
        let mut i = 0u64;
        while i < 1024 * 1024 {
            unsafe {
                *p.add(i as usize) = 1;
            }
            i += 4096;
        }
        sys_exit(82);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let signaled = (st & 0x7f) != 0;
    if !signaled {
        log("OOM child exited normally; expected SIGKILL: ");
        log_num(st as i64);
        sys_exit(1);
    }
    let events = read_file(b"/sys/fs/cgroup/oomtest/memory.events\0".as_ptr());
    if !contains(&events, b"oom_kill ") {
        log("memory.events missing oom_kill\n");
        sys_exit(1);
    }
    log("OOM kill on memory.max overrun OK\n");
    let _ = sys_rmdir(b"/sys/fs/cgroup/oomtest\0".as_ptr());

    let r = sys_mkdir(b"/sys/fs/cgroup/cputest\0".as_ptr(), 0o755);
    if r != 0 {
        log("mkdir cputest: ");
        log_num(r);
        sys_exit(1);
    }
    let w = read_file(b"/sys/fs/cgroup/cputest/cpu.weight\0".as_ptr());
    if !starts_with(&w, b"100") {
        log("default cpu.weight not 100: ");
        sys_write(1, w.as_ptr(), w.len());
        sys_exit(1);
    }
    if write_file(b"/sys/fs/cgroup/cputest/cpu.weight\0".as_ptr(), b"200") < 0 {
        log("write cpu.weight=200 failed\n");
        sys_exit(1);
    }
    let w2 = read_file(b"/sys/fs/cgroup/cputest/cpu.weight\0".as_ptr());
    if !starts_with(&w2, b"200") {
        log("cpu.weight read-back wrong: ");
        sys_write(1, w2.as_ptr(), w2.len());
        sys_exit(1);
    }
    let r = write_file(b"/sys/fs/cgroup/cputest/cpu.weight\0".as_ptr(), b"0");
    if r >= 0 {
        log("cpu.weight=0 should fail\n");
        sys_exit(1);
    }
    let r = write_file(b"/sys/fs/cgroup/cputest/cpu.weight\0".as_ptr(), b"10001");
    if r >= 0 {
        log("cpu.weight=10001 should fail\n");
        sys_exit(1);
    }
    let _ = sys_rmdir(b"/sys/fs/cgroup/cputest\0".as_ptr());
    log("cpu.weight set/get + range check OK\n");

    let r = sys_mkdir(b"/sys/fs/cgroup/iotest\0".as_ptr(), 0o755);
    if r != 0 {
        log("mkdir iotest: ");
        log_num(r);
        sys_exit(1);
    }

    let w = read_file(b"/sys/fs/cgroup/iotest/io.weight\0".as_ptr());
    if !contains(&w, b"default 100") {
        log("default io.weight not 100: ");
        sys_write(1, w.as_ptr(), w.len());
        sys_exit(1);
    }
    if write_file(b"/sys/fs/cgroup/iotest/io.weight\0".as_ptr(), b"500") < 0 {
        log("write io.weight=500 failed\n");
        sys_exit(1);
    }
    let w2 = read_file(b"/sys/fs/cgroup/iotest/io.weight\0".as_ptr());
    if !contains(&w2, b"default 500") {
        log("io.weight read-back wrong: ");
        sys_write(1, w2.as_ptr(), w2.len());
        sys_exit(1);
    }
    log("io.weight set/get OK\n");

    if write_file(
        b"/sys/fs/cgroup/iotest/io.max\0".as_ptr(),
        b"8:0 rbps=1048576 wbps=524288",
    ) < 0
    {
        log("write io.max failed\n");
        sys_exit(1);
    }
    let m = read_file(b"/sys/fs/cgroup/iotest/io.max\0".as_ptr());
    if !contains(&m, b"rbps=1048576") || !contains(&m, b"wbps=524288") {
        log("io.max read-back wrong: ");
        sys_write(1, m.as_ptr(), m.len());
        sys_exit(1);
    }
    log("io.max set/get OK\n");

    if write_file(
        b"/sys/fs/cgroup/iotest/io.max\0".as_ptr(),
        b"8:0 rbps=max wbps=max",
    ) < 0
    {
        log("write io.max max failed\n");
        sys_exit(1);
    }
    log("io.max max clear OK\n");

    let _ = sys_rmdir(b"/sys/fs/cgroup/iotest\0".as_ptr());

    let _ = sys_mkdir(b"/sys/fs/cgroup/migA\0".as_ptr(), 0o755);
    let _ = sys_mkdir(b"/sys/fs/cgroup/migB\0".as_ptr(), 0o755);
    if write_file(b"/sys/fs/cgroup/migB/memory.max\0".as_ptr(), b"1048576") < 0 {
        log("write migB memory.max failed\n");
        sys_exit(1);
    }
    let pid = sys_fork();
    if pid < 0 {
        log("mig fork fail\n");
        sys_exit(1);
    }
    if pid == 0 {
        let mut buf = [0u8; 16];
        let n = format_pid(sys_getpid(), &mut buf);
        if write_file_n(b"/sys/fs/cgroup/migA/cgroup.procs\0".as_ptr(), &buf[..n]) < 0 {
            sys_exit(70);
        }
        let map = sys_mmap(0, 16384, 3, 0x22, -1, 0);
        if map < 0 {
            sys_exit(71);
        }
        let p = map as *mut u8;
        let mut i = 0u64;
        while i < 16384 {
            unsafe {
                *p.add(i as usize) = 1;
            }
            i += 4096;
        }
        if write_file_n(b"/sys/fs/cgroup/migB/cgroup.procs\0".as_ptr(), &buf[..n]) < 0 {
            sys_exit(72);
        }
        let a_cur =
            parse_leading_u64(&read_file(b"/sys/fs/cgroup/migA/memory.current\0".as_ptr()));
        let b_cur =
            parse_leading_u64(&read_file(b"/sys/fs/cgroup/migB/memory.current\0".as_ptr()));
        if a_cur != 0 {
            sys_exit(73);
        }
        if b_cur < 16384 {
            sys_exit(74);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || code != 0 {
        log("migration charge transfer failed, code=");
        log_num(code as i64);
        sys_exit(1);
    }
    let _ = sys_rmdir(b"/sys/fs/cgroup/migA\0".as_ptr());
    let _ = sys_rmdir(b"/sys/fs/cgroup/migB\0".as_ptr());
    log("migration transfers the memory charge OK\n");

    log("all cgroups tests OK\n");
    sys_exit(0);
}

fn parse_leading_u64(buf: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in buf {
        if !b.is_ascii_digit() {
            break;
        }
        v = v.saturating_mul(10).saturating_add((b - b'0') as u64);
    }
    v
}

#[inline(never)]
fn sys_mmap(addr: u64, length: u64, prot: i32, flags: i32, fd: i32, offset: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 9u64, in("rdi") addr, in("rsi") length,
        in("rdx") prot as u64, in("r10") flags as u64, in("r8") fd as u64,
        in("r9") offset,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
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
fn sys_wait4(pid: i32, status: *mut i32, options: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid as i64, in("rsi") status,
        in("rdx") options as i64, in("r10") 0u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn read_file(path: *const u8) -> [u8; 256] {
    let fd = sys_openat(AT_FDCWD, path, O_RDONLY, 0);
    if fd < 0 {
        return [0; 256];
    }
    let mut buf = [0u8; 256];
    let _ = sys_read(fd as i32, buf.as_mut_ptr(), buf.len());
    sys_close(fd as i32);
    buf
}

fn write_file(path: *const u8, data: &[u8]) -> i64 {
    write_file_n(path, data)
}

fn write_file_n(path: *const u8, data: &[u8]) -> i64 {
    let fd = sys_openat(AT_FDCWD, path, O_WRONLY, 0);
    if fd < 0 {
        return fd;
    }
    let n = sys_write(fd as u64, data.as_ptr(), data.len());
    sys_close(fd as i32);
    if n != data.len() as i64 { -1 } else { 0 }
}

fn contains(buf: &[u8], needle: &[u8]) -> bool {
    if needle.len() > buf.len() {
        return false;
    }
    buf.windows(needle.len()).any(|w| w == needle)
}

fn contains_pid(buf: &[u8], pid: i32) -> bool {
    let mut s = [0u8; 16];
    let n = format_pid(pid, &mut s);
    let pid_bytes = &s[..n];
    for line in buf.split(|&b| b == b'\n') {
        if line == pid_bytes {
            return true;
        }
    }
    false
}

fn starts_with(buf: &[u8], prefix: &[u8]) -> bool {
    buf.len() >= prefix.len() && &buf[..prefix.len()] == prefix
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

#[inline(never)]
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
    buf[i] = b'\n';
    i += 1;
    sys_write(1, buf.as_ptr(), i);
}

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_read(fd: i32, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd as i64, in("rsi") buf, in("rdx") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_close(fd: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 257u64, in("rdi") dirfd as i64,
        in("rsi") path, in("rdx") flags as i64, in("r10") mode as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_mkdir(path: *const u8, mode: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 258u64,
        in("rdi") AT_FDCWD as i64, in("rsi") path, in("rdx") mode as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_rmdir(path: *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 263u64,
        in("rdi") AT_FDCWD as i64, in("rsi") path, in("rdx") 0x200u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_getpid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
