#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const AT_FDCWD: i32 = -100;

const F_OK: i32 = 0;
const R_OK: i32 = 4;
const W_OK: i32 = 2;

const EACCES: i64 = -13;
const EPERM: i64 = -1;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("perms test starting\n");

    let path = b"/tmp/perm-test\0";
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR | O_CREAT, 0o600);
    if fd < 0 {
        log("create: ");
        log_num(fd);
        sys_exit(1);
    }
    sys_write(fd as u64, b"hi".as_ptr(), 2);
    sys_close(fd as i32);
    sys_chmod(path.as_ptr(), 0o600);

    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR, 0);
    if fd < 0 {
        log("root open 0o600: ");
        log_num(fd);
        sys_exit(1);
    }
    sys_close(fd as i32);
    log("root opens own 0o600 file OK\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork: ");
        log_num(pid);
        sys_exit(1);
    }
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(20);
        }
        let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDONLY, 0);
        if fd != EACCES {
            sys_exit(21);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    if st != 0 {
        log("uid 1000 read 0o600: child failed ");
        log_num(st as i64);
        sys_exit(1);
    }
    log("uid 1000 read root-owned 0o600 file -> EACCES OK\n");

    sys_chmod(path.as_ptr(), 0o644);
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(30);
        }
        let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDONLY, 0);
        if fd < 0 {
            sys_exit(31);
        }
        sys_close(fd as i32);
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    if st != 0 {
        log("uid 1000 read 0o644 failed ");
        log_num(st as i64);
        sys_exit(1);
    }
    log("uid 1000 read 0o644 file OK\n");

    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(40);
        }
        let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_WRONLY, 0);
        if fd != EACCES {
            sys_exit(41);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    if st != 0 {
        log("uid 1000 write 0o644: child failed ");
        log_num(st as i64);
        sys_exit(1);
    }
    log("uid 1000 write 0o644 root file -> EACCES OK\n");

    let r = sys_faccessat(AT_FDCWD, path.as_ptr(), F_OK);
    if r != 0 {
        log("access F_OK: ");
        log_num(r);
        sys_exit(1);
    }
    log("access(F_OK) OK\n");

    sys_chmod(path.as_ptr(), 0o200);
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(60);
        }
        let r = sys_faccessat(AT_FDCWD, path.as_ptr(), R_OK);
        if r != EACCES {
            sys_exit(61);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    if st != 0 {
        log("access R_OK: child failed ");
        log_num(st as i64);
        sys_exit(1);
    }
    log("uid 1000 access(R_OK) on 0o200 -> EACCES OK\n");

    sys_chmod(path.as_ptr(), 0o644);
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(70);
        }
        if sys_chmod(path.as_ptr(), 0o666) != EPERM {
            sys_exit(71);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    if st != 0 {
        log("uid 1000 chmod root file: child failed ");
        log_num(st as i64);
        sys_exit(1);
    }
    log("uid 1000 chmod root-owned file -> EPERM OK\n");

    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(80);
        }
        if sys_fchownat(AT_FDCWD, path.as_ptr(), 0, 0, 0) != EPERM {
            sys_exit(81);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    if st != 0 {
        log("uid 1000 chown root file: child failed ");
        log_num(st as i64);
        sys_exit(1);
    }
    log("uid 1000 chown root-owned file -> EPERM OK\n");

    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(90);
        }
        if sys_truncate(path.as_ptr(), 0) != EACCES {
            sys_exit(91);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    if st != 0 {
        log("uid 1000 truncate root file: child failed ");
        log_num(st as i64);
        sys_exit(1);
    }
    log("uid 1000 truncate 0o644 root file -> EACCES OK\n");

    sys_chmod(path.as_ptr(), 0o644);

    let m600 = b"/tmp/mode600\0";
    let fd = sys_openat(AT_FDCWD, m600.as_ptr(), O_WRONLY | O_CREAT, 0o600);
    if fd < 0 {
        log("mode600 create failed\n");
        sys_exit(1);
    }
    sys_close(fd as i32);
    if stat_mode(m600.as_ptr()) != 0o600 {
        log("O_CREAT mode 0o600 not honored: ");
        log_num(stat_mode(m600.as_ptr()));
        sys_exit(1);
    }
    let m666 = b"/tmp/mode666\0";
    let fd = sys_openat(AT_FDCWD, m666.as_ptr(), O_WRONLY | O_CREAT, 0o666);
    if fd < 0 {
        log("mode666 create failed\n");
        sys_exit(1);
    }
    sys_close(fd as i32);
    if stat_mode(m666.as_ptr()) != 0o644 {
        log("O_CREAT umask not applied: ");
        log_num(stat_mode(m666.as_ptr()));
        sys_exit(1);
    }
    let d700 = b"/tmp/priv700\0";
    if sys_mkdirat(AT_FDCWD, d700.as_ptr(), 0o700) != 0 {
        log("priv700 mkdir failed\n");
        sys_exit(1);
    }
    if stat_mode(d700.as_ptr()) != 0o700 {
        log("mkdir mode 0o700 not honored: ");
        log_num(stat_mode(d700.as_ptr()));
        sys_exit(1);
    }
    log("O_CREAT/mkdir mode honored (umask applied) OK\n");

    let bufp = &raw mut PROBE_BUF as *mut u8;
    let n = read_file(b"/bin/proc_auxv_probe\0".as_ptr(), bufp, PROBE_CAP);
    if n <= 0 {
        log("read /bin/proc_auxv_probe failed ");
        log_num(n);
        sys_exit(1);
    }
    let probe_len = n as usize;

    let suid_path = b"/tmp/suid_probe\0";
    if write_file(suid_path.as_ptr(), bufp, probe_len) != n {
        log("write /tmp/suid_probe failed\n");
        sys_exit(1);
    }
    if sys_chmod(suid_path.as_ptr(), 0o4755) != 0 {
        log("chmod 04755 /tmp/suid_probe failed\n");
        sys_exit(1);
    }
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(120);
        }
        let argv: [*const u8; 2] = [suid_path.as_ptr(), core::ptr::null()];
        let envp: [*const u8; 1] = [core::ptr::null()];
        sys_execve(suid_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(121);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    if (st & 0x7f) != 0 {
        log("setuid probe killed by signal ");
        log_num(st as i64);
        sys_exit(1);
    }
    if ((st >> 8) & 0xff) != 7 {
        log("setuid execve: AT_SECURE/AT_UID/AT_EUID wrong, code=");
        log_num(((st >> 8) & 0xff) as i64);
        sys_exit(1);
    }
    log("setuid execve sets AT_SECURE=1, AT_UID=1000, AT_EUID=0 OK\n");

    let plain_path = b"/tmp/plain_probe\0";
    if write_file(plain_path.as_ptr(), bufp, probe_len) != n {
        log("write /tmp/plain_probe failed\n");
        sys_exit(1);
    }
    sys_chmod(plain_path.as_ptr(), 0o755);
    let pid = sys_fork();
    if pid == 0 {
        if sys_setresuid(1000, 1000, 1000) != 0 {
            sys_exit(122);
        }
        let argv: [*const u8; 2] = [plain_path.as_ptr(), core::ptr::null()];
        let envp: [*const u8; 1] = [core::ptr::null()];
        sys_execve(plain_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        sys_exit(123);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    if (st & 0x7f) != 0 || ((st >> 8) & 0xff) != 2 {
        log("plain execve: expected AT_SECURE=0 (code 2), got ");
        log_num(((st >> 8) & 0xff) as i64);
        sys_exit(1);
    }
    log("plain execve keeps AT_SECURE=0, AT_UID=1000, AT_EUID=1000 OK\n");

    log("all perms tests OK\n");
    sys_exit(0);
}

const PROBE_CAP: usize = 128 * 1024;
static mut PROBE_BUF: [u8; PROBE_CAP] = [0u8; PROBE_CAP];

fn read_file(path: *const u8, buf: *mut u8, cap: usize) -> i64 {
    let fd = sys_openat(AT_FDCWD, path, O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let mut total = 0usize;
    while total < cap {
        let r = sys_read(fd as i32, unsafe { buf.add(total) }, cap - total);
        if r < 0 {
            sys_close(fd as i32);
            return r;
        }
        if r == 0 {
            break;
        }
        total += r as usize;
    }
    sys_close(fd as i32);
    total as i64
}

fn write_file(path: *const u8, data: *const u8, len: usize) -> i64 {
    let fd = sys_openat(AT_FDCWD, path, O_WRONLY | O_CREAT, 0o755);
    if fd < 0 {
        return fd;
    }
    let mut total = 0usize;
    while total < len {
        let w = sys_write(fd as u64, unsafe { data.add(total) }, len - total);
        if w < 0 {
            sys_close(fd as i32);
            return w;
        }
        if w == 0 {
            break;
        }
        total += w as usize;
    }
    sys_close(fd as i32);
    total as i64
}

#[inline(never)]
fn sys_fchownat(dirfd: i32, path: *const u8, uid: u32, gid: u32, flags: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 260u64, in("rdi") dirfd as i64, in("rsi") path,
        in("rdx") uid as u64, in("r10") gid as u64, in("r8") flags as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_truncate(path: *const u8, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 76u64, in("rdi") path, in("rsi") len,
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
fn sys_execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 59u64, in("rdi") path, in("rsi") argv, in("rdx") envp,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
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
fn sys_mkdirat(dirfd: i32, path: *const u8, mode: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 258u64, in("rdi") dirfd as i64,
        in("rsi") path, in("rdx") mode as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_newfstatat(dirfd: i32, path: *const u8, statbuf: *mut u8, flags: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 262u64, in("rdi") dirfd as i64,
        in("rsi") path, in("rdx") statbuf, in("r10") flags as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn stat_mode(path: *const u8) -> i64 {
    let mut buf = [0u8; 144];
    let r = sys_newfstatat(AT_FDCWD, path, buf.as_mut_ptr(), 0);
    if r != 0 {
        return r;
    }
    let mode = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
    (mode & 0o7777) as i64
}

fn sys_chmod(path: *const u8, mode: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 90u64, in("rdi") path, in("rsi") mode as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_faccessat(dirfd: i32, path: *const u8, mode: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 269u64, in("rdi") dirfd as i64,
        in("rsi") path, in("rdx") mode as u64, in("r10") 0u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_setresuid(r: u32, e: u32, s: u32) -> i64 {
    let ret: i64;
    unsafe {
        asm!("syscall", in("rax") 117u64, in("rdi") r as u64, in("rsi") e as u64, in("rdx") s as u64,
        lateout("rax") ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
