#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const O_RDONLY: u64 = 0o0;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_DIRECTORY: u64 = 0o200000;
const AT_FDCWD: i64 = -100;

const MODE_DIR: u64 = 0o755;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("fs_extras test starting\n");

    let fd = sys_creat(b"/tmp/created_via_creat\0".as_ptr(), 0o644);
    if fd < 0 {
        log("creat() failed\n");
        sys_exit(1);
    }
    let payload = b"created via creat(2)\n";
    sys_write(fd as u64, payload.as_ptr(), payload.len());
    sys_close(fd as u64);
    let mut buf = [0u8; 64];
    let n = read_path(b"/tmp/created_via_creat\0", &mut buf);
    if n != payload.len() as i64 || &buf[..n as usize] != payload {
        log("creat() readback mismatch\n");
        sys_exit(1);
    }
    log("creat() OK\n");

    if sys_mkdirat(AT_FDCWD, b"/tmp/cd_target\0".as_ptr(), MODE_DIR) != 0 {
        log("mkdir cd_target failed\n");
        sys_exit(1);
    }
    let dirfd = sys_openat(AT_FDCWD, b"/tmp/cd_target\0".as_ptr(), O_RDONLY, 0);
    if dirfd < 0 {
        log("open cd_target failed\n");
        sys_exit(1);
    }
    if sys_fchdir(dirfd as u64) != 0 {
        log("fchdir failed\n");
        sys_exit(1);
    }
    sys_close(dirfd as u64);
    log("fchdir() OK\n");

    let fd = sys_openat(
        AT_FDCWD,
        b"/tmp/falloced\0".as_ptr(),
        O_CREAT | O_RDWR | O_TRUNC,
        0o644,
    );
    if fd < 0 {
        log("open for fallocate failed\n");
        sys_exit(1);
    }
    if sys_fallocate(fd as u64, 0, 0, 16384) != 0 {
        log("fallocate failed\n");
        sys_exit(1);
    }
    let end = sys_lseek(fd as u64, 0, 2);
    if end != 16384 {
        log("fallocate size mismatch\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("fallocate() OK\n");

    let fd = sys_openat(AT_FDCWD, b"/tmp/falloced\0".as_ptr(), O_RDWR, 0);
    if sys_flock(fd as u64, 2) != 0 {
        log("flock LOCK_EX failed\n");
        sys_exit(1);
    }
    if sys_flock(fd as u64, 8) != 0 {
        log("flock LOCK_UN failed\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("flock() OK\n");

    let fd = sys_openat(AT_FDCWD, b"/tmp/falloced\0".as_ptr(), O_RDONLY, 0);
    if sys_fadvise64(fd as u64, 0, 4096, 1) != 0 {
        log("fadvise64 failed\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("fadvise64() OK\n");

    const PROT_RW: u64 = 1 | 2;
    const MAP_PRIV_ANON: u64 = 0x02 | 0x20;
    let p = sys_mmap(0, 0x1000, PROT_RW, MAP_PRIV_ANON, u64::MAX, 0);
    if p < 0 || (p as u64 & 0xfff) != 0 {
        log("anon mmap for madvise failed\n");
        sys_exit(1);
    }
    let pp = p as u64 as *mut u8;
    unsafe { core::ptr::write_volatile(pp, 0xAB) };
    let r = sys_madvise(p as u64, 0x1000, 4);
    if r != 0 {
        log("madvise failed\n");
        sys_exit(1);
    }
    if unsafe { core::ptr::read_volatile(pp) } != 0 {
        log("madvise DONTNEED did not drop the page\n");
        sys_exit(1);
    }
    log("madvise() OK\n");

    let src = sys_openat(
        AT_FDCWD,
        b"/tmp/sf_src\0".as_ptr(),
        O_CREAT | O_RDWR | O_TRUNC,
        0o644,
    );
    if src < 0 {
        log("open sf_src failed\n");
        sys_exit(1);
    }
    let body = b"hello, sendfile world!\n";
    sys_write(src as u64, body.as_ptr(), body.len());
    sys_lseek(src as u64, 0, 0);

    let dst = sys_openat(
        AT_FDCWD,
        b"/tmp/sf_dst\0".as_ptr(),
        O_CREAT | O_RDWR | O_TRUNC,
        0o644,
    );
    if dst < 0 {
        log("open sf_dst failed\n");
        sys_exit(1);
    }
    let n = sys_sendfile(dst as u64, src as u64, 0, body.len() as u64);
    if n != body.len() as i64 {
        log("sendfile short\n");
        sys_exit(1);
    }
    sys_close(src as u64);
    sys_close(dst as u64);
    let mut rb = [0u8; 64];
    let r = read_path(b"/tmp/sf_dst\0", &mut rb);
    if r != body.len() as i64 || &rb[..r as usize] != body {
        log("sendfile readback mismatch\n");
        sys_exit(1);
    }
    log("sendfile() OK\n");

    let src = sys_openat(AT_FDCWD, b"/tmp/sf_src\0".as_ptr(), O_RDONLY, 0);
    let dst = sys_openat(
        AT_FDCWD,
        b"/tmp/cfr_dst\0".as_ptr(),
        O_CREAT | O_RDWR | O_TRUNC,
        0o644,
    );
    let n = sys_copy_file_range(src as u64, 0, dst as u64, 0, body.len() as u64, 0);
    if n != body.len() as i64 {
        log("copy_file_range short\n");
        sys_exit(1);
    }
    sys_close(src as u64);
    sys_close(dst as u64);
    let r = read_path(b"/tmp/cfr_dst\0", &mut rb);
    if r != body.len() as i64 || &rb[..r as usize] != body {
        log("copy_file_range readback mismatch\n");
        sys_exit(1);
    }
    log("copy_file_range() OK\n");

    let how_path = b"/tmp/oa2\0";
    let mut how = [0u8; 24];
    how[0..8].copy_from_slice(&(O_CREAT | O_RDWR | O_TRUNC).to_le_bytes());
    how[8..16].copy_from_slice(&0o644u64.to_le_bytes());
    let fd = sys_openat2(AT_FDCWD, how_path.as_ptr(), how.as_ptr(), 24);
    if fd < 0 {
        log("openat2 failed\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("openat2() OK\n");

    let fd = sys_openat(
        AT_FDCWD,
        b"/tmp/iov\0".as_ptr(),
        O_CREAT | O_RDWR | O_TRUNC,
        0o644,
    );
    if fd < 0 {
        log("open iov failed\n");
        sys_exit(1);
    }
    let zero = [0u8; 32];
    sys_write(fd as u64, zero.as_ptr(), zero.len());
    let v1: [u8; 4] = *b"AAAA";
    let v2: [u8; 4] = *b"BBBB";
    let iov = [v1.as_ptr() as u64, 4u64, v2.as_ptr() as u64, 4u64];
    let r = sys_pwritev(fd as u64, iov.as_ptr() as u64, 2, 4);
    if r != 8 {
        log("pwritev short\n");
        sys_exit(1);
    }
    let mut r1 = [0u8; 4];
    let mut r2 = [0u8; 4];
    let riov = [r1.as_mut_ptr() as u64, 4u64, r2.as_mut_ptr() as u64, 4u64];
    let r = sys_preadv(fd as u64, riov.as_ptr() as u64, 2, 4);
    if r != 8 || &r1 != b"AAAA" || &r2 != b"BBBB" {
        log("preadv readback mismatch\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("preadv()/pwritev() OK\n");

    let fa = sys_openat(AT_FDCWD, b"/tmp/ra\0".as_ptr(), O_CREAT | O_RDWR, 0o644);
    if fa < 0 {
        log("renameat2: ra create failed\n");
        sys_exit(1);
    }
    sys_write(fa as u64, b"AAA".as_ptr(), 3);
    sys_close(fa as u64);
    let fb = sys_openat(AT_FDCWD, b"/tmp/rb\0".as_ptr(), O_CREAT | O_RDWR, 0o644);
    if fb < 0 {
        log("renameat2: rb create failed\n");
        sys_exit(1);
    }
    sys_write(fb as u64, b"BBB".as_ptr(), 3);
    sys_close(fb as u64);
    if sys_renameat2(
        AT_FDCWD,
        b"/tmp/ra\0".as_ptr(),
        AT_FDCWD,
        b"/tmp/rb\0".as_ptr(),
        1,
    ) != -17
    {
        log("renameat2: NOREPLACE over existing not EEXIST\n");
        sys_exit(1);
    }
    if sys_renameat2(
        AT_FDCWD,
        b"/tmp/ra\0".as_ptr(),
        AT_FDCWD,
        b"/tmp/rc\0".as_ptr(),
        8,
    ) != -22
    {
        log("renameat2: unknown flag not EINVAL\n");
        sys_exit(1);
    }
    if sys_renameat2(
        AT_FDCWD,
        b"/tmp/ra\0".as_ptr(),
        AT_FDCWD,
        b"/tmp/rb\0".as_ptr(),
        2,
    ) != 0
    {
        log("renameat2: EXCHANGE failed\n");
        sys_exit(1);
    }
    let mut xb = [0u8; 4];
    if read_path(b"/tmp/ra\0", &mut xb[..3]) != 3 || &xb[..3] != b"BBB" {
        log("renameat2: EXCHANGE ra content wrong\n");
        sys_exit(1);
    }
    if read_path(b"/tmp/rb\0", &mut xb[..3]) != 3 || &xb[..3] != b"AAA" {
        log("renameat2: EXCHANGE rb content wrong\n");
        sys_exit(1);
    }
    if sys_mkdirat(AT_FDCWD, b"/tmp/dd\0".as_ptr(), MODE_DIR) != 0 {
        log("renameat2: mkdir dd failed\n");
        sys_exit(1);
    }
    if sys_renameat2(
        AT_FDCWD,
        b"/tmp/dd\0".as_ptr(),
        AT_FDCWD,
        b"/tmp/dd/sub\0".as_ptr(),
        0,
    ) != -22
    {
        log("renameat2: dir into descendant not EINVAL\n");
        sys_exit(1);
    }
    log("renameat2: NOREPLACE/EXCHANGE/validation/descendant OK\n");

    if sys_mkdirat(AT_FDCWD, b"/tmp/d1\0".as_ptr(), MODE_DIR) != 0 {
        log("xdir: mkdir d1 failed\n");
        sys_exit(1);
    }
    if sys_mkdirat(AT_FDCWD, b"/tmp/d2\0".as_ptr(), MODE_DIR) != 0 {
        log("xdir: mkdir d2 failed\n");
        sys_exit(1);
    }
    let fx = sys_openat(AT_FDCWD, b"/tmp/d1/x\0".as_ptr(), O_CREAT | O_RDWR, 0o644);
    if fx < 0 {
        log("xdir: create d1/x failed\n");
        sys_exit(1);
    }
    sys_write(fx as u64, b"XXX".as_ptr(), 3);
    sys_close(fx as u64);
    if sys_renameat2(
        AT_FDCWD,
        b"/tmp/d1/x\0".as_ptr(),
        AT_FDCWD,
        b"/tmp/d2/y\0".as_ptr(),
        0,
    ) != 0
    {
        log("xdir: cross-dir rename failed\n");
        sys_exit(1);
    }
    let mut yb = [0u8; 4];
    if read_path(b"/tmp/d2/y\0", &mut yb[..3]) != 3 || &yb[..3] != b"XXX" {
        log("xdir: moved content wrong\n");
        sys_exit(1);
    }
    if sys_openat(AT_FDCWD, b"/tmp/d1/x\0".as_ptr(), O_RDONLY, 0) != -2 {
        log("xdir: source still present after move\n");
        sys_exit(1);
    }
    let fz = sys_openat(AT_FDCWD, b"/tmp/d2/z\0".as_ptr(), O_CREAT | O_RDWR, 0o644);
    sys_write(fz as u64, b"ZZZ".as_ptr(), 3);
    sys_close(fz as u64);
    let fw = sys_openat(AT_FDCWD, b"/tmp/d1/w\0".as_ptr(), O_CREAT | O_RDWR, 0o644);
    sys_write(fw as u64, b"WWW".as_ptr(), 3);
    sys_close(fw as u64);
    if sys_renameat2(
        AT_FDCWD,
        b"/tmp/d1/w\0".as_ptr(),
        AT_FDCWD,
        b"/tmp/d2/z\0".as_ptr(),
        0,
    ) != 0
    {
        log("xdir: cross-dir overwrite failed\n");
        sys_exit(1);
    }
    if read_path(b"/tmp/d2/z\0", &mut yb[..3]) != 3 || &yb[..3] != b"WWW" {
        log("xdir: overwrite content wrong\n");
        sys_exit(1);
    }
    log("cross-dir rename + overwrite OK\n");

    if sys_openat(AT_FDCWD, b"/tmp/d2/y\0".as_ptr(), O_DIRECTORY, 0) != -20 {
        log("O_DIRECTORY on a non-dir not ENOTDIR\n");
        sys_exit(1);
    }
    if sys_openat(AT_FDCWD, b"/tmp/d1\0".as_ptr(), O_RDWR, 0) != -21 {
        log("open directory for write not EISDIR\n");
        sys_exit(1);
    }
    if sys_openat(AT_FDCWD, b"/tmp/d1\0".as_ptr(), O_DIRECTORY, 0) < 0 {
        log("O_DIRECTORY on a real dir failed\n");
        sys_exit(1);
    }
    log("O_DIRECTORY/EISDIR open semantics OK\n");

    if sys_mkdirat(AT_FDCWD, b"/jail\0".as_ptr(), MODE_DIR) != 0 {
        log("mkdir /jail failed\n");
        sys_exit(1);
    }
    if sys_mkdirat(AT_FDCWD, b"/jail/old\0".as_ptr(), MODE_DIR) != 0 {
        log("mkdir /jail/old failed\n");
        sys_exit(1);
    }
    if sys_pivot_root(b"/jail\0".as_ptr(), b"/jail/old\0".as_ptr()) != 0 {
        log("pivot_root failed\n");
        sys_exit(1);
    }
    let r = read_path(b"/old/tmp/sf_dst\0", &mut rb);
    if r != body.len() as i64 {
        log("pivot_root post-state /old/tmp/sf_dst not visible\n");
        sys_exit(1);
    }
    log("pivot_root() OK\n");

    log("all fs_extras tests OK\n");
    sys_exit(0);
}

fn read_path(path: &[u8], buf: &mut [u8]) -> i64 {
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let n = sys_read(fd as u64, buf.as_mut_ptr(), buf.len());
    sys_close(fd as u64);
    n
}

#[inline(never)]
fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
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
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_renameat2(
    olddirfd: i64,
    oldpath: *const u8,
    newdirfd: i64,
    newpath: *const u8,
    flags: u64,
) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 316u64, in("rdi") olddirfd, in("rsi") oldpath,
            in("rdx") newdirfd, in("r10") newpath, in("r8") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i64, p: *const u8, flags: u64, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 257u64, in("rdi") dirfd, in("rsi") p,
            in("rdx") flags, in("r10") mode,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_mkdirat(dirfd: i64, p: *const u8, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 258u64, in("rdi") dirfd, in("rsi") p, in("rdx") mode,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_lseek(fd: u64, off: i64, whence: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 8u64, in("rdi") fd, in("rsi") off, in("rdx") whence as u64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_creat(p: *const u8, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 85u64, in("rdi") p, in("rsi") mode,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_fchdir(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 81u64, in("rdi") fd,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_fallocate(fd: u64, mode: u64, off: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 285u64, in("rdi") fd, in("rsi") mode,
            in("rdx") off, in("r10") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_flock(fd: u64, op: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 73u64, in("rdi") fd, in("rsi") op,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_fadvise64(fd: u64, off: u64, len: u64, advice: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 221u64, in("rdi") fd, in("rsi") off,
            in("rdx") len, in("r10") advice,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_madvise(addr: u64, len: u64, advice: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 28u64, in("rdi") addr, in("rsi") len, in("rdx") advice,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 9u64, in("rdi") addr, in("rsi") len, in("rdx") prot,
            in("r10") flags, in("r8") fd, in("r9") off,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_sendfile(out_fd: u64, in_fd: u64, off: u64, count: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 40u64, in("rdi") out_fd, in("rsi") in_fd,
            in("rdx") off, in("r10") count,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_copy_file_range(fdi: u64, offi: u64, fdo: u64, offo: u64, len: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 326u64, in("rdi") fdi, in("rsi") offi,
            in("rdx") fdo, in("r10") offo, in("r8") len, in("r9") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_openat2(dirfd: i64, p: *const u8, how: *const u8, size: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 437u64, in("rdi") dirfd, in("rsi") p,
            in("rdx") how, in("r10") size,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_preadv(fd: u64, iov: u64, n: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 295u64, in("rdi") fd, in("rsi") iov,
            in("rdx") n, in("r10") off, in("r8") 0u64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_pwritev(fd: u64, iov: u64, n: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 296u64, in("rdi") fd, in("rsi") iov,
            in("rdx") n, in("r10") off, in("r8") 0u64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_pivot_root(new_root: *const u8, put_old: *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 155u64, in("rdi") new_root, in("rsi") put_old,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
