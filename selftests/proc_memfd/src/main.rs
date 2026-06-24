#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const MFD_CLOEXEC: u64 = 0x0001;
const MFD_ALLOW_SEALING: u64 = 0x0002;
const MFD_HUGETLB: u64 = 0x0004;
const SEEK_SET: i32 = 0;
const F_GETFD: u64 = 1;
const FD_CLOEXEC: i64 = 1;
const F_ADD_SEALS: u64 = 1033;
const F_GET_SEALS: u64 = 1034;
const F_SEAL_SEAL: u64 = 0x0001;
const F_SEAL_SHRINK: u64 = 0x0002;
const F_SEAL_GROW: u64 = 0x0004;
const F_SEAL_WRITE: u64 = 0x0008;
const F_SEAL_FUTURE_WRITE: u64 = 0x0010;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 1;
const EPERM: i64 = -1;
const EBUSY: i64 = -16;
const EINVAL: i64 = -22;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("memfd test starting\n");

    let name = b"my-arena\0";
    let fd = sys_memfd_create(name.as_ptr(), 0);
    if fd < 0 {
        log("memfd_create: ");
        log_num(fd);
        sys_exit(1);
    }
    log("memfd_create returned fd OK\n");

    let payload = b"hello memfd world";
    let w = sys_write(fd as u64, payload.as_ptr(), payload.len());
    if w as usize != payload.len() {
        log("write short\n");
        sys_exit(1);
    }
    let pos = sys_lseek(fd as u64, 0, SEEK_SET);
    if pos != 0 {
        log("lseek non-zero\n");
        sys_exit(1);
    }
    let mut readback = [0u8; 32];
    let r = sys_read(fd as u64, readback.as_mut_ptr(), payload.len());
    if r as usize != payload.len() {
        log("read short\n");
        sys_exit(1);
    }
    if &readback[..payload.len()] != payload.as_slice() {
        log("readback mismatch\n");
        sys_exit(1);
    }
    log("memfd write+lseek+read round-trip OK\n");

    if sys_ftruncate(fd as u64, 1024) != 0 {
        log("ftruncate up failed\n");
        sys_exit(1);
    }
    if sys_ftruncate(fd as u64, 0) != 0 {
        log("ftruncate down failed\n");
        sys_exit(1);
    }
    log("memfd ftruncate grow + shrink OK\n");
    sys_close(fd as u64);

    let fd2 = sys_memfd_create(b"cloexec\0".as_ptr(), MFD_CLOEXEC);
    if fd2 < 0 {
        log("memfd CLOEXEC: ");
        log_num(fd2);
        sys_exit(1);
    }
    let flags = sys_fcntl(fd2 as u64, F_GETFD, 0);
    if flags & FD_CLOEXEC == 0 {
        log("MFD_CLOEXEC didn't set FD_CLOEXEC\n");
        sys_exit(1);
    }
    log("MFD_CLOEXEC sets FD_CLOEXEC OK\n");
    sys_close(fd2 as u64);

    let r = sys_memfd_create(b"huge\0".as_ptr(), MFD_HUGETLB);
    if r != EINVAL {
        log("MFD_HUGETLB not rejected: ");
        log_num(r);
        sys_exit(1);
    }
    log("MFD_HUGETLB → EINVAL OK\n");

    let sf = sys_memfd_create(b"noseal\0".as_ptr(), 0);
    if sf < 0 {
        log("noseal create failed\n");
        sys_exit(1);
    }
    if sys_fcntl(sf as u64, F_GET_SEALS, 0) != F_SEAL_SEAL as i64 {
        log("noseal get_seals != SEAL\n");
        sys_exit(1);
    }
    if sys_fcntl(sf as u64, F_ADD_SEALS, F_SEAL_WRITE) != EPERM {
        log("noseal add_seals not EPERM\n");
        sys_exit(1);
    }
    sys_close(sf as u64);
    log("memfd without ALLOW_SEALING: SEAL set, add EPERM OK\n");

    let m = sys_memfd_create(b"seal\0".as_ptr(), MFD_ALLOW_SEALING);
    if m < 0 {
        log("seal create failed\n");
        sys_exit(1);
    }
    if sys_fcntl(m as u64, F_GET_SEALS, 0) != 0 {
        log("initial seals != 0\n");
        sys_exit(1);
    }
    if sys_ftruncate(m as u64, 256) != 0 {
        log("seal ftruncate failed\n");
        sys_exit(1);
    }
    if sys_fcntl(m as u64, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) != 0 {
        log("add grow|shrink failed\n");
        sys_exit(1);
    }
    if sys_ftruncate(m as u64, 512) != EPERM {
        log("grow not blocked\n");
        sys_exit(1);
    }
    if sys_ftruncate(m as u64, 128) != EPERM {
        log("shrink not blocked\n");
        sys_exit(1);
    }
    sys_lseek(m as u64, 256, SEEK_SET);
    if sys_write(m as u64, b"x".as_ptr(), 1) != EPERM {
        log("write past EOF not blocked under GROW\n");
        sys_exit(1);
    }
    if sys_fcntl(m as u64, F_GET_SEALS, 0) != (F_SEAL_GROW | F_SEAL_SHRINK) as i64 {
        log("get_seals mismatch\n");
        sys_exit(1);
    }
    log("F_SEAL_GROW/SHRINK enforce ftruncate + write-grow OK\n");

    let addr = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, m as u64, 0);
    if addr < 0 {
        log("shared-write mmap failed\n");
        log_num(addr);
        sys_exit(1);
    }
    if sys_fcntl(m as u64, F_ADD_SEALS, F_SEAL_WRITE) != EBUSY {
        log("SEAL_WRITE with live mapping not EBUSY\n");
        sys_exit(1);
    }
    sys_munmap(addr as u64, 4096);
    log("F_SEAL_WRITE with live writable mapping -> EBUSY OK\n");

    if sys_fcntl(m as u64, F_ADD_SEALS, F_SEAL_WRITE) != 0 {
        log("SEAL_WRITE after unmap failed\n");
        sys_exit(1);
    }
    sys_lseek(m as u64, 0, SEEK_SET);
    if sys_write(m as u64, b"x".as_ptr(), 1) != EPERM {
        log("write not blocked after SEAL_WRITE\n");
        sys_exit(1);
    }
    if sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, m as u64, 0) != EPERM {
        log("shared-write mmap not blocked after SEAL_WRITE\n");
        sys_exit(1);
    }
    let ro = sys_mmap(0, 4096, PROT_READ, MAP_SHARED, m as u64, 0);
    if ro < 0 {
        log("read-only mmap blocked after SEAL_WRITE\n");
        sys_exit(1);
    }
    sys_munmap(ro as u64, 4096);
    log("F_SEAL_WRITE blocks write + shared-write mmap, allows RO mmap OK\n");

    if sys_fcntl(m as u64, F_ADD_SEALS, F_SEAL_SEAL) != 0 {
        log("add SEAL_SEAL failed\n");
        sys_exit(1);
    }
    if sys_fcntl(m as u64, F_ADD_SEALS, F_SEAL_GROW) != EPERM {
        log("add after SEAL_SEAL not EPERM\n");
        sys_exit(1);
    }
    sys_close(m as u64);
    log("F_SEAL_SEAL blocks further seals OK\n");

    let fw = sys_memfd_create(b"fw\0".as_ptr(), MFD_ALLOW_SEALING);
    if fw < 0 {
        log("fw create failed\n");
        sys_exit(40);
    }
    if sys_ftruncate(fw as u64, 4096) != 0 {
        log("fw ftruncate failed\n");
        sys_exit(41);
    }
    let fa = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fw as u64, 0);
    if fa < 0 {
        log("fw mmap failed\n");
        sys_exit(42);
    }
    let fp = b"FUTUREWRITE-FLUSH";
    for (i, &b) in fp.iter().enumerate() {
        unsafe { core::ptr::write_volatile((fa as *mut u8).add(i), b) };
    }
    if sys_fcntl(fw as u64, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) != 0 {
        log("add FUTURE_WRITE failed\n");
        sys_exit(43);
    }
    sys_lseek(fw as u64, 0, SEEK_SET);
    if sys_write(fw as u64, b"x".as_ptr(), 1) != EPERM {
        log("write not blocked under FUTURE_WRITE\n");
        sys_exit(44);
    }
    sys_munmap(fa as u64, 4096);
    sys_lseek(fw as u64, 0, SEEK_SET);
    let mut rb = [0u8; 32];
    let rn = sys_read(fw as u64, rb.as_mut_ptr(), fp.len());
    if rn as usize != fp.len() || &rb[..fp.len()] != fp.as_slice() {
        log("FUTURE_WRITE existing-mapping writeback lost\n");
        sys_exit(45);
    }
    sys_close(fw as u64);
    log("F_SEAL_FUTURE_WRITE: blocks write(), preserves mapping writeback OK\n");

    let ms = sys_memfd_create(b"mseal\0".as_ptr(), MFD_ALLOW_SEALING);
    if ms < 0 {
        log("mseal create failed\n");
        sys_exit(46);
    }
    if sys_ftruncate(ms as u64, 4096) != 0 {
        log("mseal ftruncate failed\n");
        sys_exit(47);
    }
    let ra = sys_mmap(0, 4096, PROT_READ, MAP_SHARED, ms as u64, 0);
    if ra < 0 {
        log("mseal ro mmap failed\n");
        sys_exit(48);
    }
    if sys_fcntl(ms as u64, F_ADD_SEALS, F_SEAL_WRITE) != 0 {
        log("mseal F_SEAL_WRITE failed\n");
        sys_exit(49);
    }
    if sys_mprotect(ra as u64, 4096, PROT_READ | PROT_WRITE) != -13 {
        log("mprotect re-granted WRITE on a write-sealed shared mapping\n");
        sys_exit(50);
    }
    sys_munmap(ra as u64, 4096);
    sys_close(ms as u64);
    log("mprotect cannot re-grant WRITE on a write-sealed shared mapping OK\n");

    log("all memfd tests OK\n");
    sys_exit(0);
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
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_lseek(fd: u64, off: i64, whence: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 8u64, in("rdi") fd, in("rsi") off, in("rdx") whence as i64,
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
fn sys_ftruncate(fd: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 77u64, in("rdi") fd, in("rsi") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_memfd_create(name: *const u8, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 319u64, in("rdi") name, in("rsi") flags,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 72u64, in("rdi") fd, in("rsi") cmd, in("rdx") arg,
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
fn sys_munmap(addr: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 11u64, in("rdi") addr, in("rsi") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 10u64, in("rdi") addr, in("rsi") len, in("rdx") prot,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
