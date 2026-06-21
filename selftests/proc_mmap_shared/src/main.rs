#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;
const AT_FDCWD: i32 = -100;

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_SHARED: i32 = 0x01;
const MAP_ANONYMOUS: i32 = 0x20;
const MAP_FIXED: i32 = 0x10;

const MS_SYNC: i32 = 4;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("mmap_shared test starting\n");

    let path = b"/tmp/mmap-shared-test\0";
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
    if fd < 0 {
        log("open create: ");
        log_num(fd);
        sys_exit(1);
    }
    let initial = b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH";
    let n = sys_write(fd as u64, initial.as_ptr(), initial.len());
    if n != initial.len() as i64 {
        log("write initial: ");
        log_num(n);
        sys_exit(1);
    }
    log("file create + initial write OK\n");

    let map_a = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd as i32, 0);
    if map_a < 0 {
        log("mmap A: ");
        log_num(map_a);
        sys_exit(1);
    }
    let p_a = map_a as *mut u8;
    let mut got = [0u8; 32];
    unsafe {
        for i in 0..32 {
            got[i] = *p_a.add(i);
        }
    }
    if &got != initial {
        log("read-via-mmap mismatch\n");
        sys_exit(1);
    }
    log("mmap MAP_SHARED reads file content OK\n");

    let modified = b"XXXXBBBBCCCCDDDDEEEEFFFFGGGGZZZZ";
    unsafe {
        for i in 0..32 {
            *p_a.add(i) = modified[i];
        }
    }
    log("write-through-mmap OK\n");

    let map_b = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd as i32, 0);
    if map_b < 0 {
        log("mmap B: ");
        log_num(map_b);
        sys_exit(1);
    }
    let p_b = map_b as *mut u8;
    let mut got = [0u8; 32];
    unsafe {
        for i in 0..32 {
            got[i] = *p_b.add(i);
        }
    }
    if &got != modified {
        log("second-mmap doesn't see writes\n");
        sys_exit(1);
    }
    log("two MAP_SHARED in same proc share the page OK\n");

    let r = sys_msync(map_a as u64, 4096, MS_SYNC);
    if r != 0 {
        log("msync: ");
        log_num(r);
        sys_exit(1);
    }
    log("msync MS_SYNC OK\n");

    sys_close(fd as i32);
    let fd2 = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR, 0);
    if fd2 < 0 {
        log("open re: ");
        log_num(fd2);
        sys_exit(1);
    }
    let mut got = [0u8; 32];
    let n = sys_read(fd2 as u64, got.as_mut_ptr(), got.len());
    if n != 32 {
        log("re-read: ");
        log_num(n);
        sys_exit(1);
    }
    if &got != modified {
        log("re-read doesn't match post-msync\n");
        for b in got.iter() {
            log_num(*b as i64);
        }
        sys_exit(1);
    }
    log("post-msync re-read sees modified bytes OK\n");
    sys_close(fd2 as i32);

    sys_munmap(map_a as u64, 4096);
    sys_munmap(map_b as u64, 4096);

    let wt = b"/tmp/mmap-writethrough-test\0";
    let fdw = sys_openat(AT_FDCWD, wt.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
    if fdw < 0 {
        log("wt open failed\n");
        sys_exit(1);
    }
    let before = b"oldoldoldoldoldo";
    if sys_write(fdw as u64, before.as_ptr(), before.len()) != before.len() as i64 {
        log("wt initial write short\n");
        sys_exit(1);
    }
    let map_w = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fdw as i32, 0);
    if map_w < 0 {
        log("wt mmap failed\n");
        sys_exit(1);
    }
    let p_w = map_w as *mut u8;
    let _pin = unsafe { core::ptr::read_volatile(p_w) };
    sys_lseek(fdw as u64, 0, 0);
    let after = b"NEW!NEW!NEW!NEW!";
    if sys_write(fdw as u64, after.as_ptr(), after.len()) != after.len() as i64 {
        log("wt overwrite short\n");
        sys_exit(1);
    }
    let mut via_map = [0u8; 16];
    unsafe {
        for i in 0..16 {
            via_map[i] = core::ptr::read_volatile(p_w.add(i));
        }
    }
    if &via_map != after {
        log("write(2) not seen by active MAP_SHARED mapping (stale pinned page)\n");
        sys_exit(1);
    }
    sys_munmap(map_w as u64, 4096);
    sys_close(fdw as i32);
    log("write(2) coherent with active MAP_SHARED mapping OK\n");

    let ep = b"/tmp/mmap_exitflush\0";
    let efd = sys_openat(AT_FDCWD, ep.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
    if efd < 0 {
        log("exitflush open failed\n");
        sys_exit(1);
    }
    let dots = [b'.'; 32];
    if sys_write(efd as u64, dots.as_ptr(), 32) != 32 {
        log("exitflush seed write failed\n");
        sys_exit(1);
    }
    let pid = sys_fork();
    if pid < 0 {
        log("exitflush fork failed\n");
        sys_exit(1);
    }
    if pid == 0 {
        let m = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, efd as i32, 0);
        if m < 0 {
            sys_exit(70);
        }
        let payload = b"EXITEXITEXITEXITEXITEXITEXITEXIT";
        let mut i = 0usize;
        while i < 32 {
            unsafe { core::ptr::write_volatile((m as u64 + i as u64) as *mut u8, payload[i]) };
            i += 1;
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid, &mut st, 0, 0);
    sys_close(efd as i32);
    let efd3 = sys_openat(AT_FDCWD, ep.as_ptr(), O_RDWR, 0);
    if efd3 < 0 {
        log("exitflush reopen failed\n");
        sys_exit(1);
    }
    let mut rb = [0u8; 32];
    let n = sys_read(efd3 as u64, rb.as_mut_ptr(), 32);
    sys_close(efd3 as i32);
    if n != 32 || &rb != b"EXITEXITEXITEXITEXITEXITEXITEXIT" {
        log("exit did not flush MAP_SHARED dirty page (lost write)\n");
        sys_exit(1);
    }
    log("exit flushes MAP_SHARED dirty page OK\n");

    let hp = b"/tmp/mmap_holepunch\0";
    let hfd = sys_openat(AT_FDCWD, hp.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
    if hfd < 0 {
        log("holepunch open failed\n");
        sys_exit(1);
    }
    let pagebuf = [b'.'; 4096];
    let mut s = 0;
    while s < 3 {
        if sys_write(hfd as u64, pagebuf.as_ptr(), 4096) != 4096 {
            log("holepunch seed write failed\n");
            sys_exit(1);
        }
        s += 1;
    }
    let hm = sys_mmap(
        0,
        3 * 4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        hfd as i32,
        0,
    );
    if hm < 0 {
        log("holepunch mmap failed\n");
        sys_exit(1);
    }
    let marker = b"BBBB";
    let mut i = 0usize;
    while i < 4 {
        unsafe { core::ptr::write_volatile((hm as u64 + 4096 + i as u64) as *mut u8, marker[i]) };
        i += 1;
    }
    if sys_munmap(hm as u64 + 4096, 4096) != 0 {
        log("holepunch munmap failed\n");
        sys_exit(1);
    }
    sys_munmap(hm as u64, 4096);
    sys_munmap(hm as u64 + 8192, 4096);
    sys_close(hfd as i32);
    let hfd2 = sys_openat(AT_FDCWD, hp.as_ptr(), O_RDWR, 0);
    if hfd2 < 0 {
        log("holepunch reopen failed\n");
        sys_exit(1);
    }
    let mut chk = [0u8; 4];
    sys_lseek(hfd2 as u64, 4096, 0);
    if sys_read(hfd2 as u64, chk.as_mut_ptr(), 4) != 4 || &chk != b"BBBB" {
        log("holepunch: middle page not written back to its offset\n");
        sys_exit(1);
    }
    sys_lseek(hfd2 as u64, 0, 0);
    if sys_read(hfd2 as u64, chk.as_mut_ptr(), 4) != 4 || &chk != b"...." {
        log("holepunch: page 0 corrupted by misdirected writeback\n");
        sys_exit(1);
    }
    sys_close(hfd2 as i32);
    log("hole-punch MAP_SHARED writeback offset OK\n");

    let as_ = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    if as_ < 0 {
        log("anon-shared mmap failed: ");
        log_num(as_);
        sys_exit(1);
    }
    let sentinel: u32 = 0x1234_5678;
    let child_mark: u32 = 0xCAFE_BABE;
    unsafe { core::ptr::write_volatile(as_ as *mut u32, sentinel) };
    let p2 = sys_fork();
    if p2 < 0 {
        log("anon-shared fork failed\n");
        sys_exit(1);
    }
    if p2 == 0 {
        let seen = unsafe { core::ptr::read_volatile(as_ as *const u32) };
        if seen != sentinel {
            sys_exit(60);
        }
        unsafe { core::ptr::write_volatile((as_ as u64 + 32) as *mut u32, child_mark) };
        sys_exit(0);
    }
    let mut st2: i32 = 0;
    sys_wait4(p2, &mut st2, 0, 0);
    if (st2 & 0x7f) != 0 || ((st2 >> 8) & 0xff) != 0 {
        log("anon-shared child failed, status: ");
        log_num(st2 as i64);
        sys_exit(1);
    }
    let got_child = unsafe { core::ptr::read_volatile((as_ as u64 + 32) as *const u32) };
    if got_child != child_mark {
        log("anon-shared: child's write NOT visible to parent (private-copied, not shared)\n");
        sys_exit(1);
    }
    sys_munmap(as_ as u64, 4096);
    log("MAP_SHARED|MAP_ANONYMOUS coherent across fork OK\n");

    let two = sys_mmap(
        0,
        8192,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    if two < 0 {
        log("fixed-anon mmap(2pg) failed\n");
        sys_exit(1);
    }
    unsafe {
        core::ptr::write_volatile(two as *mut u32, 0xA1A1_A1A1u32);
        core::ptr::write_volatile((two as u64 + 4096) as *mut u32, 0xB2B2_B2B2u32);
    }
    let ov = sys_mmap(
        two as u64,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED,
        -1,
        0,
    );
    if ov != two {
        log("partial MAP_FIXED over anon-shared failed: ");
        log_num(ov);
        sys_exit(1);
    }
    let pg1 = unsafe { core::ptr::read_volatile((two as u64 + 4096) as *const u32) };
    if pg1 != 0xB2B2_B2B2 {
        log("partial MAP_FIXED corrupted the surviving page\n");
        sys_exit(1);
    }
    unsafe { core::ptr::write_volatile(two as *mut u32, 0xC3C3_C3C3u32) };
    if unsafe { core::ptr::read_volatile(two as *const u32) } != 0xC3C3_C3C3 {
        log("MAP_FIXED replacement page not writable\n");
        sys_exit(1);
    }
    sys_munmap(two as u64, 8192);

    let one = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    if one < 0 {
        log("fixed-anon mmap(1pg) failed\n");
        sys_exit(1);
    }
    unsafe { core::ptr::write_volatile(one as *mut u32, 0xD4D4_D4D4u32) };
    let one2 = sys_mmap(
        one as u64,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED,
        -1,
        0,
    );
    if one2 != one {
        log("full MAP_FIXED over anon-shared failed\n");
        sys_exit(1);
    }
    unsafe { core::ptr::write_volatile(one as *mut u32, 0xE5E5_E5E5u32) };
    if unsafe { core::ptr::read_volatile(one as *const u32) } != 0xE5E5_E5E5 {
        log("MAP_FIXED full-overlay page not coherent\n");
        sys_exit(1);
    }
    sys_munmap(one as u64, 4096);
    let chk = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0,
    );
    if chk < 0 {
        log("post-fixed fresh mmap failed\n");
        sys_exit(1);
    }
    unsafe { core::ptr::write_volatile(chk as *mut u32, 0x5A5A_5A5Au32) };
    if unsafe { core::ptr::read_volatile(chk as *const u32) } != 0x5A5A_5A5A {
        log("post-fixed fresh region incoherent (free-list corruption?)\n");
        sys_exit(1);
    }
    sys_munmap(chk as u64, 4096);
    log("MAP_FIXED over MAP_SHARED|MAP_ANONYMOUS OK\n");

    log("all mmap_shared tests OK\n");
    sys_exit(0);
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
fn sys_wait4(pid: i64, status: *mut i32, options: i32, rusage: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid, in("rsi") status, in("rdx") options as i64, in("r10") rusage,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_lseek(fd: u64, offset: i64, whence: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 8u64, in("rdi") fd, in("rsi") offset, in("rdx") whence as u64,
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
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
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
fn sys_munmap(addr: u64, length: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 11u64, in("rdi") addr, in("rsi") length,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_msync(addr: u64, length: u64, flags: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 26u64, in("rdi") addr, in("rsi") length,
        in("rdx") flags as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
