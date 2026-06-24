#![no_std]
#![no_main]

use core::arch::asm;

const SYS_WRITE: u64 = 1;
const SYS_CLOSE: u64 = 3;
const SYS_MMAP: u64 = 9;
const SYS_MUNMAP: u64 = 11;
const SYS_MREMAP: u64 = 25;
const SYS_FTRUNCATE: u64 = 77;
const SYS_MEMFD_CREATE: u64 = 319;
const SYS_EXIT: u64 = 60;

const MAP_SHARED: u64 = 0x01;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;

const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;

unsafe fn syscall3(nr: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        in("rdi") a, in("rsi") b, in("rdx") c,
        lateout("rcx") _, lateout("r11") _,
    );
    ret
}

unsafe fn syscall6(nr: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        in("rdi") a, in("rsi") b, in("rdx") c,
        in("r10") d, in("r8") e, in("r9") f,
        lateout("rcx") _, lateout("r11") _,
    );
    ret
}

fn mmap_anon(len: usize) -> i64 {
    unsafe {
        syscall6(
            SYS_MMAP,
            0,
            len as u64,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1i64 as u64,
            0,
        )
    }
}

fn mremap(old: u64, old_size: u64, new_size: u64, flags: u64) -> i64 {
    unsafe { syscall6(SYS_MREMAP, old, old_size, new_size, flags, 0, 0) }
}

fn mremap_fixed(old: u64, old_size: u64, new_size: u64, flags: u64, new_addr: u64) -> i64 {
    unsafe { syscall6(SYS_MREMAP, old, old_size, new_size, flags, new_addr, 0) }
}

fn munmap(addr: u64, len: u64) -> i64 {
    unsafe { syscall3(SYS_MUNMAP, addr, len, 0) }
}

fn memfd_create(name: &[u8], flags: u64) -> i64 {
    unsafe { syscall3(SYS_MEMFD_CREATE, name.as_ptr() as u64, flags, 0) }
}

fn ftruncate(fd: i64, len: u64) -> i64 {
    unsafe { syscall3(SYS_FTRUNCATE, fd as u64, len, 0) }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall3(SYS_CLOSE, fd as u64, 0, 0) }
}

fn mmap_fd_shared(len: usize, fd: i64) -> i64 {
    unsafe {
        syscall6(
            SYS_MMAP,
            0,
            len as u64,
            PROT_READ | PROT_WRITE,
            MAP_SHARED,
            fd as u64,
            0,
        )
    }
}

fn mmap_anon_shared(len: usize) -> i64 {
    unsafe {
        syscall6(
            SYS_MMAP,
            0,
            len as u64,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_SHARED,
            -1i64 as u64,
            0,
        )
    }
}

fn write_stdout(s: &[u8]) {
    unsafe { syscall3(SYS_WRITE, 1, s.as_ptr() as u64, s.len() as u64) };
}

fn exit(code: i32) -> ! {
    unsafe { syscall3(SYS_EXIT, code as u64, 0, 0) };
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(99);
}

const PAGE: usize = 4096;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    write_stdout(b"proc_mremap: starting\n");

    let p = mmap_anon(2 * PAGE);
    if p < 0 {
        write_stdout(b"proc_mremap: FAIL: mmap test1\n");
        exit(1);
    }
    let buf = p as *mut u8;
    for i in 0..(2 * PAGE) {
        unsafe { core::ptr::write_volatile(buf.add(i), 0u8) };
    }
    let shrunk = mremap(p as u64, (2 * PAGE) as u64, PAGE as u64, 0);
    if shrunk < 0 {
        write_stdout(b"proc_mremap: FAIL: mremap shrink returned negative\n");
        exit(2);
    }
    if shrunk as u64 != p as u64 {
        write_stdout(b"proc_mremap: FAIL: shrink should return same addr\n");
        exit(3);
    }
    for i in 0..PAGE {
        let v = unsafe { core::ptr::read_volatile(buf.add(i)) };
        if v != 0 {
            write_stdout(b"proc_mremap: FAIL: shrunk page corrupted\n");
            exit(4);
        }
    }
    munmap(p as u64, PAGE as u64);
    write_stdout(b"proc_mremap: test 1 (shrink) PASS\n");

    let p2 = mmap_anon(PAGE);
    if p2 < 0 {
        write_stdout(b"proc_mremap: FAIL: mmap test2\n");
        exit(5);
    }
    let pat = b"MREMAP-MAGIC-DEADBEEF-0123456789";
    let buf2 = p2 as *mut u8;
    for (i, &b) in pat.iter().enumerate() {
        unsafe { core::ptr::write_volatile(buf2.add(i), b) };
    }
    let blocker = unsafe {
        syscall6(
            SYS_MMAP,
            (p2 as u64) + PAGE as u64,
            PAGE as u64,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
            -1i64 as u64,
            0,
        )
    };
    if blocker < 0 {
        write_stdout(b"proc_mremap: FAIL: blocker mmap\n");
        exit(6);
    }
    let grown = mremap(p2 as u64, PAGE as u64, (4 * PAGE) as u64, MREMAP_MAYMOVE);
    if grown < 0 {
        write_stdout(b"proc_mremap: FAIL: mremap grow with MAYMOVE returned negative\n");
        exit(7);
    }
    if grown as u64 == p2 as u64 {
        write_stdout(b"proc_mremap: FAIL: grow should have moved\n");
        exit(8);
    }
    let nbuf = grown as *const u8;
    for (i, &expected) in pat.iter().enumerate() {
        let v = unsafe { core::ptr::read_volatile(nbuf.add(i)) };
        if v != expected {
            write_stdout(b"proc_mremap: FAIL: magic bytes not preserved across relocate\n");
            exit(9);
        }
    }
    for i in PAGE..(4 * PAGE) {
        let v = unsafe { core::ptr::read_volatile(nbuf.add(i)) };
        if v != 0 {
            write_stdout(b"proc_mremap: FAIL: new pages not zero-initialized\n");
            exit(10);
        }
    }
    munmap(grown as u64, (4 * PAGE) as u64);
    munmap(blocker as u64, PAGE as u64);
    write_stdout(b"proc_mremap: test 2 (grow+relocate+preserve) PASS\n");

    let p3 = mmap_anon(PAGE);
    if p3 < 0 {
        write_stdout(b"proc_mremap: FAIL: mmap test3\n");
        exit(11);
    }
    let blocker3 = unsafe {
        syscall6(
            SYS_MMAP,
            (p3 as u64) + PAGE as u64,
            PAGE as u64,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
            -1i64 as u64,
            0,
        )
    };
    if blocker3 < 0 {
        write_stdout(b"proc_mremap: FAIL: blocker3 mmap\n");
        exit(12);
    }
    let rejected = mremap(p3 as u64, PAGE as u64, (2 * PAGE) as u64, 0);
    if rejected != -12 {
        write_stdout(b"proc_mremap: FAIL: grow w/o MAYMOVE should have returned ENOMEM\n");
        exit(13);
    }
    munmap(p3 as u64, PAGE as u64);
    munmap(blocker3 as u64, PAGE as u64);
    write_stdout(b"proc_mremap: test 3 (refuse in-place collision) PASS\n");

    let fd = memfd_create(b"mr-shared\0", 0);
    if fd < 0 {
        write_stdout(b"proc_mremap: FAIL: memfd_create\n");
        exit(20);
    }
    if ftruncate(fd, PAGE as u64) != 0 {
        write_stdout(b"proc_mremap: FAIL: ftruncate memfd\n");
        exit(21);
    }
    let m1 = mmap_fd_shared(PAGE, fd);
    if m1 < 0 {
        write_stdout(b"proc_mremap: FAIL: shared mmap m1\n");
        exit(22);
    }
    let sblk = unsafe {
        syscall6(
            SYS_MMAP,
            (m1 as u64) + PAGE as u64,
            PAGE as u64,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
            -1i64 as u64,
            0,
        )
    };
    if sblk < 0 {
        write_stdout(b"proc_mremap: FAIL: shared blocker mmap\n");
        exit(24);
    }
    let m2 = mmap_fd_shared(PAGE, fd);
    if m2 < 0 {
        write_stdout(b"proc_mremap: FAIL: shared mmap m2\n");
        exit(33);
    }
    let b1 = m1 as *mut u8;
    let b2 = m2 as *const u8;
    let spat = b"SHARED-REMAP-COHERENCE-CHECK-0001";
    for (i, &b) in spat.iter().enumerate() {
        unsafe { core::ptr::write_volatile(b1.add(i), b) };
    }
    for (i, &e) in spat.iter().enumerate() {
        if unsafe { core::ptr::read_volatile(b2.add(i)) } != e {
            write_stdout(b"proc_mremap: FAIL: shared mappings not coherent (baseline)\n");
            exit(23);
        }
    }
    let g = mremap(m1 as u64, PAGE as u64, (2 * PAGE) as u64, MREMAP_MAYMOVE);
    if g < 0 || g as u64 == m1 as u64 {
        write_stdout(b"proc_mremap: FAIL: shared mremap did not move\n");
        exit(25);
    }
    let gb = g as *mut u8;
    for (i, &e) in spat.iter().enumerate() {
        if unsafe { core::ptr::read_volatile(gb.add(i)) } != e {
            write_stdout(b"proc_mremap: FAIL: shared move did not preserve data\n");
            exit(26);
        }
    }
    let spat2 = b"REPOINTED-NOT-COPIED-SHARED-00002";
    for (i, &b) in spat2.iter().enumerate() {
        unsafe { core::ptr::write_volatile(gb.add(i), b) };
    }
    for (i, &e) in spat2.iter().enumerate() {
        if unsafe { core::ptr::read_volatile(b2.add(i)) } != e {
            write_stdout(b"proc_mremap: FAIL: moved shared mapping is a private copy\n");
            exit(27);
        }
    }
    munmap(g as u64, (2 * PAGE) as u64);
    munmap(m2 as u64, PAGE as u64);
    munmap(sblk as u64, PAGE as u64);
    close(fd);
    write_stdout(b"proc_mremap: test 4 (shared move re-points to backing) PASS\n");

    let scratch = mmap_anon(2 * PAGE);
    if scratch < 0 {
        write_stdout(b"proc_mremap: FAIL: scratch mmap\n");
        exit(28);
    }
    let dest = scratch as u64 + PAGE as u64;
    munmap(scratch as u64, (2 * PAGE) as u64);
    let src = mmap_anon(PAGE);
    if src < 0 {
        write_stdout(b"proc_mremap: FAIL: fixed src mmap\n");
        exit(29);
    }
    let fpat = b"FIXED-DEST-MREMAP-0123456789ABCD";
    let sb = src as *mut u8;
    for (i, &b) in fpat.iter().enumerate() {
        unsafe { core::ptr::write_volatile(sb.add(i), b) };
    }
    let fr = mremap_fixed(
        src as u64,
        PAGE as u64,
        PAGE as u64,
        MREMAP_MAYMOVE | MREMAP_FIXED,
        dest,
    );
    if fr < 0 || fr as u64 != dest {
        write_stdout(b"proc_mremap: FAIL: MREMAP_FIXED did not land at dest\n");
        exit(30);
    }
    let db = dest as *const u8;
    for (i, &e) in fpat.iter().enumerate() {
        if unsafe { core::ptr::read_volatile(db.add(i)) } != e {
            write_stdout(b"proc_mremap: FAIL: MREMAP_FIXED lost data\n");
            exit(31);
        }
    }
    munmap(dest, PAGE as u64);
    write_stdout(b"proc_mremap: test 5 (MREMAP_FIXED) PASS\n");

    let sh = mmap_anon_shared(PAGE);
    if sh < 0 {
        write_stdout(b"proc_mremap: FAIL: anon-shared mmap\n");
        exit(40);
    }
    let shr = mremap(sh as u64, PAGE as u64, (2 * PAGE) as u64, MREMAP_MAYMOVE);
    if shr != -22 {
        write_stdout(b"proc_mremap: FAIL: shm grow should be EINVAL, not mapped short\n");
        exit(41);
    }
    munmap(sh as u64, PAGE as u64);
    write_stdout(b"proc_mremap: test 6 (shm grow rejected) PASS\n");

    let big = mmap_anon(3 * PAGE);
    if big < 0 {
        write_stdout(b"proc_mremap: FAIL: 3-page mmap\n");
        exit(50);
    }
    let bb = big as *mut u8;
    unsafe {
        core::ptr::write_volatile(bb, b'A');
        core::ptr::write_volatile(bb.add(PAGE), b'B');
        core::ptr::write_volatile(bb.add(PAGE + 17), 0x5Au8);
        core::ptr::write_volatile(bb.add(2 * PAGE), b'C');
    }
    let mid = mremap(
        big as u64 + PAGE as u64,
        PAGE as u64,
        (2 * PAGE) as u64,
        MREMAP_MAYMOVE,
    );
    if mid < 0 || mid as u64 == big as u64 + PAGE as u64 {
        write_stdout(b"proc_mremap: FAIL: partial sub-range mremap did not move\n");
        exit(51);
    }
    let mb = mid as *const u8;
    if unsafe { core::ptr::read_volatile(mb) } != b'B'
        || unsafe { core::ptr::read_volatile(mb.add(17)) } != 0x5A
    {
        write_stdout(b"proc_mremap: FAIL: partial move lost content\n");
        exit(52);
    }
    if unsafe { core::ptr::read_volatile(mb.add(PAGE)) } != 0 {
        write_stdout(b"proc_mremap: FAIL: partial grow tail not zero\n");
        exit(53);
    }
    if unsafe { core::ptr::read_volatile(bb) } != b'A'
        || unsafe { core::ptr::read_volatile(bb.add(2 * PAGE)) } != b'C'
    {
        write_stdout(b"proc_mremap: FAIL: source pages around the hole corrupted\n");
        exit(54);
    }
    munmap(mid as u64, (2 * PAGE) as u64);
    munmap(big as u64, PAGE as u64);
    munmap(big as u64 + (2 * PAGE) as u64, PAGE as u64);
    write_stdout(b"proc_mremap: test 7 (partial sub-range mremap) PASS\n");

    write_stdout(b"proc_mremap: ALL PASS\n");
    exit(0);
}
