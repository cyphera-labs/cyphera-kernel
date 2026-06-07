#![no_std]
#![no_main]

use core::arch::asm;

const SYS_WRITE: u64 = 1;
const SYS_MMAP: u64 = 9;
const SYS_MUNMAP: u64 = 11;
const SYS_MREMAP: u64 = 25;
const SYS_EXIT: u64 = 60;

const MAP_ANONYMOUS: u64 = 0x20;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;

const MREMAP_MAYMOVE: u64 = 1;

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

fn munmap(addr: u64, len: u64) -> i64 {
    unsafe { syscall3(SYS_MUNMAP, addr, len, 0) }
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

    write_stdout(b"proc_mremap: ALL PASS\n");
    exit(0);
}
