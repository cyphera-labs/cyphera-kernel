#![no_std]
#![no_main]

use core::arch::asm;

const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_CLOSE: u64 = 3;
const SYS_MOUNT: u64 = 165;
const SYS_OPENAT: u64 = 257;
const SYS_MKDIRAT: u64 = 258;
const SYS_UNLINKAT: u64 = 263;
const SYS_EXIT: u64 = 60;

const AT_FDCWD: u64 = (-100i64) as u64;
const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_CREAT: u64 = 0x40;

const MS_RDONLY: u64 = 1;
const MS_REMOUNT: u64 = 0x20;

const EROFS: i64 = -30;

unsafe fn sc3(nr: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        in("rdi") a, in("rsi") b, in("rdx") c,
        lateout("rcx") _, lateout("r11") _,
    );
    ret
}

unsafe fn sc4(nr: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d,
        lateout("rcx") _, lateout("r11") _,
    );
    ret
}

unsafe fn sc6(nr: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> i64 {
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

fn log(s: &[u8]) {
    unsafe { sc3(SYS_WRITE, 1, s.as_ptr() as u64, s.len() as u64) };
}

fn mount(src: &[u8], tgt: &[u8], fst: &[u8], flags: u64) -> i64 {
    unsafe {
        sc6(
            SYS_MOUNT,
            src.as_ptr() as u64,
            tgt.as_ptr() as u64,
            fst.as_ptr() as u64,
            flags,
            0,
            0,
        )
    }
}

fn openat(path: &[u8], flags: u64, mode: u64) -> i64 {
    unsafe { sc4(SYS_OPENAT, AT_FDCWD, path.as_ptr() as u64, flags, mode) }
}

fn exit(code: i32) -> ! {
    unsafe { sc3(SYS_EXIT, code as u64, 0, 0) };
    loop {}
}

fn fail(msg: &[u8], code: i32) -> ! {
    log(msg);
    exit(code);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(99);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log(b"proc_remount: starting\n");

    let md = unsafe { sc3(SYS_MKDIRAT, AT_FDCWD, b"/mnt-test\0".as_ptr() as u64, 0o755) };
    if md < 0 && md != -17 {
        fail(b"proc_remount: FAIL: mkdir mountpoint\n", 1);
    }
    if mount(b"none\0", b"/mnt-test\0", b"tmpfs\0", 0) != 0 {
        fail(b"proc_remount: FAIL: mount tmpfs\n", 2);
    }

    let fd = openat(b"/mnt-test/f\0", O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        fail(b"proc_remount: FAIL: create file on rw mount\n", 3);
    }
    unsafe { sc3(SYS_WRITE, fd as u64, b"hi".as_ptr() as u64, 2) };
    unsafe { sc3(SYS_CLOSE, fd as u64, 0, 0) };
    log(b"proc_remount: rw mount create+write OK\n");

    if mount(
        b"none\0",
        b"/mnt-test\0",
        b"tmpfs\0",
        MS_REMOUNT | MS_RDONLY,
    ) != 0
    {
        fail(b"proc_remount: FAIL: remount,ro returned error\n", 4);
    }

    if openat(b"/mnt-test/f\0", O_WRONLY, 0) != EROFS {
        fail(
            b"proc_remount: FAIL: open-for-write not EROFS on ro mount\n",
            5,
        );
    }
    if openat(b"/mnt-test/f2\0", O_CREAT | O_WRONLY, 0o644) != EROFS {
        fail(b"proc_remount: FAIL: O_CREAT not EROFS on ro mount\n", 6);
    }
    if unsafe {
        sc3(
            SYS_MKDIRAT,
            AT_FDCWD,
            b"/mnt-test/d\0".as_ptr() as u64,
            0o755,
        )
    } != EROFS
    {
        fail(b"proc_remount: FAIL: mkdir not EROFS on ro mount\n", 7);
    }
    if unsafe { sc3(SYS_UNLINKAT, AT_FDCWD, b"/mnt-test/f\0".as_ptr() as u64, 0) } != EROFS {
        fail(b"proc_remount: FAIL: unlink not EROFS on ro mount\n", 8);
    }
    log(b"proc_remount: remount,ro blocks write/create/mkdir/unlink OK\n");

    let cfd = openat(b"/mnt-test/f\0", O_RDONLY, 0);
    if cfd < 0 {
        fail(b"proc_remount: FAIL: open RO for fchmod test\n", 13);
    }
    if unsafe { sc3(91, cfd as u64, 0o600, 0) } != EROFS {
        fail(
            b"proc_remount: FAIL: fchmod(fd) not EROFS on ro mount\n",
            14,
        );
    }
    unsafe { sc3(SYS_CLOSE, cfd as u64, 0, 0) };
    if unsafe {
        sc6(
            265,
            AT_FDCWD,
            b"/mnt-test/f\0".as_ptr() as u64,
            AT_FDCWD,
            b"/mnt-test/link\0".as_ptr() as u64,
            0,
            0,
        )
    } != EROFS
    {
        fail(b"proc_remount: FAIL: linkat not EROFS on ro mount\n", 15);
    }
    log(b"proc_remount: remount,ro blocks fd-metadata + hardlink OK\n");

    let rfd = openat(b"/mnt-test/f\0", O_RDONLY, 0);
    if rfd < 0 {
        fail(b"proc_remount: FAIL: open-for-read denied on ro mount\n", 9);
    }
    let mut rb = [0u8; 8];
    let n = unsafe { sc3(SYS_READ, rfd as u64, rb.as_mut_ptr() as u64, 2) };
    unsafe { sc3(SYS_CLOSE, rfd as u64, 0, 0) };
    if n != 2 || &rb[..2] != b"hi" {
        fail(b"proc_remount: FAIL: read content wrong on ro mount\n", 10);
    }
    log(b"proc_remount: reads still allowed on ro mount OK\n");

    if mount(b"none\0", b"/mnt-test\0", b"tmpfs\0", MS_REMOUNT) != 0 {
        fail(b"proc_remount: FAIL: remount,rw returned error\n", 11);
    }
    let wfd = openat(b"/mnt-test/f\0", O_WRONLY, 0);
    if wfd < 0 {
        fail(
            b"proc_remount: FAIL: open-for-write denied after remount,rw\n",
            12,
        );
    }
    unsafe { sc3(SYS_CLOSE, wfd as u64, 0, 0) };
    log(b"proc_remount: remount,rw restores writability OK\n");

    log(b"proc_remount: ALL PASS\n");
    exit(0);
}
