#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(2);
}

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;

const PAGE: u64 = 4096;
const REGION_BYTES: u64 = 16 * PAGE;

static ARG0: &[u8] = b"/bin/proc_a\0";
static PATH: &[u8] = b"/bin/proc_a\0";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("exec_threaded: starting\n");

    let r = sys_mmap(
        0,
        REGION_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        log("exec_threaded: mmap region failed\n");
        sys_exit(1);
    }
    let region_base = r as u64;

    let started = unsafe { &*(region_base as *const AtomicU32) };
    started.store(0, Ordering::SeqCst);

    let child_stack_top = region_base + REGION_BYTES - PAGE;

    let flags = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov dword ptr [r14], 1",
            "xor r15d, r15d",
            "6:",
            "mov dword ptr [r14 + 0x1000], r15d",
            "mov dword ptr [r14 + 0x2000], r15d",
            "mov dword ptr [r14 + 0x3000], r15d",
            "mov eax, dword ptr [r14 + 0x1000]",
            "add r15d, 1",
            "mov rax, 39",
            "syscall",
            "jmp 6b",
            "2:",
            in("rdi") flags,
            in("rsi") child_stack_top,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8")  0u64,
            inout("rax") 56u64 => r,
            in("r14") region_base,
            out("r15") _,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    if r < 0 {
        log("exec_threaded: clone failed\n");
        sys_exit(1);
    }

    while started.load(Ordering::SeqCst) == 0 {
        core::hint::spin_loop();
    }
    for _ in 0..20_000_000u64 {
        core::hint::spin_loop();
    }

    log("exec_threaded: peer live, calling execve(/bin/proc_a)\n");

    let argv: [*const u8; 2] = [ARG0.as_ptr(), core::ptr::null()];
    let envp: [*const u8; 1] = [core::ptr::null()];
    let rc = sys_execve(PATH.as_ptr(), argv.as_ptr(), envp.as_ptr());

    let mut buf = [0u8; 64];
    let n = format_kv(&mut buf, b"exec_threaded: execve returned (FAIL) rc=", rc);
    sys_write(1, buf.as_ptr(), n);
    sys_exit(1);
}

#[inline(never)]
fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

fn format_kv(buf: &mut [u8], prefix: &[u8], n: i64) -> usize {
    let mut i = 0;
    for &b in prefix {
        buf[i] = b;
        i += 1;
    }
    let mut digits = [0u8; 16];
    let mut d = 0;
    let mut v = if n < 0 {
        buf[i] = b'-';
        i += 1;
        (-n) as u64
    } else {
        n as u64
    };
    if v == 0 {
        digits[0] = b'0';
        d = 1;
    } else {
        while v > 0 {
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            d += 1;
        }
    }
    while d > 0 {
        d -= 1;
        buf[i] = digits[d];
        i += 1;
    }
    buf[i] = b'\n';
    i += 1;
    i
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
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 9u64, in("rdi") addr, in("rsi") len,
            in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") off,
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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
