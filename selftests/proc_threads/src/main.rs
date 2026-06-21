#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
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

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;

const PAGE: u64 = 4096;
const REGION_BYTES: u64 = 16 * PAGE;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("threads test starting\n");

    let leader_tgid = sys_getpid();
    let leader_tid = sys_gettid();
    if leader_tgid != leader_tid {
        log("leader getpid != gettid before clone (unexpected)\n");
        sys_exit(1);
    }

    let r = sys_mmap(
        0,
        REGION_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        log("mmap region failed\n");
        sys_exit(1);
    }
    let region_base = r as u64;

    let shared_ptr = region_base as *const AtomicI32;
    let shared = unsafe { &*shared_ptr };
    shared.store(0, Ordering::SeqCst);

    let futex_addr = region_base + 8;
    let futex_ptr = futex_addr as *const AtomicU32;
    let futex_word = unsafe { &*futex_ptr };
    futex_word.store(0, Ordering::SeqCst);

    let child_stack_top = region_base + REGION_BYTES - PAGE;

    let flags = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
    let r: i64;
    let leader_tgid_arg = leader_tgid;
    let leader_tid_arg = leader_tid;
    unsafe {
        core::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov rax, r12",
            "mov rcx, r13",
            "mov r15, r14",
            "mov rax, 39",
            "syscall",
            "cmp rax, r12",
            "jne 3f",
            "mov rax, 186",
            "syscall",
            "cmp rax, r13",
            "je 4f",
            "7:",
            "mov eax, dword ptr [r14 + 24]",
            "test eax, eax",
            "jz 7b",
            "mov r15, qword ptr [r14 + 16]",
            "mov eax, dword ptr [r15]",
            "mov dword ptr [r15], 0xBEEF",
            "mov dword ptr [r14], 0xCAFE",
            "jmp 5f",
            "3:",
            "mov dword ptr [r14], -1",
            "jmp 5f",
            "4:",
            "mov dword ptr [r14], -2",
            "5:",
            "mov dword ptr [r14 + 8], 1",
            "lea rdi, [r14 + 8]",
            "mov rsi, 1",
            "mov rdx, 1",
            "xor r10, r10",
            "xor r8, r8",
            "xor r9, r9",
            "mov rax, 202",
            "syscall",
            "mov rdi, 0",
            "mov rax, 60",
            "syscall",
            "ud2",
            "2:",
            in("rdi") flags,
            in("rsi") child_stack_top,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8")  0u64,
            inout("rax") 56u64 => r,
            in("r12") leader_tgid_arg as u64,
            in("r13") leader_tid_arg as u64,
            in("r14") (region_base as u64),
            out("r15") _,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    if r < 0 {
        log("clone failed\n");
        sys_exit(1);
    }

    let child_pid = r as i32;
    let mut buf = [0u8; 64];
    let n = format_kv(&mut buf, b"parent: spawned tid=", child_pid as i64);
    sys_write(1, buf.as_ptr(), n);

    let rgn = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if rgn < 0 {
        log("parent: mmap R after clone failed\n");
        sys_exit(1);
    }
    unsafe { core::ptr::write_volatile((region_base + 16) as *mut u64, rgn as u64) };
    unsafe { core::ptr::write_volatile((region_base + 24) as *mut u32, 1u32) };

    while futex_word.load(Ordering::SeqCst) == 0 {
        let r = sys_futex(futex_addr, FUTEX_WAIT, 0, 0, 0, 0);
        if r < 0 && r != -11 {
            log("parent: futex_wait returned negative\n");
            sys_exit(1);
        }
    }
    log("parent: futex_wait woke\n");

    let v = shared.load(Ordering::SeqCst);
    if v != 0xCAFE {
        if v == -1 {
            log("child: getpid (TGID) didn't match parent\n");
        } else if v == -2 {
            log("child: gettid same as parent (CLONE_THREAD broken)\n");
        } else {
            log("shared word: unexpected value\n");
        }
        sys_exit(1);
    }
    log("CLONE_VM shared write visible to parent OK\n");
    log("CLONE_THREAD same TGID, distinct TIDs OK\n");
    log("cross-thread futex wait/wake OK\n");

    let rv = unsafe { core::ptr::read_volatile(rgn as *const u32) };
    if rv != 0xBEEF {
        log("CLONE_VM: child could not see/write a post-clone mmap\n");
        sys_exit(1);
    }
    log("CLONE_VM post-clone mmap visible + writable across threads OK\n");

    log("all threads tests OK\n");
    sys_exit(0);
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
fn sys_clone(flags: u64, child_stack: u64, ptid: u64, ctid: u64, tls: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 56u64, in("rdi") flags, in("rsi") child_stack,
            in("rdx") ptid, in("r10") ctid, in("r8") tls,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_futex(uaddr: u64, op: u64, val: u32, timeout: u64, uaddr2: u64, val3: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 202u64, in("rdi") uaddr, in("rsi") op,
            in("rdx") val as u64, in("r10") timeout, in("r8") uaddr2, in("r9") val3,
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

#[inline(never)]
fn sys_gettid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 186u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
