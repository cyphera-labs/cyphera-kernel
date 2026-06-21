#![no_std]
#![no_main]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SYS_FUTEX: u64 = 202;
const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;

const SYS_MMAP: u64 = 9;
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

const AT_FDCWD: i64 = -100;

const ROUNDS: u32 = 3000;

static TURN: AtomicU32 = AtomicU32::new(0);
static CHILD_DONE: AtomicU32 = AtomicU32::new(0);

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("loadtick test starting\n");

    let (load0, jif0, resched0) = match read_schedstat() {
        Some(v) => v,
        None => {
            log("schedstat parse failed (pre)\n");
            sys_exit(1);
        }
    };

    let region = sys_mmap(
        0,
        REGION_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        log("mmap child stack failed\n");
        sys_exit(1);
    }
    let child_stack_top = region as u64 + REGION_BYTES - PAGE;
    let flags = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
    let cr: i64;
    unsafe {
        asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "call {child_entry}",
            "mov rax, 60",
            "xor rdi, rdi",
            "syscall",
            "ud2",
            "2:",
            child_entry = sym ping_child,
            in("rdi") flags,
            in("rsi") child_stack_top,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8") 0u64,
            inout("rax") 56u64 => cr,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    if cr < 0 {
        log("clone failed\n");
        sys_exit(1);
    }

    let a = &TURN as *const _ as u64;
    for _ in 0..ROUNDS {
        TURN.store(1, Ordering::SeqCst);
        let _ = sys_futex(a, FUTEX_WAKE, 1);
        while TURN.load(Ordering::SeqCst) == 1 {
            let _ = sys_futex(a, FUTEX_WAIT, 1);
        }
    }

    CHILD_DONE.store(1, Ordering::SeqCst);
    TURN.store(1, Ordering::SeqCst);
    let _ = sys_futex(a, FUTEX_WAKE, 1);
    while CHILD_DONE.load(Ordering::SeqCst) != 2 {
        let _ = sys_futex(&CHILD_DONE as *const _ as u64, FUTEX_WAIT, 1);
        core::hint::spin_loop();
    }

    let (load1, jif1, resched1) = match read_schedstat() {
        Some(v) => v,
        None => {
            log("schedstat parse failed (post)\n");
            sys_exit(1);
        }
    };
    let dload = load1.wrapping_sub(load0);
    let djif = jif1.wrapping_sub(jif0);
    let dresched = resched1.wrapping_sub(resched0);
    let diff = if dload > djif {
        dload - djif
    } else {
        djif - dload
    };
    log("loadtick: dload=");
    log_num(dload as i64);
    log(" djif=");
    log_num(djif as i64);
    log(" dresched=");
    log_num(dresched as i64);
    log(" diff=");
    log_num(diff as i64);
    log("\n");
    if dresched == 0 {
        log("no reschedule IPIs fired — test vacuous (peer never crossed CPUs)\n");
        sys_exit(1);
    }
    if diff > 8 {
        log("loadavg_ticks diverged from jiffies (sampled on resched IPI?)\n");
        sys_exit(1);
    }

    log("LOADTICK_OK\n");
    sys_exit(0);
}

extern "C" fn ping_child() -> ! {
    let a = &TURN as *const _ as u64;
    loop {
        if CHILD_DONE.load(Ordering::SeqCst) != 0 {
            break;
        }
        while TURN.load(Ordering::SeqCst) == 0 {
            let _ = sys_futex(a, FUTEX_WAIT, 0);
            if CHILD_DONE.load(Ordering::SeqCst) != 0 {
                break;
            }
        }
        if CHILD_DONE.load(Ordering::SeqCst) != 0 {
            break;
        }
        TURN.store(0, Ordering::SeqCst);
        let _ = sys_futex(a, FUTEX_WAKE, 1);
    }
    CHILD_DONE.store(2, Ordering::SeqCst);
    let _ = sys_futex(&CHILD_DONE as *const _ as u64, FUTEX_WAKE, 1);
    sys_exit(0);
}

fn read_schedstat() -> Option<(u64, u64, u64)> {
    let mut buf = [0u8; 256];
    let n = read_path(b"/proc/schedstat\0", &mut buf);
    if n <= 0 {
        return None;
    }
    let s = &buf[..n as usize];
    let load = parse_field(s, b"loadavg_ticks ")?;
    let jif = parse_field(s, b"jiffies ")?;
    let resched = parse_field(s, b"resched_ticks ")?;
    Some((load, jif, resched))
}

fn parse_field(hay: &[u8], key: &[u8]) -> Option<u64> {
    let mut i = 0usize;
    'outer: while i + key.len() <= hay.len() {
        for (k, &kb) in key.iter().enumerate() {
            if hay[i + k] != kb {
                i += 1;
                continue 'outer;
            }
        }
        let mut j = i + key.len();
        let mut v: u64 = 0;
        let mut any = false;
        while j < hay.len() && hay[j].is_ascii_digit() {
            v = v.wrapping_mul(10).wrapping_add((hay[j] - b'0') as u64);
            j += 1;
            any = true;
        }
        return if any { Some(v) } else { None };
    }
    None
}

fn read_path(path: &[u8], buf: &mut [u8]) -> i64 {
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), 0, 0);
    if fd < 0 {
        return fd;
    }
    let mut total = 0usize;
    while total < buf.len() {
        let n = sys_read(
            fd as u64,
            unsafe { buf.as_mut_ptr().add(total) },
            buf.len() - total,
        );
        if n < 0 {
            sys_close(fd as u64);
            return n;
        }
        if n == 0 {
            break;
        }
        total += n as usize;
    }
    sys_close(fd as u64);
    total as i64
}

#[inline(never)]
fn sys_futex(uaddr: u64, op: u64, val: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_FUTEX, in("rdi") uaddr, in("rsi") op, in("rdx") val,
            in("r10") 0u64, in("r8") 0u64, in("r9") 0u64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_MMAP, in("rdi") addr, in("rsi") len,
            in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") off,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i64, pathname: *const u8, flags: u64, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 257u64, in("rdi") dirfd, in("rsi") pathname, in("rdx") flags, in("r10") mode,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

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
    sys_write(1, buf.as_ptr(), i);
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
