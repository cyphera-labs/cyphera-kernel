#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicU32, Ordering};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(3);
}

const PROT_NONE: u64 = 0;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;

const IPC_PRIVATE: i64 = 0;
const IPC_CREAT: i64 = 0o1000;
const IPC_RMID: i64 = 0;

const MADV_DONTNEED: u64 = 4;
const MREMAP_MAYMOVE: u64 = 1;
const ENOMEM: i64 = -12;

const PAGE: u64 = 4096;

const O_LEADER_DONE: u64 = 0;
const O_PEER_RESULT: u64 = 8;
const O_PEER_DONE: u64 = 16;
const O_MMAP: u64 = 24;
const O_MUNMAP: u64 = 32;
const O_MPROT: u64 = 40;
const O_MREMAP: u64 = 48;
const O_MADV: u64 = 56;
const O_BRK: u64 = 64;
const O_SHMAT: u64 = 72;
const O_SHMDT: u64 = 80;

const REGION_BYTES: u64 = 16 * PAGE;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("threads_coherence: starting\n");

    let coord = match sys_mmap(
        0,
        REGION_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    ) {
        a if a < 0 => {
            log("coord mmap failed\n");
            sys_exit(1);
        }
        a => a as u64,
    };
    let cw = |off: u64, v: u64| unsafe { core::ptr::write_volatile((coord + off) as *mut u64, v) };
    let cwu = |off: u64, v: u32| unsafe { core::ptr::write_volatile((coord + off) as *mut u32, v) };
    cwu(O_LEADER_DONE, 0);
    cwu(O_PEER_DONE, 0);
    unsafe { core::ptr::write_volatile((coord + O_PEER_RESULT) as *mut i64, -1) };

    let child_stack_top = coord + REGION_BYTES - PAGE;

    let flags = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
    let rc: i64;
    unsafe {
        asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov rdi, r14",
            "and rsp, -16",
            "call {entry}",
            "ud2",
            "2:",
            entry = sym child_entry,
            in("rdi") flags,
            in("rsi") child_stack_top,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8") 0u64,
            inout("rax") 56u64 => rc,
            in("r14") coord,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    if rc < 0 {
        log("clone failed\n");
        sys_exit(1);
    }

    let r1 = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r1 < 0 {
        fail(coord, 1);
    }
    unsafe { core::ptr::write_volatile(r1 as u64 as *mut u32, 0xA1A1) };
    cw(O_MMAP, r1 as u64);

    let r2 = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r2 < 0 {
        fail(coord, 2);
    }
    cw(O_MUNMAP, r2 as u64);
    if sys_munmap(r2 as u64, PAGE) != 0 {
        fail(coord, 2);
    }

    let r3 = sys_mmap(
        0,
        PAGE,
        PROT_NONE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r3 < 0 {
        fail(coord, 3);
    }
    if sys_mprotect(r3 as u64, PAGE, PROT_READ | PROT_WRITE) != 0 {
        fail(coord, 3);
    }
    unsafe { core::ptr::write_volatile(r3 as u64 as *mut u32, 0xA3A3) };
    cw(O_MPROT, r3 as u64);

    let r4 = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r4 < 0 {
        fail(coord, 4);
    }
    unsafe { core::ptr::write_volatile(r4 as u64 as *mut u32, 0xA4A4) };
    let r4n = sys_mremap(r4 as u64, PAGE, 2 * PAGE, MREMAP_MAYMOVE, 0);
    if r4n < 0 {
        fail(coord, 4);
    }
    cw(O_MREMAP, r4n as u64);

    let r5 = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r5 < 0 {
        fail(coord, 5);
    }
    unsafe { core::ptr::write_volatile(r5 as u64 as *mut u32, 0xA5A5) };
    if sys_madvise(r5 as u64, PAGE, MADV_DONTNEED) != 0 {
        fail(coord, 5);
    }
    cw(O_MADV, r5 as u64);

    let cur = sys_brk(0);
    if cur <= 0 {
        fail(coord, 6);
    }
    let newb = sys_brk(cur as u64 + PAGE);
    if newb < cur as u64 as i64 + PAGE as i64 {
        fail(coord, 6);
    }
    cw(O_BRK, cur as u64);

    let id7 = sys_shmget(IPC_PRIVATE, PAGE as usize, IPC_CREAT | 0o600);
    if id7 < 0 {
        fail(coord, 7);
    }
    let s7 = sys_shmat(id7 as i64, 0, 0);
    if s7 < 0 {
        sys_shmctl(id7 as i64, IPC_RMID, 0);
        fail(coord, 7);
    }
    unsafe { core::ptr::write_volatile(s7 as u64 as *mut u32, 0xA7A7) };
    cw(O_SHMAT, s7 as u64);

    let id8 = sys_shmget(IPC_PRIVATE, PAGE as usize, IPC_CREAT | 0o600);
    if id8 < 0 {
        fail(coord, 8);
    }
    let s8 = sys_shmat(id8 as i64, 0, 0);
    if s8 < 0 {
        sys_shmctl(id8 as i64, IPC_RMID, 0);
        fail(coord, 8);
    }
    cw(O_SHMDT, s8 as u64);
    if sys_shmdt(s8 as u64) != 0 {
        fail(coord, 8);
    }

    let leader_done = unsafe { &*((coord + O_LEADER_DONE) as *const AtomicU32) };
    leader_done.store(1, Ordering::Release);

    let peer_done = unsafe { &*((coord + O_PEER_DONE) as *const AtomicU32) };
    while peer_done.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    let result = unsafe { core::ptr::read_volatile((coord + O_PEER_RESULT) as *const i64) };

    sys_shmctl(id7 as i64, IPC_RMID, 0);
    sys_shmctl(id8 as i64, IPC_RMID, 0);

    if result != 0 {
        let mut buf = [0u8; 64];
        let n = format_kv(
            &mut buf,
            b"threads_coherence: peer did NOT observe op #",
            result,
        );
        sys_write(1, buf.as_ptr(), n);
        sys_exit(1);
    }
    log("threads_coherence: peer observed all 8 VM-shape mutations OK\n");
    log("threads_coherence: all tests OK\n");
    sys_exit(0);
}

extern "C" fn child_entry(coord: u64) -> ! {
    let leader_done = unsafe { &*((coord + O_LEADER_DONE) as *const AtomicU32) };
    while leader_done.load(Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    let rd = |off: u64| unsafe { core::ptr::read_volatile((coord + off) as *const u64) };
    let mut fail_tag: i64 = 0;

    let r1 = rd(O_MMAP);
    if unsafe { core::ptr::read_volatile(r1 as *const u32) } != 0xA1A1 {
        fail_tag = 1;
    }
    if fail_tag == 0 && sys_mincore(rd(O_MUNMAP), PAGE, scratch()) != ENOMEM {
        fail_tag = 2;
    }
    if fail_tag == 0 && unsafe { core::ptr::read_volatile(rd(O_MPROT) as *const u32) } != 0xA3A3 {
        fail_tag = 3;
    }
    if fail_tag == 0 {
        let r4 = rd(O_MREMAP);
        if unsafe { core::ptr::read_volatile(r4 as *const u32) } != 0xA4A4 {
            fail_tag = 4;
        } else {
            unsafe { core::ptr::write_volatile((r4 + PAGE) as *mut u32, 0x4444) };
            if unsafe { core::ptr::read_volatile((r4 + PAGE) as *const u32) } != 0x4444 {
                fail_tag = 4;
            }
        }
    }
    if fail_tag == 0 && unsafe { core::ptr::read_volatile(rd(O_MADV) as *const u32) } != 0 {
        fail_tag = 5;
    }
    if fail_tag == 0 {
        let b = rd(O_BRK);
        unsafe { core::ptr::write_volatile(b as *mut u32, 0x6666) };
        if unsafe { core::ptr::read_volatile(b as *const u32) } != 0x6666 {
            fail_tag = 6;
        }
    }
    if fail_tag == 0 && unsafe { core::ptr::read_volatile(rd(O_SHMAT) as *const u32) } != 0xA7A7 {
        fail_tag = 7;
    }
    if fail_tag == 0 && sys_mincore(rd(O_SHMDT), PAGE, scratch()) != ENOMEM {
        fail_tag = 8;
    }

    unsafe { core::ptr::write_volatile((coord + O_PEER_RESULT) as *mut i64, fail_tag) };
    let peer_done = unsafe { &*((coord + O_PEER_DONE) as *const AtomicU32) };
    peer_done.store(1, Ordering::Release);
    sys_exit(0);
}

static mut MINCORE_SCRATCH: [u8; 8] = [0; 8];
fn scratch() -> u64 {
    core::ptr::addr_of_mut!(MINCORE_SCRATCH) as u64
}

fn fail(coord: u64, tag: i64) -> ! {
    unsafe { core::ptr::write_volatile((coord + O_PEER_RESULT) as *mut i64, 1000 + tag) };
    let peer_done = unsafe { &*((coord + O_PEER_DONE) as *const AtomicU32) };
    peer_done.store(1, Ordering::Release);
    let mut buf = [0u8; 64];
    let n = format_kv(
        &mut buf,
        b"threads_coherence: leader mutation failed op #",
        tag,
    );
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
    let mut digits = [0u8; 20];
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
        asm!("syscall", in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 9u64, in("rdi") addr, in("rsi") len, in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") off, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_munmap(addr: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 11u64, in("rdi") addr, in("rsi") len, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 10u64, in("rdi") addr, in("rsi") len, in("rdx") prot, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_mremap(addr: u64, old: u64, new: u64, flags: u64, naddr: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 25u64, in("rdi") addr, in("rsi") old, in("rdx") new, in("r10") flags, in("r8") naddr, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_madvise(addr: u64, len: u64, advice: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 28u64, in("rdi") addr, in("rsi") len, in("rdx") advice, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_brk(addr: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 12u64, in("rdi") addr, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_mincore(addr: u64, len: u64, vec: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 27u64, in("rdi") addr, in("rsi") len, in("rdx") vec, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_shmget(key: i64, size: usize, flags: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 29u64, in("rdi") key, in("rsi") size, in("rdx") flags, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_shmat(shmid: i64, addr: u64, flags: i64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 30u64, in("rdi") shmid, in("rsi") addr, in("rdx") flags, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_shmctl(shmid: i64, cmd: i64, buf: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 31u64, in("rdi") shmid, in("rsi") cmd, in("rdx") buf, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_shmdt(addr: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 67u64, in("rdi") addr, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
