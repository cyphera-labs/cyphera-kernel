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

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;

const PAGE: u64 = 4096;
const REGION_BYTES: u64 = 16 * PAGE;

const MARKER: u32 = 0xCAFE;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("threads_shm: starting\n");

    let id = sys_shmget(IPC_PRIVATE, PAGE as usize, IPC_CREAT | 0o600);
    if id < 0 {
        log("threads_shm: shmget failed\n");
        sys_exit(1);
    }
    let s = sys_shmat(id as i32, 0, 0);
    if s < 0 {
        log("threads_shm: shmat failed\n");
        sys_shmctl(id as i32, IPC_RMID, 0);
        sys_exit(1);
    }
    let shm = unsafe { &*(s as u64 as *const AtomicU32) };
    shm.store(MARKER, Ordering::SeqCst);

    let r = sys_mmap(
        0,
        REGION_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        log("threads_shm: mmap coord failed\n");
        sys_shmctl(id as i32, IPC_RMID, 0);
        sys_exit(1);
    }
    let region_base = r as u64;
    let peer_done = unsafe { &*(region_base as *const AtomicU32) };
    peer_done.store(0, Ordering::SeqCst);
    let child_stack_top = region_base + REGION_BYTES - PAGE;

    let flags = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
    let rc: i64;
    unsafe {
        asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov eax, dword ptr [r13]",
            "mov dword ptr [r14], 1",
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
            inout("rax") 56u64 => rc,
            in("r14") region_base,
            in("r13") s as u64,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    if rc < 0 {
        log("threads_shm: clone failed\n");
        sys_shmdt(s as u64);
        sys_shmctl(id as i32, IPC_RMID, 0);
        sys_exit(1);
    }

    while peer_done.load(Ordering::SeqCst) == 0 {
        core::hint::spin_loop();
    }
    for _ in 0..20_000_000u64 {
        core::hint::spin_loop();
    }

    let v = shm.load(Ordering::SeqCst);
    if v != MARKER {
        log("threads_shm: shm marker LOST after sibling exit (FAIL)\n");
        sys_shmdt(s as u64);
        sys_shmctl(id as i32, IPC_RMID, 0);
        sys_exit(1);
    }
    log("threads_shm: sibling exit left shm mapping intact OK\n");

    sys_shmdt(s as u64);
    sys_shmctl(id as i32, IPC_RMID, 0);
    log("threads_shm: all tests OK\n");
    sys_exit(0);
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
fn sys_shmget(key: i32, size: usize, flags: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 29u64, in("rdi") key as i64, in("rsi") size,
            in("rdx") flags as i64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_shmat(shmid: i32, addr: u64, flags: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 30u64, in("rdi") shmid as i64, in("rsi") addr,
            in("rdx") flags as i64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_shmctl(shmid: i32, cmd: i32, buf: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 31u64, in("rdi") shmid as i64, in("rsi") cmd as i64,
            in("rdx") buf, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_shmdt(addr: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 67u64, in("rdi") addr,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
