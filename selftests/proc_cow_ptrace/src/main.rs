#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

const SYS_PTRACE: u64 = 101;
const PTRACE_PEEKDATA: u64 = 2;
const PTRACE_POKEDATA: u64 = 5;
const PTRACE_CONT: u64 = 7;
const PTRACE_TRACEME: u64 = 0;

const SIGSTOP: u64 = 19;
const PAGE: u64 = 4096;

const INIT_WORD: u64 = 0x1111_1111_2222_2222;
const POKE_WORD: u64 = 0xDEAD_BEEF_CAFE_F00D;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("cow_ptrace: starting\n");

    let region = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        sys_exit(1);
    }
    let word = region as u64;
    wr64(word, INIT_WORD);

    let pid = sys_fork();
    if pid < 0 {
        sys_exit(2);
    }
    if pid == 0 {
        if sys_ptrace(PTRACE_TRACEME, 0, 0, 0) != 0 {
            sys_exit(11);
        }
        let self_pid = sys_getpid() as u64;
        sys_kill(self_pid, SIGSTOP);
        if rd64(word) != POKE_WORD {
            sys_exit(12);
        }
        sys_exit(0);
    }

    let child = pid as u64;
    let mut status: i32 = 0;
    sys_wait4(child, &mut status as *mut i32, 0, 0);
    if status & 0xff != 0x7f {
        sys_exit(3);
    }

    if sys_ptrace(PTRACE_POKEDATA, child, word, POKE_WORD) != 0 {
        sys_exit(4);
    }

    if rd64(word) != INIT_WORD {
        log("cow_ptrace: parent copy corrupted by poke\n");
        sys_exit(5);
    }

    let mut peeked: u64 = 0;
    if sys_ptrace(PTRACE_PEEKDATA, child, word, &mut peeked as *mut u64 as u64) != 0 {
        sys_exit(6);
    }
    if peeked != POKE_WORD {
        log("cow_ptrace: poke did not land in child\n");
        sys_exit(7);
    }

    sys_ptrace(PTRACE_CONT, child, 0, 0);
    let mut st2: i32 = 0;
    sys_wait4(child, &mut st2 as *mut i32, 0, 0);
    if !(st2 & 0x7f == 0 && (st2 >> 8) & 0xff == 0) {
        sys_exit(8);
    }

    if rd64(word) != INIT_WORD {
        sys_exit(9);
    }

    log("COW_PTRACE_OK\n");
    sys_exit(0)
}

fn rd64(p: u64) -> u64 {
    unsafe { core::ptr::read_volatile(p as *const u64) }
}
fn wr64(p: u64, v: u64) {
    unsafe { core::ptr::write_volatile(p as *mut u64, v) }
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
        asm!("syscall", in("rax") 9u64, in("rdi") addr, in("rsi") len, in("rdx") prot,
             in("r10") flags, in("r8") fd, in("r9") off,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_kill(pid: u64, sig: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 62u64, in("rdi") pid, in("rsi") sig,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_wait4(pid: u64, status: *mut i32, options: i32, rusage: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid, in("rsi") status,
             in("rdx") options as i64, in("r10") rusage,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_ptrace(req: u64, pid: u64, addr: u64, data: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_PTRACE, in("rdi") req, in("rsi") pid, in("rdx") addr,
             in("r10") data,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn sys_exit(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
