#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const SYS_WRITE: u64 = 1;
const SYS_MMAP: u64 = 9;
const SYS_RT_SIGPROCMASK: u64 = 14;
const SYS_KILL: u64 = 62;
const SYS_GETPID: u64 = 39;
const SYS_GETCPU: u64 = 309;
const SYS_MEMBARRIER: u64 = 324;
const SYS_RT_SIGPENDING: u64 = 127;
const SYS_MLOCK: u64 = 149;
const SYS_MUNLOCK: u64 = 150;
const SYS_EXIT: u64 = 60;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

const SIGUSR1: u64 = 10;
const SIG_BLOCK: u64 = 0;

const MEMBARRIER_CMD_QUERY: u64 = 0;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED: u64 = 8;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("misc_quickwins test starting\n");

    let mut cpu: u32 = u32::MAX;
    let mut node: u32 = u32::MAX;
    let r = sys_getcpu(&mut cpu, &mut node);
    if r != 0 {
        log("getcpu returned non-zero\n");
        sys_exit(1);
    }
    if cpu >= 64 {
        log("getcpu cpu out of range\n");
        sys_exit(2);
    }
    if node != 0 {
        log("getcpu node should be 0 (single-NUMA)\n");
        sys_exit(3);
    }
    log("getcpu: in-range OK\n");

    let r = sys_membarrier(MEMBARRIER_CMD_QUERY, 0, 0);
    if r <= 0 {
        log("membarrier(QUERY) returned non-positive\n");
        sys_exit(4);
    }
    let r = sys_membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0);
    if r != 0 {
        log("membarrier(PRIVATE_EXPEDITED) returned non-zero\n");
        sys_exit(5);
    }
    log("membarrier: QUERY + PRIVATE_EXPEDITED OK\n");

    let block_mask: u64 = 1u64 << SIGUSR1;
    let mut old_mask: u64 = 0;
    let r = sys_rt_sigprocmask(SIG_BLOCK, &block_mask, &mut old_mask);
    if r != 0 {
        log("rt_sigprocmask(BLOCK) failed\n");
        sys_exit(6);
    }
    let me = sys_getpid();
    if sys_kill(me as u64, SIGUSR1) != 0 {
        log("kill(self, USR1) failed\n");
        sys_exit(7);
    }
    let mut pending: u64 = 0;
    let r = sys_rt_sigpending(&mut pending);
    if r != 0 {
        log("rt_sigpending failed\n");
        sys_exit(8);
    }
    if (pending & (1u64 << SIGUSR1)) == 0 {
        log("rt_sigpending didn't report SIGUSR1\n");
        sys_exit(9);
    }
    log("rt_sigpending: blocked-then-pending USR1 OK\n");

    let r = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        log("mmap for mlock test failed\n");
        sys_exit(10);
    }
    let addr = r as u64;
    if sys_mlock(addr, 4096) != 0 {
        log("mlock failed\n");
        sys_exit(11);
    }
    if sys_munlock(addr, 4096) != 0 {
        log("munlock failed\n");
        sys_exit(12);
    }
    log("mlock + munlock round-trip OK\n");

    log("MISC_QUICKWINS_OK\n");
    sys_exit(0);
}

fn log(msg: &str) {
    sys_write(1, msg.as_ptr(), msg.len());
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_WRITE, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_GETPID, lateout("rax") r,
            out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_kill(pid: u64, sig: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_KILL, in("rdi") pid, in("rsi") sig,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_mmap(addr: u64, length: u64, prot: u64, flags: u64, fd: u64, offset: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall",
            in("rax") SYS_MMAP, in("rdi") addr, in("rsi") length,
            in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") offset,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_getcpu(cpu: *mut u32, node: *mut u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_GETCPU, in("rdi") cpu, in("rsi") node,
            in("rdx") 0u64, lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack));
    }
    r
}

fn sys_membarrier(cmd: u64, flags: u64, cpu_id: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_MEMBARRIER, in("rdi") cmd, in("rsi") flags,
            in("rdx") cpu_id, lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack));
    }
    r
}

fn sys_rt_sigprocmask(how: u64, set: *const u64, oldset: *mut u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_RT_SIGPROCMASK, in("rdi") how,
            in("rsi") set, in("rdx") oldset, in("r10") 8u64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_rt_sigpending(set: *mut u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_RT_SIGPENDING, in("rdi") set,
            in("rsi") 8u64, lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack));
    }
    r
}

fn sys_mlock(addr: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_MLOCK, in("rdi") addr, in("rsi") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_munlock(addr: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") SYS_MUNLOCK, in("rdi") addr, in("rsi") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") SYS_EXIT, in("rdi") code as u64,
            options(noreturn, nostack));
    }
}
