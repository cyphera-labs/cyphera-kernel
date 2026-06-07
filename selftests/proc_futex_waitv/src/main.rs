#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const SYS_FUTEX_WAITV: u64 = 449;
const SYS_MMAP: u64 = 9;
const SYS_CLONE: u64 = 56;
const SYS_EXIT: u64 = 60;
const SYS_WRITE: u64 = 1;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;

const FUTEX2_SIZE_U32: u32 = 2;

const ETIMEDOUT: i64 = -110;
const EAGAIN: i64 = -11;

const PAGE: u64 = 4096;
const REGION_BYTES: u64 = 16 * PAGE;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct FutexWaitv {
    val: u64,
    uaddr: u64,
    flags: u32,
    __reserved: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("futex_waitv test starting\n");

    let r = sys_mmap(
        0,
        REGION_BYTES,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1i64 as u64,
        0,
    );
    if r < 0 {
        log("mmap failed\n");
        sys_exit(1);
    }
    let region = r as u64;

    let f0 = region;
    let f1 = region + 16;
    let f2 = region + 32;
    let go = region + 48;
    unsafe {
        *(f0 as *mut u32) = 0;
        *(f1 as *mut u32) = 0;
        *(f2 as *mut u32) = 0;
        *(go as *mut u32) = 0;
    }

    let child_stack_top = region + REGION_BYTES - PAGE;
    let flags = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;

    let r: i64;
    unsafe {
        asm!(
            "syscall",
            "test rax, rax",
            "jnz 22f",
            "33:",
            "mov eax, dword ptr [r12 + 48]",
            "test eax, eax",
            "jz 33b",
            "mov dword ptr [r12 + 16], 1",
            "lea rdi, [r12 + 16]",
            "mov rsi, -1",
            "mov rdx, 1",
            "mov r10, 2",
            "mov rax, 454",
            "syscall",
            "mov rdi, 0",
            "mov rax, 60",
            "syscall",
            "ud2",
            "22:",
            in("rdi") flags,
            in("rsi") child_stack_top,
            in("rdx") 0u64,
            in("r10") 0u64,
            in("r8")  0u64,
            inout("rax") SYS_CLONE => r,
            in("r12") region,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    if r < 0 {
        log("clone failed\n");
        sys_exit(2);
    }

    let waiters = [
        FutexWaitv {
            val: 0,
            uaddr: f0,
            flags: FUTEX2_SIZE_U32,
            __reserved: 0,
        },
        FutexWaitv {
            val: 0,
            uaddr: f1,
            flags: FUTEX2_SIZE_U32,
            __reserved: 0,
        },
        FutexWaitv {
            val: 0,
            uaddr: f2,
            flags: FUTEX2_SIZE_U32,
            __reserved: 0,
        },
    ];
    unsafe {
        *(go as *mut u32) = 1;
    }
    let r = sys_futex_waitv(waiters.as_ptr(), 3, 0, core::ptr::null(), 0);
    let f1_published = unsafe { *(f1 as *const u32) } == 1;
    if !(r == 1 || (r == EAGAIN && f1_published)) {
        log("futex_waitv didn't wake at index 1 (no EAGAIN publication either); r=");
        log_num(r);
        sys_exit(3);
    }
    log("futex_waitv woke at index 1 OK\n");

    unsafe {
        *(f1 as *mut u32) = 0;
    }
    let zero_ts = Timespec { sec: 0, nsec: 0 };
    let r = sys_futex_waitv(waiters.as_ptr(), 3, 0, &zero_ts, 1);
    if r != ETIMEDOUT {
        log("futex_waitv with past deadline should -ETIMEDOUT; r=");
        log_num(r);
        sys_exit(4);
    }
    log("futex_waitv -ETIMEDOUT on past deadline OK\n");

    let waiters_bad = [
        FutexWaitv {
            val: 0,
            uaddr: f0,
            flags: FUTEX2_SIZE_U32,
            __reserved: 0,
        },
        FutexWaitv {
            val: 99,
            uaddr: f1,
            flags: FUTEX2_SIZE_U32,
            __reserved: 0,
        },
        FutexWaitv {
            val: 0,
            uaddr: f2,
            flags: FUTEX2_SIZE_U32,
            __reserved: 0,
        },
    ];
    let r = sys_futex_waitv(waiters_bad.as_ptr(), 3, 0, core::ptr::null(), 0);
    if r != EAGAIN {
        log("futex_waitv with mismatched val should -EAGAIN; r=");
        log_num(r);
        sys_exit(5);
    }
    log("futex_waitv -EAGAIN on val-mismatch OK\n");

    log("FUTEX_WAITV_OK\n");
    sys_exit(0);
}

fn log(msg: &str) {
    sys_write(1, msg.as_ptr(), msg.len());
}

fn log_num(n: i64) {
    let mut buf = [0u8; 24];
    let mut i = 0usize;
    let neg = n < 0;
    let mut v = if neg { -n as u64 } else { n as u64 };
    if v == 0 {
        buf[i] = b'0';
        i += 1;
    } else {
        let mut tmp = [0u8; 24];
        let mut j = 0usize;
        while v > 0 {
            tmp[j] = b'0' + (v % 10) as u8;
            v /= 10;
            j += 1;
        }
        if neg {
            buf[i] = b'-';
            i += 1;
        }
        while j > 0 {
            j -= 1;
            buf[i] = tmp[j];
            i += 1;
        }
    }
    buf[i] = b'\n';
    sys_write(1, buf.as_ptr(), i + 1);
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_WRITE,
            in("rdi") fd,
            in("rsi") buf,
            in("rdx") len,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_mmap(addr: u64, length: u64, prot: u64, flags: u64, fd: u64, offset: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_MMAP,
            in("rdi") addr,
            in("rsi") length,
            in("rdx") prot,
            in("r10") flags,
            in("r8") fd,
            in("r9") offset,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_futex_waitv(
    waiters: *const FutexWaitv,
    nr: u32,
    flags: u32,
    timeout: *const Timespec,
    clockid: u32,
) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_FUTEX_WAITV,
            in("rdi") waiters,
            in("rsi") nr as u64,
            in("rdx") flags as u64,
            in("r10") timeout,
            in("r8") clockid as u64,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") SYS_EXIT, in("rdi") code as u64, options(noreturn, nostack));
    }
}
