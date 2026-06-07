#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const RSEQ_FLAG_UNREGISTER: u64 = 1;
const RSEQ_SIG: u32 = 0x53053053;
const RSEQ_LEN_V0: u64 = 32;
const EINVAL: i64 = -22;
const EBUSY: i64 = -16;
const EPERM: i64 = -1;
const RSEQ_CPU_ID_UNINITIALIZED: u32 = 0xffff_ffff;

#[repr(C, align(32))]
struct RseqArea {
    cpu_id_start: u32,
    cpu_id: u32,
    rseq_cs: u64,
    flags: u32,
    _pad: u32,
    _spare1: u32,
    _spare2: u32,
}

static mut RSEQ_AREA: RseqArea = RseqArea {
    cpu_id_start: RSEQ_CPU_ID_UNINITIALIZED,
    cpu_id: RSEQ_CPU_ID_UNINITIALIZED,
    rseq_cs: 0,
    flags: 0,
    _pad: 0,
    _spare1: 0,
    _spare2: 0,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("rseq test starting\n");

    let area_ptr = &raw mut RSEQ_AREA as *mut RseqArea as u64;

    let r = sys_rseq(area_ptr, RSEQ_LEN_V0, 0, RSEQ_SIG as u64);
    if r != 0 {
        log("rseq register: ");
        log_num(r);
        sys_exit(1);
    }
    log("rseq register OK\n");

    let cpu_id = unsafe { core::ptr::read_volatile(&raw const RSEQ_AREA.cpu_id) };
    if cpu_id == RSEQ_CPU_ID_UNINITIALIZED {
        log("rseq cpu_id still UNINITIALIZED\n");
        sys_exit(1);
    }
    log("rseq cpu_id populated OK\n");

    let r = sys_rseq(area_ptr, RSEQ_LEN_V0, 0, RSEQ_SIG as u64);
    if r != 0 {
        log("rseq idempotent: ");
        log_num(r);
        sys_exit(1);
    }
    log("rseq idempotent re-register OK\n");

    let r = sys_rseq(area_ptr, RSEQ_LEN_V0, 0, 0xdeadbeef);
    if r != EBUSY {
        log("rseq EBUSY expected: ");
        log_num(r);
        sys_exit(1);
    }
    log("rseq mismatched sig → EBUSY OK\n");

    let r = sys_rseq(area_ptr, RSEQ_LEN_V0, RSEQ_FLAG_UNREGISTER, 0xbad);
    if r != EPERM {
        log("rseq unreg EPERM expected: ");
        log_num(r);
        sys_exit(1);
    }
    log("rseq unreg wrong sig → EPERM OK\n");

    let r = sys_rseq(area_ptr, RSEQ_LEN_V0, RSEQ_FLAG_UNREGISTER, RSEQ_SIG as u64);
    if r != 0 {
        log("rseq unreg: ");
        log_num(r);
        sys_exit(1);
    }
    log("rseq unregister OK\n");

    let r = sys_rseq(area_ptr, RSEQ_LEN_V0, RSEQ_FLAG_UNREGISTER, RSEQ_SIG as u64);
    if r != EINVAL {
        log("rseq unreg-when-none: ");
        log_num(r);
        sys_exit(1);
    }
    log("rseq unreg when-not-registered → EINVAL OK\n");

    let r = sys_rseq(area_ptr + 1, RSEQ_LEN_V0, 0, RSEQ_SIG as u64);
    if r != EINVAL {
        log("rseq unaligned: ");
        log_num(r);
        sys_exit(1);
    }
    log("rseq unaligned → EINVAL OK\n");

    log("all rseq tests OK\n");
    sys_exit(0);
}

#[inline(never)]
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
    buf[i] = b'\n';
    i += 1;
    sys_write(1, buf.as_ptr(), i);
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
fn sys_rseq(rseq: u64, rseq_len: u64, flags: u64, sig: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 334u64, in("rdi") rseq, in("rsi") rseq_len,
        in("rdx") flags, in("r10") sig,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
