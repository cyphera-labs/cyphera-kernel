#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_PRIVATE_FLAG: u64 = 0x80;
const EAGAIN: i64 = -11;

static mut FUTEX_WORD: i32 = 0;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe { FUTEX_WORD = 5 };
    let addr = &raw const FUTEX_WORD as u64;

    let r = sys_futex(addr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 42, 0, 0, 0);
    if r != EAGAIN {
        report(b"futex: WAIT mismatched did not return EAGAIN\n");
        sys_exit(1);
    }
    report(b"futex: WAIT mismatched -> EAGAIN ok\n");

    let r = sys_futex(addr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0);
    if r != 0 {
        report(b"futex: WAKE empty queue returned non-zero\n");
        sys_exit(2);
    }
    report(b"futex: WAKE empty -> 0 ok\n");

    let r = sys_futex(addr + 1, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0, 0, 0);
    if r != -22 {
        report(b"futex: misaligned addr did not return EINVAL\n");
        sys_exit(3);
    }
    report(b"futex: misaligned -> EINVAL ok\n");

    sys_exit(0);
}

fn report(msg: &[u8]) {
    sys_write(1, msg.as_ptr(), msg.len());
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_futex(uaddr: u64, op: u64, val: u64, timeout: u64, uaddr2: u64, val3: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 202u64,
            in("rdi") uaddr,
            in("rsi") op,
            in("rdx") val,
            in("r10") timeout,
            in("r8")  uaddr2,
            in("r9")  val3,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
