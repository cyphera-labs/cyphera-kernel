#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Timespec {
    sec: i64,
    nsec: i64,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Timeval {
    sec: i64,
    usec: i64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Timex {
    bytes: [u8; 184],
}

impl Default for Timex {
    fn default() -> Self {
        Self { bytes: [0u8; 184] }
    }
}

const CLOCK_REALTIME: i32 = 0;
const ADJ_SETOFFSET: i32 = 0x0100;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut t0 = Timespec::default();
    if sys_clock_gettime(CLOCK_REALTIME, &mut t0) != 0 {
        report(b"clock_gettime baseline failed\n");
        sys_exit(1);
    }
    report(b"clock_settime: gettime baseline ok\n");

    let target = Timespec {
        sec: 1_700_000_000,
        nsec: 0,
    };
    let r = sys_clock_settime(CLOCK_REALTIME, &target);
    if r != 0 {
        report(b"clock_settime as root failed\n");
        sys_exit(2);
    }
    let mut t1 = Timespec::default();
    if sys_clock_gettime(CLOCK_REALTIME, &mut t1) != 0 {
        report(b"clock_gettime post-set failed\n");
        sys_exit(3);
    }
    if t1.sec < target.sec {
        report(b"clock_settime didn't take effect\n");
        sys_exit(4);
    }
    report(b"clock_settime: REALTIME write + read-back ok\n");

    let tv = Timeval {
        sec: 1_710_000_000,
        usec: 0,
    };
    if sys_settimeofday(&tv, core::ptr::null::<u8>()) != 0 {
        report(b"settimeofday failed\n");
        sys_exit(5);
    }
    let mut tv_back = Timeval::default();
    if sys_gettimeofday(&mut tv_back, core::ptr::null_mut::<u8>()) != 0 {
        report(b"gettimeofday post-set failed\n");
        sys_exit(6);
    }
    if tv_back.sec < tv.sec {
        report(b"settimeofday didn't take effect\n");
        sys_exit(7);
    }
    report(b"settimeofday: round-trip ok\n");

    let mut tx = Timex::default();
    let r = sys_adjtimex(&mut tx);
    if r < 0 {
        report(b"adjtimex(read) failed\n");
        sys_exit(8);
    }
    if r > 4 {
        report(b"adjtimex returned out-of-range status\n");
        sys_exit(9);
    }
    report(b"adjtimex(read) ok\n");

    let mut tx2 = Timex::default();
    tx2.bytes[0..4].copy_from_slice(&ADJ_SETOFFSET.to_le_bytes());
    let off_sec: i64 = 60;
    tx2.bytes[96..104].copy_from_slice(&off_sec.to_le_bytes());
    tx2.bytes[104..112].copy_from_slice(&0i64.to_le_bytes());
    let mut t_pre = Timespec::default();
    let _ = sys_clock_gettime(CLOCK_REALTIME, &mut t_pre);
    let r = sys_adjtimex(&mut tx2);
    if r < 0 {
        report(b"adjtimex(SETOFFSET) failed\n");
        sys_exit(10);
    }
    let mut t_post = Timespec::default();
    let _ = sys_clock_gettime(CLOCK_REALTIME, &mut t_post);
    if t_post.sec < t_pre.sec + 60 {
        report(b"ADJ_SETOFFSET shift not visible in gettime\n");
        sys_exit(11);
    }
    report(b"adjtimex(SETOFFSET) shift applied ok\n");

    let r = sys_setresuid(1000, 1000, 1000);
    if r != 0 {
        report(b"setresuid to non-root failed\n");
        sys_exit(12);
    }
    let target2 = Timespec {
        sec: 1_720_000_000,
        nsec: 0,
    };
    let r = sys_clock_settime(CLOCK_REALTIME, &target2);
    if r != -1 {
        report(b"clock_settime as non-root should EPERM but didn't\n");
        sys_exit(13);
    }
    report(b"clock_settime: non-root -> EPERM ok\n");

    report(b"CLOCK_SETTIME_OK\n");
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

fn sys_clock_gettime(clock: i32, ts: *mut Timespec) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 228u64,
            in("rdi") clock as i64,
            in("rsi") ts,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_clock_settime(clock: i32, ts: *const Timespec) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 227u64,
            in("rdi") clock as i64,
            in("rsi") ts,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_settimeofday(tv: *const Timeval, tz: *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 164u64,
            in("rdi") tv,
            in("rsi") tz,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_gettimeofday(tv: *mut Timeval, tz: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 96u64,
            in("rdi") tv,
            in("rsi") tz,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_adjtimex(tx: *mut Timex) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 159u64,
            in("rdi") tx,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_setresuid(ruid: u32, euid: u32, suid: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 117u64,
            in("rdi") ruid as u64,
            in("rsi") euid as u64,
            in("rdx") suid as u64,
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
