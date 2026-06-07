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

const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut t1 = Timespec::default();
    if sys_clock_gettime(CLOCK_MONOTONIC, &mut t1) != 0 {
        report(b"clock_gettime(MONOTONIC) #1 failed\n");
        sys_exit(1);
    }
    report(b"clock: t1 monotonic captured\n");

    spin(2_000_000);

    let mut t2 = Timespec::default();
    if sys_clock_gettime(CLOCK_MONOTONIC, &mut t2) != 0 {
        report(b"clock_gettime(MONOTONIC) #2 failed\n");
        sys_exit(2);
    }

    let advanced = (t2.sec, t2.nsec) > (t1.sec, t1.nsec);
    if !advanced {
        report(b"clock did not advance between samples\n");
        sys_exit(3);
    }
    report(b"clock: monotonic advanced (ok)\n");

    let mut tr = Timespec::default();
    if sys_clock_gettime(CLOCK_REALTIME, &mut tr) != 0 {
        report(b"clock_gettime(REALTIME) failed\n");
        sys_exit(4);
    }
    if tr.sec >= 1_577_836_800 {
        report(b"clock: REALTIME is real wall time (post-2020) ok\n");
    } else {
        report(b"clock: REALTIME falls back to monotonic (pvclock unavailable)\n");
    }

    let mut tv = Timeval::default();
    if sys_gettimeofday(&mut tv, core::ptr::null_mut()) != 0 {
        report(b"gettimeofday failed\n");
        sys_exit(5);
    }
    report(b"clock: gettimeofday ok\n");

    let mut res = Timespec::default();
    if sys_clock_getres(CLOCK_MONOTONIC, &mut res) != 0 {
        report(b"clock_getres failed\n");
        sys_exit(6);
    }
    if res.sec != 0 || res.nsec != 1 {
        report(b"clock_getres: unexpected resolution\n");
        sys_exit(7);
    }
    report(b"clock: getres ok (1 ns)\n");

    let mut p1 = Timespec::default();
    if sys_clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut p1) != 0 {
        report(b"clock_gettime(PROCESS_CPUTIME) failed\n");
        sys_exit(8);
    }
    if p1.sec == 0 && p1.nsec == 0 {
        report(b"CPUTIME(process) read zero\n");
        sys_exit(9);
    }
    spin(2_000_000);
    let mut p2 = Timespec::default();
    if sys_clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut p2) != 0 {
        report(b"clock_gettime(PROCESS_CPUTIME) #2 failed\n");
        sys_exit(10);
    }
    if (p2.sec, p2.nsec) <= (p1.sec, p1.nsec) {
        report(b"CPUTIME(process) did not advance\n");
        sys_exit(10);
    }
    let mut th = Timespec::default();
    if sys_clock_gettime(CLOCK_THREAD_CPUTIME_ID, &mut th) != 0 || (th.sec == 0 && th.nsec == 0) {
        report(b"CPUTIME(thread) read zero\n");
        sys_exit(11);
    }
    report(b"clock: CPUTIME(process+thread) nonzero and advancing ok\n");

    let mut pa = Timespec::default();
    if sys_clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut pa) != 0 {
        report(b"clock_gettime(PROCESS_CPUTIME) pre-sleep failed\n");
        sys_exit(12);
    }
    let req = Timespec {
        sec: 0,
        nsec: 20_000_000,
    };
    sys_nanosleep(&req);
    let mut pb = Timespec::default();
    if sys_clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut pb) != 0 {
        report(b"clock_gettime(PROCESS_CPUTIME) post-sleep failed\n");
        sys_exit(13);
    }
    if (pb.sec, pb.nsec) < (pa.sec, pa.nsec) {
        report(b"CPUTIME went backwards across a blocking sleep\n");
        sys_exit(14);
    }
    report(b"clock: CPUTIME monotonic across blocking syscall ok\n");

    sys_exit(0);
}

fn sys_nanosleep(req: &Timespec) {
    unsafe {
        asm!(
            "syscall",
            in("rax") 35u64,
            in("rdi") req as *const Timespec,
            in("rsi") 0u64,
            lateout("rax") _, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
}

fn spin(n: u64) {
    let mut i = 0u64;
    while i < n {
        unsafe {
            asm!("pause", options(nomem, nostack, preserves_flags));
        }
        i += 1;
    }
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

fn sys_clock_getres(clock: i32, res: *mut Timespec) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 229u64,
            in("rdi") clock as i64,
            in("rsi") res,
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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
