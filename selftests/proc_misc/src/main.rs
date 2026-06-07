#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

#[repr(C)]
struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Rlimit64 {
    cur: u64,
    max: u64,
}

#[repr(C, align(64))]
struct TlsArea {
    self_ptr: u64,
    pad: [u64; 7],
}

static mut TLS: TlsArea = TlsArea {
    self_ptr: 0,
    pad: [0; 7],
};

const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut u: Utsname = unsafe { core::mem::zeroed() };
    let r = sys_uname(&mut u as *mut Utsname as u64);
    if r != 0 {
        report(b"uname failed\n");
        sys_exit(1);
    }
    if &u.sysname[..5] != b"Linux" {
        report(b"uname.sysname wrong\n");
        sys_exit(2);
    }
    if &u.machine[..6] != b"x86_64" {
        report(b"uname.machine wrong\n");
        sys_exit(3);
    }
    report(b"misc: uname ok\n");

    if sys_call0(102) != 0 || sys_call0(107) != 0 || sys_call0(104) != 0 || sys_call0(108) != 0 {
        report(b"getuid family wrong\n");
        sys_exit(4);
    }
    report(b"misc: getuid family ok\n");

    let tid = sys_call0(186);
    let pid = sys_call0(39);
    if tid != pid {
        report(b"gettid != getpid\n");
        sys_exit(5);
    }
    report(b"misc: gettid ok\n");

    let mut child_tid: i32 = 0;
    let r = sys_set_tid_address(&mut child_tid as *mut i32 as u64);
    if r != tid {
        report(b"set_tid_address ret wrong\n");
        sys_exit(6);
    }
    report(b"misc: set_tid_address ok\n");

    let tls_addr = &raw const TLS as u64;
    unsafe {
        (&raw mut TLS).write_volatile(TlsArea {
            self_ptr: tls_addr,
            pad: [0; 7],
        });
    }
    if sys_arch_prctl(ARCH_SET_FS, tls_addr) != 0 {
        report(b"arch_prctl(SET_FS) failed\n");
        sys_exit(7);
    }
    let fs_self: u64;
    unsafe {
        asm!("mov {}, fs:0", out(reg) fs_self, options(nostack, preserves_flags));
    }
    if fs_self != tls_addr {
        report(b"fs:0 read wrong\n");
        sys_exit(8);
    }
    let mut got: u64 = 0;
    if sys_arch_prctl(ARCH_GET_FS, &mut got as *mut u64 as u64) != 0 {
        report(b"arch_prctl(GET_FS) failed\n");
        sys_exit(9);
    }
    if got != tls_addr {
        report(b"GET_FS mismatch\n");
        sys_exit(10);
    }
    report(b"misc: arch_prctl ok\n");

    let name = b"myproc\0";
    if sys_prctl(PR_SET_NAME, name.as_ptr() as u64, 0, 0, 0) != 0 {
        report(b"prctl(SET_NAME) failed\n");
        sys_exit(11);
    }
    let mut buf = [0u8; 16];
    if sys_prctl(PR_GET_NAME, buf.as_mut_ptr() as u64, 0, 0, 0) != 0 {
        report(b"prctl(GET_NAME) failed\n");
        sys_exit(12);
    }
    if &buf[..6] != b"myproc" {
        report(b"PR_GET_NAME mismatch\n");
        sys_exit(13);
    }
    report(b"misc: prctl ok\n");

    let mut r = Rlimit64 { cur: 0, max: 0 };
    if sys_getrlimit(7, &mut r as *mut Rlimit64 as u64) != 0 {
        report(b"getrlimit failed\n");
        sys_exit(14);
    }
    if r.cur != 1024 {
        report(b"getrlimit(NOFILE) cur != 1024\n");
        sys_exit(15);
    }
    report(b"misc: getrlimit ok\n");

    let mut rnd = [0u8; 32];
    let n = sys_getrandom(rnd.as_mut_ptr() as u64, rnd.len() as u64, 0);
    if n != rnd.len() as i64 {
        report(b"getrandom short\n");
        sys_exit(16);
    }
    let any_nonzero = rnd.iter().any(|&b| b != 0);
    if !any_nonzero {
        report(b"getrandom: all zeros\n");
        sys_exit(17);
    }
    report(b"misc: getrandom ok\n");

    let mut rnd2 = [0u8; 32];
    if sys_getrandom(rnd2.as_mut_ptr() as u64, rnd2.len() as u64, 1)
        != rnd2.len() as i64
    {
        report(b"getrandom nonblock short\n");
        sys_exit(19);
    }
    let mut rnd3 = [0u8; 32];
    if sys_getrandom(rnd3.as_mut_ptr() as u64, rnd3.len() as u64, 2)
        != rnd3.len() as i64
    {
        report(b"getrandom GRND_RANDOM short\n");
        sys_exit(20);
    }
    let mut rnd4 = [0u8; 32];
    if sys_getrandom(rnd4.as_mut_ptr() as u64, rnd4.len() as u64, 0x10) != -22 {
        report(b"getrandom bad-flags not EINVAL\n");
        sys_exit(21);
    }
    report(b"misc: getrandom flags ok\n");

    let img_page = 0x30000000u64;
    let r = sys_mprotect(img_page, 4096, 5);
    if r != 0 {
        report(b"mprotect failed\n");
        sys_exit(18);
    }
    report(b"misc: mprotect ok\n");

    sys_exit(0);
}

fn report(msg: &[u8]) {
    sys_write(1, msg.as_ptr(), msg.len());
}

fn sys_call0(nr: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") nr, lateout("rax") r,
             out("rcx") _, out("r11") _, options(nostack));
    }
    r
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

fn sys_uname(buf: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 63u64, in("rdi") buf,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_set_tid_address(addr: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 218u64, in("rdi") addr,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_arch_prctl(code: u64, addr: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 158u64, in("rdi") code, in("rsi") addr,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_prctl(option: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 157u64, in("rdi") option, in("rsi") a2,
            in("rdx") a3, in("r10") a4, in("r8") a5,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_getrlimit(resource: u64, rlim: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 97u64, in("rdi") resource, in("rsi") rlim,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_getrandom(buf: u64, count: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 318u64, in("rdi") buf, in("rsi") count, in("rdx") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall", in("rax") 10u64, in("rdi") addr, in("rsi") len, in("rdx") prot,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
