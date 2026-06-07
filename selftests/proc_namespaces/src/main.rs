#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const CLONE_NEWUTS: u64 = 0x0400_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const CLONE_NEWTIME: u64 = 0x0000_0080;

#[repr(C)]
struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("namespaces test starting\n");

    let mut u: Utsname = unsafe { core::mem::zeroed() };
    if sys_uname(&mut u as *mut Utsname as u64) != 0 {
        log("uname1 fail\n");
        sys_exit(1);
    }
    if !nodename_is(&u, b"cyphera") {
        log("default nodename wrong\n");
        sys_exit(1);
    }
    log("default nodename = cyphera OK\n");

    if sys_sethostname(b"host-a".as_ptr(), 6) != 0 {
        log("sethostname host-a: failed\n");
        sys_exit(1);
    }
    let mut u: Utsname = unsafe { core::mem::zeroed() };
    sys_uname(&mut u as *mut Utsname as u64);
    if !nodename_is(&u, b"host-a") {
        log("post-sethostname nodename wrong\n");
        sys_exit(1);
    }
    log("sethostname(host-a) takes effect OK\n");

    let pid = sys_fork();
    if pid < 0 {
        log("fork: ");
        log_num(pid);
        sys_exit(1);
    }
    if pid == 0 {
        if sys_unshare(CLONE_NEWUTS) != 0 {
            sys_exit(30);
        }
        if sys_sethostname(b"child-uts".as_ptr(), 9) != 0 {
            sys_exit(31);
        }
        let mut u: Utsname = unsafe { core::mem::zeroed() };
        sys_uname(&mut u as *mut Utsname as u64);
        if !nodename_is(&u, b"child-uts") {
            sys_exit(32);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("child UTS: failed ");
        log_num(exit_code as i64);
        sys_exit(1);
    }
    let mut u: Utsname = unsafe { core::mem::zeroed() };
    sys_uname(&mut u as *mut Utsname as u64);
    if !nodename_is(&u, b"host-a") {
        log("parent nodename clobbered by child\n");
        sys_exit(1);
    }
    log("CLONE_NEWUTS isolates per-process hostname OK\n");

    const KEY: i32 = 0x1234;
    const IPC_CREAT: u32 = 0o1000;
    const IPC_EXCL: u32 = 0o2000;
    const ENOENT: i64 = -2;
    const EEXIST: i64 = -17;
    const SIGCHLD: u64 = 17;
    const SENTINEL: u32 = 0xCAFE;

    let host_id = sys_shmget(KEY, 4096, IPC_CREAT | 0o666);
    if host_id < 0 {
        log("shmget host create failed\n");
        sys_exit(1);
    }
    let host_addr = sys_shmat(host_id as i32, 0, 0);
    if host_addr < 0 {
        log("shmat host failed\n");
        sys_exit(1);
    }
    unsafe {
        *(host_addr as *mut u32) = SENTINEL;
    }
    sys_shmdt(host_addr as u64);

    let pid = sys_fork();
    if pid < 0 {
        log("shm fork A fail\n");
        sys_exit(1);
    }
    if pid == 0 {
        if sys_unshare(CLONE_NEWIPC) != 0 {
            sys_exit(50);
        }
        if sys_shmget(KEY, 4096, 0) != ENOENT {
            sys_exit(51);
        }
        let nid = sys_shmget(KEY, 4096, IPC_CREAT | 0o666);
        if nid < 0 {
            sys_exit(52);
        }
        let naddr = sys_shmat(nid as i32, 0, 0);
        if naddr < 0 {
            sys_exit(53);
        }
        if unsafe { *(naddr as *const u32) } != 0 {
            sys_exit(54);
        }
        if sys_shmget(KEY, 4096, IPC_CREAT | IPC_EXCL | 0o666) != EEXIST {
            sys_exit(55);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || code != 0 {
        log("shm unshare-isolation child failed, code=");
        log_num(code as i64);
        sys_exit(1);
    }
    log("unshare(CLONE_NEWIPC) isolates SysV shm OK\n");

    let pid = sys_clone(CLONE_NEWIPC | SIGCHLD, 0, 0, 0, 0);
    if pid < 0 {
        log("clone(CLONE_NEWIPC) fail\n");
        sys_exit(1);
    }
    if pid == 0 {
        if sys_shmget(KEY, 4096, 0) != ENOENT {
            sys_exit(60);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(pid as i32, &mut st, 0);
    let code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || code != 0 {
        log("shm clone-isolation child failed, code=");
        log_num(code as i64);
        sys_exit(1);
    }
    log("clone(CLONE_NEWIPC) gives the child a fresh IPC ns OK\n");

    if sys_shmget(KEY, 4096, 0) != host_id {
        log("host lost visibility of its own shm segment\n");
        sys_exit(1);
    }
    log("host namespace retains its shm segment OK\n");

    let combined = CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWCGROUP | CLONE_NEWTIME;
    if sys_unshare(combined) != 0 {
        log("unshare(NEWPID|IPC|CGROUP|TIME): failed\n");
        sys_exit(1);
    }
    log("unshare(other CLONE_NEW* markers) accepts OK\n");

    log("all namespaces tests OK\n");
    sys_exit(0);
}

fn nodename_is(u: &Utsname, want: &[u8]) -> bool {
    let n = u.nodename.iter().position(|&b| b == 0).unwrap_or(65);
    &u.nodename[..n] == want
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
fn sys_uname(buf: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 63u64, in("rdi") buf,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_sethostname(name: *const u8, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 170u64, in("rdi") name, in("rsi") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_unshare(flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 272u64, in("rdi") flags,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_fork() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 57u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_wait4(pid: i32, status: *mut i32, options: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid as i64, in("rsi") status,
        in("rdx") options as i64, in("r10") 0u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_shmget(key: i32, size: usize, flags: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 29u64, in("rdi") key as i64, in("rsi") size, in("rdx") flags as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_shmat(shmid: i32, shmaddr: u64, flags: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 30u64, in("rdi") shmid as i64, in("rsi") shmaddr, in("rdx") flags as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_shmdt(shmaddr: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 67u64, in("rdi") shmaddr,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_clone(flags: u64, child_stack: u64, ptid: u64, ctid: u64, tls: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 56u64, in("rdi") flags, in("rsi") child_stack,
        in("rdx") ptid, in("r10") ctid, in("r8") tls,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
