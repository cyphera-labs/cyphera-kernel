#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SIGTERM: i32 = 15;
const O_CREAT: u64 = 0o100;
const O_RDWR: u64 = 0o2;
const AT_FDCWD: i64 = -100;

const F_GETLK: u64 = 5;
const F_SETLK: u64 = 6;
const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;

const EAGAIN: i64 = -11;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("jobctl test starting\n");

    let r = sys_fork();
    if r < 0 {
        log("fork failed\n");
        sys_exit(1);
    }
    if r == 0 {
        if sys_setpgid(0, 0) != 0 {
            sys_exit(11);
        }
        let pgid = sys_getpgid(0);
        if pgid <= 0 {
            sys_exit(12);
        }
        let mypid = sys_getpid();
        if pgid != mypid {
            sys_exit(13);
        }
        loop {
            sys_sched_yield();
        }
    }
    let child1 = r as i32;
    for _ in 0..1000 {
        sys_sched_yield();
    }
    sys_kill(child1, SIGTERM);
    let mut st: i32 = 0;
    sys_wait4(child1, &mut st, 0);
    if (st & 0x7f) != SIGTERM {
        log("setpgid+kill: child not signal-terminated\n");
        sys_exit(1);
    }
    log("setpgid + getpgid + signal-terminate OK\n");

    let r1 = sys_fork();
    if r1 < 0 {
        log("fork r1 failed\n");
        sys_exit(1);
    }
    if r1 == 0 {
        sys_setpgid(0, 0);
        loop {
            sys_sched_yield();
        }
    }
    let leader_pid = r1 as i32;
    sys_setpgid(leader_pid, leader_pid);

    let r2 = sys_fork();
    if r2 < 0 {
        log("fork r2 failed\n");
        sys_exit(1);
    }
    if r2 == 0 {
        sys_setpgid(0, leader_pid);
        loop {
            sys_sched_yield();
        }
    }
    let member_pid = r2 as i32;
    sys_setpgid(member_pid, leader_pid);

    sys_kill(-leader_pid, SIGTERM);
    let mut s1: i32 = 0;
    let mut s2: i32 = 0;
    sys_wait4(leader_pid, &mut s1, 0);
    sys_wait4(member_pid, &mut s2, 0);
    if (s1 & 0x7f) != SIGTERM || (s2 & 0x7f) != SIGTERM {
        log("kill(-pgid) didn't kill all members\n");
        sys_exit(1);
    }
    log("kill(-pgid) process-group fan-out OK\n");

    let r = sys_fork();
    if r < 0 {
        log("fork sid failed\n");
        sys_exit(1);
    }
    if r == 0 {
        let r = sys_setsid();
        let mypid = sys_getpid();
        if r != mypid {
            sys_exit(20);
        }
        let sid = sys_getsid(0);
        if sid != mypid {
            sys_exit(21);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("setsid child exited bad\n");
        sys_exit(1);
    }
    log("setsid + getsid OK\n");

    let path = b"/tmp/jobctl_lock\0";
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_CREAT | O_RDWR, 0o644);
    if fd < 0 {
        log("open lock file failed\n");
        sys_exit(1);
    }
    let mut flock = [0u8; 32];
    flock[0..2].copy_from_slice(&F_WRLCK.to_le_bytes());
    flock[8..16].copy_from_slice(&0i64.to_le_bytes());
    flock[16..24].copy_from_slice(&100i64.to_le_bytes());
    if sys_fcntl(fd as u64, F_SETLK, flock.as_mut_ptr() as u64) != 0 {
        log("F_SETLK initial WRLCK failed\n");
        sys_exit(1);
    }
    let r = sys_fork();
    if r < 0 {
        log("fork lock failed\n");
        sys_exit(1);
    }
    if r == 0 {
        let mut child_flock = [0u8; 32];
        child_flock[0..2].copy_from_slice(&F_WRLCK.to_le_bytes());
        child_flock[8..16].copy_from_slice(&50i64.to_le_bytes());
        child_flock[16..24].copy_from_slice(&50i64.to_le_bytes());
        let r = sys_fcntl(fd as u64, F_SETLK, child_flock.as_mut_ptr() as u64);
        if r == EAGAIN {
            sys_exit(0);
        } else {
            sys_exit(40);
        }
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("fcntl conflict: child got wrong return\n");
        sys_exit(1);
    }
    log("F_SETLK conflict → -EAGAIN OK\n");

    let r = sys_fork();
    if r < 0 {
        log("fork getlk failed\n");
        sys_exit(1);
    }
    if r == 0 {
        let mut probe = [0u8; 32];
        probe[0..2].copy_from_slice(&F_WRLCK.to_le_bytes());
        probe[8..16].copy_from_slice(&50i64.to_le_bytes());
        probe[16..24].copy_from_slice(&50i64.to_le_bytes());
        if sys_fcntl(fd as u64, F_GETLK, probe.as_mut_ptr() as u64) != 0 {
            sys_exit(50);
        }
        let probe_type = i16::from_le_bytes(probe[0..2].try_into().unwrap());
        if probe_type != F_WRLCK {
            sys_exit(51);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("F_GETLK probe child got wrong return\n");
        sys_exit(1);
    }
    log("F_GETLK conflict probe (cross-process) OK\n");

    let mut unlock = [0u8; 32];
    unlock[0..2].copy_from_slice(&F_UNLCK.to_le_bytes());
    unlock[8..16].copy_from_slice(&0i64.to_le_bytes());
    unlock[16..24].copy_from_slice(&100i64.to_le_bytes());
    if sys_fcntl(fd as u64, F_SETLK, unlock.as_mut_ptr() as u64) != 0 {
        log("F_SETLK F_UNLCK failed\n");
        sys_exit(1);
    }
    let r = sys_fork();
    if r < 0 {
        log("fork getlk2 failed\n");
        sys_exit(1);
    }
    if r == 0 {
        let mut probe2 = [0u8; 32];
        probe2[0..2].copy_from_slice(&F_WRLCK.to_le_bytes());
        probe2[8..16].copy_from_slice(&50i64.to_le_bytes());
        probe2[16..24].copy_from_slice(&50i64.to_le_bytes());
        sys_fcntl(fd as u64, F_GETLK, probe2.as_mut_ptr() as u64);
        let probe2_type = i16::from_le_bytes(probe2[0..2].try_into().unwrap());
        if probe2_type != F_UNLCK {
            sys_exit(60);
        }
        sys_exit(0);
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    let exit_code = (st >> 8) & 0xff;
    if (st & 0x7f) != 0 || exit_code != 0 {
        log("F_UNLCK followup probe child wrong return\n");
        sys_exit(1);
    }
    log("F_UNLCK + F_GETLK clear OK\n");

    if parent_set(fd as u64, F_WRLCK, 0, 100) != 0 {
        log("split: initial WRLCK[0,100) failed\n");
        sys_exit(70);
    }
    if parent_set(fd as u64, F_RDLCK, 10, 10) != 0 {
        log("split: RDLCK[10,20) demote failed\n");
        sys_exit(71);
    }
    if child_wrlck(fd as u64, 0, 5) != 1 {
        log("split: WRLCK[0,5) should conflict on surviving flank\n");
        sys_exit(72);
    }
    if child_wrlck(fd as u64, 20, 80) != 1 {
        log("split: WRLCK[20,100) should conflict on surviving flank\n");
        sys_exit(73);
    }
    if child_wrlck(fd as u64, 12, 4) != 1 {
        log("split: WRLCK[12,16) should conflict with RDLCK middle\n");
        sys_exit(74);
    }
    if parent_set(fd as u64, F_UNLCK, 40, 20) != 0 {
        log("split: F_UNLCK[40,60) failed\n");
        sys_exit(75);
    }
    if child_wrlck(fd as u64, 45, 5) != 0 {
        log("split: WRLCK[45,50) should be granted in the hole\n");
        sys_exit(76);
    }
    if child_wrlck(fd as u64, 30, 5) != 1 {
        log("split: WRLCK[30,35) should still conflict below the hole\n");
        sys_exit(77);
    }
    parent_set(fd as u64, F_UNLCK, 0, 100);
    log("fcntl byte-range split OK\n");

    let path2 = b"/tmp/jobctl_close_lock\0";
    let cfd = sys_openat(AT_FDCWD, path2.as_ptr(), O_CREAT | O_RDWR, 0o644);
    if cfd < 0 {
        log("close-drop: open failed\n");
        sys_exit(80);
    }
    if parent_set(cfd as u64, F_WRLCK, 0, 100) != 0 {
        log("close-drop: initial WRLCK[0,100) failed\n");
        sys_exit(81);
    }
    if child_wrlck(cfd as u64, 0, 100) != 1 {
        log("close-drop: lock should conflict while held\n");
        sys_exit(82);
    }
    sys_close(cfd as u64);
    let cfd2 = sys_openat(AT_FDCWD, path2.as_ptr(), O_RDWR, 0);
    if cfd2 < 0 {
        log("close-drop: reopen failed\n");
        sys_exit(83);
    }
    if child_wrlck(cfd2 as u64, 0, 100) != 0 {
        log("close-drop: lock NOT released on close\n");
        sys_exit(84);
    }
    sys_close(cfd2 as u64);
    log("close() releases POSIX locks OK\n");

    sys_close(fd as u64);
    log("all jobctl tests OK\n");
    sys_exit(0);
}

#[inline(never)]
fn parent_set(fd: u64, kind: i16, start: i64, len: i64) -> i64 {
    let mut fl = [0u8; 32];
    fl[0..2].copy_from_slice(&kind.to_le_bytes());
    fl[8..16].copy_from_slice(&start.to_le_bytes());
    fl[16..24].copy_from_slice(&len.to_le_bytes());
    sys_fcntl(fd, F_SETLK, fl.as_mut_ptr() as u64)
}

#[inline(never)]
fn child_wrlck(fd: u64, start: i64, len: i64) -> i64 {
    let r = sys_fork();
    if r == 0 {
        let mut fl = [0u8; 32];
        fl[0..2].copy_from_slice(&F_WRLCK.to_le_bytes());
        fl[8..16].copy_from_slice(&start.to_le_bytes());
        fl[16..24].copy_from_slice(&len.to_le_bytes());
        let rc = sys_fcntl(fd, F_SETLK, fl.as_mut_ptr() as u64);
        sys_exit(if rc == 0 {
            0
        } else if rc == EAGAIN {
            1
        } else {
            2
        });
    }
    let mut st: i32 = 0;
    sys_wait4(r as i32, &mut st, 0);
    if (st & 0x7f) != 0 {
        return -1;
    }
    ((st >> 8) & 0xff) as i64
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
fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i64, p: *const u8, flags: u64, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 257u64, in("rdi") dirfd, in("rsi") p,
            in("rdx") flags, in("r10") mode,
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
fn sys_kill(pid: i32, signal: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 62u64, in("rdi") pid as i64, in("rsi") signal as i64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
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
fn sys_sched_yield() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 24u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_getpid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

#[inline(never)]
fn sys_setpgid(pid: i32, pgid: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 109u64, in("rdi") pid as i64, in("rsi") pgid as i64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_getpgid(pid: i32) -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 121u64, in("rdi") pid as i64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

#[inline(never)]
fn sys_setsid() -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 112u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

#[inline(never)]
fn sys_getsid(pid: i32) -> i32 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 124u64, in("rdi") pid as i64,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r as i32
}

#[inline(never)]
fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 72u64, in("rdi") fd, in("rsi") cmd, in("rdx") arg,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
