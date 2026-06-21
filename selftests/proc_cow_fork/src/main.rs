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

const PAGE: u64 = 4096;
const PARENT_MARK: u32 = 0xAAAA_AAAA;
const CHILD_MARK: u32 = 0x5555_5555;
const INIT_MARK: u32 = 0x1111_1111;

static mut DEEP_STACK_HIT: u32 = 0;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("cow_fork: starting\n");

    if !test_isolation_mmap() {
        sys_exit(1);
    }
    log("cow_fork: mmap-anon isolation OK\n");

    if !test_isolation_brk() {
        sys_exit(2);
    }
    log("cow_fork: brk-heap isolation OK\n");

    if !test_isolation_stack() {
        sys_exit(3);
    }
    log("cow_fork: deep-stack isolation OK\n");

    if !test_mprotect_roundtrip() {
        sys_exit(4);
    }
    log("cow_fork: mprotect roundtrip OK\n");

    if !test_firstwrite_rendezvous() {
        sys_exit(5);
    }
    log("cow_fork: parent/child first-write rendezvous OK\n");

    if !test_prot_read_write_faults() {
        sys_exit(7);
    }
    log("cow_fork: PROT_READ write faults (no silent COW break) OK\n");

    if !test_kernel_write_breaks_cow() {
        sys_exit(8);
    }
    log("cow_fork: kernel->user write breaks COW OK\n");

    if !test_refcount_baseline() {
        sys_exit(6);
    }
    log("cow_fork: refcount baseline OK\n");

    log("COW_FORK_OK\n");
    sys_exit(0)
}

fn test_prot_read_write_faults() -> bool {
    let region = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        return false;
    }
    let region = region as u64;
    wr32(region, INIT_MARK);
    let pid = sys_fork();
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        if sys_mprotect(region, PAGE, PROT_READ) != 0 {
            sys_exit(71);
        }
        wr32(region, CHILD_MARK);
        sys_exit(72);
    }
    let mut status: i32 = 0;
    if sys_wait4(pid, &mut status as *mut i32, 0, 0) < 0 {
        return false;
    }
    let killed_by_segv = (status & 0x7f) == 11;
    let parent_intact = rd32(region) == INIT_MARK;
    wr32(region, PARENT_MARK);
    let parent_writable = rd32(region) == PARENT_MARK;
    sys_munmap(region, PAGE);
    killed_by_segv && parent_intact && parent_writable
}

fn test_kernel_write_breaks_cow() -> bool {
    let region = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        return false;
    }
    let region = region as u64;
    wr32(region, INIT_MARK);

    let mut fds = [0i32; 2];
    if sys_pipe2(fds.as_mut_ptr(), 0) != 0 {
        return false;
    }
    let pid = sys_fork();
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        sys_close(fds[1]);
        if sys_read(fds[0] as u64, region as *mut u8, 4) != 4 {
            sys_exit(81);
        }
        if rd32(region) != CHILD_MARK {
            sys_exit(82);
        }
        sys_exit(0);
    }
    sys_close(fds[0]);
    let payload = CHILD_MARK.to_ne_bytes();
    if sys_write(fds[1] as u64, payload.as_ptr(), 4) != 4 {
        return false;
    }
    if !wait_ok(pid) {
        return false;
    }
    let parent_intact = rd32(region) == INIT_MARK;
    sys_close(fds[1]);
    sys_munmap(region, PAGE);
    parent_intact
}

fn test_isolation_mmap() -> bool {
    let region = sys_mmap(
        0,
        4 * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        return false;
    }
    let region = region as u64;
    for i in 0..4u64 {
        wr32(region + i * PAGE, INIT_MARK);
    }
    let pid = sys_fork();
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        for i in 0..4u64 {
            wr32(region + i * PAGE, CHILD_MARK);
        }
        for i in 0..4u64 {
            if rd32(region + i * PAGE) != CHILD_MARK {
                sys_exit(31);
            }
        }
        sys_exit(0);
    }
    for i in 0..4u64 {
        wr32(region + i * PAGE, PARENT_MARK);
    }
    if !wait_ok(pid) {
        return false;
    }
    for i in 0..4u64 {
        if rd32(region + i * PAGE) != PARENT_MARK {
            return false;
        }
    }
    sys_munmap(region, 4 * PAGE);
    true
}

fn test_isolation_brk() -> bool {
    let base = sys_brk(0);
    if base <= 0 {
        return false;
    }
    let base = base as u64;
    let grown = sys_brk(base + 8 * PAGE);
    if (grown as u64) < base + 8 * PAGE {
        return false;
    }
    let p = base + PAGE;
    wr32(p, INIT_MARK);
    let pid = sys_fork();
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        wr32(p, CHILD_MARK);
        if rd32(p) != CHILD_MARK {
            sys_exit(32);
        }
        sys_exit(0);
    }
    wr32(p, PARENT_MARK);
    if !wait_ok(pid) {
        return false;
    }
    rd32(p) == PARENT_MARK
}

#[inline(never)]
fn touch_deep_stack(v: u32) -> u32 {
    let mut filler = [0u32; 4096];
    let mut i = 0usize;
    while i < filler.len() {
        filler[i] = v ^ (i as u32);
        i += 64;
    }
    unsafe { core::ptr::write_volatile(&raw mut DEEP_STACK_HIT, filler[0]) };
    filler[0]
}

fn test_isolation_stack() -> bool {
    let probe = touch_deep_stack(INIT_MARK);
    let pid = sys_fork();
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        let c = touch_deep_stack(CHILD_MARK);
        if c != CHILD_MARK {
            sys_exit(33);
        }
        sys_exit(0);
    }
    let p = touch_deep_stack(PARENT_MARK);
    if p != PARENT_MARK {
        return false;
    }
    if !wait_ok(pid) {
        return false;
    }
    let _ = probe;
    touch_deep_stack(PARENT_MARK) == PARENT_MARK
}

fn test_mprotect_roundtrip() -> bool {
    let region = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        return false;
    }
    let region = region as u64;
    wr32(region, INIT_MARK);
    let pid = sys_fork();
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        if rd32(region) != INIT_MARK {
            sys_exit(41);
        }
        wr32(region, CHILD_MARK);
        if rd32(region) != CHILD_MARK {
            sys_exit(42);
        }
        sys_exit(0);
    }
    if sys_mprotect(region, PAGE, PROT_READ) != 0 {
        return false;
    }
    if rd32(region) != INIT_MARK {
        return false;
    }
    if sys_mprotect(region, PAGE, PROT_READ | PROT_WRITE) != 0 {
        return false;
    }
    wr32(region, PARENT_MARK);
    if !wait_ok(pid) {
        return false;
    }
    let ok = rd32(region) == PARENT_MARK;
    sys_munmap(region, PAGE);
    ok
}

fn test_firstwrite_rendezvous() -> bool {
    let region = sys_mmap(
        0,
        PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        return false;
    }
    let region = region as u64;
    wr32(region, INIT_MARK);

    let mut to_child = [0i32; 2];
    let mut to_parent = [0i32; 2];
    if sys_pipe2(to_child.as_mut_ptr(), 0) != 0 || sys_pipe2(to_parent.as_mut_ptr(), 0) != 0 {
        return false;
    }

    let pid = sys_fork();
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        sys_close(to_child[1]);
        sys_close(to_parent[0]);
        let mut b = [0u8; 1];
        if sys_read(to_child[0] as u64, b.as_mut_ptr(), 1) != 1 {
            sys_exit(51);
        }
        wr32(region, CHILD_MARK);
        let ack = [1u8];
        sys_write(to_parent[1] as u64, ack.as_ptr(), 1);
        let mut i = 0u64;
        while i < 200_000 {
            if rd32(region) != CHILD_MARK {
                sys_exit(52);
            }
            i += 1;
            sys_sched_yield();
        }
        sys_exit(0);
    }
    sys_close(to_child[0]);
    sys_close(to_parent[1]);
    let go = [1u8];
    sys_write(to_child[1] as u64, go.as_ptr(), 1);
    wr32(region, PARENT_MARK);
    let mut b = [0u8; 1];
    sys_read(to_parent[0] as u64, b.as_mut_ptr(), 1);
    let mut i = 0u64;
    let mut ok = true;
    while i < 200_000 {
        if rd32(region) != PARENT_MARK {
            ok = false;
            break;
        }
        i += 1;
        sys_sched_yield();
    }
    if !wait_ok(pid) {
        ok = false;
    }
    let final_ok = rd32(region) == PARENT_MARK;
    sys_close(to_child[1]);
    sys_close(to_parent[0]);
    sys_munmap(region, PAGE);
    ok && final_ok
}

fn one_fork_round(region: u64, round: u32) -> bool {
    for i in 0..8u64 {
        wr32(region + i * PAGE, INIT_MARK ^ round);
    }
    let pid = sys_fork();
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        for i in 0..8u64 {
            wr32(region + i * PAGE, CHILD_MARK);
        }
        sys_exit(0);
    }
    wr32(region + 3 * PAGE, PARENT_MARK);
    if !wait_ok(pid) {
        return false;
    }
    if rd32(region + 3 * PAGE) != PARENT_MARK {
        return false;
    }
    for i in 0..8u64 {
        if i == 3 {
            continue;
        }
        if rd32(region + i * PAGE) != (INIT_MARK ^ round) {
            return false;
        }
    }
    true
}

fn test_refcount_baseline() -> bool {
    let region = sys_mmap(
        0,
        8 * PAGE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1i64 as u64,
        0,
    );
    if region < 0 {
        return false;
    }
    let region = region as u64;

    if !one_fork_round(region, 0) {
        return false;
    }
    let baseline_free = match free_ram() {
        Some(f) => f,
        None => return false,
    };

    let mut round = 1u32;
    while round < 64 {
        if !one_fork_round(region, round) {
            return false;
        }
        round += 1;
    }

    let after_free = match free_ram() {
        Some(f) => f,
        None => return false,
    };
    sys_munmap(region, 8 * PAGE);

    let slack = 64u64 * PAGE;
    after_free + slack >= baseline_free
}

fn free_ram() -> Option<u64> {
    let mut buf = [0u8; 112];
    if sys_sysinfo(buf.as_mut_ptr()) != 0 {
        return None;
    }
    let mut f = [0u8; 8];
    f.copy_from_slice(&buf[40..48]);
    let freeram = u64::from_ne_bytes(f);
    let mut u = [0u8; 4];
    u.copy_from_slice(&buf[104..108]);
    let mem_unit = u32::from_ne_bytes(u) as u64;
    Some(freeram.saturating_mul(mem_unit.max(1)))
}

fn wait_ok(pid: i64) -> bool {
    let mut status: i32 = 0;
    if sys_wait4(pid, &mut status as *mut i32, 0, 0) < 0 {
        return false;
    }
    status & 0x7f == 0 && (status >> 8) & 0xff == 0
}

fn rd32(p: u64) -> u32 {
    unsafe { core::ptr::read_volatile(p as *const u32) }
}
fn wr32(p: u64, v: u32) {
    unsafe { core::ptr::write_volatile(p as *mut u32, v) }
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
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_close(fd: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd as i64,
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
fn sys_munmap(addr: u64, length: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 11u64, in("rdi") addr, in("rsi") length,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 10u64, in("rdi") addr, in("rsi") len, in("rdx") prot,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_brk(addr: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 12u64, in("rdi") addr,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_pipe2(fds: *mut i32, flags: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 293u64, in("rdi") fds, in("rsi") flags as i64,
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
fn sys_wait4(pid: i64, status: *mut i32, options: i32, rusage: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 61u64, in("rdi") pid, in("rsi") status,
             in("rdx") options as i64, in("r10") rusage,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_sched_yield() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 24u64,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
#[inline(never)]
fn sys_sysinfo(info: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 99u64, in("rdi") info,
             lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn sys_exit(code: i32) -> ! {
    unsafe { asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack)) }
}
