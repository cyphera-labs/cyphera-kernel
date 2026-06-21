#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_SHARED: i32 = 0x01;
const MAP_PRIVATE: i32 = 0x02;
const MAP_ANONYMOUS: i32 = 0x20;

const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;
const AT_FDCWD: i32 = -100;

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_RMID: i32 = 0;
const IPC_SET: i32 = 1;
const IPC_STAT: i32 = 2;
const SHMID_DS_LEN: usize = 112;

const MARK_A: u8 = 0xA1;
const MARK_B: u8 = 0xB2;

const SPIN_LIMIT: u64 = 2_000_000;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("fork_shared test starting\n");

    if !test_file_shared() {
        sys_exit(1);
    }
    log("MAP_SHARED file inherited across fork OK\n");

    if !test_shm_shared() {
        sys_exit(2);
    }
    log("SysV shm inherited across fork OK\n");

    if !test_shmctl_stat_set() {
        sys_exit(3);
    }
    log("shmctl IPC_STAT/IPC_SET OK\n");

    if !test_pipe_across_fork() {
        sys_exit(4);
    }
    log("pipe inherited across fork OK\n");

    if !test_vfork_shared_mem() {
        sys_exit(5);
    }
    log("vfork shares the address space OK\n");

    if !test_vfork_madvise_denied() {
        sys_exit(6);
    }
    log("vfork denies madvise(MADV_DONTNEED) reclaim on the shared AS OK\n");

    log("all fork_shared tests OK\n");
    sys_exit(0);
}

static mut VFORK_VAR: u32 = 0;

fn test_vfork_shared_mem() -> bool {
    unsafe { core::ptr::write_volatile(&raw mut VFORK_VAR, 0x1111_1111) };
    let var_addr = &raw mut VFORK_VAR as u64;
    let child_pid: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov dword ptr [{var}], 0x22222222",
            "mov rax, 60",
            "xor edi, edi",
            "syscall",
            "2:",
            in("rax") 58u64,
            var = in(reg) var_addr,
            lateout("rax") child_pid,
            lateout("rdi") _,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    if child_pid <= 0 {
        log("vfork failed\n");
        return false;
    }
    let v = unsafe { core::ptr::read_volatile(&raw const VFORK_VAR) };
    if v != 0x2222_2222 {
        log("vfork: parent did not see child's shared-AS write (copy, not share)\n");
        return false;
    }
    let mut st = 0i32;
    sys_wait4(-1, &mut st, 0, 0);
    true
}

fn test_vfork_madvise_denied() -> bool {
    let page = sys_mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if page < 0 {
        log("madvise test: mmap failed\n");
        return false;
    }
    let page = page as u64;
    unsafe { core::ptr::write_volatile(page as *mut u32, 0xFEED_BEEF) };
    let child_pid: i64;
    unsafe {
        asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "mov rax, 28",
            "mov rdi, {pg}",
            "mov rsi, 4096",
            "mov rdx, 4",
            "syscall",
            "mov rax, 60",
            "xor edi, edi",
            "syscall",
            "2:",
            in("rax") 58u64,
            pg = in(reg) page,
            lateout("rax") child_pid,
            lateout("rdi") _,
            lateout("rsi") _,
            lateout("rdx") _,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    if child_pid <= 0 {
        log("madvise test: vfork failed\n");
        return false;
    }
    let v = unsafe { core::ptr::read_volatile(page as *const u32) };
    if v != 0xFEED_BEEF {
        log("vfork: madvise(DONTNEED) was NOT denied — parent's shared page dropped\n");
        return false;
    }
    let mut st = 0i32;
    sys_wait4(-1, &mut st, 0, 0);
    true
}

fn test_pipe_across_fork() -> bool {
    let mut fds = [0i32; 2];
    if sys_pipe2(fds.as_mut_ptr(), 0) != 0 {
        log("pipe2 failed\n");
        return false;
    }
    let (rfd, wfd) = (fds[0], fds[1]);
    let pid = sys_fork();
    if pid < 0 {
        log("pipe fork failed\n");
        return false;
    }
    if pid == 0 {
        sys_close(rfd);
        let b = [0x5Au8];
        sys_write(wfd as u64, b.as_ptr(), 1);
        sys_close(wfd);
        sys_exit(0);
    }
    sys_close(wfd);
    let mut buf = [0u8; 1];
    let n = sys_read(rfd as u64, buf.as_mut_ptr(), 1);
    if n != 1 || buf[0] != 0x5A {
        log("pipe-across-fork: parent did not read the child's byte\n");
        return false;
    }
    let n2 = sys_read(rfd as u64, buf.as_mut_ptr(), 1);
    if n2 != 0 {
        log("pipe-across-fork: expected EOF after all writers closed\n");
        return false;
    }
    let mut st = 0i32;
    sys_wait4(-1, &mut st, 0, 0);
    sys_close(rfd);
    true
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
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn test_shmctl_stat_set() -> bool {
    let my_pid = sys_getpid();
    if my_pid <= 0 {
        log("getpid failed\n");
        return false;
    }
    let id = sys_shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0o600);
    if id < 0 {
        log("shmctl test: shmget failed\n");
        return false;
    }
    let id = id as i32;

    let mut ds = [0xEEu8; SHMID_DS_LEN];
    if sys_shmctl(id, IPC_STAT, ds.as_mut_ptr() as u64) != 0 {
        log("IPC_STAT failed\n");
        sys_shmctl(id, IPC_RMID, 0);
        return false;
    }
    if rd_u64(&ds[48..56]) != 8192
        || rd_u16(&ds[20..22]) & 0o777 != 0o600
        || rd_u64(&ds[88..96]) != 0
        || rd_u32(&ds[80..84]) != my_pid as u32
    {
        log("IPC_STAT fields wrong\n");
        sys_shmctl(id, IPC_RMID, 0);
        return false;
    }

    let a = sys_shmat(id, 0, 0);
    if a < 0 {
        log("shmat failed\n");
        sys_shmctl(id, IPC_RMID, 0);
        return false;
    }
    let mut ds = [0u8; SHMID_DS_LEN];
    if sys_shmctl(id, IPC_STAT, ds.as_mut_ptr() as u64) != 0 {
        log("IPC_STAT #2 failed\n");
        sys_shmdt(a as u64);
        sys_shmctl(id, IPC_RMID, 0);
        return false;
    }
    if rd_u64(&ds[88..96]) != 1 || rd_u64(&ds[56..64]) == 0 || rd_u32(&ds[84..88]) != my_pid as u32
    {
        log("post-attach IPC_STAT wrong (nattch/atime/lpid)\n");
        sys_shmdt(a as u64);
        sys_shmctl(id, IPC_RMID, 0);
        return false;
    }

    let mut set = [0u8; SHMID_DS_LEN];
    set[4..12].copy_from_slice(&ds[4..12]);
    set[20..22].copy_from_slice(&0o640u16.to_le_bytes());
    if sys_shmctl(id, IPC_SET, set.as_ptr() as u64) != 0 {
        log("IPC_SET failed\n");
        sys_shmdt(a as u64);
        sys_shmctl(id, IPC_RMID, 0);
        return false;
    }
    let mut ds = [0u8; SHMID_DS_LEN];
    sys_shmctl(id, IPC_STAT, ds.as_mut_ptr() as u64);
    if rd_u16(&ds[20..22]) & 0o777 != 0o640 {
        log("IPC_SET did not apply mode\n");
        sys_shmdt(a as u64);
        sys_shmctl(id, IPC_RMID, 0);
        return false;
    }

    if sys_shmctl(id, IPC_STAT, 0) != -14 || sys_shmctl(id, IPC_STAT, 0x10) != -14 {
        log("IPC_STAT bad-buf did not return EFAULT\n");
        sys_shmdt(a as u64);
        sys_shmctl(id, IPC_RMID, 0);
        return false;
    }

    sys_shmdt(a as u64);
    sys_shmctl(id, IPC_RMID, 0);
    true
}

fn rd_u16(b: &[u8]) -> u16 {
    let mut a = [0u8; 2];
    a.copy_from_slice(b);
    u16::from_le_bytes(a)
}
fn rd_u32(b: &[u8]) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(b);
    u32::from_le_bytes(a)
}
fn rd_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    u64::from_le_bytes(a)
}

#[inline(never)]
fn sys_getpid() -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 39u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn test_file_shared() -> bool {
    let path = b"/tmp/fork-shared-file\0";
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
    if fd < 0 {
        log("file open\n");
        return false;
    }
    let init = [0u8; 32];
    if sys_write(fd as u64, init.as_ptr(), init.len()) != init.len() as i64 {
        log("file write init\n");
        return false;
    }
    let m = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd as i32, 0);
    if m < 0 {
        log("file mmap\n");
        return false;
    }
    let p = m as *mut u8;
    let _ = read_vol(p, 0);
    sys_close(fd as i32);

    let ok = rendezvous_fork(p);
    sys_munmap(m as u64, 4096);
    ok
}

fn test_shm_shared() -> bool {
    let id = sys_shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0o600);
    if id < 0 {
        log("shmget\n");
        return false;
    }
    let a = sys_shmat(id as i32, 0, 0);
    if a < 0 {
        log("shmat\n");
        sys_shmctl(id as i32, IPC_RMID, 0);
        return false;
    }
    let p = a as *mut u8;
    let ok = rendezvous_fork(p);
    sys_shmdt(p as u64);
    sys_shmctl(id as i32, IPC_RMID, 0);
    ok
}

fn rendezvous_fork(p: *mut u8) -> bool {
    let pid = sys_fork();
    if pid < 0 {
        log("fork\n");
        return false;
    }
    if pid == 0 {
        if !spin_until(p, 0, MARK_A) {
            sys_exit(11);
        }
        write_vol(p, 8, MARK_B);
        sys_exit(0);
    }

    write_vol(p, 0, MARK_A);
    if !spin_until(p, 8, MARK_B) {
        log("parent never saw child's write\n");
        return false;
    }
    let mut status: i32 = 0;
    sys_wait4(pid, &mut status as *mut i32, 0, 0);

    let probe = sys_mmap(
        0,
        16 * 4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    if probe >= 0 {
        let pp = probe as *mut u8;
        let mut i = 0usize;
        while i < 16 * 4096 {
            write_vol(pp, i, 0xCC);
            i += 4096;
        }
        sys_munmap(probe as u64, 16 * 4096);
    }

    if read_vol(p, 0) != MARK_A || read_vol(p, 8) != MARK_B {
        log("shared frame corrupted after child exit\n");
        return false;
    }
    true
}

fn spin_until(p: *const u8, off: usize, want: u8) -> bool {
    let mut i = 0u64;
    while i < SPIN_LIMIT {
        if read_vol(p, off) == want {
            return true;
        }
        sys_sched_yield();
        i += 1;
    }
    false
}

fn read_vol(p: *const u8, off: usize) -> u8 {
    unsafe { core::ptr::read_volatile(p.add(off)) }
}

fn write_vol(p: *mut u8, off: usize, v: u8) {
    unsafe { core::ptr::write_volatile(p.add(off), v) }
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
fn sys_close(fd: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 257u64, in("rdi") dirfd as i64,
        in("rsi") path, in("rdx") flags as i64, in("r10") mode as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_mmap(addr: u64, length: u64, prot: i32, flags: i32, fd: i32, offset: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 9u64, in("rdi") addr, in("rsi") length,
        in("rdx") prot as u64, in("r10") flags as u64, in("r8") fd as u64,
        in("r9") offset,
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
fn sys_shmget(key: i32, size: usize, flags: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 29u64, in("rdi") key as i64, in("rsi") size,
        in("rdx") flags as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_shmat(shmid: i32, addr: u64, flags: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 30u64, in("rdi") shmid as i64, in("rsi") addr,
        in("rdx") flags as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_shmctl(shmid: i32, cmd: i32, buf: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 31u64, in("rdi") shmid as i64, in("rsi") cmd as i64,
        in("rdx") buf,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_shmdt(addr: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 67u64, in("rdi") addr,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
