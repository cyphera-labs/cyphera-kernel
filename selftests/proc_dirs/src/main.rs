#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const O_RDONLY: u64 = 0o0;
const AT_FDCWD: i64 = -100;

const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFMT: u32 = 0o170_000;

const DT_CHR: u8 = 2;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("dirs test starting\n");

    let mut cwd = [0u8; 64];
    let n = sys_getcwd(cwd.as_mut_ptr(), cwd.len() as u64);
    if n != 2 || cwd[0] != b'/' || cwd[1] != 0 {
        log("getcwd at start != \"/\"\n");
        sys_exit(1);
    }
    log("getcwd = / OK\n");

    let dev_path: &[u8; 5] = b"/dev\0";
    if sys_chdir(dev_path.as_ptr()) != 0 {
        log("chdir /dev failed\n");
        sys_exit(1);
    }
    let n = sys_getcwd(cwd.as_mut_ptr(), cwd.len() as u64);
    if n != 5 || &cwd[..4] != b"/dev" || cwd[4] != 0 {
        log("getcwd after chdir != /dev\n");
        sys_exit(1);
    }
    log("chdir /dev OK\n");

    let null_rel: &[u8; 5] = b"null\0";
    let fd = sys_openat(AT_FDCWD, null_rel.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        log("openat AT_FDCWD null (cwd=/dev) failed\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("openat cwd-relative OK\n");

    let dotdot: &[u8; 3] = b"..\0";
    if sys_chdir(dotdot.as_ptr()) != 0 {
        log("chdir .. failed\n");
        sys_exit(1);
    }
    let n = sys_getcwd(cwd.as_mut_ptr(), cwd.len() as u64);
    if n != 2 || cwd[0] != b'/' || cwd[1] != 0 {
        log("getcwd after .. != /\n");
        sys_exit(1);
    }
    log("chdir .. → / OK\n");

    let urandom: &[u8; 13] = b"/dev/urandom\0";
    let fd = sys_openat(AT_FDCWD, urandom.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        log("open /dev/urandom failed\n");
        sys_exit(1);
    }
    let mut st = [0u8; 144];
    if sys_fstat(fd as u64, st.as_mut_ptr()) != 0 {
        log("fstat /dev/urandom failed\n");
        sys_exit(1);
    }
    let mode = u32::from_le_bytes([st[24], st[25], st[26], st[27]]);
    if mode & S_IFMT != S_IFCHR {
        log("urandom st_mode kind != S_IFCHR\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("fstat /dev/urandom kind=chr OK\n");

    let dev: &[u8; 5] = b"/dev\0";
    if sys_newfstatat(AT_FDCWD, dev.as_ptr(), st.as_mut_ptr(), 0) != 0 {
        log("newfstatat /dev failed\n");
        sys_exit(1);
    }
    let mode = u32::from_le_bytes([st[24], st[25], st[26], st[27]]);
    if mode & S_IFMT != S_IFDIR {
        log("/dev st_mode kind != S_IFDIR\n");
        sys_exit(1);
    }
    log("newfstatat /dev kind=dir OK\n");

    let fd = sys_openat(AT_FDCWD, dev.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        log("open /dev failed\n");
        sys_exit(1);
    }
    let mut dirbuf = [0u8; 512];
    let n = sys_getdents64(fd as u64, dirbuf.as_mut_ptr(), dirbuf.len() as u64);
    if n <= 0 {
        log("getdents64 /dev returned no entries\n");
        sys_exit(1);
    }
    let mut found_null = false;
    let mut found_urandom = false;
    let mut off = 0usize;
    while off < n as usize {
        let reclen = u16::from_le_bytes([dirbuf[off + 16], dirbuf[off + 17]]) as usize;
        let d_type = dirbuf[off + 18];
        let name_start = off + 19;
        let mut name_end = name_start;
        while dirbuf[name_end] != 0 {
            name_end += 1;
        }
        let name = &dirbuf[name_start..name_end];
        if d_type != DT_CHR
            && name != b"input"
            && name != b"shm"
            && name != b"snd"
            && name != b"dri"
        {
            log("/dev entry has non-CHR d_type\n");
            sys_exit(1);
        }
        if name == b"null" {
            found_null = true;
        }
        if name == b"urandom" {
            found_urandom = true;
        }
        off += reclen;
    }
    if !found_null || !found_urandom {
        log("/dev getdents missing null or urandom\n");
        sys_exit(1);
    }
    let n2 = sys_getdents64(fd as u64, dirbuf.as_mut_ptr(), dirbuf.len() as u64);
    if n2 != 0 {
        log("getdents64 second call != 0\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("getdents64 /dev: null + urandom present, EOD OK\n");

    let foo_path: &[u8; 9] = b"/tmp/foo\0";
    let fd = sys_openat(AT_FDCWD, foo_path.as_ptr(), 0o100 | 0o2 | 0o1000, 0o644);
    if fd < 0 {
        log("create /tmp/foo failed\n");
        sys_exit(1);
    }
    let payload = b"hello\n";
    if sys_write(fd as u64, payload.as_ptr(), payload.len()) != payload.len() as i64 {
        log("write /tmp/foo failed\n");
        sys_exit(1);
    }
    if sys_fstat(fd as u64, st.as_mut_ptr()) != 0 {
        log("fstat /tmp/foo failed\n");
        sys_exit(1);
    }
    let size = u64::from_le_bytes([
        st[48], st[49], st[50], st[51], st[52], st[53], st[54], st[55],
    ]);
    if size != payload.len() as u64 {
        log("/tmp/foo st_size mismatch\n");
        sys_exit(1);
    }
    let mode = u32::from_le_bytes([st[24], st[25], st[26], st[27]]);
    if mode & S_IFMT != S_IFREG {
        log("/tmp/foo st_mode kind != S_IFREG\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("fstat /tmp/foo size+kind OK\n");

    log("all dir syscalls OK\n");
    sys_exit(0);
}

#[inline(never)]
fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

#[inline(never)]
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

#[inline(never)]
fn sys_close(fd: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 3u64, in("rdi") fd,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_fstat(fd: u64, statbuf: *mut u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 5u64, in("rdi") fd, in("rsi") statbuf,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_getcwd(buf: *mut u8, size: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 79u64, in("rdi") buf, in("rsi") size,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_chdir(path: *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 80u64, in("rdi") path,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_getdents64(fd: u64, dirp: *mut u8, count: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 217u64, in("rdi") fd, in("rsi") dirp, in("rdx") count,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_openat(dirfd: i64, pathname: *const u8, flags: u64, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 257u64, in("rdi") dirfd, in("rsi") pathname,
            in("rdx") flags, in("r10") mode,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_newfstatat(dirfd: i64, pathname: *const u8, statbuf: *mut u8, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 262u64, in("rdi") dirfd, in("rsi") pathname,
            in("rdx") statbuf, in("r10") flags,
            lateout("rax") r, out("rcx") _, out("r11") _,
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
