#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const O_RDONLY: u64 = 0o0;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const AT_FDCWD: i64 = -100;
const AT_REMOVEDIR: u64 = 0x200;
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_SHARED: u64 = 0x01;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("ext4 test starting\n");

    let mut buf = [0u8; 64];
    let n = read_path(b"/mnt/hello.txt\0", &mut buf);
    let expected: &[u8] = b"hello, ext4 world!\n";
    if n != expected.len() as i64 || &buf[..n as usize] != expected {
        log("/mnt/hello.txt mismatch\n");
        sys_exit(1);
    }
    log("/mnt/hello.txt OK\n");

    let n = read_path(b"/mnt/etc/hostname\0", &mut buf);
    let expected: &[u8] = b"cyphera\n";
    if n != expected.len() as i64 || &buf[..n as usize] != expected {
        log("/mnt/etc/hostname mismatch\n");
        sys_exit(1);
    }
    log("/mnt/etc/hostname OK\n");

    let n = read_path(b"/mnt/etc/motd\0", &mut buf);
    if n <= 0 || find(&buf[..n as usize], b"Welcome to Cyphera Kernel").is_none() {
        log("/mnt/etc/motd content unexpected\n");
        sys_exit(1);
    }
    log("/mnt/etc/motd OK\n");

    let n = read_path(b"/mnt/var/log/sample\0", &mut buf);
    if n <= 0 || find(&buf[..n as usize], b"log line two").is_none() {
        log("/mnt/var/log/sample content unexpected\n");
        sys_exit(1);
    }
    log("/mnt/var/log/sample OK\n");

    let large = b"/mnt/large.bin\0";
    let fd = sys_openat(AT_FDCWD, large.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        log("open /mnt/large.bin failed\n");
        sys_exit(1);
    }
    let mut start_marker = [0u8; 16];
    let r = sys_read(fd as u64, start_marker.as_mut_ptr(), 16);
    if r != 16 || &start_marker != b"EXT4-LARGE-START" {
        log("large.bin start marker mismatch\n");
        sys_exit(1);
    }
    let off = sys_lseek(fd as u64, 4 * 1024 * 1024, 0);
    if off != 4 * 1024 * 1024 {
        log("lseek past 4MiB failed\n");
        sys_exit(1);
    }
    let mut cap_marker = [0u8; 13];
    let r = sys_read(fd as u64, cap_marker.as_mut_ptr(), 13);
    if r != 13 || &cap_marker != b"PAST-EXT2-CAP" {
        log("large.bin past-4MiB marker mismatch\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("/mnt/large.bin (6 MiB, multi-extent) OK\n");

    let mnt: &[u8; 5] = b"/mnt\0";
    let fd = sys_openat(AT_FDCWD, mnt.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        log("open /mnt failed\n");
        sys_exit(1);
    }
    let mut dirbuf = [0u8; 1024];
    let n = sys_getdents64(fd as u64, dirbuf.as_mut_ptr(), dirbuf.len() as u64);
    if n <= 0 {
        log("getdents /mnt failed\n");
        sys_exit(1);
    }
    let mut found_hello = false;
    let mut found_etc = false;
    let mut found_large = false;
    let mut found_htree = false;
    let mut off = 0usize;
    while off < n as usize {
        let reclen = u16::from_le_bytes([dirbuf[off + 16], dirbuf[off + 17]]) as usize;
        if reclen == 0 {
            break;
        }
        let name_start = off + 19;
        let mut name_end = name_start;
        while name_end < dirbuf.len() && dirbuf[name_end] != 0 {
            name_end += 1;
        }
        let name = &dirbuf[name_start..name_end];
        if name == b"hello.txt" {
            found_hello = true;
        }
        if name == b"etc" {
            found_etc = true;
        }
        if name == b"large.bin" {
            found_large = true;
        }
        if name == b"htree-dir" {
            found_htree = true;
        }
        off += reclen;
    }
    if !(found_hello && found_etc && found_large && found_htree) {
        log("getdents /mnt missing entries\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("getdents /mnt OK (hello.txt, etc, large.bin, htree-dir)\n");

    let htree: &[u8; 16] = b"/mnt/htree-dir\0\0";
    let fd = sys_openat(AT_FDCWD, htree.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        log("open /mnt/htree-dir failed\n");
        sys_exit(1);
    }
    let mut entries = 0;
    loop {
        let n = sys_getdents64(fd as u64, dirbuf.as_mut_ptr(), dirbuf.len() as u64);
        if n <= 0 {
            break;
        }
        let mut off = 0usize;
        while off < n as usize {
            let reclen = u16::from_le_bytes([dirbuf[off + 16], dirbuf[off + 17]]) as usize;
            if reclen == 0 {
                break;
            }
            entries += 1;
            off += reclen;
        }
    }
    sys_close(fd as u64);
    if entries < 64 {
        log("htree-dir entry count short\n");
        sys_exit(1);
    }
    log("/mnt/htree-dir 64+ entries OK\n");

    log("all ext4 reads OK\n");

    let new_path: &[u8; 14] = b"/mnt/created\0\0";
    let fd = sys_openat(
        AT_FDCWD,
        new_path.as_ptr(),
        O_CREAT | O_RDWR | O_TRUNC,
        0o644,
    );
    if fd < 0 {
        log("create /mnt/created failed\n");
        sys_exit(1);
    }
    let payload = b"freshly written through ext4 write path\n";
    let w = sys_write(fd as u64, payload.as_ptr(), payload.len());
    if w != payload.len() as i64 {
        log("ext4 write short\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    let mut readback = [0u8; 64];
    let n = read_path(b"/mnt/created\0", &mut readback);
    if n != payload.len() as i64 || &readback[..n as usize] != payload {
        log("ext4 readback mismatch\n");
        sys_exit(1);
    }
    log("ext4 create/write/read OK\n");

    let subdir: &[u8; 11] = b"/mnt/subd\0\0";
    if sys_mkdirat(AT_FDCWD, subdir.as_ptr(), 0o755) != 0 {
        log("ext4 mkdirat failed\n");
        sys_exit(1);
    }
    let inside: &[u8; 16] = b"/mnt/subd/file\0\0";
    let fd = sys_openat(AT_FDCWD, inside.as_ptr(), O_CREAT | O_WRONLY, 0o644);
    if fd < 0 {
        log("ext4 create-in-subd failed\n");
        sys_exit(1);
    }
    sys_write(fd as u64, b"nested\n".as_ptr(), 7);
    sys_close(fd as u64);
    if sys_unlinkat(AT_FDCWD, inside.as_ptr(), 0) != 0 {
        log("ext4 unlinkat file failed\n");
        sys_exit(1);
    }
    if sys_unlinkat(AT_FDCWD, subdir.as_ptr(), AT_REMOVEDIR) != 0 {
        log("ext4 rmdir failed\n");
        sys_exit(1);
    }
    if sys_unlinkat(AT_FDCWD, new_path.as_ptr(), 0) != 0 {
        log("ext4 unlinkat created failed\n");
        sys_exit(1);
    }
    log("ext4 mkdirat/unlinkat/rmdir OK\n");

    let big_path: &[u8; 13] = b"/mnt/grown\0\0\0";
    let fd = sys_openat(
        AT_FDCWD,
        big_path.as_ptr(),
        O_CREAT | O_RDWR | O_TRUNC,
        0o644,
    );
    if fd < 0 {
        log("create /mnt/grown failed\n");
        sys_exit(1);
    }
    let chunk = [0xABu8; 4096];
    let mut total = 0;
    while total < 48 {
        let w = sys_write(fd as u64, chunk.as_ptr(), chunk.len());
        if w != chunk.len() as i64 {
            log("ext4 grown write short\n");
            sys_exit(1);
        }
        total += 1;
    }
    sys_close(fd as u64);
    let fd = sys_openat(AT_FDCWD, big_path.as_ptr(), O_RDONLY, 0);
    let off = sys_lseek(fd as u64, 32 * 4096, 0);
    if off != 32 * 4096 {
        log("ext4 grown lseek failed\n");
        sys_exit(1);
    }
    let mut spot = [0u8; 16];
    let r = sys_read(fd as u64, spot.as_mut_ptr(), 16);
    if r != 16 || spot.iter().any(|&b| b != 0xAB) {
        log("ext4 grown content mismatch\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    if sys_unlinkat(AT_FDCWD, big_path.as_ptr(), 0) != 0 {
        log("ext4 unlinkat grown failed\n");
        sys_exit(1);
    }
    log("ext4 multi-extent grow OK (192 KiB write, mid-file readback)\n");

    let sparse = b"/mnt/sparse\0";
    let fd = sys_openat(AT_FDCWD, sparse.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
    if fd < 0 {
        log("create /mnt/sparse failed\n");
        sys_exit(1);
    }
    let mut blk = [0u8; 4096];
    for lb in 0..200u32 {
        if !write_marked_block(fd as u64, lb, &mut blk) {
            log("sparse fill (lower) short\n");
            sys_exit(1);
        }
    }
    for lb in 201..341u32 {
        if !write_marked_block(fd as u64, lb, &mut blk) {
            log("sparse fill (upper) short\n");
            sys_exit(1);
        }
    }
    if !write_marked_block(fd as u64, 200, &mut blk) {
        log("sparse gap write short\n");
        sys_exit(1);
    }
    for &lb in &[0u32, 169, 170, 199, 200, 201, 250, 339, 340] {
        if read_block_marker(fd as u64, lb, &mut blk) != marker_for(lb) {
            log("sparse split: block read back wrong marker (extent mis-routed)\n");
            sys_exit(1);
        }
    }
    sys_close(fd as u64);
    if sys_unlinkat(AT_FDCWD, sparse.as_ptr(), 0) != 0 {
        log("sparse unlink failed\n");
        sys_exit(1);
    }
    log("ext4 sparse multi-leaf split OK (340-extent leaf + gap fill, no data loss)\n");

    let leak = b"/mnt/leakf\0";
    let mut round = 0u32;
    while round < 16 {
        let fd = sys_openat(AT_FDCWD, leak.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
        if fd < 0 {
            log("leak-loop create failed\n");
            sys_exit(1);
        }
        let mut lb = 0u32;
        while lb < 512 {
            if !write_marked_block(fd as u64, lb, &mut blk) {
                log("ext4 depth-1 truncate leak: out of space (blocks not freed)\n");
                sys_exit(1);
            }
            lb += 1;
        }
        sys_close(fd as u64);
        if sys_unlinkat(AT_FDCWD, leak.as_ptr(), 0) != 0 {
            log("leak-loop unlink failed\n");
            sys_exit(1);
        }
        round += 1;
    }
    log("ext4 depth-1 truncate frees blocks OK (16x 2 MiB create/delete, no leak)\n");

    let wt = b"/mnt/wt\0";
    let fdw = sys_openat(AT_FDCWD, wt.as_ptr(), O_CREAT | O_RDWR | O_TRUNC, 0o644);
    if fdw < 0 {
        log("wt open failed\n");
        sys_exit(1);
    }
    let before = b"oldoldoldoldoldo";
    if sys_write(fdw as u64, before.as_ptr(), before.len()) != before.len() as i64 {
        log("wt initial write short\n");
        sys_exit(1);
    }
    let map_w = sys_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fdw as u64, 0);
    if map_w < 0 {
        log("wt mmap failed\n");
        sys_exit(1);
    }
    let p_w = map_w as *mut u8;
    let _pin = unsafe { core::ptr::read_volatile(p_w) };
    sys_lseek(fdw as u64, 0, 0);
    let after = b"NEW!NEW!NEW!NEW!";
    if sys_write(fdw as u64, after.as_ptr(), after.len()) != after.len() as i64 {
        log("wt overwrite short\n");
        sys_exit(1);
    }
    let mut via_map = [0u8; 16];
    unsafe {
        for i in 0..16 {
            via_map[i] = core::ptr::read_volatile(p_w.add(i));
        }
    }
    if &via_map != after {
        log("write(2) not seen by active MAP_SHARED mapping (stale pinned page)\n");
        sys_exit(1);
    }
    sys_lseek(fdw as u64, 0, 0);
    let mut via_read = [0u8; 16];
    if sys_read(fdw as u64, via_read.as_mut_ptr(), 16) != 16 || &via_read != after {
        log("write(2) not seen by read(2) (stale pinned cache page)\n");
        sys_exit(1);
    }
    sys_munmap(map_w as u64, 4096);
    sys_close(fdw as u64);
    if sys_unlinkat(AT_FDCWD, wt.as_ptr(), 0) != 0 {
        log("wt unlink failed\n");
        sys_exit(1);
    }
    log("ext4 write(2) coherent with active MAP_SHARED mapping OK\n");

    log("all ext4 write ops OK\n");
    sys_exit(0);
}

#[inline(never)]
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 9u64, in("rdi") addr, in("rsi") len,
            in("rdx") prot, in("r10") flags, in("r8") fd, in("r9") off,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_munmap(addr: u64, len: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 11u64, in("rdi") addr, in("rsi") len,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn marker_for(logical: u32) -> u32 {
    0xEF53_0000u32.wrapping_add(logical)
}

fn write_marked_block(fd: u64, logical: u32, buf: &mut [u8; 4096]) -> bool {
    for b in buf.iter_mut() {
        *b = 0;
    }
    buf[0..4].copy_from_slice(&marker_for(logical).to_le_bytes());
    let off = logical as i64 * 4096;
    if sys_lseek(fd, off, 0) != off {
        return false;
    }
    sys_write(fd, buf.as_ptr(), 4096) == 4096
}

fn read_block_marker(fd: u64, logical: u32, buf: &mut [u8; 4096]) -> u32 {
    let off = logical as i64 * 4096;
    if sys_lseek(fd, off, 0) != off {
        return u32::MAX;
    }
    if sys_read(fd, buf.as_mut_ptr(), 4096) != 4096 {
        return u32::MAX;
    }
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

fn read_path(path: &[u8], buf: &mut [u8]) -> i64 {
    let fd = sys_openat(AT_FDCWD, path.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        return fd;
    }
    let mut total = 0usize;
    while total < buf.len() {
        let n = sys_read(
            fd as u64,
            unsafe { buf.as_mut_ptr().add(total) },
            buf.len() - total,
        );
        if n < 0 {
            sys_close(fd as u64);
            return n;
        }
        if n == 0 {
            break;
        }
        total += n as usize;
    }
    sys_close(fd as u64);
    total as i64
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
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
fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 0u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
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
fn sys_mkdirat(dirfd: i64, pathname: *const u8, mode: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 258u64, in("rdi") dirfd, in("rsi") pathname, in("rdx") mode,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_unlinkat(dirfd: i64, pathname: *const u8, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 263u64, in("rdi") dirfd, in("rsi") pathname, in("rdx") flags,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_lseek(fd: u64, offset: i64, whence: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 8u64, in("rdi") fd, in("rsi") offset, in("rdx") whence as u64,
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
