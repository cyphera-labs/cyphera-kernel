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
const O_CLOEXEC: u64 = 0o2_000_000;
const AT_FDCWD: i64 = -100;
const AT_REMOVEDIR: u64 = 0x200;

const F_DUPFD: u64 = 0;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const FD_CLOEXEC: u64 = 1;
const O_NONBLOCK: u64 = 0o4000;
const EAGAIN: i64 = -11;
const TIOCGWINSZ: u64 = 0x5413;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("abi test starting\n");

    let mut fds = [0i32; 2];
    if sys_pipe2(fds.as_mut_ptr() as *mut u8, 0) != 0 {
        log("pipe2 failed\n");
        sys_exit(1);
    }
    let r = fds[0] as u64;
    let w = fds[1] as u64;
    let payload = b"pipe-message";
    if sys_write(w, payload.as_ptr(), payload.len()) != payload.len() as i64 {
        log("pipe write failed\n");
        sys_exit(1);
    }
    let mut rb = [0u8; 32];
    let n = sys_read(r, rb.as_mut_ptr(), rb.len());
    if n != payload.len() as i64 || &rb[..n as usize] != payload {
        log("pipe read mismatch\n");
        sys_exit(1);
    }
    sys_close(w);
    let n2 = sys_read(r, rb.as_mut_ptr(), rb.len());
    if n2 != 0 {
        log("pipe EOF after writer-close not seen\n");
        sys_exit(1);
    }
    sys_close(r);
    log("pipe2 + read/write + EOF OK\n");

    let mut fds2 = [0i32; 2];
    sys_pipe2(fds2.as_mut_ptr() as *mut u8, 0);
    let dup_w = sys_dup(fds2[1] as u64);
    if dup_w < 0 {
        log("dup failed\n");
        sys_exit(1);
    }
    if sys_write(dup_w as u64, b"a".as_ptr(), 1) != 1 {
        log("write via dup failed\n");
        sys_exit(1);
    }
    if sys_dup2(fds2[1] as u64, 50) != 50 {
        log("dup2 to 50 failed\n");
        sys_exit(1);
    }
    if sys_write(50, b"b".as_ptr(), 1) != 1 {
        log("write via dup2 fd failed\n");
        sys_exit(1);
    }
    if sys_dup3(fds2[1] as u64, 51, O_CLOEXEC) != 51 {
        log("dup3 to 51 failed\n");
        sys_exit(1);
    }
    if sys_write(51, b"c".as_ptr(), 1) != 1 {
        log("write via dup3 fd failed\n");
        sys_exit(1);
    }
    sys_close(fds2[1] as u64);
    sys_close(dup_w as u64);
    sys_close(50);
    sys_close(51);
    let mut readback = [0u8; 8];
    let n = sys_read(fds2[0] as u64, readback.as_mut_ptr(), readback.len());
    if n != 3 || &readback[..3] != b"abc" {
        log("dup readback mismatch\n");
        sys_exit(1);
    }
    sys_close(fds2[0] as u64);
    log("dup / dup2 / dup3 OK\n");

    let mut fds3 = [0i32; 2];
    sys_pipe2(fds3.as_mut_ptr() as *mut u8, 0);
    let part1 = b"hello, ";
    let part2 = b"writev";
    let iov: [Iovec; 2] = [
        Iovec {
            base: part1.as_ptr(),
            len: part1.len(),
        },
        Iovec {
            base: part2.as_ptr(),
            len: part2.len(),
        },
    ];
    let n = sys_writev(fds3[1] as u64, iov.as_ptr() as *const u8, 2);
    if n != (part1.len() + part2.len()) as i64 {
        log("writev short\n");
        sys_exit(1);
    }
    let mut p1 = [0u8; 7];
    let mut p2 = [0u8; 6];
    let riov: [IovecMut; 2] = [
        IovecMut {
            base: p1.as_mut_ptr(),
            len: p1.len(),
        },
        IovecMut {
            base: p2.as_mut_ptr(),
            len: p2.len(),
        },
    ];
    let n = sys_readv(fds3[0] as u64, riov.as_ptr() as *const u8, 2);
    if n != 13 || &p1 != b"hello, " || &p2 != b"writev" {
        log("readv mismatch\n");
        sys_exit(1);
    }
    sys_close(fds3[0] as u64);
    sys_close(fds3[1] as u64);
    log("writev / readv OK\n");

    let pw_path: &[u8; 8] = b"/tmp/pw\0";
    let fd = sys_openat(
        AT_FDCWD,
        pw_path.as_ptr(),
        O_RDWR | O_CREAT | O_TRUNC,
        0o644,
    );
    if fd < 0 {
        log("open /tmp/pw failed\n");
        sys_exit(1);
    }
    if sys_pwrite64(fd as u64, b"hello".as_ptr(), 5, 100) != 5 {
        log("pwrite failed\n");
        sys_exit(1);
    }
    let mut pb = [0u8; 5];
    if sys_pread64(fd as u64, pb.as_mut_ptr(), 5, 100) != 5 || &pb != b"hello" {
        log("pread mismatch\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("pread / pwrite OK\n");

    let console: &[u8; 14] = b"/dev/console\0\0";
    let fd = sys_openat(AT_FDCWD, console.as_ptr(), O_WRONLY, 0);
    if fd < 0 {
        log("open /dev/console failed\n");
        sys_exit(1);
    }
    let flags = sys_fcntl(fd as u64, F_GETFD, 0);
    if flags != 0 {
        log("F_GETFD initial nonzero\n");
        sys_exit(1);
    }
    if sys_fcntl(fd as u64, F_SETFD, FD_CLOEXEC) != 0 {
        log("F_SETFD failed\n");
        sys_exit(1);
    }
    if sys_fcntl(fd as u64, F_GETFD, 0) != FD_CLOEXEC as i64 {
        log("F_GETFD after SETFD wrong\n");
        sys_exit(1);
    }
    let fl = sys_fcntl(fd as u64, F_GETFL, 0);
    if fl as u64 & 3 != O_WRONLY {
        log("F_GETFL access mode wrong\n");
        sys_exit(1);
    }
    let dup_fd = sys_fcntl(fd as u64, F_DUPFD, 100);
    if dup_fd < 100 {
        log("F_DUPFD min didn't take\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    sys_close(dup_fd as u64);
    log("fcntl OK\n");

    let mut nbfds = [0i32; 2];
    if sys_pipe2(nbfds.as_mut_ptr() as *mut u8, 0) != 0 {
        log("pipe2 for nonblock test failed\n");
        sys_exit(1);
    }
    let rfd = nbfds[0] as u64;
    let fl0 = sys_fcntl(rfd, F_GETFL, 0);
    if fl0 < 0 {
        log("F_GETFL before set failed\n");
        sys_exit(1);
    }
    if sys_fcntl(rfd, F_SETFL, fl0 as u64 | O_NONBLOCK) != 0 {
        log("F_SETFL O_NONBLOCK failed\n");
        sys_exit(1);
    }
    let fl1 = sys_fcntl(rfd, F_GETFL, 0);
    if fl1 < 0 || (fl1 as u64) & O_NONBLOCK == 0 {
        log("F_GETFL missing O_NONBLOCK after F_SETFL\n");
        sys_exit(1);
    }
    if (fl1 as u64) & 3 != (fl0 as u64) & 3 {
        log("F_SETFL changed the access mode\n");
        sys_exit(1);
    }
    let mut one = [0u8; 1];
    if sys_read(rfd, one.as_mut_ptr(), 1) != EAGAIN {
        log("nonblocking empty-pipe read not EAGAIN\n");
        sys_exit(1);
    }
    sys_close(nbfds[0] as u64);
    sys_close(nbfds[1] as u64);
    log("fcntl F_SETFL O_NONBLOCK + EAGAIN OK\n");

    let tty: &[u8; 9] = b"/dev/tty\0";
    let fd = sys_openat(AT_FDCWD, tty.as_ptr(), O_RDWR, 0);
    if fd < 0 {
        log("open /dev/tty failed\n");
        sys_exit(1);
    }
    let mut ws = [0u16; 4];
    if sys_ioctl(fd as u64, TIOCGWINSZ, ws.as_mut_ptr() as *mut u8) != 0 {
        log("TIOCGWINSZ failed\n");
        sys_exit(1);
    }
    if ws[0] != 24 || ws[1] != 80 {
        log("TIOCGWINSZ rows/cols wrong\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    log("ioctl(TIOCGWINSZ) OK\n");

    let dir: &[u8; 9] = b"/tmp/dir\0";
    if sys_mkdirat(AT_FDCWD, dir.as_ptr(), 0o755) != 0 {
        log("mkdirat failed\n");
        sys_exit(1);
    }
    if sys_unlinkat(AT_FDCWD, dir.as_ptr(), AT_REMOVEDIR) != 0 {
        log("unlinkat AT_REMOVEDIR failed\n");
        sys_exit(1);
    }
    log("mkdirat / unlinkat OK\n");

    const ENOTEMPTY: i64 = -39;
    const EISDIR: i64 = -21;
    const ENOTDIR: i64 = -20;
    const ENOENT: i64 = -2;

    let rdir = b"/tmp/rdir\0";
    let rchild = b"/tmp/rdir/x\0";
    if sys_mkdirat(AT_FDCWD, rdir.as_ptr(), 0o755) != 0 {
        log("rdir mkdir failed\n");
        sys_exit(1);
    }
    let fd = sys_openat(AT_FDCWD, rchild.as_ptr(), O_WRONLY | O_CREAT, 0o644);
    if fd < 0 {
        log("rdir child create failed\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    if sys_unlinkat(AT_FDCWD, rdir.as_ptr(), AT_REMOVEDIR) != ENOTEMPTY {
        log("rmdir non-empty not ENOTEMPTY\n");
        sys_exit(1);
    }
    if sys_unlinkat(AT_FDCWD, rchild.as_ptr(), 0) != 0 {
        log("rchild unlink failed\n");
        sys_exit(1);
    }
    if sys_unlinkat(AT_FDCWD, rdir.as_ptr(), AT_REMOVEDIR) != 0 {
        log("rmdir empty failed\n");
        sys_exit(1);
    }
    if sys_mkdirat(AT_FDCWD, rdir.as_ptr(), 0o755) != 0 {
        log("rdir recreate failed (parent poisoned)\n");
        sys_exit(1);
    }
    if sys_unlinkat(AT_FDCWD, rdir.as_ptr(), AT_REMOVEDIR) != 0 {
        log("rdir recreate rmdir failed\n");
        sys_exit(1);
    }
    log("rmdir emptiness enforced OK\n");

    let fa = b"/tmp/rn_a\0";
    let fb = b"/tmp/rn_b\0";
    let w = sys_openat(AT_FDCWD, fa.as_ptr(), O_WRONLY | O_CREAT, 0o644);
    sys_write(w as u64, b"AAAA".as_ptr(), 4);
    sys_close(w as u64);
    let w = sys_openat(AT_FDCWD, fb.as_ptr(), O_WRONLY | O_CREAT, 0o644);
    sys_write(w as u64, b"BBBBBB".as_ptr(), 6);
    sys_close(w as u64);
    if sys_renameat(AT_FDCWD, fa.as_ptr(), AT_FDCWD, fb.as_ptr()) != 0 {
        log("rename file-over-file failed\n");
        sys_exit(1);
    }
    let r = sys_openat(AT_FDCWD, fb.as_ptr(), O_RDONLY, 0);
    let mut rb = [0u8; 8];
    let n = sys_read(r as u64, rb.as_mut_ptr(), rb.len());
    sys_close(r as u64);
    if n != 4 || &rb[..4] != b"AAAA" {
        log("rename overwrite content wrong\n");
        sys_exit(1);
    }
    if sys_openat(AT_FDCWD, fa.as_ptr(), O_RDONLY, 0) != ENOENT {
        log("rename source still exists\n");
        sys_exit(1);
    }
    sys_unlinkat(AT_FDCWD, fb.as_ptr(), 0);

    let fdir = b"/tmp/rn_dir\0";
    sys_mkdirat(AT_FDCWD, fdir.as_ptr(), 0o755);
    let w = sys_openat(AT_FDCWD, fa.as_ptr(), O_WRONLY | O_CREAT, 0o644);
    sys_close(w as u64);
    if sys_renameat(AT_FDCWD, fa.as_ptr(), AT_FDCWD, fdir.as_ptr()) != EISDIR {
        log("rename file-onto-dir not EISDIR\n");
        sys_exit(1);
    }
    if sys_renameat(AT_FDCWD, fdir.as_ptr(), AT_FDCWD, fa.as_ptr()) != ENOTDIR {
        log("rename dir-onto-file not ENOTDIR\n");
        sys_exit(1);
    }

    let fdir2 = b"/tmp/rn_dir2\0";
    let fdir2_child = b"/tmp/rn_dir2/c\0";
    sys_mkdirat(AT_FDCWD, fdir2.as_ptr(), 0o755);
    let c = sys_openat(AT_FDCWD, fdir2_child.as_ptr(), O_WRONLY | O_CREAT, 0o644);
    sys_close(c as u64);
    if sys_renameat(AT_FDCWD, fdir.as_ptr(), AT_FDCWD, fdir2.as_ptr()) != ENOTEMPTY {
        log("rename dir-onto-nonempty not ENOTEMPTY\n");
        sys_exit(1);
    }
    if sys_openat(AT_FDCWD, fdir2_child.as_ptr(), O_RDONLY, 0) < 0 {
        log("rename clobbered a non-empty dir's child\n");
        sys_exit(1);
    }

    let de1 = b"/tmp/rn_de1\0";
    let de2 = b"/tmp/rn_de2\0";
    sys_mkdirat(AT_FDCWD, de1.as_ptr(), 0o755);
    sys_mkdirat(AT_FDCWD, de2.as_ptr(), 0o755);
    if sys_renameat(AT_FDCWD, de1.as_ptr(), AT_FDCWD, de2.as_ptr()) != 0 {
        log("rename dir-over-empty-dir failed\n");
        sys_exit(1);
    }
    if sys_openat(AT_FDCWD, de1.as_ptr(), O_RDONLY, 0) != ENOENT {
        log("rename de1 still exists\n");
        sys_exit(1);
    }
    if sys_unlinkat(AT_FDCWD, de2.as_ptr(), AT_REMOVEDIR) != 0 {
        log("rename de2 rmdir failed (nlink wrong?)\n");
        sys_exit(1);
    }

    sys_unlinkat(AT_FDCWD, fa.as_ptr(), 0);
    sys_unlinkat(AT_FDCWD, fdir2_child.as_ptr(), 0);
    sys_unlinkat(AT_FDCWD, fdir2.as_ptr(), AT_REMOVEDIR);
    sys_unlinkat(AT_FDCWD, fdir.as_ptr(), AT_REMOVEDIR);
    log("rename POSIX overwrite OK\n");

    let target = b"/etc/hostname\0";
    let linkpath: &[u8; 10] = b"/tmp/lnk\0\0";
    if sys_symlinkat(target.as_ptr(), AT_FDCWD, linkpath.as_ptr()) != 0 {
        log("symlinkat failed\n");
        sys_exit(1);
    }
    let mut tbuf = [0u8; 32];
    let n = sys_readlinkat(
        AT_FDCWD,
        linkpath.as_ptr(),
        tbuf.as_mut_ptr(),
        tbuf.len() as u64,
    );
    if n != 13 || &tbuf[..13] != b"/etc/hostname" {
        log("readlinkat mismatch\n");
        sys_exit(1);
    }
    sys_unlinkat(AT_FDCWD, linkpath.as_ptr(), 0);
    log("symlinkat / readlinkat OK\n");

    let foo: &[u8; 9] = b"/tmp/foo\0";
    let foo2: &[u8; 10] = b"/tmp/foo2\0";
    let foo3: &[u8; 10] = b"/tmp/foo3\0";
    let fd = sys_openat(AT_FDCWD, foo.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    sys_write(fd as u64, b"data".as_ptr(), 4);
    sys_close(fd as u64);
    if sys_linkat(AT_FDCWD, foo.as_ptr(), AT_FDCWD, foo2.as_ptr(), 0) != 0 {
        log("linkat failed\n");
        sys_exit(1);
    }
    let fd = sys_openat(AT_FDCWD, foo2.as_ptr(), O_RDONLY, 0);
    if fd < 0 {
        log("open hard-link failed\n");
        sys_exit(1);
    }
    let mut ldata = [0u8; 4];
    sys_read(fd as u64, ldata.as_mut_ptr(), 4);
    if &ldata != b"data" {
        log("hard-link content mismatch\n");
        sys_exit(1);
    }
    sys_close(fd as u64);
    if sys_renameat(AT_FDCWD, foo2.as_ptr(), AT_FDCWD, foo3.as_ptr()) != 0 {
        log("renameat failed\n");
        sys_exit(1);
    }
    sys_unlinkat(AT_FDCWD, foo.as_ptr(), 0);
    sys_unlinkat(AT_FDCWD, foo3.as_ptr(), 0);
    log("linkat / renameat OK\n");

    let mut cmdline_buf = [0u8; 64];
    let n = read_path(b"/proc/self/cmdline\0", &mut cmdline_buf);
    if n <= 0 || find(&cmdline_buf[..n as usize], b"abi-test").is_none() {
        log("/proc/self/cmdline missing 'abi-test'\n");
        sys_exit(1);
    }
    log("/proc/self/cmdline OK\n");

    let cur_brk = sys_brk(0) as u64;
    if (sys_brk(cur_brk + 0x1000) as u64) <= cur_brk {
        log("brk grow failed\n");
        sys_exit(1);
    }
    {
        const PROT_R: u64 = 1;
        const MAP_PRIV_ANON: u64 = 0x02 | 0x20;
        let ro = sys_mmap(0, 0x1000, PROT_R, MAP_PRIV_ANON, u64::MAX, 0);
        if ro < 0 || (ro as u64 & 0xfff) != 0 {
            log("anon PROT_READ mmap failed\n");
            sys_exit(1);
        }
    }
    let mut maps_buf = [0u8; 1024];
    let n = read_path(b"/proc/self/maps\0", &mut maps_buf);
    if n <= 0 {
        log("/proc/self/maps read failed\n");
        sys_exit(1);
    }
    let m = &maps_buf[..n as usize];
    if find(m, b"[heap]").is_none() {
        log("/proc/self/maps missing [heap]\n");
        sys_exit(1);
    }
    if find(m, b"[stack]").is_none() {
        log("/proc/self/maps missing [stack]\n");
        sys_exit(1);
    }
    if find(m, b"[mmap]").is_some() {
        log("/proc/self/maps still emits a coalesced [mmap] line\n");
        sys_exit(1);
    }
    if find(m, b"r-x").is_none() {
        log("/proc/self/maps missing an r-x image segment\n");
        sys_exit(1);
    }
    if find(m, b"r--p").is_none() {
        log("/proc/self/maps missing a read-only (r--p) mapping\n");
        sys_exit(1);
    }
    log("/proc/self/maps OK (real perms, [stack], no coalesced [mmap])\n");

    let mut ot = [0u8; 16];
    let n = read_path(b"/sys/kernel/ostype\0", &mut ot);
    if n <= 0 || &ot[..n as usize] != b"Linux\n" {
        log("/sys/kernel/ostype mismatch\n");
        sys_exit(1);
    }
    log("/sys/kernel/ostype OK\n");

    let mut sz = [0u8; 32];
    let n = read_path(b"/sys/block/vda/size\0", &mut sz);
    if n <= 0 {
        log("/sys/block/vda/size missing\n");
        sys_exit(1);
    }
    let mut sectors: u64 = 0;
    let mut saw_digit = false;
    for &b in &sz[..n as usize] {
        if b == b'\n' {
            break;
        }
        if !b.is_ascii_digit() {
            log("/sys/block/vda/size not a number\n");
            sys_exit(1);
        }
        sectors = sectors * 10 + (b - b'0') as u64;
        saw_digit = true;
    }
    if !saw_digit || sectors == 0 {
        log("/sys/block/vda/size not positive\n");
        sys_exit(1);
    }
    let mut ro = [0u8; 8];
    let n = read_path(b"/sys/block/vda/ro\0", &mut ro);
    if n <= 0 || &ro[..n as usize] != b"0\n" {
        log("/sys/block/vda/ro mismatch\n");
        sys_exit(1);
    }
    let mut rm = [0u8; 8];
    let n = read_path(b"/sys/block/vda/removable\0", &mut rm);
    if n <= 0 || &rm[..n as usize] != b"0\n" {
        log("/sys/block/vda/removable mismatch\n");
        sys_exit(1);
    }
    let mut lbs = [0u8; 8];
    let n = read_path(b"/sys/block/vda/queue/logical_block_size\0", &mut lbs);
    if n <= 0 || &lbs[..n as usize] != b"512\n" {
        log("/sys/block/vda/queue/logical_block_size mismatch\n");
        sys_exit(1);
    }
    log("/sys/block/vda topology OK\n");

    let mmpath: &[u8; 11] = b"/tmp/mmap\0\0";
    let fd = sys_openat(AT_FDCWD, mmpath.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        log("create /tmp/mmap failed\n");
        sys_exit(1);
    }
    let mmpayload = b"hello-from-mmap\n";
    sys_write(fd as u64, mmpayload.as_ptr(), mmpayload.len());

    const PROT_READ: u64 = 1;
    const MAP_PRIVATE: u64 = 0x02;
    let addr = sys_mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd as u64, 0);
    if (addr as i64) < 0 {
        log("file mmap failed\n");
        sys_exit(1);
    }
    let mapped = unsafe { core::slice::from_raw_parts(addr as *const u8, mmpayload.len()) };
    if mapped != mmpayload {
        log("file mmap content mismatch\n");
        sys_exit(1);
    }
    sys_munmap(addr as u64, 4096);
    sys_close(fd as u64);
    sys_unlinkat(AT_FDCWD, mmpath.as_ptr(), 0);
    log("file mmap OK\n");

    log("all abi syscalls OK\n");
    sys_exit(0);
}

#[repr(C)]
struct Iovec {
    base: *const u8,
    len: usize,
}
#[repr(C)]
struct IovecMut {
    base: *mut u8,
    len: usize,
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

macro_rules! syscall {
    ($n:expr $(,)?) => {{
        let r: i64;
        unsafe { asm!("syscall", in("rax") $n as u64, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack)); }
        r
    }};
    ($n:expr, $a0:expr $(,)?) => {{
        let r: i64;
        unsafe { asm!("syscall", in("rax") $n as u64, in("rdi") $a0, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack)); }
        r
    }};
    ($n:expr, $a0:expr, $a1:expr $(,)?) => {{
        let r: i64;
        unsafe { asm!("syscall", in("rax") $n as u64, in("rdi") $a0, in("rsi") $a1, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack)); }
        r
    }};
    ($n:expr, $a0:expr, $a1:expr, $a2:expr $(,)?) => {{
        let r: i64;
        unsafe { asm!("syscall", in("rax") $n as u64, in("rdi") $a0, in("rsi") $a1, in("rdx") $a2, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack)); }
        r
    }};
    ($n:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr $(,)?) => {{
        let r: i64;
        unsafe { asm!("syscall", in("rax") $n as u64, in("rdi") $a0, in("rsi") $a1, in("rdx") $a2, in("r10") $a3, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack)); }
        r
    }};
    ($n:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr $(,)?) => {{
        let r: i64;
        unsafe { asm!("syscall", in("rax") $n as u64, in("rdi") $a0, in("rsi") $a1, in("rdx") $a2, in("r10") $a3, in("r8") $a4, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack)); }
        r
    }};
}

fn sys_read(fd: u64, buf: *mut u8, len: usize) -> i64 {
    syscall!(0, fd, buf, len)
}
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    syscall!(1, fd, buf, len)
}
fn sys_close(fd: u64) -> i64 {
    syscall!(3, fd)
}
fn sys_ioctl(fd: u64, cmd: u64, arg: *mut u8) -> i64 {
    syscall!(16, fd, cmd, arg)
}
fn sys_pread64(fd: u64, buf: *mut u8, count: usize, off: u64) -> i64 {
    syscall!(17, fd, buf, count, off)
}
fn sys_pwrite64(fd: u64, buf: *const u8, count: usize, off: u64) -> i64 {
    syscall!(18, fd, buf, count, off)
}
fn sys_readv(fd: u64, iov: *const u8, iovcnt: u64) -> i64 {
    syscall!(19, fd, iov, iovcnt)
}
fn sys_writev(fd: u64, iov: *const u8, iovcnt: u64) -> i64 {
    syscall!(20, fd, iov, iovcnt)
}
fn sys_pipe2(fds: *mut u8, flags: u64) -> i64 {
    syscall!(293, fds, flags)
}
fn sys_dup(fd: u64) -> i64 {
    syscall!(32, fd)
}
fn sys_dup2(oldfd: u64, newfd: u64) -> i64 {
    syscall!(33, oldfd, newfd)
}
fn sys_dup3(oldfd: u64, newfd: u64, flags: u64) -> i64 {
    syscall!(292, oldfd, newfd, flags)
}
fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> i64 {
    syscall!(72, fd, cmd, arg)
}
fn sys_openat(dirfd: i64, pathname: *const u8, flags: u64, mode: u64) -> i64 {
    syscall!(257, dirfd, pathname, flags, mode)
}
fn sys_mkdirat(dirfd: i64, pathname: *const u8, mode: u64) -> i64 {
    syscall!(258, dirfd, pathname, mode)
}
fn sys_unlinkat(dirfd: i64, pathname: *const u8, flags: u64) -> i64 {
    syscall!(263, dirfd, pathname, flags)
}
fn sys_renameat(olddirfd: i64, oldpath: *const u8, newdirfd: i64, newpath: *const u8) -> i64 {
    syscall!(264, olddirfd, oldpath, newdirfd, newpath)
}
fn sys_linkat(
    olddirfd: i64,
    oldpath: *const u8,
    newdirfd: i64,
    newpath: *const u8,
    flags: u64,
) -> i64 {
    syscall!(265, olddirfd, oldpath, newdirfd, newpath, flags)
}
fn sys_symlinkat(target: *const u8, newdirfd: i64, linkpath: *const u8) -> i64 {
    syscall!(266, target, newdirfd, linkpath)
}
fn sys_readlinkat(dirfd: i64, pathname: *const u8, buf: *mut u8, bufsize: u64) -> i64 {
    syscall!(267, dirfd, pathname, buf, bufsize)
}
fn sys_brk(addr: u64) -> i64 {
    syscall!(12, addr)
}
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 9u64, in("rdi") addr, in("rsi") len, in("rdx") prot,
            in("r10") flags, in("r8") fd, in("r9") off,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}
fn sys_munmap(addr: u64, len: u64) -> i64 {
    syscall!(11, addr, len)
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
