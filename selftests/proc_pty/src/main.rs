#![no_std]
#![no_main]

use core::arch::asm;

const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_IOCTL: u64 = 16;
const SYS_EXIT: u64 = 60;

const TIOCGPTN: u64 = 0x80045430;

unsafe fn syscall3(nr: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        in("rdi") a, in("rsi") b, in("rdx") c,
        lateout("rcx") _, lateout("r11") _,
    );
    ret
}

fn open(path: &[u8], flags: i64) -> i64 {
    let mut buf = [0u8; 64];
    buf[..path.len()].copy_from_slice(path);
    unsafe { syscall3(SYS_OPEN, buf.as_ptr() as u64, flags as u64, 0) }
}

fn write(fd: i64, s: &[u8]) -> i64 {
    unsafe { syscall3(SYS_WRITE, fd as u64, s.as_ptr() as u64, s.len() as u64) }
}

fn read(fd: i64, buf: &mut [u8]) -> i64 {
    unsafe {
        syscall3(
            SYS_READ,
            fd as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        )
    }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall3(SYS_CLOSE, fd as u64, 0, 0) }
}

fn ioctl(fd: i64, cmd: u64, arg: u64) -> i64 {
    unsafe { syscall3(SYS_IOCTL, fd as u64, cmd, arg) }
}

fn exit(code: i32) -> ! {
    unsafe { syscall3(SYS_EXIT, code as u64, 0, 0) };
    loop {}
}

fn print(s: &[u8]) {
    write(1, s);
}

fn print_dec(n: u32) {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    let mut v = n;
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    write(1, &buf[i..]);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    print(b"pty: open /dev/ptmx\n");
    let m = open(b"/dev/ptmx\0", 0o2);
    if m < 0 {
        print(b"FAIL ptmx open\n");
        exit(1);
    }

    let mut nbuf = [0u8; 4];
    let r = ioctl(m, TIOCGPTN, nbuf.as_mut_ptr() as u64);
    if r < 0 {
        print(b"FAIL TIOCGPTN\n");
        exit(2);
    }
    let n = u32::from_le_bytes(nbuf);
    print(b"pty: slave n=");
    print_dec(n);
    print(b"\n");

    let mut path = *b"/dev/pts/0000000\0";
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    let mut v = n;
    if v == 0 {
        i -= 1;
        digits[i] = b'0';
    }
    while v > 0 {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let dlen = digits.len() - i;
    path[9..9 + dlen].copy_from_slice(&digits[i..]);
    path[9 + dlen] = 0;

    let s = open(&path[..10 + dlen], 0o2);
    if s < 0 {
        print(b"FAIL slave open\n");
        exit(3);
    }
    print(b"pty: slave open ok\n");

    const TIOCSWINSZ: u64 = 0x5414;
    const TIOCGWINSZ: u64 = 0x5413;
    let ws_set: [u8; 8] = [50, 0, 200, 0, 0, 0, 0, 0];
    if ioctl(m, TIOCSWINSZ, ws_set.as_ptr() as u64) < 0 {
        print(b"FAIL TIOCSWINSZ\n");
        exit(6);
    }
    let mut ws_get = [0u8; 8];
    if ioctl(s, TIOCGWINSZ, ws_get.as_mut_ptr() as u64) < 0 {
        print(b"FAIL TIOCGWINSZ\n");
        exit(7);
    }
    if ws_get != ws_set {
        print(b"FAIL winsize mismatch\n");
        exit(8);
    }
    print(b"pty: winsize round-trip (master->slave) ok\n");

    write(m, b"hi\n");
    let mut buf = [0u8; 16];
    let r = read(s, &mut buf);
    if r < 0 {
        print(b"FAIL slave read\n");
        exit(4);
    }
    print(b"pty: slave got: ");
    write(1, &buf[..r as usize]);

    write(s, b"ack\n");
    let r = read(m, &mut buf);
    if r < 0 {
        print(b"FAIL master read\n");
        exit(5);
    }
    print(b"pty: master got: ");
    write(1, &buf[..r as usize]);

    close(s);
    close(m);
    print(b"pty: ok\n");
    exit(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(99)
}
