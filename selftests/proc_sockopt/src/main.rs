#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const SOL_SOCKET: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_IP: i32 = 0;

const SO_REUSEADDR: i32 = 2;
const SO_TYPE: i32 = 3;
const SO_RCVBUF: i32 = 8;
const SO_KEEPALIVE: i32 = 9;
const SO_RCVTIMEO: i32 = 20;
const SO_DOMAIN: i32 = 39;
const SO_PROTOCOL: i32 = 38;
const TCP_NODELAY: i32 = 1;
const IP_TTL: i32 = 2;

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;

const SHUT_RD: i32 = 0;
const SHUT_WR: i32 = 1;

const ENOPROTOOPT: i64 = -92;
const EPIPE: i64 = -32;

const SIGPIPE: i32 = 13;
const SIG_IGN: u64 = 1;

#[repr(C)]
#[derive(Copy, Clone)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("sockopt test starting\n");

    let act = SigAction {
        handler: SIG_IGN,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    let _ = sys_rt_sigaction(SIGPIPE, &act as *const SigAction as u64, 0);

    let tcp = sys_socket(AF_INET, SOCK_STREAM, 0);
    if tcp < 0 {
        log("socket TCP: ");
        log_num(tcp);
        sys_exit(1);
    }
    let udp = sys_socket(AF_INET, SOCK_DGRAM, 0);
    if udp < 0 {
        log("socket UDP: ");
        log_num(udp);
        sys_exit(1);
    }

    if get_int(tcp as i32, SOL_SOCKET, SO_TYPE) != SOCK_STREAM as i64 {
        log("SO_TYPE TCP fail\n");
        sys_exit(1);
    }
    if get_int(udp as i32, SOL_SOCKET, SO_TYPE) != SOCK_DGRAM as i64 {
        log("SO_TYPE UDP fail\n");
        sys_exit(1);
    }
    if get_int(tcp as i32, SOL_SOCKET, SO_PROTOCOL) != 6 {
        log("SO_PROTOCOL TCP fail\n");
        sys_exit(1);
    }
    if get_int(udp as i32, SOL_SOCKET, SO_PROTOCOL) != 17 {
        log("SO_PROTOCOL UDP fail\n");
        sys_exit(1);
    }
    if get_int(tcp as i32, SOL_SOCKET, SO_DOMAIN) != AF_INET as i64 {
        log("SO_DOMAIN fail\n");
        sys_exit(1);
    }
    log("SO_TYPE / SO_PROTOCOL / SO_DOMAIN OK\n");

    set_int(tcp as i32, SOL_SOCKET, SO_REUSEADDR, 1);
    if get_int(tcp as i32, SOL_SOCKET, SO_REUSEADDR) != 1 {
        log("SO_REUSEADDR fail\n");
        sys_exit(1);
    }
    log("SO_REUSEADDR set+get OK\n");

    set_int(tcp as i32, IPPROTO_TCP, TCP_NODELAY, 1);
    if get_int(tcp as i32, IPPROTO_TCP, TCP_NODELAY) != 1 {
        log("TCP_NODELAY fail\n");
        sys_exit(1);
    }
    log("TCP_NODELAY set+get OK\n");

    let r = set_int_raw(udp as i32, IPPROTO_TCP, TCP_NODELAY, 1);
    if r != ENOPROTOOPT {
        log("TCP_NODELAY on UDP: expected ENOPROTOOPT got ");
        log_num(r);
        sys_exit(1);
    }
    log("TCP_NODELAY on UDP -> ENOPROTOOPT OK\n");

    set_int(tcp as i32, SOL_SOCKET, SO_RCVBUF, 16384);
    let v = get_int(tcp as i32, SOL_SOCKET, SO_RCVBUF);
    if v != 32768 {
        log("SO_RCVBUF readback: ");
        log_num(v);
        sys_exit(1);
    }
    log("SO_RCVBUF set+get OK\n");

    let tv: [i64; 2] = [3, 250_000];
    if sys_setsockopt(tcp as i32, SOL_SOCKET, SO_RCVTIMEO, tv.as_ptr() as u64, 16) != 0 {
        log("SO_RCVTIMEO set fail\n");
        sys_exit(1);
    }
    let mut tvr: [i64; 2] = [0, 0];
    let mut len: u32 = 16;
    if sys_getsockopt(
        tcp as i32,
        SOL_SOCKET,
        SO_RCVTIMEO,
        tvr.as_mut_ptr() as u64,
        &mut len as *mut u32 as u64,
    ) != 0
    {
        log("SO_RCVTIMEO get fail\n");
        sys_exit(1);
    }
    if tvr[0] != 3 || tvr[1] != 250_000 {
        log("SO_RCVTIMEO readback wrong: ");
        log_num(tvr[0]);
        log_num(tvr[1]);
        sys_exit(1);
    }
    log("SO_RCVTIMEO set+get OK\n");

    let rxto = sys_socket(AF_INET, SOCK_DGRAM, 0);
    if rxto < 0 {
        log("rxto socket fail\n");
        sys_exit(1);
    }
    let to: [i64; 2] = [0, 50_000];
    if sys_setsockopt(rxto as i32, SOL_SOCKET, SO_RCVTIMEO, to.as_ptr() as u64, 16) != 0 {
        log("rxto SO_RCVTIMEO set fail\n");
        sys_exit(1);
    }
    let mut rb = [0u8; 8];
    let n = sys_recv(rxto as i32, rb.as_mut_ptr(), rb.len());
    if n != -11 {
        log("SO_RCVTIMEO recv() not EAGAIN: ");
        log_num(n);
        sys_exit(1);
    }
    log("SO_RCVTIMEO recv() timed out -> EAGAIN OK\n");
    let n2 = sys_recvfrom(
        rxto as i32,
        rb.as_mut_ptr(),
        rb.len(),
        0,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );
    if n2 != -11 {
        log("SO_RCVTIMEO recvfrom() not EAGAIN: ");
        log_num(n2);
        sys_exit(1);
    }
    log("SO_RCVTIMEO recvfrom() timed out -> EAGAIN OK\n");
    sys_close(rxto as i32);

    let mut buf = [0u8; 16];
    let r = sys_shutdown(udp as i32, SHUT_RD);
    if r != 0 {
        log("shutdown SHUT_RD: ");
        log_num(r);
        sys_exit(1);
    }
    let n = sys_recv(udp as i32, buf.as_mut_ptr(), buf.len());
    if n != 0 {
        log("recv after SHUT_RD: expected 0 got ");
        log_num(n);
        sys_exit(1);
    }
    log("shutdown(UDP, SHUT_RD) -> recv returns 0 OK\n");

    let r = sys_shutdown(udp as i32, SHUT_WR);
    if r != 0 {
        log("shutdown SHUT_WR: ");
        log_num(r);
        sys_exit(1);
    }
    let n = sys_send(udp as i32, b"hi".as_ptr(), 2);
    if n != EPIPE {
        log("send after SHUT_WR: expected EPIPE got ");
        log_num(n);
        sys_exit(1);
    }
    log("shutdown(UDP, SHUT_WR) -> send returns EPIPE OK\n");

    let r = set_int_raw(tcp as i32, 4242, 9999, 1);
    if r != ENOPROTOOPT {
        log("unknown level: expected ENOPROTOOPT got ");
        log_num(r);
        sys_exit(1);
    }
    log("unknown sockopt -> ENOPROTOOPT OK\n");

    set_int(tcp as i32, IPPROTO_IP, IP_TTL, 32);
    if get_int(tcp as i32, IPPROTO_IP, IP_TTL) != 32 {
        log("IP_TTL fail\n");
        sys_exit(1);
    }
    log("IP_TTL set+get OK\n");

    set_int(tcp as i32, SOL_SOCKET, SO_KEEPALIVE, 1);
    if get_int(tcp as i32, SOL_SOCKET, SO_KEEPALIVE) != 1 {
        log("SO_KEEPALIVE fail\n");
        sys_exit(1);
    }
    log("SO_KEEPALIVE set+get OK\n");

    const SO_ERROR: i32 = 4;
    const ECONNREFUSED: i64 = 111;
    let c = sys_socket(AF_INET, SOCK_STREAM, 0);
    if c < 0 {
        log("SO_ERROR socket fail\n");
        sys_exit(1);
    }
    let sa = build_sockaddr_in([127, 0, 0, 1], 1);
    let _ = sys_connect(c as i32, sa.as_ptr(), 16);
    let mut latched = false;
    for _ in 0..1000 {
        let e = get_int(c as i32, SOL_SOCKET, SO_ERROR);
        if e == ECONNREFUSED {
            latched = true;
            break;
        }
        if e != 0 {
            log("SO_ERROR unexpected: ");
            log_num(e);
            sys_exit(1);
        }
    }
    if !latched {
        log("SO_ERROR never reached ECONNREFUSED\n");
        sys_exit(1);
    }
    let e2 = get_int(c as i32, SOL_SOCKET, SO_ERROR);
    if e2 != 0 {
        log("SO_ERROR not cleared: ");
        log_num(e2);
        sys_exit(1);
    }
    sys_close(c as i32);
    log("SO_ERROR refused-connect read+clear OK\n");

    let f = sys_socket(AF_INET, SOCK_STREAM, 0);
    if get_int(f as i32, SOL_SOCKET, SO_ERROR) != 0 {
        log("SO_ERROR fresh socket nonzero\n");
        sys_exit(1);
    }
    sys_close(f as i32);
    log("SO_ERROR fresh-socket 0 OK\n");

    sys_close(tcp as i32);
    sys_close(udp as i32);

    log("all sockopt+shutdown tests OK\n");
    sys_exit(0);
}

fn set_int(fd: i32, level: i32, opt: i32, val: i32) {
    let r = set_int_raw(fd, level, opt, val);
    if r != 0 {
        log("setsockopt ");
        log_num(opt as i64);
        log(": ");
        log_num(r);
        sys_exit(1);
    }
}

fn set_int_raw(fd: i32, level: i32, opt: i32, val: i32) -> i64 {
    let v: i32 = val;
    sys_setsockopt(fd, level, opt, &v as *const i32 as u64, 4)
}

fn get_int(fd: i32, level: i32, opt: i32) -> i64 {
    let mut v: i32 = -1;
    let mut len: u32 = 4;
    let r = sys_getsockopt(
        fd,
        level,
        opt,
        &mut v as *mut i32 as u64,
        &mut len as *mut u32 as u64,
    );
    if r != 0 {
        return r;
    }
    v as i64
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
fn sys_close(fd: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_rt_sigaction(sig: i32, new_act: u64, old_act: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 13u64, in("rdi") sig as i64,
        in("rsi") new_act, in("rdx") old_act, in("r10") 8u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_socket(domain: i32, ty: i32, proto: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 41u64, in("rdi") domain as i64,
        in("rsi") ty as i64, in("rdx") proto as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_setsockopt(fd: i32, level: i32, opt: i32, optval: u64, optlen: u32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 54u64, in("rdi") fd as i64,
        in("rsi") level as i64, in("rdx") opt as i64,
        in("r10") optval, in("r8") optlen as u64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_getsockopt(fd: i32, level: i32, opt: i32, optval: u64, optlen_ptr: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 55u64, in("rdi") fd as i64,
        in("rsi") level as i64, in("rdx") opt as i64,
        in("r10") optval, in("r8") optlen_ptr,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_shutdown(fd: i32, how: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 48u64, in("rdi") fd as i64,
        in("rsi") how as i64,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_recv(fd: i32, buf: *mut u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 0u64, in("rdi") fd as i64,
        in("rsi") buf, in("rdx") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_send(fd: i32, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 1u64, in("rdi") fd as i64,
        in("rsi") buf, in("rdx") len,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_connect(fd: i32, addr: *const u8, addrlen: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 42u64, in("rdi") fd as i64,
        in("rsi") addr, in("rdx") addrlen,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

#[inline(never)]
fn sys_recvfrom(
    fd: i32,
    buf: *mut u8,
    len: usize,
    flags: u64,
    addr: *mut u8,
    addrlen: *mut u8,
) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 45u64, in("rdi") fd as i64,
        in("rsi") buf, in("rdx") len, in("r10") flags, in("r8") addr, in("r9") addrlen,
        lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn build_sockaddr_in(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&2u16.to_le_bytes());
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    sa[4..8].copy_from_slice(&ip);
    sa
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
