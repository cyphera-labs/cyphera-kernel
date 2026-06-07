#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_NONBLOCK: u64 = 0o4000;
const AF_NETLINK: u64 = 16;

const EPOLL_CTL_ADD: u64 = 1;
const EPOLLIN: u32 = 0x001;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("net test starting\n");

    let mut sv = [0i32; 2];
    if sys_socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as *mut u8) != 0 {
        log("socketpair failed\n");
        sys_exit(1);
    }
    let a = sv[0] as u64;
    let b = sv[1] as u64;
    if sys_write(a, b"ping".as_ptr(), 4) != 4 {
        log("unix send a->b failed\n");
        sys_exit(1);
    }
    let mut buf = [0u8; 16];
    let n = sys_read(b, buf.as_mut_ptr(), buf.len());
    if n != 4 || &buf[..4] != b"ping" {
        log("unix recv b mismatch\n");
        sys_exit(1);
    }
    if sys_write(b, b"pong".as_ptr(), 4) != 4 {
        log("unix send b->a failed\n");
        sys_exit(1);
    }
    let n = sys_read(a, buf.as_mut_ptr(), buf.len());
    if n != 4 || &buf[..4] != b"pong" {
        log("unix recv a mismatch\n");
        sys_exit(1);
    }
    log("AF_UNIX socketpair OK\n");

    let epfd = sys_epoll_create1(0);
    if epfd < 0 {
        log("epoll_create1 failed\n");
        sys_exit(1);
    }
    let mut ev = [0u8; 12];
    ev[0..4].copy_from_slice(&EPOLLIN.to_le_bytes());
    ev[4..12].copy_from_slice(&0xdeadbeef_u64.to_le_bytes());
    if sys_epoll_ctl(epfd as u64, EPOLL_CTL_ADD, b, ev.as_ptr()) != 0 {
        log("epoll_ctl ADD failed\n");
        sys_exit(1);
    }
    sys_write(a, b"x".as_ptr(), 1);
    let mut events = [0u8; 12];
    let n = sys_epoll_wait(epfd as u64, events.as_mut_ptr(), 1, 0);
    if n != 1 {
        log("epoll_wait didn't see ready\n");
        sys_exit(1);
    }
    let got_evts = u32::from_le_bytes([events[0], events[1], events[2], events[3]]);
    let got_data = u64::from_le_bytes([
        events[4], events[5], events[6], events[7], events[8], events[9], events[10], events[11],
    ]);
    if got_evts & EPOLLIN == 0 || got_data != 0xdeadbeef {
        log("epoll_wait wrong contents\n");
        sys_exit(1);
    }
    sys_close(epfd as u64);
    sys_close(a);
    sys_close(b);
    log("epoll OK\n");

    let udp = sys_socket(AF_INET, SOCK_DGRAM, 0);
    if udp < 0 {
        log("socket(AF_INET, SOCK_DGRAM) failed\n");
        sys_exit(1);
    }
    let sa = build_sockaddr_in([10, 0, 2, 3], 53);
    let mut q = [0u8; 64];
    let qlen = build_dns_query(&mut q, b"cyphera.test");
    if sys_sendto(
        udp as u64,
        q.as_ptr(),
        qlen,
        0,
        sa.as_ptr(),
        sa.len() as u64,
    ) != qlen as i64
    {
        log("UDP sendto failed\n");
        sys_exit(1);
    }
    let mut rbuf = [0u8; 512];
    let mut sa_in = [0u8; 16];
    let mut sa_in_len: u32 = sa_in.len() as u32;
    let mut got = 0i64;
    for _ in 0..100_000 {
        let r = sys_recvfrom(
            udp as u64,
            rbuf.as_mut_ptr(),
            rbuf.len(),
            0,
            sa_in.as_mut_ptr(),
            (&mut sa_in_len) as *mut u32 as *mut u8,
        );
        if r > 0 {
            got = r;
            break;
        }
    }
    if got <= 0 {
        log("UDP recvfrom timeout\n");
        sys_exit(1);
    }
    if rbuf[0] != 0x12 || rbuf[1] != 0x34 {
        log("DNS reply id mismatch\n");
        sys_exit(1);
    }
    if rbuf[2] & 0x80 == 0 {
        log("DNS reply QR bit unset\n");
        sys_exit(1);
    }
    sys_close(udp as u64);
    log("UDP/DNS round-trip OK\n");

    let tcp = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if tcp < 0 {
        log("socket(AF_INET, SOCK_STREAM) failed\n");
        sys_exit(1);
    }
    let sa = build_sockaddr_in([0, 0, 0, 0], 9999);
    if sys_bind(tcp as u64, sa.as_ptr(), sa.len() as u64) != 0 {
        log("TCP bind failed\n");
        sys_exit(1);
    }
    if sys_listen(tcp as u64, 8) != 0 {
        log("TCP listen failed\n");
        sys_exit(1);
    }
    let mut nm = [0u8; 16];
    let mut nm_len: u32 = nm.len() as u32;
    if sys_getsockname(tcp as u64, nm.as_mut_ptr(), (&mut nm_len) as *mut u32 as *mut u8) != 0 {
        log("getsockname failed\n");
        sys_exit(1);
    }
    if nm_len != 16
        || u16::from_le_bytes([nm[0], nm[1]]) != 2
        || u16::from_be_bytes([nm[2], nm[3]]) != 9999
        || nm[4] != 0
        || nm[5] != 0
        || nm[6] != 0
        || nm[7] != 0
    {
        log("getsockname wrong endpoint\n");
        sys_exit(1);
    }
    if sys_getpeername(tcp as u64, nm.as_mut_ptr(), (&mut nm_len) as *mut u32 as *mut u8) != -107 {
        log("getpeername(listener) not ENOTCONN\n");
        sys_exit(1);
    }
    log("getsockname/getpeername OK\n");

    let acc = sys_accept(tcp as u64, core::ptr::null_mut(), core::ptr::null_mut());
    if acc != -11 {
        log("TCP accept didn't return EAGAIN\n");
        sys_exit(1);
    }

    let cli = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if cli < 0 {
        log("loopback client socket failed\n");
        sys_exit(1);
    }
    let dst = build_sockaddr_in([127, 0, 0, 1], 9999);
    if sys_connect(cli as u64, dst.as_ptr(), dst.len() as u64) != 0 {
        log("loopback connect failed\n");
        sys_exit(1);
    }
    let mut peer = [0u8; 16];
    let mut peer_len: u32 = peer.len() as u32;
    let mut afd = -1i64;
    for _ in 0..100_000 {
        let r = sys_accept(tcp as u64, peer.as_mut_ptr(), (&mut peer_len) as *mut u32 as *mut u8);
        if r >= 0 {
            afd = r;
            break;
        }
        if r != -11 {
            log("loopback accept hard error\n");
            sys_exit(1);
        }
        let _ = sys_getpeername(cli as u64, core::ptr::null_mut(), core::ptr::null_mut());
    }
    if afd < 0 {
        log("loopback accept never completed\n");
        sys_exit(1);
    }
    if peer_len != 16
        || u16::from_le_bytes([peer[0], peer[1]]) != 2
        || &peer[4..8] != &[127, 0, 0, 1]
        || u16::from_be_bytes([peer[2], peer[3]]) < 32768
    {
        log("accept peer address wrong\n");
        sys_exit(1);
    }
    let peer_port = u16::from_be_bytes([peer[2], peer[3]]);
    let mut gp = [0u8; 16];
    let mut gp_len: u32 = gp.len() as u32;
    if sys_getpeername(afd as u64, gp.as_mut_ptr(), (&mut gp_len) as *mut u32 as *mut u8) != 0 {
        log("getpeername(accepted) failed\n");
        sys_exit(1);
    }
    if &gp[4..8] != &[127, 0, 0, 1] || u16::from_be_bytes([gp[2], gp[3]]) != peer_port {
        log("getpeername(accepted) mismatch\n");
        sys_exit(1);
    }
    let cli2 = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if cli2 < 0 {
        log("cli2 socket failed\n");
        sys_exit(1);
    }
    if sys_connect(cli2 as u64, dst.as_ptr(), dst.len() as u64) != 0 {
        log("cli2 connect failed\n");
        sys_exit(1);
    }
    let mut small = [0xFFu8; 16];
    let mut small_len: u32 = 8;
    let mut afd2 = -1i64;
    for _ in 0..100_000 {
        let r = sys_accept(tcp as u64, small.as_mut_ptr(), (&mut small_len) as *mut u32 as *mut u8);
        if r >= 0 {
            afd2 = r;
            break;
        }
        if r != -11 {
            log("cli2 accept hard error\n");
            sys_exit(1);
        }
        let _ = sys_getpeername(cli2 as u64, core::ptr::null_mut(), core::ptr::null_mut());
    }
    if afd2 < 0 {
        log("cli2 accept never completed\n");
        sys_exit(1);
    }
    if small_len != 16 {
        log("accept addrlen not written back as 16\n");
        sys_exit(1);
    }
    if small[8..16] != [0xFFu8; 8] {
        log("accept overran addrlen capacity\n");
        sys_exit(1);
    }
    if &small[4..8] != &[127, 0, 0, 1] {
        log("accept truncated addr wrong\n");
        sys_exit(1);
    }
    sys_close(afd2 as u64);
    sys_close(cli2 as u64);
    log("accept addrlen truncation OK\n");

    if so_error(cli as u64) != 0 {
        log("established client SO_ERROR != 0\n");
        sys_exit(1);
    }
    sys_shutdown(cli as u64, 2);
    sys_shutdown(afd as u64, 2);
    for _ in 0..2000 {
        let _ = sys_getpeername(cli as u64, core::ptr::null_mut(), core::ptr::null_mut());
    }
    if so_error(cli as u64) != 0 {
        log("closed-after-established SO_ERROR != 0 (mislabel)\n");
        sys_exit(1);
    }
    log("SO_ERROR established+closed not mislabeled OK\n");
    sys_close(afd as u64);
    sys_close(cli as u64);
    sys_close(tcp as u64);
    log("TCP loopback accept peer-addr OK\n");

    let mut nd = [0u8; 512];
    let n = read_path(b"/proc/net/dev\0", &mut nd);
    if n <= 0 || find(&nd[..n as usize], b"eth0:").is_none() {
        log("/proc/net/dev missing eth0\n");
        sys_exit(1);
    }
    log("/proc/net/dev OK\n");

    let mut sb = [0u8; 32];
    let n = read_path(b"/sys/class/net/eth0/address\0", &mut sb);
    if n <= 0 || find(&sb[..n as usize], b"52:54:00:12:34:56").is_none() {
        log("/sys/class/net/eth0/address mismatch\n");
        sys_exit(1);
    }
    log("/sys/class/net/eth0/address OK\n");

    let nl = sys_socket(AF_NETLINK, SOCK_DGRAM, 0);
    if nl < 0 {
        log("socket(AF_NETLINK) failed\n");
        sys_exit(1);
    }
    let mut req = [0u8; 32];
    req[0] = 32;
    req[4] = 18;
    req[6] = 0x05;
    req[8] = 0x42;
    if sys_write(nl as u64, req.as_ptr(), req.len()) != req.len() as i64 {
        log("netlink write failed\n");
        sys_exit(1);
    }
    let mut got_lo = false;
    let mut got_eth0 = false;
    let mut got_done = false;
    let mut rb = [0u8; 1024];
    for _ in 0..8 {
        let r = sys_read(nl as u64, rb.as_mut_ptr(), rb.len());
        if r <= 0 {
            break;
        }
        let mtype = u16::from_le_bytes([rb[4], rb[5]]);
        if mtype == 3 {
            got_done = true;
            break;
        }
        if mtype == 16 {
            if find(&rb[..r as usize], b"lo").is_some() {
                got_lo = true;
            }
            if find(&rb[..r as usize], b"eth0").is_some() {
                got_eth0 = true;
            }
        }
    }
    if !got_lo || !got_eth0 || !got_done {
        log("netlink dump incomplete\n");
        sys_exit(1);
    }
    sys_close(nl as u64);
    log("AF_NETLINK RTM_GETLINK OK\n");

    log("all networking tests OK\n");
    sys_exit(0);
}

fn build_sockaddr_in(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&2u16.to_le_bytes());
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    sa[4..8].copy_from_slice(&ip);
    sa
}

fn build_dns_query(out: &mut [u8], qname: &[u8]) -> usize {
    out[0] = 0x12;
    out[1] = 0x34;
    out[2] = 0x01;
    out[3] = 0x00;
    out[4] = 0x00;
    out[5] = 0x01;
    let mut off = 12;
    let mut start = 0;
    for i in 0..qname.len() {
        if qname[i] == b'.' {
            out[off] = (i - start) as u8;
            off += 1;
            for j in start..i {
                out[off] = qname[j];
                off += 1;
            }
            start = i + 1;
        }
    }
    let last = qname.len() - start;
    out[off] = last as u8;
    off += 1;
    for j in start..qname.len() {
        out[off] = qname[j];
        off += 1;
    }
    out[off] = 0;
    off += 1;
    out[off] = 0;
    out[off + 1] = 1;
    out[off + 2] = 0;
    out[off + 3] = 1;
    off + 4
}

#[inline(never)]
fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

macro_rules! syscall {
    ($n:expr, $a0:expr, $a1:expr, $a2:expr $(,)?) => {{
        let r: i64;
        unsafe {
            asm!(
                "syscall",
                in("rax") $n as u64, in("rdi") $a0, in("rsi") $a1, in("rdx") $a2,
                lateout("rax") r, out("rcx") _, out("r11") _,
                options(nostack),
            );
        }
        r
    }};
    ($n:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr $(,)?) => {{
        let r: i64;
        unsafe {
            asm!(
                "syscall",
                in("rax") $n as u64, in("rdi") $a0, in("rsi") $a1, in("rdx") $a2, in("r10") $a3,
                lateout("rax") r, out("rcx") _, out("r11") _,
                options(nostack),
            );
        }
        r
    }};
    ($n:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr $(,)?) => {{
        let r: i64;
        unsafe {
            asm!(
                "syscall",
                in("rax") $n as u64, in("rdi") $a0, in("rsi") $a1, in("rdx") $a2,
                in("r10") $a3, in("r8") $a4, in("r9") $a5,
                lateout("rax") r, out("rcx") _, out("r11") _,
                options(nostack),
            );
        }
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
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 3u64, in("rdi") fd, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn sys_socket(domain: u64, kind: u64, proto: u64) -> i64 {
    syscall!(41, domain, kind, proto)
}
fn sys_sendto(
    fd: u64,
    buf: *const u8,
    len: usize,
    flags: u64,
    addr: *const u8,
    addrlen: u64,
) -> i64 {
    syscall!(44, fd, buf, len, flags, addr, addrlen)
}
fn sys_recvfrom(
    fd: u64,
    buf: *mut u8,
    len: usize,
    flags: u64,
    addr: *mut u8,
    addrlen: *mut u8,
) -> i64 {
    syscall!(45, fd, buf, len, flags, addr, addrlen)
}
fn sys_socketpair(domain: u64, kind: u64, proto: u64, sv: *mut u8) -> i64 {
    syscall!(53, domain, kind, proto, sv)
}
fn sys_epoll_wait(epfd: u64, events: *mut u8, max: u64, timeout: u64) -> i64 {
    syscall!(232, epfd, events, max, timeout)
}
fn sys_epoll_ctl(epfd: u64, op: u64, fd: u64, ev: *const u8) -> i64 {
    syscall!(233, epfd, op, fd, ev)
}
fn sys_epoll_create1(flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 291u64, in("rdi") flags, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}

fn sys_bind(fd: u64, addr: *const u8, addrlen: u64) -> i64 {
    syscall!(49, fd, addr, addrlen)
}
fn sys_listen(fd: u64, backlog: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 50u64, in("rdi") fd, in("rsi") backlog, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
}
fn sys_accept(fd: u64, addr: *mut u8, addrlen: *mut u8) -> i64 {
    syscall!(43, fd, addr, addrlen)
}
fn sys_connect(fd: u64, addr: *const u8, addrlen: u64) -> i64 {
    syscall!(42, fd, addr, addrlen)
}
fn sys_getsockname(fd: u64, addr: *mut u8, addrlen: *mut u8) -> i64 {
    syscall!(51, fd, addr, addrlen)
}
fn sys_getpeername(fd: u64, addr: *mut u8, addrlen: *mut u8) -> i64 {
    syscall!(52, fd, addr, addrlen)
}
fn sys_shutdown(fd: u64, how: u64) -> i64 {
    syscall!(48, fd, how, 0u64)
}
fn so_error(fd: u64) -> i64 {
    let mut v: i32 = -1;
    let mut len: u32 = 4;
    let r = syscall!(
        55,
        fd,
        1u64,
        4u64,
        &mut v as *mut i32 as *mut u8,
        &mut len as *mut u32 as *mut u8,
        0u64
    );
    if r != 0 {
        return r;
    }
    v as i64
}

fn read_path(path: &[u8], buf: &mut [u8]) -> i64 {
    const O_RDONLY: u64 = 0;
    let fd = sys_openat(-100, path.as_ptr(), O_RDONLY, 0);
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

fn sys_openat(dirfd: i64, pathname: *const u8, flags: u64, mode: u64) -> i64 {
    syscall!(257, dirfd, pathname, flags, mode)
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

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
