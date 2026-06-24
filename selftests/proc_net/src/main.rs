#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(1);
}

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_NONBLOCK: u64 = 0o4000;
const AF_NETLINK: u64 = 16;
const RTM_GETADDR: u16 = 22;
const EINPROGRESS: i64 = -115;
const EAGAIN: i64 = -11;
const ESOCKTNOSUPPORT: i64 = -94;

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

    let mut dg = [0i32; 2];
    if sys_socketpair(AF_UNIX, SOCK_DGRAM, 0, dg.as_mut_ptr() as *mut u8) != 0 {
        log("dgram socketpair failed\n");
        sys_exit(1);
    }
    sys_write(dg[0] as u64, b"AAA".as_ptr(), 3);
    sys_write(dg[0] as u64, b"BB".as_ptr(), 2);
    let mut m = [0u8; 16];
    if sys_read(dg[1] as u64, m.as_mut_ptr(), m.len()) != 3 || &m[..3] != b"AAA" {
        log("dgram boundary: first message not 3 bytes AAA\n");
        sys_exit(1);
    }
    if sys_read(dg[1] as u64, m.as_mut_ptr(), m.len()) != 2 || &m[..2] != b"BB" {
        log("dgram boundary: second message not 2 bytes BB\n");
        sys_exit(1);
    }
    sys_write(dg[0] as u64, b"HELLO".as_ptr(), 5);
    sys_write(dg[0] as u64, b"XY".as_ptr(), 2);
    let mut small = [0u8; 3];
    if sys_read(dg[1] as u64, small.as_mut_ptr(), small.len()) != 3 || &small != b"HEL" {
        log("dgram truncate: short read not 3 bytes HEL\n");
        sys_exit(1);
    }
    if sys_read(dg[1] as u64, m.as_mut_ptr(), m.len()) != 2 || &m[..2] != b"XY" {
        log("dgram truncate: leftover leaked instead of next message XY\n");
        sys_exit(1);
    }
    sys_close(dg[0] as u64);
    sys_close(dg[1] as u64);
    log("AF_UNIX dgram socketpair boundaries + truncation OK\n");

    let mut bad = [0i32; 2];
    if sys_socketpair(AF_UNIX, 999, 0, bad.as_mut_ptr() as *mut u8) != ESOCKTNOSUPPORT {
        log("socketpair unknown type should ESOCKTNOSUPPORT\n");
        sys_exit(1);
    }
    log("AF_UNIX socketpair unknown-type reject OK\n");

    let mut nb = [0i32; 2];
    if sys_socketpair(
        AF_UNIX,
        SOCK_STREAM | SOCK_NONBLOCK,
        0,
        nb.as_mut_ptr() as *mut u8,
    ) != 0
    {
        log("nonblock socketpair failed\n");
        sys_exit(1);
    }
    if sys_read(nb[0] as u64, buf.as_mut_ptr(), buf.len()) != EAGAIN {
        log("unix nonblock read on empty should EAGAIN\n");
        sys_exit(1);
    }
    sys_close(nb[0] as u64);
    sys_close(nb[1] as u64);
    log("AF_UNIX nonblock read EAGAIN OK\n");

    let mut nbw = [0i32; 2];
    if sys_socketpair(
        AF_UNIX,
        SOCK_STREAM | SOCK_NONBLOCK,
        0,
        nbw.as_mut_ptr() as *mut u8,
    ) != 0
    {
        log("nonblock write socketpair failed\n");
        sys_exit(1);
    }
    let chunk = [0u8; 4096];
    let mut saw_eagain = false;
    for _ in 0..256 {
        let r = sys_write(nbw[0] as u64, chunk.as_ptr(), chunk.len());
        if r == EAGAIN {
            saw_eagain = true;
            break;
        }
        if r <= 0 {
            log("unix nonblock write unexpected result\n");
            sys_exit(1);
        }
    }
    if !saw_eagain {
        log("unix nonblock write never returned EAGAIN\n");
        sys_exit(1);
    }
    sys_close(nbw[0] as u64);
    sys_close(nbw[1] as u64);
    log("AF_UNIX nonblock write EAGAIN OK\n");

    let mut nbm = [0i32; 2];
    if sys_socketpair(
        AF_UNIX,
        SOCK_STREAM | SOCK_NONBLOCK,
        0,
        nbm.as_mut_ptr() as *mut u8,
    ) != 0
    {
        log("nonblock sendmsg socketpair failed\n");
        sys_exit(1);
    }
    let mdata = [0u8; 4096];
    let miov = [mdata.as_ptr() as u64, mdata.len() as u64];
    let mut mmh = [0u8; 56];
    mmh[16..24].copy_from_slice(&(miov.as_ptr() as u64).to_le_bytes());
    mmh[24..32].copy_from_slice(&1u64.to_le_bytes());
    let mut saw_eagain_msg = false;
    for _ in 0..256 {
        let r = sys_sendmsg(nbm[0] as u64, mmh.as_ptr() as u64, 0);
        if r == EAGAIN {
            saw_eagain_msg = true;
            break;
        }
        if r <= 0 {
            log("nonblock sendmsg unexpected result\n");
            sys_exit(1);
        }
    }
    if !saw_eagain_msg {
        log("nonblock sendmsg never returned EAGAIN\n");
        sys_exit(1);
    }
    sys_close(nbm[0] as u64);
    sys_close(nbm[1] as u64);
    log("AF_UNIX nonblock sendmsg EAGAIN OK\n");

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
    if sys_getsockname(
        tcp as u64,
        nm.as_mut_ptr(),
        (&mut nm_len) as *mut u32 as *mut u8,
    ) != 0
    {
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
    if sys_getpeername(
        tcp as u64,
        nm.as_mut_ptr(),
        (&mut nm_len) as *mut u32 as *mut u8,
    ) != -107
    {
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
    let crc = sys_connect(cli as u64, dst.as_ptr(), dst.len() as u64);
    if crc != 0 && crc != EINPROGRESS {
        log("loopback connect failed\n");
        sys_exit(1);
    }
    let mut peer = [0u8; 16];
    let mut peer_len: u32 = peer.len() as u32;
    let mut afd = -1i64;
    for _ in 0..100_000 {
        let r = sys_accept(
            tcp as u64,
            peer.as_mut_ptr(),
            (&mut peer_len) as *mut u32 as *mut u8,
        );
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
    if sys_getpeername(
        afd as u64,
        gp.as_mut_ptr(),
        (&mut gp_len) as *mut u32 as *mut u8,
    ) != 0
    {
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
    let crc2 = sys_connect(cli2 as u64, dst.as_ptr(), dst.len() as u64);
    if crc2 != 0 && crc2 != EINPROGRESS {
        log("cli2 connect failed\n");
        sys_exit(1);
    }
    let mut small = [0xFFu8; 16];
    let mut small_len: u32 = 8;
    let mut afd2 = -1i64;
    for _ in 0..100_000 {
        let r = sys_accept(
            tcp as u64,
            small.as_mut_ptr(),
            (&mut small_len) as *mut u32 as *mut u8,
        );
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

    loopback_listener_regression();

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

    {
        let nl = sys_socket(AF_NETLINK, SOCK_DGRAM, 0);
        if nl < 0 {
            log("netlink(addr) socket failed\n");
            sys_exit(1);
        }
        let mut snl = [0u8; 12];
        snl[0] = AF_NETLINK as u8;
        if sys_bind(nl as u64, snl.as_ptr(), snl.len() as u64) != 0 {
            log("netlink bind failed\n");
            sys_exit(1);
        }
        let mut req = [0u8; 32];
        req[0] = 32;
        req[4] = (RTM_GETADDR & 0xff) as u8;
        req[5] = (RTM_GETADDR >> 8) as u8;
        req[6] = 0x05;
        req[8] = 0x43;
        if sys_write(nl as u64, req.as_ptr(), req.len()) != req.len() as i64 {
            log("netlink GETADDR write failed\n");
            sys_exit(1);
        }
        let mut saw_v4 = false;
        let mut saw_v6 = false;
        let mut done = false;
        let mut rb = [0u8; 1024];
        for _ in 0..16 {
            let r = sys_read(nl as u64, rb.as_mut_ptr(), rb.len());
            if r <= 0 {
                break;
            }
            let mtype = u16::from_le_bytes([rb[4], rb[5]]);
            if mtype == 3 {
                done = true;
                break;
            }
            if mtype == 20 {
                match rb[16] {
                    2 => saw_v4 = true,
                    10 => saw_v6 = true,
                    _ => {}
                }
            }
        }
        if !saw_v4 || !saw_v6 || !done {
            log("RTM_GETADDR dump incomplete (need v4+v6)\n");
            sys_exit(1);
        }
        sys_close(nl as u64);
        log("rtnetlink RTM_GETADDR + bind OK\n");
    }

    {
        let path = b"/tmp/pgu.sock";
        let mut sa = [0u8; 32];
        sa[0] = AF_UNIX as u8;
        sa[2..2 + path.len()].copy_from_slice(path);
        let salen = (2 + path.len() + 1) as u64;

        let srv = sys_socket(AF_UNIX, SOCK_STREAM, 0);
        if srv < 0 {
            log("AF_UNIX socket(server) failed\n");
            sys_exit(1);
        }
        if sys_bind(srv as u64, sa.as_ptr(), salen) != 0 {
            log("AF_UNIX bind failed\n");
            sys_exit(1);
        }
        if sys_listen(srv as u64, 8) != 0 {
            log("AF_UNIX listen failed\n");
            sys_exit(1);
        }
        let cli = sys_socket(AF_UNIX, SOCK_STREAM, 0);
        if cli < 0 {
            log("AF_UNIX socket(client) failed\n");
            sys_exit(1);
        }
        if sys_connect(cli as u64, sa.as_ptr(), salen) != 0 {
            log("AF_UNIX connect failed\n");
            sys_exit(1);
        }
        let conn = sys_accept(srv as u64, core::ptr::null_mut(), core::ptr::null_mut());
        if conn < 0 {
            log("AF_UNIX accept failed\n");
            sys_exit(1);
        }
        if sys_write(cli as u64, b"ping".as_ptr(), 4) != 4 {
            log("AF_UNIX write(client) failed\n");
            sys_exit(1);
        }
        let mut rb = [0u8; 8];
        if sys_read(conn as u64, rb.as_mut_ptr(), rb.len()) != 4 || &rb[..4] != b"ping" {
            log("AF_UNIX server read mismatch\n");
            sys_exit(1);
        }
        if sys_write(conn as u64, b"pong".as_ptr(), 4) != 4 {
            log("AF_UNIX write(conn) failed\n");
            sys_exit(1);
        }
        let mut rb2 = [0u8; 8];
        if sys_read(cli as u64, rb2.as_mut_ptr(), rb2.len()) != 4 || &rb2[..4] != b"pong" {
            log("AF_UNIX client read mismatch\n");
            sys_exit(1);
        }
        sys_close(cli as u64);
        if sys_read(conn as u64, rb.as_mut_ptr(), rb.len()) != 0 {
            log("AF_UNIX EOF expected after peer close\n");
            sys_exit(1);
        }
        sys_close(conn as u64);
        sys_close(srv as u64);
        log("AF_UNIX stream bind/listen/connect/accept/echo/EOF OK\n");
    }

    {
        let mut srv_sa = [0u8; 16];
        srv_sa[0] = AF_UNIX as u8;
        srv_sa[2] = 0;
        srv_sa[3..7].copy_from_slice(b"pgdg");
        let srv_salen = 7u64;

        let mut cli_sa = [0u8; 16];
        cli_sa[0] = AF_UNIX as u8;
        cli_sa[2] = 0;
        cli_sa[3..7].copy_from_slice(b"pgcl");
        let cli_salen = 7u64;

        let srv = sys_socket(AF_UNIX, SOCK_DGRAM, 0);
        let cli = sys_socket(AF_UNIX, SOCK_DGRAM, 0);
        if srv < 0 || cli < 0 {
            log("AF_UNIX dgram socket failed\n");
            sys_exit(1);
        }
        if sys_bind(srv as u64, srv_sa.as_ptr(), srv_salen) != 0 {
            log("AF_UNIX dgram server bind failed\n");
            sys_exit(1);
        }
        if sys_bind(cli as u64, cli_sa.as_ptr(), cli_salen) != 0 {
            log("AF_UNIX dgram client bind failed\n");
            sys_exit(1);
        }
        if sys_sendto(
            cli as u64,
            b"hello".as_ptr(),
            5,
            0,
            srv_sa.as_ptr(),
            srv_salen,
        ) != 5
        {
            log("AF_UNIX dgram sendto failed\n");
            sys_exit(1);
        }
        let mut rb = [0u8; 16];
        let mut from = [0u8; 16];
        let mut from_len: u32 = from.len() as u32;
        let n = sys_recvfrom(
            srv as u64,
            rb.as_mut_ptr(),
            rb.len(),
            0,
            from.as_mut_ptr(),
            (&mut from_len) as *mut u32 as *mut u8,
        );
        if n != 5 || &rb[..5] != b"hello" {
            log("AF_UNIX dgram recvfrom payload mismatch\n");
            sys_exit(1);
        }
        if from_len != 7 || from[0] != AF_UNIX as u8 || from[2] != 0 || &from[3..7] != b"pgcl" {
            log("AF_UNIX dgram sender address wrong\n");
            sys_exit(1);
        }
        if sys_sendto(
            srv as u64,
            b"ack".as_ptr(),
            3,
            0,
            from.as_ptr(),
            from_len as u64,
        ) != 3
        {
            log("AF_UNIX dgram reply failed\n");
            sys_exit(1);
        }
        let mut rb2 = [0u8; 16];
        let n2 = sys_recvfrom(
            cli as u64,
            rb2.as_mut_ptr(),
            rb2.len(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        if n2 != 3 || &rb2[..3] != b"ack" {
            log("AF_UNIX dgram reply mismatch\n");
            sys_exit(1);
        }
        sys_close(cli as u64);
        sys_close(srv as u64);
        log("AF_UNIX dgram + abstract names OK\n");
    }

    {
        let srv = sys_socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if srv < 0 {
            log("AF_INET6 socket failed\n");
            sys_exit(1);
        }
        let any6 = build_sockaddr_in6([0u8; 16], 9998);
        if sys_bind(srv as u64, any6.as_ptr(), 28) != 0 {
            log("v6 bind failed\n");
            sys_exit(1);
        }
        if sys_listen(srv as u64, 8) != 0 {
            log("v6 listen failed\n");
            sys_exit(1);
        }
        let mut nm = [0u8; 28];
        let mut nm_len: u32 = 28;
        if sys_getsockname(
            srv as u64,
            nm.as_mut_ptr(),
            (&mut nm_len) as *mut u32 as *mut u8,
        ) != 0
            || nm_len != 28
            || u16::from_le_bytes([nm[0], nm[1]]) != 10
            || u16::from_be_bytes([nm[2], nm[3]]) != 9998
        {
            log("v6 getsockname wrong\n");
            sys_exit(1);
        }
        let one: i32 = 1;
        if sys_setsockopt(srv as u64, 41, 26, &one as *const i32 as *const u8, 4) != 0 {
            log("v6 set V6ONLY failed\n");
            sys_exit(1);
        }
        let mut v6only: i32 = 0;
        let mut vlen: u32 = 4;
        if sys_getsockopt(
            srv as u64,
            41,
            26,
            &mut v6only as *mut i32 as *mut u8,
            (&mut vlen) as *mut u32 as *mut u8,
        ) != 0
            || v6only != 1
        {
            log("v6 V6ONLY getsockopt wrong\n");
            sys_exit(1);
        }
        let cli = sys_socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if cli < 0 {
            log("v6 client socket failed\n");
            sys_exit(1);
        }
        let mut lo6 = [0u8; 16];
        lo6[15] = 1;
        let dst = build_sockaddr_in6(lo6, 9998);
        let crc = sys_connect(cli as u64, dst.as_ptr(), 28);
        if crc != 0 && crc != EINPROGRESS {
            log("v6 connect failed\n");
            sys_exit(1);
        }
        let mut afd = -1i64;
        for _ in 0..100_000 {
            let r = sys_accept(srv as u64, core::ptr::null_mut(), core::ptr::null_mut());
            if r >= 0 {
                afd = r;
                break;
            }
            if r != -11 {
                log("v6 accept hard error\n");
                sys_exit(1);
            }
            let _ = sys_getpeername(cli as u64, core::ptr::null_mut(), core::ptr::null_mut());
        }
        if afd < 0 {
            log("v6 accept never completed\n");
            sys_exit(1);
        }
        if sys_write(afd as u64, b"v6pong".as_ptr(), 6) != 6 {
            log("v6 write failed\n");
            sys_exit(1);
        }
        let mut rb = [0u8; 8];
        let mut from = [0u8; 28];
        let mut from_len: u32 = 28;
        let mut got = 0i64;
        for _ in 0..100_000 {
            let r = sys_recvfrom(
                cli as u64,
                rb.as_mut_ptr(),
                rb.len(),
                0,
                from.as_mut_ptr(),
                (&mut from_len) as *mut u32 as *mut u8,
            );
            if r > 0 {
                got = r;
                break;
            }
            if r != -11 {
                log("v6 recv hard error\n");
                sys_exit(1);
            }
        }
        if got != 6 || &rb[..6] != b"v6pong" {
            log("v6 echo mismatch\n");
            sys_exit(1);
        }
        sys_close(afd as u64);
        sys_close(cli as u64);
        sys_close(srv as u64);
        log("IPv6 loopback TCP OK\n");
    }

    {
        const IPPROTO_ICMP: u64 = 1;
        let s = sys_socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_ICMP);
        if s < 0 {
            log("ICMP socket failed\n");
            sys_exit(1);
        }
        let mut pkt = [0u8; 16];
        pkt[0] = 8;
        pkt[4] = 0x12;
        pkt[5] = 0x34;
        pkt[7] = 1;
        for (i, b) in pkt.iter_mut().enumerate().skip(8) {
            *b = i as u8;
        }
        let csum = icmp_checksum(&pkt);
        pkt[2] = (csum >> 8) as u8;
        pkt[3] = (csum & 0xff) as u8;

        let dst = build_sockaddr_in([127, 0, 0, 1], 0);
        if sys_sendto(
            s as u64,
            pkt.as_ptr(),
            pkt.len(),
            0,
            dst.as_ptr(),
            dst.len() as u64,
        ) != pkt.len() as i64
        {
            log("ICMP sendto failed\n");
            sys_exit(1);
        }
        let mut rb = [0u8; 64];
        let mut got_reply = false;
        for _ in 0..200_000 {
            let r = sys_recvfrom(
                s as u64,
                rb.as_mut_ptr(),
                rb.len(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
            if r >= 8 {
                if rb[0] == 0 && rb[4] == 0x12 && rb[5] == 0x34 {
                    got_reply = true;
                    break;
                }
                continue;
            }
            if r != -11 {
                log("ICMP recv hard error\n");
                sys_exit(1);
            }
        }
        if !got_reply {
            log("ICMP echo reply not received\n");
            sys_exit(1);
        }
        sys_close(s as u64);
        log("ICMP echo (ping) loopback OK\n");
    }

    {
        let mut sv = [0i32; 2];
        if sys_socketpair(AF_UNIX, SOCK_STREAM, 0, sv.as_mut_ptr() as *mut u8) != 0 {
            log("SCM transport socketpair failed\n");
            sys_exit(1);
        }
        let a = sv[0] as u64;
        let b = sv[1] as u64;
        let mut pv = [0i32; 2];
        if sys_socketpair(AF_UNIX, SOCK_STREAM, 0, pv.as_mut_ptr() as *mut u8) != 0 {
            log("SCM payload socketpair failed\n");
            sys_exit(1);
        }
        let p0 = pv[0];
        let p1 = pv[1] as u64;

        let data = [0x5au8; 1];
        let iov = [data.as_ptr() as u64, 1u64];
        let mut control = [0u8; 24];
        control[0..8].copy_from_slice(&20u64.to_le_bytes());
        control[8..12].copy_from_slice(&1i32.to_le_bytes());
        control[12..16].copy_from_slice(&1i32.to_le_bytes());
        control[16..20].copy_from_slice(&p0.to_le_bytes());
        let mut mh = [0u8; 56];
        mh[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_le_bytes());
        mh[24..32].copy_from_slice(&1u64.to_le_bytes());
        mh[32..40].copy_from_slice(&(control.as_ptr() as u64).to_le_bytes());
        mh[40..48].copy_from_slice(&24u64.to_le_bytes());
        if sys_sendmsg(a, mh.as_ptr() as u64, 0) != 1 {
            log("SCM sendmsg failed\n");
            sys_exit(1);
        }

        let mut rdata = [0u8; 4];
        let riov = [rdata.as_mut_ptr() as u64, 4u64];
        let mut rcontrol = [0u8; 64];
        let mut rmh = [0u8; 56];
        rmh[16..24].copy_from_slice(&(riov.as_ptr() as u64).to_le_bytes());
        rmh[24..32].copy_from_slice(&1u64.to_le_bytes());
        rmh[32..40].copy_from_slice(&(rcontrol.as_mut_ptr() as u64).to_le_bytes());
        rmh[40..48].copy_from_slice(&64u64.to_le_bytes());
        if sys_recvmsg(b, rmh.as_mut_ptr() as u64, 0) != 1 || rdata[0] != 0x5a {
            log("SCM recvmsg data wrong\n");
            sys_exit(1);
        }
        let clen = u64::from_le_bytes(rmh[40..48].try_into().unwrap());
        if clen < 20 {
            log("SCM no control returned\n");
            sys_exit(1);
        }
        let rfd = i32::from_le_bytes(rcontrol[16..20].try_into().unwrap());
        if rfd < 0 {
            log("SCM received bad fd\n");
            sys_exit(1);
        }
        if sys_write(p1, b"OK".as_ptr(), 2) != 2 {
            log("SCM payload write failed\n");
            sys_exit(1);
        }
        let mut vbuf = [0u8; 4];
        if sys_read(rfd as u64, vbuf.as_mut_ptr(), vbuf.len()) != 2 || &vbuf[..2] != b"OK" {
            log("SCM passed-fd read-through wrong\n");
            sys_exit(1);
        }
        sys_close(a);
        sys_close(b);
        sys_close(p1);
        sys_close(p0 as u64);
        sys_close(rfd as u64);
        log("SCM_RIGHTS fd passing OK\n");
    }

    {
        const CLONE_NEWNET: u64 = 0x4000_0000;
        let mut sa = [0u8; 16];
        sa[0] = AF_UNIX as u8;
        sa[2] = 0;
        sa[3..7].copy_from_slice(b"nns0");
        let salen = 7u64;

        let host_srv = sys_socket(AF_UNIX, SOCK_STREAM, 0);
        if host_srv < 0
            || sys_bind(host_srv as u64, sa.as_ptr(), salen) != 0
            || sys_listen(host_srv as u64, 1) != 0
        {
            log("netns: host abstract bind/listen failed\n");
            sys_exit(1);
        }

        if sys_unshare(CLONE_NEWNET) != 0 {
            log("netns: unshare(CLONE_NEWNET) failed\n");
            sys_exit(1);
        }

        let c1 = sys_socket(AF_UNIX, SOCK_STREAM, 0);
        if c1 < 0 {
            log("netns: socket failed\n");
            sys_exit(1);
        }
        if sys_connect(c1 as u64, sa.as_ptr(), salen) == 0 {
            log("netns: connect crossed the namespace boundary\n");
            sys_exit(1);
        }
        sys_close(c1 as u64);

        let srv = sys_socket(AF_UNIX, SOCK_STREAM, 0);
        if srv < 0
            || sys_bind(srv as u64, sa.as_ptr(), salen) != 0
            || sys_listen(srv as u64, 1) != 0
        {
            log("netns: rebind in new namespace failed\n");
            sys_exit(1);
        }
        let c2 = sys_socket(AF_UNIX, SOCK_STREAM, 0);
        if c2 < 0 || sys_connect(c2 as u64, sa.as_ptr(), salen) != 0 {
            log("netns: intra-namespace connect failed\n");
            sys_exit(1);
        }
        sys_close(c2 as u64);
        sys_close(srv as u64);
        sys_close(host_srv as u64);
        log("net namespace isolation OK\n");
    }

    log("all networking tests OK\n");
    sys_exit(0);
}

#[inline(never)]
fn loopback_listener_regression() {
    let lsn = sys_socket(AF_INET, SOCK_STREAM, 0);
    if lsn < 0 {
        log("loopback listener socket failed\n");
        sys_exit(1);
    }
    let la = build_sockaddr_in([127, 0, 0, 1], 9997);
    if sys_bind(lsn as u64, la.as_ptr(), la.len() as u64) != 0 {
        log("loopback listener bind failed\n");
        sys_exit(1);
    }
    if sys_listen(lsn as u64, 8) != 0 {
        log("loopback listener listen failed\n");
        sys_exit(1);
    }
    sys_close(lsn as u64);
    log("loopback listener close (no accept) OK\n");

    let lsn = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if lsn < 0 {
        log("reuse listener socket failed\n");
        sys_exit(1);
    }
    let la = build_sockaddr_in([127, 0, 0, 1], 9996);
    if sys_bind(lsn as u64, la.as_ptr(), la.len() as u64) != 0 || sys_listen(lsn as u64, 8) != 0 {
        log("reuse listener bind/listen failed\n");
        sys_exit(1);
    }
    let c = sys_socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if c < 0 {
        log("reuse client socket failed\n");
        sys_exit(1);
    }
    let crc = sys_connect(c as u64, la.as_ptr(), la.len() as u64);
    if crc != 0 && crc != EINPROGRESS {
        log("reuse connect failed\n");
        sys_exit(1);
    }
    let mut conn = -1i64;
    for _ in 0..100_000 {
        let r = sys_accept(lsn as u64, core::ptr::null_mut(), core::ptr::null_mut());
        if r >= 0 {
            conn = r;
            break;
        }
        if r != EAGAIN {
            log("reuse accept hard error\n");
            sys_exit(1);
        }
        let _ = sys_getpeername(c as u64, core::ptr::null_mut(), core::ptr::null_mut());
    }
    if conn < 0 {
        log("reuse accept never completed\n");
        sys_exit(1);
    }
    let _ = so_error(c as u64);
    sys_close(conn as u64);
    let mut tbuf = [0u8; 4];
    let mut saw_teardown = false;
    for _ in 0..100_000 {
        let r = sys_read(c as u64, tbuf.as_mut_ptr(), tbuf.len());
        if r != EAGAIN && r <= 0 {
            saw_teardown = true;
            break;
        }
        let _ = sys_getpeername(c as u64, core::ptr::null_mut(), core::ptr::null_mut());
    }
    if !saw_teardown {
        log("client never saw RST teardown after server close\n");
        sys_exit(1);
    }
    log("close sends RST; peer observes teardown OK\n");
    sys_close(c as u64);
    sys_close(lsn as u64);
    let lsn2 = sys_socket(AF_INET, SOCK_STREAM, 0);
    let la2 = build_sockaddr_in([127, 0, 0, 1], 9995);
    if lsn2 < 0
        || sys_bind(lsn2 as u64, la2.as_ptr(), la2.len() as u64) != 0
        || sys_listen(lsn2 as u64, 8) != 0
    {
        log("reuse second listener failed\n");
        sys_exit(1);
    }
    sys_close(lsn2 as u64);
    log("loopback listener slot-reuse OK\n");
}

fn build_sockaddr_in(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&2u16.to_le_bytes());
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    sa[4..8].copy_from_slice(&ip);
    sa
}

fn build_sockaddr_in6(ip: [u8; 16], port: u16) -> [u8; 28] {
    let mut sa = [0u8; 28];
    sa[0..2].copy_from_slice(&10u16.to_le_bytes());
    sa[2..4].copy_from_slice(&port.to_be_bytes());
    sa[8..24].copy_from_slice(&ip);
    sa
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
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
fn sys_unshare(flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!("syscall", in("rax") 272u64, in("rdi") flags, lateout("rax") r, out("rcx") _, out("r11") _, options(nostack));
    }
    r
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
fn sys_sendmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    syscall!(46, fd, msg, flags)
}
fn sys_recvmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    syscall!(47, fd, msg, flags)
}
fn sys_setsockopt(fd: u64, level: u64, opt: u64, val: *const u8, len: u64) -> i64 {
    syscall!(54, fd, level, opt, val, len, 0u64)
}
fn sys_getsockopt(fd: u64, level: u64, opt: u64, val: *mut u8, len: *mut u8) -> i64 {
    syscall!(55, fd, level, opt, val, len, 0u64)
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
