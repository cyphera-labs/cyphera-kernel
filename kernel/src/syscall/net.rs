use alloc::sync::Arc;

use crate::errno::{EFAULT, EINVAL, ENOTCONN};
use crate::sched;
use crate::vfs::{self, Inode, OpenFile, OpenFlags};

use super::fs::{READ_BUF_MAX, WRITE_BUF_MAX};
use super::util::{fd_is_nonblock, lookup_inet_from_fd};

const AF_INET: u32 = 2;
const AF_UNIX: u32 = 1;
const AF_NETLINK: u32 = 16;

pub(super) fn sys_socket(domain: u64, kind: u64, _protocol: u64) -> i64 {
    let domain = domain as u32;
    let stype = (kind as u32) & 0xff;
    let nonblock = kind & 0o4000 != 0;
    let cloexec = if kind & 0o2_000_000 != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    let inode: Arc<dyn Inode> = match (domain, stype) {
        (AF_INET, crate::net::inet::SOCK_DGRAM) => {
            let s = match crate::net::inet::InetSocket::new_udp() {
                Ok(s) => s,
                Err(e) => return e.errno(),
            };
            crate::net::inet::register(&s);
            s
        }
        (AF_INET, crate::net::inet::SOCK_STREAM) => {
            let s = match crate::net::inet::InetSocket::new_tcp() {
                Ok(s) => s,
                Err(e) => return e.errno(),
            };
            crate::net::inet::register(&s);
            s
        }
        (AF_NETLINK, _) => crate::net::netlink::NetlinkSocket::new(),
        _ => return -97,
    };
    let mut flags = OpenFlags::RDWR;
    if nonblock {
        flags |= OpenFlags::NONBLOCK;
    }
    let file = Arc::new(OpenFile::new(inode, flags));
    match sched::with_current_fds(|t| t.install_from(file, 0, cloexec)) {
        Ok(fd) => fd as i64,
        Err(e) => e as i64,
    }
}

pub(super) fn sys_socketpair(domain: u64, _kind: u64, _protocol: u64, sv: u64) -> i64 {
    if domain as u32 != AF_UNIX {
        return -97;
    }
    let (a, b) = crate::net::unix::UnixEnd::pair();
    let a_dyn: Arc<dyn Inode> = a;
    let b_dyn: Arc<dyn Inode> = b;
    let fa = Arc::new(OpenFile::new(a_dyn, OpenFlags::RDWR));
    let fb = Arc::new(OpenFile::new(b_dyn, OpenFlags::RDWR));
    let (fda, fdb) = sched::with_current_fds(|t| {
        let a = t.install(fa);
        let b = match a {
            Ok(_) => t.install(fb),
            Err(e) => Err(e),
        };
        (a, b)
    });
    let fda = match fda {
        Ok(f) => f,
        Err(e) => return e as i64,
    };
    let fdb = match fdb {
        Ok(f) => f,
        Err(e) => {
            sched::with_current_fds(|t| t.remove(fda));
            return e as i64;
        }
    };
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&fda.to_le_bytes());
    buf[4..8].copy_from_slice(&fdb.to_le_bytes());
    if frame::user::copy_to_user(sv, &buf).is_err() {
        sched::with_current_fds(|t| {
            t.remove(fda);
            t.remove(fdb);
        });
        return EFAULT;
    }
    0
}

fn read_sockaddr(addr: u64, addrlen: u64) -> Result<alloc::vec::Vec<u8>, i64> {
    if addrlen == 0 || addrlen > 64 {
        return Err(EINVAL);
    }
    let mut buf = alloc::vec![0u8; addrlen as usize];
    if frame::user::copy_from_user(addr, &mut buf).is_err() {
        return Err(EFAULT);
    }
    Ok(buf)
}

pub(super) fn sys_bind(fd: u64, addr: u64, addrlen: u64) -> i64 {
    let sock = match lookup_inet_from_fd(fd as i32) {
        Some(s) => s,
        None => return -88,
    };
    let buf = match read_sockaddr(addr, addrlen) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let ep = match crate::net::inet::parse_sockaddr_in(&buf) {
        Ok(e) => e,
        Err(e) => return e.errno(),
    };
    if ep.port != 0 && ep.port < 1024 {
        let allowed =
            sched::with_current_creds(|c| c.capable_host(crate::process::CAP_NET_BIND_SERVICE));
        if !allowed {
            return -13;
        }
    }
    let listen = smoltcp::wire::IpListenEndpoint {
        addr: if ep.addr.is_unspecified() {
            None
        } else {
            Some(ep.addr)
        },
        port: ep.port,
    };
    match sock.bind(listen) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_listen(fd: u64, backlog: u64) -> i64 {
    let sock = match lookup_inet_from_fd(fd as i32) {
        Some(s) => s,
        None => return -88,
    };
    match sock.listen(backlog as i32) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_accept(fd: u64, addr: u64, addrlen: u64) -> i64 {
    let sock = match lookup_inet_from_fd(fd as i32) {
        Some(s) => s,
        None => return -88,
    };
    let nonblock = fd_is_nonblock(fd as i32);
    let new_sock = loop {
        match sock.try_accept() {
            Ok(s) => break s,
            Err(crate::vfs::FsError::WouldBlock) => {
                if nonblock {
                    return crate::vfs::FsError::WouldBlock.errno();
                }
                sock.wait_queue().park();
                if sched::current_signal_pending() {
                    return crate::vfs::FsError::Interrupted.errno();
                }
            }
            Err(e) => return e.errno(),
        }
    };
    crate::net::inet::register(&new_sock);
    if addr != 0 && addrlen != 0 {
        if let Some(ep) = new_sock.peer_endpoint() {
            let mut cap = [0u8; 4];
            if frame::user::copy_from_user(addrlen, &mut cap).is_ok() {
                let cap = u32::from_le_bytes(cap) as usize;
                let mut ab = [0u8; 16];
                let full = crate::net::inet::write_sockaddr_in(&ep, &mut ab);
                let n = full.min(cap);
                let _ = frame::user::copy_to_user(addr, &ab[..n]);
                let _ = frame::user::copy_to_user(addrlen, &(full as u32).to_le_bytes());
            }
        }
    }
    let dyn_inode: Arc<dyn Inode> = new_sock;
    let of = Arc::new(OpenFile::new(dyn_inode, OpenFlags::RDWR));
    match sched::with_current_fds(|t| t.install(of)) {
        Ok(fd) => fd as i64,
        Err(e) => e as i64,
    }
}

pub(super) fn sys_connect(fd: u64, addr: u64, addrlen: u64) -> i64 {
    let sock = match lookup_inet_from_fd(fd as i32) {
        Some(s) => s,
        None => return -88,
    };
    let buf = match read_sockaddr(addr, addrlen) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let ep = match crate::net::inet::parse_sockaddr_in(&buf) {
        Ok(e) => e,
        Err(e) => return e.errno(),
    };
    match sock.connect(ep) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_sendto(
    fd: u64,
    buf: u64,
    count: u64,
    _flags: u64,
    addr: u64,
    addrlen: u64,
) -> i64 {
    let n = count as usize;
    if n == 0 {
        return 0;
    }
    let n = n.min(WRITE_BUF_MAX);
    let sock = match lookup_inet_from_fd(fd as i32) {
        Some(s) => s,
        None => return -88,
    };
    let mut payload = alloc::vec![0u8; n];
    if frame::user::copy_from_user(buf, &mut payload).is_err() {
        return EFAULT;
    }
    let peer = if addr != 0 && addrlen != 0 {
        let ab = match read_sockaddr(addr, addrlen) {
            Ok(b) => b,
            Err(e) => return e,
        };
        match crate::net::inet::parse_sockaddr_in(&ab) {
            Ok(e) => Some(e),
            Err(e) => return e.errno(),
        }
    } else {
        None
    };
    match sock.send_to(&payload, peer) {
        Ok(w) => w as i64,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_recvfrom(
    fd: u64,
    buf: u64,
    count: u64,
    _flags: u64,
    addr: u64,
    addrlen_ptr: u64,
) -> i64 {
    let n = count as usize;
    if n == 0 {
        return 0;
    }
    if n > READ_BUF_MAX {
        return EINVAL;
    }
    let sock = match lookup_inet_from_fd(fd as i32) {
        Some(s) => s,
        None => return -88,
    };
    let mut tmp = alloc::vec![0u8; n];
    let nonblock = fd_is_nonblock(fd as i32);
    let rcvtimeo_us = sock.opts.lock().rcvtimeo_us;
    let deadline = if !nonblock && rcvtimeo_us != 0 {
        Some(
            frame::cpu::clock::nanos_since_boot().saturating_add(rcvtimeo_us.saturating_mul(1_000)),
        )
    } else {
        None
    };
    let pid = sched::current_pid();
    let (read, peer) = loop {
        match sock.try_recv_from(&mut tmp[..]) {
            Ok(r) => {
                if deadline.is_some() {
                    let _ = crate::timeout::unregister(pid);
                }
                break r;
            }
            Err(crate::vfs::FsError::WouldBlock) => {
                if nonblock {
                    return crate::vfs::FsError::WouldBlock.errno();
                }
                if let Some(d) = deadline {
                    if frame::cpu::clock::nanos_since_boot() >= d {
                        let _ = crate::timeout::unregister(pid);
                        return crate::vfs::FsError::WouldBlock.errno();
                    }
                    crate::timeout::register(d, pid);
                }
                sock.wait_queue().park();
                sock.wait_queue().dequeue(pid);
                if sched::current_signal_pending() {
                    if deadline.is_some() {
                        let _ = crate::timeout::unregister(pid);
                    }
                    return crate::vfs::FsError::Interrupted.errno();
                }
            }
            Err(e) => {
                if deadline.is_some() {
                    let _ = crate::timeout::unregister(pid);
                }
                return e.errno();
            }
        }
    };
    if read > 0 && frame::user::copy_to_user(buf, &tmp[..read]).is_err() {
        return EFAULT;
    }
    if addr != 0 && addrlen_ptr != 0 {
        if let Some(ep) = peer {
            let mut ab = [0u8; 16];
            let len = crate::net::inet::write_sockaddr_in(&ep, &mut ab);
            let _ = frame::user::copy_to_user(addr, &ab[..len]);
            let len32: u32 = len as u32;
            let _ = frame::user::copy_to_user(addrlen_ptr, &len32.to_le_bytes());
        }
    }
    read as i64
}

pub(super) fn sys_shutdown(fd: u64, how: u64) -> i64 {
    let sock = match lookup_inet_from_fd(fd as i32) {
        Some(s) => s,
        None => return -88,
    };
    match sock.shutdown(how as i32) {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

const SOL_SOCKET: u64 = 1;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_IP: u64 = 0;

const SO_DEBUG: u64 = 1;
const SO_REUSEADDR: u64 = 2;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_DONTROUTE: u64 = 5;
const SO_BROADCAST: u64 = 6;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_KEEPALIVE: u64 = 9;
const SO_OOBINLINE: u64 = 10;
const SO_LINGER: u64 = 13;
const SO_REUSEPORT: u64 = 15;
const SO_RCVTIMEO: u64 = 20;
const SO_SNDTIMEO: u64 = 21;
const SO_DOMAIN: u64 = 39;
const SO_PROTOCOL: u64 = 38;

const TCP_NODELAY: u64 = 1;
const TCP_KEEPIDLE: u64 = 4;
const TCP_KEEPINTVL: u64 = 5;
const TCP_KEEPCNT: u64 = 6;

const IP_TTL: u64 = 2;
const IP_TOS: u64 = 1;
const IP_PKTINFO: u64 = 8;

pub(super) fn sys_setsockopt(fd: u64, level: u64, opt: u64, optval: u64, optlen: u64) -> i64 {
    let sock = match lookup_inet_from_fd(fd as i32) {
        Some(s) => s,
        None => return -88,
    };
    let read_int = || -> Result<i32, i64> {
        if optlen < 4 {
            return Err(EINVAL);
        }
        let mut buf = [0u8; 4];
        if frame::user::copy_from_user(optval, &mut buf).is_err() {
            return Err(EFAULT);
        }
        Ok(i32::from_le_bytes(buf))
    };
    let read_timeval_us = || -> Result<u64, i64> {
        if optlen < 16 {
            return Err(EINVAL);
        }
        let mut buf = [0u8; 16];
        if frame::user::copy_from_user(optval, &mut buf).is_err() {
            return Err(EFAULT);
        }
        let sec = i64::from_le_bytes(buf[0..8].try_into().unwrap()).max(0) as u64;
        let usec = i64::from_le_bytes(buf[8..16].try_into().unwrap()).max(0) as u64;
        Ok(sec.saturating_mul(1_000_000).saturating_add(usec))
    };

    match (level, opt) {
        (SOL_SOCKET, SO_REUSEADDR) => {
            let v = match read_int() {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.opts.lock().reuseaddr = v != 0;
            0
        }
        (SOL_SOCKET, SO_REUSEPORT) => {
            let v = match read_int() {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.opts.lock().reuseport = v != 0;
            0
        }
        (SOL_SOCKET, SO_KEEPALIVE) => {
            let v = match read_int() {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.opts.lock().keepalive = v != 0;
            if sock.is_tcp() {
                sock.apply_smoltcp_sockopt(
                    crate::net::inet::SmoltcpOpt::Keepalive,
                    if v != 0 { 1 } else { 0 },
                );
            }
            0
        }
        (SOL_SOCKET, SO_BROADCAST) => {
            let v = match read_int() {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.opts.lock().broadcast = v != 0;
            0
        }
        (SOL_SOCKET, SO_RCVBUF) => {
            let v = match read_int() {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.opts.lock().rcvbuf = (v.max(0) as u32).saturating_mul(2);
            0
        }
        (SOL_SOCKET, SO_SNDBUF) => {
            let v = match read_int() {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.opts.lock().sndbuf = (v.max(0) as u32).saturating_mul(2);
            0
        }
        (SOL_SOCKET, SO_RCVTIMEO) => {
            let us = match read_timeval_us() {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.opts.lock().rcvtimeo_us = us;
            0
        }
        (SOL_SOCKET, SO_SNDTIMEO) => {
            let us = match read_timeval_us() {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.opts.lock().sndtimeo_us = us;
            0
        }
        (SOL_SOCKET, SO_LINGER) => {
            if optlen < 8 {
                return EINVAL;
            }
            let mut buf = [0u8; 8];
            if frame::user::copy_from_user(optval, &mut buf).is_err() {
                return EFAULT;
            }
            let onoff = i32::from_le_bytes(buf[0..4].try_into().unwrap());
            let secs = i32::from_le_bytes(buf[4..8].try_into().unwrap()).max(0) as u32;
            let mut o = sock.opts.lock();
            o.linger_on = onoff != 0;
            o.linger_seconds = secs;
            0
        }
        (SOL_SOCKET, SO_DEBUG | SO_DONTROUTE | SO_OOBINLINE) => {
            let _ = read_int();
            0
        }
        (IPPROTO_TCP, TCP_NODELAY) => {
            if !sock.is_tcp() {
                return -92;
            }
            let v = match read_int() {
                Ok(v) => v,
                Err(e) => return e,
            };
            sock.opts.lock().nodelay = v != 0;
            sock.apply_smoltcp_sockopt(
                crate::net::inet::SmoltcpOpt::TcpNoDelay,
                if v != 0 { 1 } else { 0 },
            );
            0
        }
        (IPPROTO_TCP, TCP_KEEPIDLE | TCP_KEEPINTVL | TCP_KEEPCNT) => {
            let _ = read_int();
            0
        }
        (IPPROTO_IP, IP_TTL) => {
            let v = match read_int() {
                Ok(v) => v,
                Err(e) => return e,
            };
            let ttl = v.clamp(1, 255) as u8;
            sock.opts.lock().ip_ttl = ttl;
            if sock.is_tcp() {
                sock.apply_smoltcp_sockopt(crate::net::inet::SmoltcpOpt::HopLimit, ttl as u64);
            }
            0
        }
        (IPPROTO_IP, IP_TOS | IP_PKTINFO) => {
            let _ = read_int();
            0
        }
        _ => -92,
    }
}

pub(super) fn sys_getsockopt(fd: u64, level: u64, opt: u64, optval: u64, optlen_ptr: u64) -> i64 {
    let sock = match lookup_inet_from_fd(fd as i32) {
        Some(s) => s,
        None => return -88,
    };
    let mut user_len = [0u8; 4];
    if frame::user::copy_from_user(optlen_ptr, &mut user_len).is_err() {
        return EFAULT;
    }
    let mut user_len = u32::from_le_bytes(user_len) as usize;
    let write_int = |val: i32| -> i64 {
        if user_len < 4 {
            return EINVAL;
        }
        let bytes = val.to_le_bytes();
        if frame::user::copy_to_user(optval, &bytes).is_err() {
            return EFAULT;
        }
        if frame::user::copy_to_user(optlen_ptr, &4u32.to_le_bytes()).is_err() {
            return EFAULT;
        }
        0
    };
    let write_timeval = |us: u64| -> i64 {
        if user_len < 16 {
            return EINVAL;
        }
        let mut buf = [0u8; 16];
        let sec = (us / 1_000_000) as i64;
        let usec = (us % 1_000_000) as i64;
        buf[0..8].copy_from_slice(&sec.to_le_bytes());
        buf[8..16].copy_from_slice(&usec.to_le_bytes());
        if frame::user::copy_to_user(optval, &buf).is_err() {
            return EFAULT;
        }
        if frame::user::copy_to_user(optlen_ptr, &16u32.to_le_bytes()).is_err() {
            return EFAULT;
        }
        0
    };

    let opts = *sock.opts.lock();
    match (level, opt) {
        (SOL_SOCKET, SO_TYPE) => write_int(sock.sock_type() as i32),
        (SOL_SOCKET, SO_PROTOCOL) => write_int(sock.proto() as i32),
        (SOL_SOCKET, SO_DOMAIN) => write_int(2),
        (SOL_SOCKET, SO_ERROR) => write_int(sock.take_so_error() as i32),
        (SOL_SOCKET, SO_REUSEADDR) => write_int(opts.reuseaddr as i32),
        (SOL_SOCKET, SO_REUSEPORT) => write_int(opts.reuseport as i32),
        (SOL_SOCKET, SO_KEEPALIVE) => write_int(opts.keepalive as i32),
        (SOL_SOCKET, SO_BROADCAST) => write_int(opts.broadcast as i32),
        (SOL_SOCKET, SO_RCVBUF) => write_int(opts.rcvbuf as i32),
        (SOL_SOCKET, SO_SNDBUF) => write_int(opts.sndbuf as i32),
        (SOL_SOCKET, SO_RCVTIMEO) => write_timeval(opts.rcvtimeo_us),
        (SOL_SOCKET, SO_SNDTIMEO) => write_timeval(opts.sndtimeo_us),
        (SOL_SOCKET, SO_LINGER) => {
            if user_len < 8 {
                return EINVAL;
            }
            let mut buf = [0u8; 8];
            buf[0..4].copy_from_slice(&(opts.linger_on as i32).to_le_bytes());
            buf[4..8].copy_from_slice(&(opts.linger_seconds as i32).to_le_bytes());
            if frame::user::copy_to_user(optval, &buf).is_err() {
                return EFAULT;
            }
            if frame::user::copy_to_user(optlen_ptr, &8u32.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        (SOL_SOCKET, SO_DEBUG | SO_DONTROUTE | SO_OOBINLINE) => write_int(0),
        (IPPROTO_TCP, TCP_NODELAY) => write_int(opts.nodelay as i32),
        (IPPROTO_TCP, TCP_KEEPIDLE) => write_int(60),
        (IPPROTO_TCP, TCP_KEEPINTVL) => write_int(60),
        (IPPROTO_TCP, TCP_KEEPCNT) => write_int(9),
        (IPPROTO_IP, IP_TTL) => write_int(opts.ip_ttl as i32),
        (IPPROTO_IP, IP_TOS) => write_int(0),
        _ => {
            user_len = user_len.min(4);
            let zeroes = [0u8; 4];
            let _ = frame::user::copy_to_user(optval, &zeroes[..user_len]);
            -92
        }
    }
}

fn copy_sockaddr_to_user(ep: &smoltcp::wire::IpEndpoint, addr: u64, addrlen_ptr: u64) -> i64 {
    if addr == 0 || addrlen_ptr == 0 {
        return EFAULT;
    }
    let mut cap = [0u8; 4];
    if frame::user::copy_from_user(addrlen_ptr, &mut cap).is_err() {
        return EFAULT;
    }
    let cap = u32::from_le_bytes(cap) as usize;
    let mut ab = [0u8; 16];
    let full = crate::net::inet::write_sockaddr_in(ep, &mut ab);
    let n = full.min(cap);
    if n > 0 && frame::user::copy_to_user(addr, &ab[..n]).is_err() {
        return EFAULT;
    }
    let full32 = full as u32;
    if frame::user::copy_to_user(addrlen_ptr, &full32.to_le_bytes()).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_getsockname(fd: u64, addr: u64, addrlen_ptr: u64) -> i64 {
    let sock = match lookup_inet_from_fd(fd as i32) {
        Some(s) => s,
        None => return -88,
    };
    let ep = sock.local_name();
    copy_sockaddr_to_user(&ep, addr, addrlen_ptr)
}

pub(super) fn sys_getpeername(fd: u64, addr: u64, addrlen_ptr: u64) -> i64 {
    let sock = match lookup_inet_from_fd(fd as i32) {
        Some(s) => s,
        None => return -88,
    };
    let ep = match sock.peer_endpoint() {
        Some(ep) => ep,
        None => return ENOTCONN,
    };
    copy_sockaddr_to_user(&ep, addr, addrlen_ptr)
}
