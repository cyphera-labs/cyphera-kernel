use alloc::sync::Arc;

use crate::core as sched;
use crate::errno::{EAFNOSUPPORT, EBADF, EFAULT, EINVAL, ESOCKTNOSUPPORT};
use crate::vfs::{self, Inode, OpenFile, OpenFlags};

use super::fs::{READ_BUF_MAX, WRITE_BUF_MAX};
use super::util::fd_is_nonblock;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const AF_UNIX: u32 = 1;
const AF_NETLINK: u32 = 16;

fn inet_family(domain: u32) -> crate::net::inet::Family {
    if domain == AF_INET6 {
        crate::net::inet::Family::Inet6
    } else {
        crate::net::inet::Family::Inet
    }
}

const SOCK_RAW: u32 = 3;
const SOCK_SEQPACKET: u32 = 5;
const IPPROTO_ICMP: u32 = 1;
const IPPROTO_ICMPV6: u32 = 58;

pub(super) fn sys_socket(domain: u64, kind: u64, protocol: u64) -> i64 {
    let domain = domain as u32;
    let stype = (kind as u32) & 0xff;
    let proto = protocol as u32;
    let nonblock = kind & 0o4000 != 0;
    let cloexec = if kind & 0o2_000_000 != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    let inode: Arc<dyn Inode> = match (domain, stype) {
        (AF_INET | AF_INET6, crate::net::inet::SOCK_DGRAM | SOCK_RAW)
            if matches!(proto, IPPROTO_ICMP | IPPROTO_ICMPV6) =>
        {
            let s = match crate::net::icmp::IcmpSocket::new() {
                Ok(s) => s,
                Err(e) => return e.as_neg_i64(),
            };
            crate::net::icmp::register(&s);
            s
        }
        (AF_INET | AF_INET6, crate::net::inet::SOCK_DGRAM) => {
            let s = match crate::net::inet::InetSocket::new_udp(inet_family(domain)) {
                Ok(s) => s,
                Err(e) => return e.as_neg_i64(),
            };
            crate::net::inet::register(&s);
            s
        }
        (AF_INET | AF_INET6, crate::net::inet::SOCK_STREAM) => {
            let s = match crate::net::inet::InetSocket::new_tcp(inet_family(domain)) {
                Ok(s) => s,
                Err(e) => return e.as_neg_i64(),
            };
            crate::net::inet::register(&s);
            s
        }
        (AF_UNIX, crate::net::inet::SOCK_STREAM) => crate::net::unix::UnixSocket::new_unbound(),
        (AF_UNIX, SOCK_SEQPACKET) => crate::net::unix::UnixSocket::new_seqpacket(),
        (AF_UNIX, crate::net::inet::SOCK_DGRAM) => crate::net::unix::UnixSocket::new_dgram(),
        (AF_NETLINK, _) => crate::net::netlink::NetlinkSocket::new(proto as i32),
        _ => return EAFNOSUPPORT,
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

pub(super) fn sys_socketpair(domain: u64, kind: u64, _protocol: u64, sv: u64) -> i64 {
    if domain as u32 != AF_UNIX {
        return EAFNOSUPPORT;
    }
    let framed = match (kind & 0xf) as u32 {
        crate::net::inet::SOCK_STREAM => false,
        crate::net::inet::SOCK_DGRAM | SOCK_SEQPACKET => true,
        _ => return ESOCKTNOSUPPORT,
    };
    let mut flags = OpenFlags::RDWR;
    if kind & 0o4000 != 0 {
        flags |= OpenFlags::NONBLOCK;
    }
    let cloexec = if kind & 0o2_000_000 != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    let (a, b) = crate::net::unix::UnixEnd::pair(framed);
    let a_dyn: Arc<dyn Inode> = a;
    let b_dyn: Arc<dyn Inode> = b;
    let fa = Arc::new(OpenFile::new(a_dyn, flags));
    let fb = Arc::new(OpenFile::new(b_dyn, flags));
    let (fda, fdb) = sched::with_current_fds(|t| {
        let a = t.install_from(fa, 0, cloexec);
        let b = match a {
            Ok(_) => t.install_from(fb, 0, cloexec),
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
    if addrlen == 0 || addrlen > 128 {
        return Err(EINVAL);
    }
    let mut buf = alloc::vec![0u8; addrlen as usize];
    if frame::user::copy_from_user(addr, &mut buf).is_err() {
        return Err(EFAULT);
    }
    Ok(buf)
}

fn socket_from_fd(fd: u64) -> Result<Arc<OpenFile>, i64> {
    sched::with_current_fds(|t| t.get(fd as i32)).ok_or(crate::errno::ENOTSOCK)
}

pub(super) fn sys_bind(fd: u64, addr: u64, addrlen: u64) -> i64 {
    let buf = match read_sockaddr(addr, addrlen) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let file = match socket_from_fd(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    match file.inode.as_socket() {
        Some(s) => s.bind(&buf),
        None => crate::errno::ENOTSOCK,
    }
}

pub(super) fn sys_listen(fd: u64, backlog: u64) -> i64 {
    let file = match socket_from_fd(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    match file.inode.as_socket() {
        Some(s) => s.listen(backlog as i32),
        None => crate::errno::ENOTSOCK,
    }
}

pub(super) fn sys_accept(fd: u64, addr: u64, addrlen: u64) -> i64 {
    let file = match socket_from_fd(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let nonblock = fd_is_nonblock(fd as i32);
    let peer_out = if addr != 0 && addrlen != 0 {
        Some((addr, addrlen))
    } else {
        None
    };
    let new_inode = match file.inode.as_socket() {
        Some(s) => match s.accept(peer_out, nonblock) {
            Ok(i) => i,
            Err(e) => return e,
        },
        None => return crate::errno::ENOTSOCK,
    };
    let of = Arc::new(OpenFile::new_no_open(new_inode, OpenFlags::RDWR));
    match sched::with_current_fds(|t| t.install(of)) {
        Ok(fd) => fd as i64,
        Err(e) => e as i64,
    }
}

pub(super) fn sys_connect(fd: u64, addr: u64, addrlen: u64) -> i64 {
    let buf = match read_sockaddr(addr, addrlen) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let file = match socket_from_fd(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    match file.inode.as_socket() {
        Some(s) => s.connect(&buf, fd_is_nonblock(fd as i32)),
        None => crate::errno::ENOTSOCK,
    }
}

pub(super) fn sys_sendto(
    fd: u64,
    buf: u64,
    count: u64,
    flags: u64,
    addr: u64,
    addrlen: u64,
) -> i64 {
    let n = count as usize;
    if n == 0 {
        return 0;
    }
    let n = n.min(WRITE_BUF_MAX);
    let file = match socket_from_fd(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.inode.as_socket() {
        Some(s) => s,
        None => return crate::errno::ENOTSOCK,
    };
    let mut payload = alloc::vec![0u8; n];
    if frame::user::copy_from_user(buf, &mut payload).is_err() {
        return EFAULT;
    }
    let nonblock = fd_is_nonblock(fd as i32) || flags & MSG_DONTWAIT != 0;
    if addr != 0 && addrlen != 0 {
        let ab = match read_sockaddr(addr, addrlen) {
            Ok(b) => b,
            Err(e) => return e,
        };
        sock.send_to(&payload, Some(&ab), nonblock)
    } else {
        sock.send_to(&payload, None, nonblock)
    }
}

pub(super) fn sys_recvfrom(
    fd: u64,
    buf: u64,
    count: u64,
    flags: u64,
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
    let file = match socket_from_fd(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    let sock = match file.inode.as_socket() {
        Some(s) => s,
        None => return crate::errno::ENOTSOCK,
    };
    let mut tmp = alloc::vec![0u8; n];
    let nonblock = fd_is_nonblock(fd as i32) || flags & MSG_DONTWAIT != 0;
    let peer_out = if addr != 0 && addrlen_ptr != 0 {
        Some((addr, addrlen_ptr))
    } else {
        None
    };
    let r = sock.recv_from(&mut tmp, peer_out, nonblock);
    if r < 0 {
        return r;
    }
    let read = r as usize;
    if read > 0 && frame::user::copy_to_user(buf, &tmp[..read]).is_err() {
        return EFAULT;
    }
    r
}

const MSGHDR_SIZE: usize = 56;
const MH_NAMELEN: u64 = 8;
const MH_IOV: usize = 16;
const MH_IOVLEN: usize = 24;
const MH_CONTROL: usize = 32;
const MH_CONTROLLEN: u64 = 40;
const MH_FLAGS: u64 = 48;

const CMSG_HDR_LEN: usize = 16;
const SCM_SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const MSG_CTRUNC: u32 = 8;
const MSG_DONTWAIT: u64 = 0x40;
const SCM_CREDENTIALS: i32 = 2;
const UCRED_LEN: usize = 12;

fn parse_scm_rights(control: u64, controllen: u64) -> Result<alloc::vec::Vec<Arc<OpenFile>>, i64> {
    let mut out = alloc::vec::Vec::new();
    if control == 0 || controllen < CMSG_HDR_LEN as u64 {
        return Ok(out);
    }
    let mut chdr = [0u8; CMSG_HDR_LEN];
    if frame::user::copy_from_user(control, &mut chdr).is_err() {
        return Err(EFAULT);
    }
    let cmsg_len = u64::from_le_bytes(chdr[0..8].try_into().unwrap()) as usize;
    let level = i32::from_le_bytes(chdr[8..12].try_into().unwrap());
    let ctype = i32::from_le_bytes(chdr[12..16].try_into().unwrap());
    if level != SCM_SOL_SOCKET || ctype != SCM_RIGHTS {
        return Ok(out);
    }
    if cmsg_len < CMSG_HDR_LEN || cmsg_len as u64 > controllen {
        return Err(EINVAL);
    }
    let nfds = (cmsg_len - CMSG_HDR_LEN) / 4;
    for i in 0..nfds {
        let mut b = [0u8; 4];
        if frame::user::copy_from_user(control + CMSG_HDR_LEN as u64 + (i as u64) * 4, &mut b)
            .is_err()
        {
            return Err(EFAULT);
        }
        let fdnum = i32::from_le_bytes(b);
        match sched::with_current_fds(|t| t.get(fdnum)) {
            Some(of) => out.push(of),
            None => return Err(EBADF),
        }
    }
    Ok(out)
}

fn cmsg_align(n: usize) -> usize {
    (n + 7) & !7
}

fn push_cmsg(cbuf: &mut alloc::vec::Vec<u8>, ctype: i32, payload: &[u8]) {
    let pad = cmsg_align(cbuf.len());
    cbuf.resize(pad, 0);
    let cmsg_len = CMSG_HDR_LEN + payload.len();
    cbuf.extend_from_slice(&(cmsg_len as u64).to_le_bytes());
    cbuf.extend_from_slice(&SCM_SOL_SOCKET.to_le_bytes());
    cbuf.extend_from_slice(&ctype.to_le_bytes());
    cbuf.extend_from_slice(payload);
}

fn deliver_control(
    fds: alloc::vec::Vec<Arc<OpenFile>>,
    creds: Option<(i32, u32, u32)>,
    control: u64,
    controllen: u64,
) -> (u64, bool) {
    if fds.is_empty() && creds.is_none() {
        return (0, false);
    }
    if control == 0 {
        return (0, true);
    }
    let cap = controllen as usize;
    let mut cbuf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut truncated = false;

    if !fds.is_empty() {
        let need = cmsg_align(cbuf.len()) + CMSG_HDR_LEN + fds.len() * 4;
        if need > cap {
            truncated = true;
        } else {
            let mut ints: alloc::vec::Vec<i32> = alloc::vec::Vec::new();
            for of in fds {
                match sched::with_current_fds(|t| t.install(of)) {
                    Ok(fd) => ints.push(fd),
                    Err(_) => break,
                }
            }
            let mut payload: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(ints.len() * 4);
            for fd in &ints {
                payload.extend_from_slice(&fd.to_le_bytes());
            }
            push_cmsg(&mut cbuf, SCM_RIGHTS, &payload);
        }
    }

    if let Some((pid, uid, gid)) = creds {
        let mut payload = [0u8; UCRED_LEN];
        payload[0..4].copy_from_slice(&pid.to_le_bytes());
        payload[4..8].copy_from_slice(&uid.to_le_bytes());
        payload[8..12].copy_from_slice(&gid.to_le_bytes());
        let need = cmsg_align(cbuf.len()) + CMSG_HDR_LEN + UCRED_LEN;
        if need > cap {
            truncated = true;
        } else {
            push_cmsg(&mut cbuf, SCM_CREDENTIALS, &payload);
        }
    }

    if cbuf.is_empty() {
        return (0, truncated);
    }
    if frame::user::copy_to_user(control, &cbuf).is_err() {
        return (0, true);
    }
    (cbuf.len() as u64, truncated)
}

pub(super) fn sys_recvmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    let mut hdr = [0u8; MSGHDR_SIZE];
    if frame::user::copy_from_user(msg, &mut hdr).is_err() {
        return EFAULT;
    }
    let iov = u64::from_le_bytes(hdr[MH_IOV..MH_IOV + 8].try_into().unwrap());
    let iovlen = u64::from_le_bytes(hdr[MH_IOVLEN..MH_IOVLEN + 8].try_into().unwrap());
    let vecs = match super::fs::read_iovecs(iov, iovlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let total: usize = vecs
        .iter()
        .fold(0usize, |acc, (_, l)| acc.saturating_add(*l));
    if total == 0 {
        return 0;
    }
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let cap = total.min(READ_BUF_MAX);
    let mut tmp = alloc::vec![0u8; cap];
    let nonblock = fd_is_nonblock(fd as i32) || flags & MSG_DONTWAIT != 0;
    let (read, fds) = match file.inode.read_with_fds(&mut tmp, nonblock) {
        Ok(r) => r,
        Err(e) => return e.as_neg_i64(),
    };
    let mut off = 0usize;
    for (base, len) in &vecs {
        if off >= read {
            break;
        }
        let take = (*len).min(read - off);
        if take > 0 && frame::user::copy_to_user(*base, &tmp[off..off + take]).is_err() {
            return EFAULT;
        }
        off += take;
    }
    let control = u64::from_le_bytes(hdr[MH_CONTROL..MH_CONTROL + 8].try_into().unwrap());
    let controllen = u64::from_le_bytes(hdr[MH_CONTROL + 8..MH_CONTROL + 16].try_into().unwrap());
    let creds = file.inode.as_socket().and_then(|s| s.recv_creds());
    let src = file.inode.as_socket().and_then(|s| s.recv_src_addr());
    let (ctrl_len, ctrunc) = deliver_control(fds, creds, control, controllen);
    let name_ptr = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
    let name_cap = u32::from_le_bytes(
        hdr[MH_NAMELEN as usize..MH_NAMELEN as usize + 4]
            .try_into()
            .unwrap(),
    );
    let namelen = match &src {
        Some(a) if name_ptr != 0 && name_cap > 0 => {
            let n = a.len().min(name_cap as usize);
            let _ = frame::user::copy_to_user(name_ptr, &a[..n]);
            a.len() as u32
        }
        _ => 0u32,
    };
    let _ = frame::user::copy_to_user(msg + MH_NAMELEN, &namelen.to_le_bytes());
    let _ = frame::user::copy_to_user(msg + MH_CONTROLLEN, &ctrl_len.to_le_bytes());
    let flags = if ctrunc { MSG_CTRUNC } else { 0 };
    let _ = frame::user::copy_to_user(msg + MH_FLAGS, &flags.to_le_bytes());
    read as i64
}

pub(super) fn sys_sendmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    let mut hdr = [0u8; MSGHDR_SIZE];
    if frame::user::copy_from_user(msg, &mut hdr).is_err() {
        return EFAULT;
    }
    let iov = u64::from_le_bytes(hdr[MH_IOV..MH_IOV + 8].try_into().unwrap());
    let iovlen = u64::from_le_bytes(hdr[MH_IOVLEN..MH_IOVLEN + 8].try_into().unwrap());
    let vecs = match super::fs::read_iovecs(iov, iovlen) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let total: usize = vecs
        .iter()
        .fold(0usize, |acc, (_, l)| acc.saturating_add(*l));
    let control = u64::from_le_bytes(hdr[MH_CONTROL..MH_CONTROL + 8].try_into().unwrap());
    let controllen = u64::from_le_bytes(hdr[MH_CONTROL + 8..MH_CONTROL + 16].try_into().unwrap());
    let fds = match parse_scm_rights(control, controllen) {
        Ok(f) => f,
        Err(e) => return e,
    };
    if total == 0 && fds.is_empty() {
        return 0;
    }
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let cap = total.min(WRITE_BUF_MAX);
    let mut tmp = alloc::vec![0u8; cap];
    let mut off = 0usize;
    for (base, len) in &vecs {
        if off >= cap {
            break;
        }
        let take = (*len).min(cap - off);
        if take > 0 && frame::user::copy_from_user(*base, &mut tmp[off..off + take]).is_err() {
            return EFAULT;
        }
        off += take;
    }
    let nonblock = fd_is_nonblock(fd as i32) || flags & MSG_DONTWAIT != 0;
    let r = if fds.is_empty() {
        let wf = if nonblock {
            OpenFlags::NONBLOCK
        } else {
            OpenFlags::empty()
        };
        file.inode.write_at_with_flags(0, &tmp[..off], wf)
    } else {
        file.inode.write_with_fds(&tmp[..off], fds, nonblock)
    };
    match r {
        Ok(w) => w as i64,
        Err(e) => e.as_neg_i64(),
    }
}

pub(super) fn sys_shutdown(fd: u64, how: u64) -> i64 {
    let file = match socket_from_fd(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    match file.inode.as_socket() {
        Some(s) => s.shutdown(how as i32),
        None => crate::errno::ENOTSOCK,
    }
}

pub(super) fn sys_setsockopt(fd: u64, level: u64, opt: u64, optval: u64, optlen: u64) -> i64 {
    let file = match socket_from_fd(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    match file.inode.as_socket() {
        Some(s) => s.setsockopt(level as i32, opt as i32, optval, optlen),
        None => crate::errno::ENOTSOCK,
    }
}

pub(super) fn sys_getsockopt(fd: u64, level: u64, opt: u64, optval: u64, optlen_ptr: u64) -> i64 {
    let file = match socket_from_fd(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    match file.inode.as_socket() {
        Some(s) => s.getsockopt(level as i32, opt as i32, optval, optlen_ptr),
        None => crate::errno::ENOTSOCK,
    }
}

pub(super) fn sys_getsockname(fd: u64, addr: u64, addrlen_ptr: u64) -> i64 {
    let file = match socket_from_fd(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    match file.inode.as_socket() {
        Some(s) => s.getsockname(addr, addrlen_ptr),
        None => crate::errno::ENOTSOCK,
    }
}

pub(super) fn sys_getpeername(fd: u64, addr: u64, addrlen_ptr: u64) -> i64 {
    let file = match socket_from_fd(fd) {
        Ok(f) => f,
        Err(e) => return e,
    };
    match file.inode.as_socket() {
        Some(s) => s.getpeername(addr, addrlen_ptr),
        None => crate::errno::ENOTSOCK,
    }
}
