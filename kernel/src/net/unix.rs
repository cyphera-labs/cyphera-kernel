extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use frame::sync::SpinIrq;

use cyphera_kapi::{Errno, KResult};

use crate::core::wait::WaitQueue;
use crate::vfs::{Inode, InodeKind, OpenFile, OpenFlags, Stat};

const UNIX_CAPACITY: usize = 64 * 1024;

fn current_ucred() -> (i32, u32, u32) {
    let pid = crate::core::current_tgid().raw() as i32;
    let (uid, gid) = crate::core::with_current_creds(|c| (c.euid, c.egid));
    (pid, uid, gid)
}

type FdBatch = (usize, alloc::vec::Vec<Arc<OpenFile>>);

struct Ring {
    buf: VecDeque<u8>,
    readers: u32,
    writers: u32,
    written: usize,
    read: usize,
    fds: VecDeque<FdBatch>,
    bounds: VecDeque<usize>,
    writer_creds: Option<(i32, u32, u32)>,
}

struct Channel {
    ring: SpinIrq<Ring>,
    read_waiters: WaitQueue,
    write_waiters: WaitQueue,
    framed: bool,
    rd_closed: AtomicBool,
}

impl Ring {
    fn read_into(&mut self, framed: bool, buf: &mut [u8]) -> usize {
        if framed {
            let msg_len = match self.bounds.pop_front() {
                Some(l) => l,
                None => return 0,
            };
            let copy = msg_len.min(buf.len());
            for slot in buf.iter_mut().take(copy) {
                *slot = self.buf.pop_front().unwrap_or(0);
            }
            for _ in copy..msg_len {
                self.buf.pop_front();
            }
            self.read += msg_len;
            copy
        } else {
            let mut n = 0;
            while n < buf.len() {
                match self.buf.pop_front() {
                    Some(b) => {
                        buf[n] = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            self.read += n;
            n
        }
    }

    fn write_from(&mut self, framed: bool, buf: &[u8]) -> Option<usize> {
        let room = UNIX_CAPACITY.saturating_sub(self.buf.len());
        if framed {
            if buf.len() > room {
                return None;
            }
            self.buf.extend(buf.iter().copied());
            self.bounds.push_back(buf.len());
            self.written += buf.len();
            self.writer_creds = Some(current_ucred());
            Some(buf.len())
        } else {
            if room == 0 {
                return None;
            }
            let n = buf.len().min(room);
            self.buf.extend(buf[..n].iter().copied());
            self.written += n;
            self.writer_creds = Some(current_ucred());
            Some(n)
        }
    }

    fn has_unit(&self, framed: bool) -> bool {
        if framed {
            !self.bounds.is_empty()
        } else {
            !self.buf.is_empty()
        }
    }
}

pub struct UnixEnd {
    inbox: Arc<Channel>,
    peer_inbox: Arc<Channel>,
    passcred: AtomicBool,
}

impl UnixEnd {
    pub fn pair(framed: bool) -> (Arc<Self>, Arc<Self>) {
        let a_chan = Arc::new(Channel {
            ring: SpinIrq::new(Ring {
                buf: VecDeque::with_capacity(UNIX_CAPACITY),
                readers: 0,
                writers: 0,
                written: 0,
                read: 0,
                fds: VecDeque::new(),
                bounds: VecDeque::new(),
                writer_creds: None,
            }),
            read_waiters: WaitQueue::new(),
            write_waiters: WaitQueue::new(),
            framed,
            rd_closed: AtomicBool::new(false),
        });
        let b_chan = Arc::new(Channel {
            ring: SpinIrq::new(Ring {
                buf: VecDeque::with_capacity(UNIX_CAPACITY),
                readers: 0,
                writers: 0,
                written: 0,
                read: 0,
                fds: VecDeque::new(),
                bounds: VecDeque::new(),
                writer_creds: None,
            }),
            read_waiters: WaitQueue::new(),
            write_waiters: WaitQueue::new(),
            framed,
            rd_closed: AtomicBool::new(false),
        });
        let a = Arc::new(Self {
            inbox: a_chan.clone(),
            peer_inbox: b_chan.clone(),
            passcred: AtomicBool::new(false),
        });
        let b = Arc::new(Self {
            inbox: b_chan,
            peer_inbox: a_chan,
            passcred: AtomicBool::new(false),
        });
        (a, b)
    }
}

impl Inode for UnixEnd {
    fn kind(&self) -> InodeKind {
        InodeKind::Pipe
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Pipe, 0, 0o600)
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(&self, _off: u64, buf: &mut [u8], flags: OpenFlags) -> KResult<usize> {
        let nonblock = flags.contains(OpenFlags::NONBLOCK);
        crate::vfs::blocking::block_io(
            "unix_read",
            &self.inbox.read_waiters,
            nonblock,
            None,
            || {
                if self.inbox.rd_closed.load(Ordering::Relaxed) {
                    return crate::vfs::blocking::IoAttempt::Ready(0);
                }
                let mut s = self.inbox.ring.lock();
                let framed = self.inbox.framed;
                if s.has_unit(framed) {
                    let n = s.read_into(framed, buf);
                    while matches!(s.fds.front(), Some((pos, _)) if *pos < s.read) {
                        s.fds.pop_front();
                    }
                    drop(s);
                    self.inbox.write_waiters.wake_one();
                    crate::vfs::blocking::IoAttempt::Ready(n)
                } else if s.writers == 0 {
                    crate::vfs::blocking::IoAttempt::Ready(0)
                } else {
                    crate::vfs::blocking::IoAttempt::WouldBlock
                }
            },
        )
    }

    fn write_at(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn write_at_with_flags(&self, _off: u64, buf: &[u8], flags: OpenFlags) -> KResult<usize> {
        use crate::vfs::blocking::IoAttempt;
        let nonblock = flags.contains(OpenFlags::NONBLOCK);
        crate::vfs::blocking::block_io(
            "unix_write",
            &self.peer_inbox.write_waiters,
            nonblock,
            None,
            || {
                if self.peer_inbox.rd_closed.load(Ordering::Relaxed) {
                    return IoAttempt::Err(Errno::PIPE);
                }
                let mut s = self.peer_inbox.ring.lock();
                if s.readers == 0 {
                    return IoAttempt::Err(Errno::PIPE);
                }
                let framed = self.peer_inbox.framed;
                match s.write_from(framed, buf) {
                    Some(n) => {
                        drop(s);
                        self.peer_inbox.read_waiters.wake_one();
                        IoAttempt::Ready(n)
                    }
                    None => IoAttempt::WouldBlock,
                }
            },
        )
    }

    fn write_with_fds(
        &self,
        buf: &[u8],
        mut fds: Vec<Arc<OpenFile>>,
        nonblock: bool,
    ) -> KResult<usize> {
        use crate::vfs::blocking::IoAttempt;
        crate::vfs::blocking::block_io(
            "unix_write_fds",
            &self.peer_inbox.write_waiters,
            nonblock,
            None,
            || {
                if self.peer_inbox.rd_closed.load(Ordering::Relaxed) {
                    return IoAttempt::Err(Errno::PIPE);
                }
                let mut s = self.peer_inbox.ring.lock();
                if s.readers == 0 {
                    return IoAttempt::Err(Errno::PIPE);
                }
                let framed = self.peer_inbox.framed;
                let pos = s.written;
                match s.write_from(framed, buf) {
                    Some(n) => {
                        if !fds.is_empty() {
                            s.fds.push_back((pos, core::mem::take(&mut fds)));
                        }
                        drop(s);
                        self.peer_inbox.read_waiters.wake_one();
                        IoAttempt::Ready(n)
                    }
                    None => IoAttempt::WouldBlock,
                }
            },
        )
    }

    fn read_with_fds(
        &self,
        buf: &mut [u8],
        nonblock: bool,
    ) -> KResult<(usize, Vec<Arc<OpenFile>>)> {
        use crate::vfs::blocking::IoAttempt;
        crate::vfs::blocking::block_io(
            "unix_recvmsg",
            &self.inbox.read_waiters,
            nonblock,
            None,
            || {
                if self.inbox.rd_closed.load(Ordering::Relaxed) {
                    return IoAttempt::Ready((0, Vec::new()));
                }
                let mut s = self.inbox.ring.lock();
                let framed = self.inbox.framed;
                if s.has_unit(framed) {
                    let n = s.read_into(framed, buf);
                    let fds = match s.fds.front() {
                        Some((pos, _)) if *pos < s.read => {
                            s.fds.pop_front().map(|(_, f)| f).unwrap_or_default()
                        }
                        _ => Vec::new(),
                    };
                    drop(s);
                    self.inbox.write_waiters.wake_one();
                    IoAttempt::Ready((n, fds))
                } else if s.writers == 0 {
                    IoAttempt::Ready((0, Vec::new()))
                } else {
                    IoAttempt::WouldBlock
                }
            },
        )
    }

    fn poll(&self) -> crate::vfs::PollMask {
        use crate::vfs::PollMask;
        let inbox = self.inbox.ring.lock();
        let peer = self.peer_inbox.ring.lock();
        let rd_closed = self.inbox.rd_closed.load(Ordering::Relaxed);
        let wr_closed = self.peer_inbox.rd_closed.load(Ordering::Relaxed);
        let mut m = PollMask::empty();
        if rd_closed || inbox.has_unit(self.inbox.framed) || inbox.writers == 0 {
            m |= PollMask::IN;
        }
        if wr_closed || peer.buf.len() < UNIX_CAPACITY || peer.readers == 0 {
            m |= PollMask::OUT;
        }
        if inbox.writers == 0 && inbox.buf.is_empty() {
            m |= PollMask::HUP;
        }
        m
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&self.inbox.read_waiters);
        f(&self.peer_inbox.write_waiters);
    }

    fn as_socket(&self) -> Option<&dyn super::Socket> {
        Some(self)
    }

    fn on_open(&self, flags: OpenFlags) {
        if flags.is_readable() {
            self.inbox.ring.lock().readers += 1;
        }
        if flags.is_writable() {
            self.peer_inbox.ring.lock().writers += 1;
        }
    }
    fn on_close(&self, flags: OpenFlags) {
        if flags.is_readable() {
            let mut s = self.inbox.ring.lock();
            s.readers = s.readers.saturating_sub(1);
            let last = s.readers == 0;
            drop(s);
            if last {
                self.inbox.write_waiters.wake_all();
            }
        }
        if flags.is_writable() {
            let mut s = self.peer_inbox.ring.lock();
            s.writers = s.writers.saturating_sub(1);
            let last = s.writers == 0;
            drop(s);
            if last {
                self.peer_inbox.read_waiters.wake_all();
            }
        }
    }
}

impl UnixEnd {
    fn shutdown_dirs(&self, how: i32) -> i64 {
        const SHUT_RD: i32 = 0;
        const SHUT_WR: i32 = 1;
        const SHUT_RDWR: i32 = 2;
        if !matches!(how, SHUT_RD | SHUT_WR | SHUT_RDWR) {
            return crate::errno::EINVAL;
        }
        if how == SHUT_RD || how == SHUT_RDWR {
            self.inbox.rd_closed.store(true, Ordering::Relaxed);
            self.inbox.read_waiters.wake_all();
        }
        if how == SHUT_WR || how == SHUT_RDWR {
            self.peer_inbox.rd_closed.store(true, Ordering::Relaxed);
            self.peer_inbox.read_waiters.wake_all();
            self.inbox.write_waiters.wake_all();
        }
        0
    }
}

impl super::Socket for UnixEnd {
    fn shutdown(&self, how: i32) -> i64 {
        self.shutdown_dirs(how)
    }

    fn setsockopt(&self, level: i32, opt: i32, _optval: u64, _optlen: u64) -> i64 {
        const SOL_SOCKET: i32 = 1;
        const SO_PASSCRED: i32 = 16;
        if level == SOL_SOCKET && opt == SO_PASSCRED {
            self.passcred.store(true, Ordering::Relaxed);
        }
        0
    }

    fn recv_creds(&self) -> Option<(i32, u32, u32)> {
        if self.passcred.load(Ordering::Relaxed) {
            self.inbox.ring.lock().writer_creds
        } else {
            None
        }
    }
}

const AF_UNIX: u32 = 1;

fn parse_sockaddr_un(buf: &[u8]) -> Result<String, i64> {
    if buf.len() < 2 {
        return Err(crate::errno::EINVAL);
    }
    let family = u16::from_le_bytes([buf[0], buf[1]]) as u32;
    if family != AF_UNIX {
        return Err(crate::errno::EINVAL);
    }
    let path = &buf[2..];
    if !path.is_empty() && path[0] == 0 {
        let mut s = String::from("\0");
        s.push_str(&String::from_utf8_lossy(&path[1..]));
        return Ok(s);
    }
    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    if end == 0 {
        return Err(crate::errno::EINVAL);
    }
    Ok(String::from_utf8_lossy(&path[..end]).into_owned())
}

fn write_sockaddr_un(path: Option<&str>, addr: u64, addrlen_ptr: u64) {
    if addr == 0 || addrlen_ptr == 0 {
        return;
    }
    let mut cap = [0u8; 4];
    if frame::user::copy_from_user(addrlen_ptr, &mut cap).is_err() {
        return;
    }
    let cap = u32::from_le_bytes(cap) as usize;
    let mut sa = alloc::vec::Vec::with_capacity(16);
    sa.extend_from_slice(&(AF_UNIX as u16).to_le_bytes());
    match path {
        Some(p) if p.starts_with('\0') => {
            sa.push(0);
            sa.extend_from_slice(&p.as_bytes()[1..]);
        }
        Some(p) => {
            sa.extend_from_slice(p.as_bytes());
            sa.push(0);
        }
        None => {}
    }
    let full = sa.len();
    let n = full.min(cap);
    let _ = frame::user::copy_to_user(addr, &sa[..n]);
    let _ = frame::user::copy_to_user(addrlen_ptr, &(full as u32).to_le_bytes());
}

enum SockState {
    Unbound,
    Listening {
        backlog: VecDeque<Arc<UnixEnd>>,
        cap: usize,
    },
    Connected(Arc<UnixEnd>),
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum UnixKind {
    Stream,
    Seqpacket,
    Dgram,
}

const DGRAM_QUEUE_BYTES: usize = 256 * 1024;

type Datagram = (Option<String>, alloc::vec::Vec<u8>);

pub struct UnixSocket {
    me: Weak<Self>,
    ns: Arc<crate::net::NetNamespace>,
    kind: UnixKind,
    state: SpinIrq<SockState>,
    bound_path: SpinIrq<Option<String>>,
    accept_waiters: WaitQueue,
    dgram_rx: SpinIrq<VecDeque<Datagram>>,
    dgram_bytes: SpinIrq<usize>,
    dgram_waiters: WaitQueue,
    dgram_peer: SpinIrq<Option<String>>,
    passcred: AtomicBool,
}

impl UnixSocket {
    fn new(kind: UnixKind) -> Arc<Self> {
        let ns = crate::core::current_net_ns();
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            ns,
            kind,
            state: SpinIrq::new(SockState::Unbound),
            bound_path: SpinIrq::new(None),
            accept_waiters: WaitQueue::new(),
            dgram_rx: SpinIrq::new(VecDeque::new()),
            dgram_bytes: SpinIrq::new(0),
            dgram_waiters: WaitQueue::new(),
            dgram_peer: SpinIrq::new(None),
            passcred: AtomicBool::new(false),
        })
    }

    pub fn new_unbound() -> Arc<Self> {
        Self::new(UnixKind::Stream)
    }

    pub fn new_seqpacket() -> Arc<Self> {
        Self::new(UnixKind::Seqpacket)
    }

    pub fn new_dgram() -> Arc<Self> {
        Self::new(UnixKind::Dgram)
    }

    fn is_stream_like(&self) -> bool {
        matches!(self.kind, UnixKind::Stream | UnixKind::Seqpacket)
    }

    fn rendezvous_insert(&self, path: &str) -> Result<(), i64> {
        let taken = if path.starts_with('\0') {
            !self.ns.try_bind_abstract(path.into(), self.me.clone())
        } else {
            !self.ns.try_bind_fs(path.into(), self.me.clone())
        };
        if taken {
            Err(crate::errno::EADDRINUSE)
        } else {
            Ok(())
        }
    }

    fn rendezvous_lookup(&self, path: &str) -> Option<Arc<UnixSocket>> {
        if path.starts_with('\0') {
            self.ns.lookup_abstract(path)
        } else {
            self.ns.lookup_fs(path)
        }
    }

    fn rendezvous_remove(&self, path: &str) {
        if path.starts_with('\0') {
            self.ns.unbind_abstract(path);
        } else {
            self.ns.unbind_fs(path);
        }
    }

    fn dgram_send_to(&self, buf: &[u8], dest: &str) -> i64 {
        let target = match self.rendezvous_lookup(dest) {
            Some(t) => t,
            None => return crate::errno::ECONNREFUSED,
        };
        if target.kind != UnixKind::Dgram {
            return crate::errno::ECONNREFUSED;
        }
        {
            let mut bytes = target.dgram_bytes.lock();
            if *bytes + buf.len() > DGRAM_QUEUE_BYTES {
                return crate::errno::EAGAIN;
            }
            *bytes += buf.len();
        }
        let sender = self.bound_path.lock().clone();
        target.dgram_rx.lock().push_back((sender, buf.to_vec()));
        target.dgram_waiters.wake_one();
        buf.len() as i64
    }

    fn dgram_recv_from(&self, buf: &mut [u8], peer_out: Option<(u64, u64)>, nonblock: bool) -> i64 {
        use crate::vfs::blocking::IoAttempt;
        let got = crate::vfs::blocking::block_io::<Datagram>(
            "unix_dgram_recv",
            &self.dgram_waiters,
            nonblock,
            None,
            || {
                if let Some(d) = self.dgram_rx.lock().pop_front() {
                    *self.dgram_bytes.lock() -= d.1.len();
                    IoAttempt::Ready(d)
                } else {
                    IoAttempt::WouldBlock
                }
            },
        );
        let (sender, payload) = match got {
            Ok(d) => d,
            Err(Errno::AGAIN) => return crate::errno::EAGAIN,
            Err(Errno::INTR) => return crate::errno::EINTR,
            Err(e) => return e.as_neg_i64(),
        };
        let n = payload.len().min(buf.len());
        buf[..n].copy_from_slice(&payload[..n]);
        if let Some((addr, addrlen)) = peer_out {
            write_sockaddr_un(sender.as_deref(), addr, addrlen);
        }
        n as i64
    }

    fn bind_path(&self, path: String) -> Result<(), i64> {
        let mut bp = self.bound_path.lock();
        if bp.is_some() {
            return Err(crate::errno::EINVAL);
        }
        self.rendezvous_insert(&path)?;
        *bp = Some(path);
        Ok(())
    }

    fn do_listen(&self, backlog: i32) -> Result<(), i64> {
        if self.bound_path.lock().is_none() {
            return Err(crate::errno::EINVAL);
        }
        let cap = (backlog.max(1) as usize).min(128);
        let mut st = self.state.lock();
        match &mut *st {
            SockState::Connected(_) => Err(crate::errno::EINVAL),
            SockState::Listening { cap: c, .. } => {
                *c = cap;
                Ok(())
            }
            SockState::Unbound => {
                *st = SockState::Listening {
                    backlog: VecDeque::new(),
                    cap,
                };
                Ok(())
            }
        }
    }

    pub fn try_accept(&self) -> KResult<Arc<UnixEnd>> {
        let mut st = self.state.lock();
        match &mut *st {
            SockState::Listening { backlog, .. } => backlog.pop_front().ok_or(Errno::AGAIN),
            _ => Err(Errno::INVAL),
        }
    }

    fn connect_path(&self, path: &str) -> Result<(), i64> {
        let listener = match self.rendezvous_lookup(path) {
            Some(l) => l,
            None => return Err(crate::errno::ECONNREFUSED),
        };
        if core::ptr::eq(self as *const _, Arc::as_ptr(&listener)) {
            return Err(crate::errno::ECONNREFUSED);
        }
        let framed = self.kind == UnixKind::Seqpacket;
        let (server, client) = UnixEnd::pair(framed);
        client.on_open(OpenFlags::RDWR);
        server.on_open(OpenFlags::RDWR);
        let mut st = self.state.lock();
        if matches!(&*st, SockState::Connected(_)) {
            drop(st);
            client.on_close(OpenFlags::RDWR);
            server.on_close(OpenFlags::RDWR);
            return Err(crate::errno::EISCONN);
        }
        {
            let mut lst = listener.state.lock();
            let refused = match &mut *lst {
                SockState::Listening { backlog, cap } if backlog.len() < *cap => {
                    backlog.push_back(server.clone());
                    false
                }
                _ => true,
            };
            if refused {
                drop(lst);
                drop(st);
                client.on_close(OpenFlags::RDWR);
                server.on_close(OpenFlags::RDWR);
                return Err(crate::errno::ECONNREFUSED);
            }
        }
        if self.passcred.load(Ordering::Relaxed) {
            client.passcred.store(true, Ordering::Relaxed);
        }
        *st = SockState::Connected(client);
        drop(st);
        listener.accept_waiters.wake_one();
        Ok(())
    }

    fn connected_end(&self) -> Option<Arc<UnixEnd>> {
        match &*self.state.lock() {
            SockState::Connected(end) => Some(end.clone()),
            _ => None,
        }
    }
}

impl Inode for UnixSocket {
    fn kind(&self) -> InodeKind {
        InodeKind::Pipe
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Pipe, 0, 0o600)
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(&self, off: u64, buf: &mut [u8], flags: OpenFlags) -> KResult<usize> {
        let nonblock = flags.contains(OpenFlags::NONBLOCK);
        if self.kind == UnixKind::Dgram {
            let r = self.dgram_recv_from(buf, None, nonblock);
            return match r {
                r if r >= 0 => Ok(r as usize),
                e if e == crate::errno::EINTR => Err(Errno::INTR),
                e if e == crate::errno::EAGAIN => Err(Errno::AGAIN),
                _ => Err(Errno::IO),
            };
        }
        match self.connected_end() {
            Some(end) => end.read_at_with_flags(off, buf, flags),
            None => Err(Errno::INVAL),
        }
    }

    fn write_at(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn write_at_with_flags(&self, off: u64, buf: &[u8], flags: OpenFlags) -> KResult<usize> {
        if self.kind == UnixKind::Dgram {
            let dest = match self.dgram_peer.lock().clone() {
                Some(p) => p,
                None => return Err(Errno::INVAL),
            };
            let r = self.dgram_send_to(buf, &dest);
            return match r {
                r if r >= 0 => Ok(r as usize),
                e if e == crate::errno::EINTR => Err(Errno::INTR),
                e if e == crate::errno::EAGAIN => Err(Errno::AGAIN),
                _ => Err(Errno::IO),
            };
        }
        match self.connected_end() {
            Some(end) => end.write_at_with_flags(off, buf, flags),
            None => Err(Errno::INVAL),
        }
    }

    fn poll(&self) -> crate::vfs::PollMask {
        use crate::vfs::PollMask;
        if self.kind == UnixKind::Dgram {
            let mut m = PollMask::OUT;
            if !self.dgram_rx.lock().is_empty() {
                m |= PollMask::IN;
            }
            return m;
        }
        let st = self.state.lock();
        match &*st {
            SockState::Listening { backlog, .. } => {
                if backlog.is_empty() {
                    PollMask::empty()
                } else {
                    PollMask::IN
                }
            }
            SockState::Connected(end) => {
                let end = end.clone();
                drop(st);
                end.poll()
            }
            SockState::Unbound => PollMask::empty(),
        }
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        if self.kind == UnixKind::Dgram {
            f(&self.dgram_waiters);
            return;
        }
        f(&self.accept_waiters);
        if let Some(end) = self.connected_end() {
            end.for_each_wait_queue(f);
        }
    }

    fn write_with_fds(
        &self,
        buf: &[u8],
        fds: Vec<Arc<OpenFile>>,
        nonblock: bool,
    ) -> KResult<usize> {
        match self.connected_end() {
            Some(end) => end.write_with_fds(buf, fds, nonblock),
            None => Err(Errno::INVAL),
        }
    }

    fn read_with_fds(
        &self,
        buf: &mut [u8],
        nonblock: bool,
    ) -> KResult<(usize, Vec<Arc<OpenFile>>)> {
        match self.connected_end() {
            Some(end) => end.read_with_fds(buf, nonblock),
            None => Err(Errno::INVAL),
        }
    }

    fn as_socket(&self) -> Option<&dyn super::Socket> {
        Some(self)
    }

    fn on_close(&self, _flags: OpenFlags) {
        if let Some(end) = self.connected_end() {
            end.on_close(OpenFlags::RDWR);
        }
        if let Some(p) = self.bound_path.lock().take() {
            self.rendezvous_remove(&p);
        }
    }
}

impl super::Socket for UnixSocket {
    fn bind(&self, addr: &[u8]) -> i64 {
        let path = match parse_sockaddr_un(addr) {
            Ok(p) => p,
            Err(e) => return e,
        };
        if !path.starts_with('\0') {
            let ctx = crate::vfs::path::Context::current();
            let start = if path.starts_with('/') {
                ctx.root.clone()
            } else {
                crate::core::with_current_cwd(|c| c.inode.clone())
                    .unwrap_or_else(|| ctx.root.clone())
            };
            if let Ok((parent, leaf)) = crate::vfs::path::resolve_parent(&ctx, &start, &path) {
                match parent.create(leaf, InodeKind::Socket) {
                    Ok(node) => {
                        let (euid, egid) = crate::core::with_current_creds(|c| (c.euid, c.egid));
                        let _ = node.set_owner(Some(euid), Some(egid));
                    }
                    Err(Errno::EXIST) => return crate::errno::EADDRINUSE,
                    Err(e) => return e.as_neg_i64(),
                }
            }
        }
        match self.bind_path(path) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    fn setsockopt(&self, level: i32, opt: i32, _optval: u64, _optlen: u64) -> i64 {
        const SOL_SOCKET: i32 = 1;
        const SO_PASSCRED: i32 = 16;
        if level == SOL_SOCKET && opt == SO_PASSCRED {
            self.passcred.store(true, Ordering::Relaxed);
            if let Some(end) = self.connected_end() {
                end.passcred.store(true, Ordering::Relaxed);
            }
        }
        0
    }

    fn recv_creds(&self) -> Option<(i32, u32, u32)> {
        if !self.passcred.load(Ordering::Relaxed) {
            return None;
        }
        self.connected_end().and_then(|e| e.recv_creds())
    }

    fn listen(&self, backlog: i32) -> i64 {
        if !self.is_stream_like() {
            return crate::errno::EOPNOTSUPP;
        }
        match self.do_listen(backlog) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    fn shutdown(&self, how: i32) -> i64 {
        match self.connected_end() {
            Some(end) => end.shutdown_dirs(how),
            None => crate::errno::ENOTCONN,
        }
    }

    fn accept(&self, peer_out: Option<(u64, u64)>, nonblock: bool) -> Result<Arc<dyn Inode>, i64> {
        if !self.is_stream_like() {
            return Err(crate::errno::EOPNOTSUPP);
        }
        let end = crate::vfs::blocking::block_io::<Arc<UnixEnd>>(
            "unix_accept",
            &self.accept_waiters,
            nonblock,
            None,
            || match self.try_accept() {
                Ok(e) => crate::vfs::blocking::IoAttempt::Ready(e),
                Err(Errno::AGAIN) => crate::vfs::blocking::IoAttempt::WouldBlock,
                Err(e) => crate::vfs::blocking::IoAttempt::Err(e),
            },
        )
        .map_err(|e| e.as_neg_i64())?;
        if let Some((addr, addrlen)) = peer_out {
            if addr != 0 && addrlen != 0 {
                let mut cap = [0u8; 4];
                if frame::user::copy_from_user(addrlen, &mut cap).is_ok() {
                    let cap = u32::from_le_bytes(cap) as usize;
                    let fam = (AF_UNIX as u16).to_le_bytes();
                    let n = fam.len().min(cap);
                    let _ = frame::user::copy_to_user(addr, &fam[..n]);
                    let _ = frame::user::copy_to_user(addrlen, &2u32.to_le_bytes());
                }
            }
        }
        Ok(end)
    }

    fn connect(&self, addr: &[u8], _nonblock: bool) -> i64 {
        let path = match parse_sockaddr_un(addr) {
            Ok(p) => p,
            Err(e) => return e,
        };
        match self.kind {
            UnixKind::Stream | UnixKind::Seqpacket => match self.connect_path(&path) {
                Ok(()) => 0,
                Err(e) => e,
            },
            UnixKind::Dgram => {
                if self.rendezvous_lookup(&path).is_none() {
                    return crate::errno::ECONNREFUSED;
                }
                *self.dgram_peer.lock() = Some(path);
                0
            }
        }
    }

    fn send_to(&self, buf: &[u8], addr: Option<&[u8]>, _nonblock: bool) -> i64 {
        if self.kind != UnixKind::Dgram {
            return crate::errno::EOPNOTSUPP;
        }
        let dest = match addr {
            Some(ab) => match parse_sockaddr_un(ab) {
                Ok(p) => p,
                Err(e) => return e,
            },
            None => match self.dgram_peer.lock().clone() {
                Some(p) => p,
                None => return crate::errno::EDESTADDRREQ,
            },
        };
        self.dgram_send_to(buf, &dest)
    }

    fn recv_from(&self, buf: &mut [u8], peer_out: Option<(u64, u64)>, nonblock: bool) -> i64 {
        if self.kind != UnixKind::Dgram {
            return crate::errno::EOPNOTSUPP;
        }
        self.dgram_recv_from(buf, peer_out, nonblock)
    }
}
