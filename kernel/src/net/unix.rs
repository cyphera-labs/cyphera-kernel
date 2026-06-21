extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use frame::sync::SpinIrq;

use crate::vfs::{FsError, Inode, InodeKind, OpenFile, OpenFlags, Stat};
use crate::wait::WaitQueue;

const UNIX_CAPACITY: usize = 64 * 1024;

type FdBatch = (usize, alloc::vec::Vec<Arc<OpenFile>>);

struct Ring {
    buf: VecDeque<u8>,
    readers: u32,
    writers: u32,
    written: usize,
    read: usize,
    fds: VecDeque<FdBatch>,
}

struct Channel {
    ring: SpinIrq<Ring>,
    read_waiters: WaitQueue,
    write_waiters: WaitQueue,
}

pub struct UnixEnd {
    inbox: Arc<Channel>,
    peer_inbox: Arc<Channel>,
}

impl UnixEnd {
    pub fn pair() -> (Arc<Self>, Arc<Self>) {
        let a_chan = Arc::new(Channel {
            ring: SpinIrq::new(Ring {
                buf: VecDeque::with_capacity(UNIX_CAPACITY),
                readers: 0,
                writers: 0,
                written: 0,
                read: 0,
                fds: VecDeque::new(),
            }),
            read_waiters: WaitQueue::new(),
            write_waiters: WaitQueue::new(),
        });
        let b_chan = Arc::new(Channel {
            ring: SpinIrq::new(Ring {
                buf: VecDeque::with_capacity(UNIX_CAPACITY),
                readers: 0,
                writers: 0,
                written: 0,
                read: 0,
                fds: VecDeque::new(),
            }),
            read_waiters: WaitQueue::new(),
            write_waiters: WaitQueue::new(),
        });
        let a = Arc::new(Self {
            inbox: a_chan.clone(),
            peer_inbox: b_chan.clone(),
        });
        let b = Arc::new(Self {
            inbox: b_chan,
            peer_inbox: a_chan,
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

    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        self.read_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(
        &self,
        _off: u64,
        buf: &mut [u8],
        flags: OpenFlags,
    ) -> Result<usize, FsError> {
        let nonblock = flags.contains(OpenFlags::NONBLOCK);
        crate::vfs::blocking::block_io(
            "unix_read",
            &self.inbox.read_waiters,
            nonblock,
            None,
            || {
                let mut s = self.inbox.ring.lock();
                if !s.buf.is_empty() {
                    let mut n = 0;
                    while n < buf.len() {
                        match s.buf.pop_front() {
                            Some(b) => {
                                buf[n] = b;
                                n += 1;
                            }
                            None => break,
                        }
                    }
                    s.read += n;
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

    fn write_at(&self, off: u64, buf: &[u8]) -> Result<usize, FsError> {
        self.write_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn write_at_with_flags(
        &self,
        _off: u64,
        buf: &[u8],
        flags: OpenFlags,
    ) -> Result<usize, FsError> {
        use crate::vfs::blocking::IoAttempt;
        let nonblock = flags.contains(OpenFlags::NONBLOCK);
        crate::vfs::blocking::block_io(
            "unix_write",
            &self.peer_inbox.write_waiters,
            nonblock,
            None,
            || {
                let mut s = self.peer_inbox.ring.lock();
                if s.readers == 0 {
                    return IoAttempt::Err(FsError::BrokenPipe);
                }
                let room = UNIX_CAPACITY.saturating_sub(s.buf.len());
                if room == 0 {
                    return IoAttempt::WouldBlock;
                }
                let n = buf.len().min(room);
                s.buf.extend(buf[..n].iter().copied());
                s.written += n;
                drop(s);
                self.peer_inbox.read_waiters.wake_one();
                IoAttempt::Ready(n)
            },
        )
    }

    fn write_with_fds(&self, buf: &[u8], mut fds: Vec<Arc<OpenFile>>) -> Result<usize, FsError> {
        use crate::vfs::blocking::IoAttempt;
        crate::vfs::blocking::block_io(
            "unix_write_fds",
            &self.peer_inbox.write_waiters,
            false,
            None,
            || {
                let mut s = self.peer_inbox.ring.lock();
                if s.readers == 0 {
                    return IoAttempt::Err(FsError::BrokenPipe);
                }
                let room = UNIX_CAPACITY.saturating_sub(s.buf.len());
                if room == 0 {
                    return IoAttempt::WouldBlock;
                }
                let n = buf.len().min(room);
                if !fds.is_empty() {
                    let pos = s.written;
                    s.fds.push_back((pos, core::mem::take(&mut fds)));
                }
                s.buf.extend(buf[..n].iter().copied());
                s.written += n;
                drop(s);
                self.peer_inbox.read_waiters.wake_one();
                IoAttempt::Ready(n)
            },
        )
    }

    fn read_with_fds(&self, buf: &mut [u8]) -> Result<(usize, Vec<Arc<OpenFile>>), FsError> {
        use crate::vfs::blocking::IoAttempt;
        crate::vfs::blocking::block_io(
            "unix_recvmsg",
            &self.inbox.read_waiters,
            false,
            None,
            || {
                let mut s = self.inbox.ring.lock();
                if !s.buf.is_empty() {
                    let mut n = 0;
                    while n < buf.len() {
                        match s.buf.pop_front() {
                            Some(b) => {
                                buf[n] = b;
                                n += 1;
                            }
                            None => break,
                        }
                    }
                    s.read += n;
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
        let mut m = PollMask::empty();
        if !inbox.buf.is_empty() || inbox.writers == 0 {
            m |= PollMask::IN;
        }
        if peer.buf.len() < UNIX_CAPACITY || peer.readers == 0 {
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

static BOUND: SpinIrq<BTreeMap<String, Weak<UnixSocket>>> = SpinIrq::new(BTreeMap::new());

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
}

impl UnixSocket {
    fn new(kind: UnixKind) -> Arc<Self> {
        let ns = crate::sched::current_net_ns();
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
        })
    }

    pub fn new_unbound() -> Arc<Self> {
        Self::new(UnixKind::Stream)
    }

    pub fn new_dgram() -> Arc<Self> {
        Self::new(UnixKind::Dgram)
    }

    fn rendezvous_insert(&self, path: &str) -> Result<(), i64> {
        let taken = if path.starts_with('\0') {
            !self.ns.try_bind_abstract(path.into(), self.me.clone())
        } else {
            let mut bound = BOUND.lock();
            if bound.get(path).and_then(|w| w.upgrade()).is_some() {
                true
            } else {
                bound.insert(path.into(), self.me.clone());
                false
            }
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
            BOUND.lock().get(path).and_then(|w| w.upgrade())
        }
    }

    fn rendezvous_remove(&self, path: &str) {
        if path.starts_with('\0') {
            self.ns.unbind_abstract(path);
        } else {
            BOUND.lock().remove(path);
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
            Err(FsError::WouldBlock) => return crate::errno::EAGAIN,
            Err(FsError::Interrupted) => return crate::errno::EINTR,
            Err(e) => return e.errno(),
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

    pub fn try_accept(&self) -> Result<Arc<UnixEnd>, FsError> {
        let mut st = self.state.lock();
        match &mut *st {
            SockState::Listening { backlog, .. } => backlog.pop_front().ok_or(FsError::WouldBlock),
            _ => Err(FsError::InvalidArgument),
        }
    }

    fn connect_path(&self, path: &str) -> Result<(), i64> {
        if matches!(&*self.state.lock(), SockState::Connected(_)) {
            return Err(crate::errno::EINVAL);
        }
        let listener = match self.rendezvous_lookup(path) {
            Some(l) => l,
            None => return Err(crate::errno::ECONNREFUSED),
        };
        let (server, client) = UnixEnd::pair();
        client.on_open(OpenFlags::RDWR);
        server.on_open(OpenFlags::RDWR);
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
                client.on_close(OpenFlags::RDWR);
                server.on_close(OpenFlags::RDWR);
                return Err(crate::errno::ECONNREFUSED);
            }
        }
        *self.state.lock() = SockState::Connected(client);
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

    fn read_at(&self, off: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        self.read_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(
        &self,
        off: u64,
        buf: &mut [u8],
        flags: OpenFlags,
    ) -> Result<usize, FsError> {
        let nonblock = flags.contains(OpenFlags::NONBLOCK);
        if self.kind == UnixKind::Dgram {
            let r = self.dgram_recv_from(buf, None, nonblock);
            return match r {
                r if r >= 0 => Ok(r as usize),
                e if e == crate::errno::EINTR => Err(FsError::Interrupted),
                e if e == crate::errno::EAGAIN => Err(FsError::WouldBlock),
                _ => Err(FsError::Io),
            };
        }
        match self.connected_end() {
            Some(end) => end.read_at_with_flags(off, buf, flags),
            None => Err(FsError::InvalidArgument),
        }
    }

    fn write_at(&self, off: u64, buf: &[u8]) -> Result<usize, FsError> {
        self.write_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn write_at_with_flags(
        &self,
        off: u64,
        buf: &[u8],
        flags: OpenFlags,
    ) -> Result<usize, FsError> {
        if self.kind == UnixKind::Dgram {
            let dest = match self.dgram_peer.lock().clone() {
                Some(p) => p,
                None => return Err(FsError::InvalidArgument),
            };
            let r = self.dgram_send_to(buf, &dest);
            return match r {
                r if r >= 0 => Ok(r as usize),
                e if e == crate::errno::EINTR => Err(FsError::Interrupted),
                e if e == crate::errno::EAGAIN => Err(FsError::WouldBlock),
                _ => Err(FsError::Io),
            };
        }
        match self.connected_end() {
            Some(end) => end.write_at_with_flags(off, buf, flags),
            None => Err(FsError::InvalidArgument),
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

    fn write_with_fds(&self, buf: &[u8], fds: Vec<Arc<OpenFile>>) -> Result<usize, FsError> {
        match self.connected_end() {
            Some(end) => end.write_with_fds(buf, fds),
            None => Err(FsError::InvalidArgument),
        }
    }

    fn read_with_fds(&self, buf: &mut [u8]) -> Result<(usize, Vec<Arc<OpenFile>>), FsError> {
        match self.connected_end() {
            Some(end) => end.read_with_fds(buf),
            None => Err(FsError::InvalidArgument),
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
                crate::sched::with_current_cwd(|c| c.inode.clone())
                    .unwrap_or_else(|| ctx.root.clone())
            };
            if let Ok((parent, leaf)) = crate::vfs::path::resolve_parent(&ctx, &start, &path) {
                match parent.create(leaf, InodeKind::Socket) {
                    Ok(node) => {
                        let (euid, egid) = crate::sched::with_current_creds(|c| (c.euid, c.egid));
                        let _ = node.set_owner(Some(euid), Some(egid));
                    }
                    Err(FsError::Exists) => return crate::errno::EADDRINUSE,
                    Err(e) => return e.errno(),
                }
            }
        }
        match self.bind_path(path) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    fn listen(&self, backlog: i32) -> i64 {
        if self.kind != UnixKind::Stream {
            return crate::errno::EOPNOTSUPP;
        }
        match self.do_listen(backlog) {
            Ok(()) => 0,
            Err(e) => e,
        }
    }

    fn accept(&self, peer_out: Option<(u64, u64)>, nonblock: bool) -> Result<Arc<dyn Inode>, i64> {
        if self.kind != UnixKind::Stream {
            return Err(crate::errno::EOPNOTSUPP);
        }
        let end = crate::vfs::blocking::block_io::<Arc<UnixEnd>>(
            "unix_accept",
            &self.accept_waiters,
            nonblock,
            None,
            || match self.try_accept() {
                Ok(e) => crate::vfs::blocking::IoAttempt::Ready(e),
                Err(FsError::WouldBlock) => crate::vfs::blocking::IoAttempt::WouldBlock,
                Err(e) => crate::vfs::blocking::IoAttempt::Err(e),
            },
        )
        .map_err(|e| e.errno())?;
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
            UnixKind::Stream => match self.connect_path(&path) {
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
