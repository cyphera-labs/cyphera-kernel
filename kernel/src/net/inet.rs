extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;

use frame::sync::SpinIrq;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address};

use crate::vfs::{FsError, Inode, InodeKind, OpenFlags, PollMask, Stat};
use crate::wait::WaitQueue;

static REGISTRY: SpinIrq<BTreeMap<usize, Arc<InetSocket>>> = SpinIrq::new(BTreeMap::new());

pub fn register(s: &Arc<InetSocket>) {
    let key = Arc::as_ptr(s) as *const () as usize;
    REGISTRY.lock().insert(key, s.clone());
}

pub fn lookup_by_inode(inode: &dyn Inode) -> Option<Arc<InetSocket>> {
    let key = (inode as *const dyn Inode) as *const () as usize;
    REGISTRY.lock().get(&key).cloned()
}

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;

const UDP_BUFFER_BYTES: usize = 64 * 1024;
const UDP_META_SLOTS: usize = 64;
const TCP_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SockKind {
    Udp,
    Tcp,
}

const MAX_LISTEN_BACKLOG: usize = 16;

#[derive(Default, Copy, Clone, Debug)]
pub struct SockOpts {
    pub reuseaddr: bool,
    pub reuseport: bool,
    pub keepalive: bool,
    pub broadcast: bool,
    pub nodelay: bool,
    pub rcvbuf: u32,
    pub sndbuf: u32,
    pub rcvtimeo_us: u64,
    pub sndtimeo_us: u64,
    pub linger_on: bool,
    pub linger_seconds: u32,
    pub ip_ttl: u8,
    pub shut_rd: bool,
    pub shut_wr: bool,
    pub so_error: u16,
    pub so_error_seen: bool,
    pub ever_established: bool,
}

impl SockOpts {
    fn fresh() -> Self {
        Self {
            rcvbuf: TCP_BUFFER_BYTES as u32,
            sndbuf: TCP_BUFFER_BYTES as u32,
            ip_ttl: 64,
            ..Self::default()
        }
    }
}

pub struct InetSocket {
    handle: SocketHandle,
    kind: SockKind,
    peer: SpinIrq<Option<IpEndpoint>>,
    bound_local: SpinIrq<Option<IpListenEndpoint>>,
    listening: SpinIrq<bool>,
    listeners: SpinIrq<alloc::vec::Vec<SocketHandle>>,
    wait: WaitQueue,
    pub opts: SpinIrq<SockOpts>,
}

impl InetSocket {
    pub fn new_udp() -> Result<Arc<Self>, FsError> {
        let metadata_storage = vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS];
        let payload_storage = vec![0u8; UDP_BUFFER_BYTES];
        let metadata_storage_2 = metadata_storage.clone();
        let payload_storage_2 = payload_storage.clone();
        let rx = udp::PacketBuffer::new(metadata_storage, payload_storage);
        let tx = udp::PacketBuffer::new(metadata_storage_2, payload_storage_2);
        let socket = udp::Socket::new(rx, tx);
        let handle = super::with_stack(|s| s.sockets.add(socket)).ok_or(FsError::NotSupported)?;
        Ok(Arc::new(Self {
            handle,
            kind: SockKind::Udp,
            peer: SpinIrq::new(None),
            bound_local: SpinIrq::new(None),
            listening: SpinIrq::new(false),
            listeners: SpinIrq::new(alloc::vec::Vec::new()),
            wait: WaitQueue::new(),
            opts: SpinIrq::new(SockOpts::fresh()),
        }))
    }

    pub fn new_tcp() -> Result<Arc<Self>, FsError> {
        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let socket = tcp::Socket::new(rx, tx);
        let handle = super::with_stack(|s| s.sockets.add(socket)).ok_or(FsError::NotSupported)?;
        Ok(Arc::new(Self {
            handle,
            kind: SockKind::Tcp,
            peer: SpinIrq::new(None),
            bound_local: SpinIrq::new(None),
            listening: SpinIrq::new(false),
            listeners: SpinIrq::new(alloc::vec::Vec::new()),
            wait: WaitQueue::new(),
            opts: SpinIrq::new(SockOpts::fresh()),
        }))
    }

    fn new_tcp_listener(local: IpListenEndpoint) -> Result<SocketHandle, FsError> {
        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let socket = tcp::Socket::new(rx, tx);
        let handle = super::with_stack(|s| {
            let h = s.sockets.add(socket);
            let sock = s.sockets.get_mut::<tcp::Socket>(h);
            sock.listen(local)
                .map(|_| h)
                .map_err(|_| FsError::InvalidArgument)
        })
        .ok_or(FsError::NotSupported)??;
        Ok(handle)
    }

    pub fn handle(&self) -> SocketHandle {
        self.handle
    }

    pub fn bind(&self, ep: IpListenEndpoint) -> Result<(), FsError> {
        match self.kind {
            SockKind::Udp => super::with_stack(|s| {
                let sock = s.sockets.get_mut::<udp::Socket>(self.handle);
                sock.bind(ep).map_err(|_| FsError::InvalidArgument)
            })
            .ok_or(FsError::NotSupported)??,
            SockKind::Tcp => {
            }
        }
        *self.bound_local.lock() = Some(ep);
        Ok(())
    }

    pub fn connect(&self, ep: IpEndpoint) -> Result<(), FsError> {
        match self.kind {
            SockKind::Udp => {
                *self.peer.lock() = Some(ep);
                Ok(())
            }
            SockKind::Tcp => {
                let local = self
                    .bound_local
                    .lock()
                    .map(|le| le.port)
                    .filter(|p| *p != 0)
                    .unwrap_or_else(ephemeral_port);
                super::with_stack(|s| {
                    let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
                    let is_loop = matches!(
                        ep.addr,
                        smoltcp::wire::IpAddress::Ipv4(a) if a.is_loopback()
                    );
                    let ctx = match (is_loop, s.iface.as_mut()) {
                        (false, Some(iface)) => iface.context(),
                        _ => s.loop_iface.context(),
                    };
                    sock.connect(ctx, ep, local)
                        .map_err(|_| FsError::InvalidArgument)
                })
                .ok_or(FsError::NotSupported)??;
                {
                    let mut bl = self.bound_local.lock();
                    let addr = bl.and_then(|le| le.addr);
                    *bl = Some(IpListenEndpoint { addr, port: local });
                }
                {
                    let mut o = self.opts.lock();
                    o.so_error = 0;
                    o.so_error_seen = false;
                    o.ever_established = false;
                }
                *self.peer.lock() = Some(ep);
                Ok(())
            }
        }
    }

    pub fn listen(&self, backlog: i32) -> Result<(), FsError> {
        match self.kind {
            SockKind::Udp => Err(FsError::InvalidArgument),
            SockKind::Tcp => {
                let local = self.bound_local.lock().ok_or(FsError::InvalidArgument)?;
                let n = (backlog.max(1) as usize).min(MAX_LISTEN_BACKLOG);
                let mut pool = alloc::vec::Vec::with_capacity(n);
                for _ in 0..n {
                    pool.push(Self::new_tcp_listener(local)?);
                }
                *self.listeners.lock() = pool;
                *self.listening.lock() = true;
                Ok(())
            }
        }
    }

    pub fn try_accept(&self) -> Result<Arc<Self>, FsError> {
        if self.kind != SockKind::Tcp || !*self.listening.lock() {
            return Err(FsError::InvalidArgument);
        }
        let local = self.bound_local.lock().ok_or(FsError::InvalidArgument)?;

        let mut pool = self.listeners.lock();
        if pool.is_empty() {
            return Err(FsError::InvalidArgument);
        }

        let mut active_idx = None;
        for (i, &h) in pool.iter().enumerate() {
            let active = super::with_stack(|s| {
                let sock = s.sockets.get::<tcp::Socket>(h);
                sock.is_active()
            })
            .ok_or(FsError::NotSupported)?;
            if active {
                active_idx = Some(i);
                break;
            }
        }
        let idx = match active_idx {
            Some(i) => i,
            None => return Err(FsError::WouldBlock),
        };
        let accepted_handle = pool[idx];
        let replacement = Self::new_tcp_listener(local)?;
        pool[idx] = replacement;
        drop(pool);

        let remote = super::with_stack(|s| {
            s.sockets
                .get::<tcp::Socket>(accepted_handle)
                .remote_endpoint()
        })
        .flatten();

        Ok(Arc::new(InetSocket {
            handle: accepted_handle,
            kind: SockKind::Tcp,
            peer: SpinIrq::new(remote),
            bound_local: SpinIrq::new(Some(local)),
            listening: SpinIrq::new(false),
            listeners: SpinIrq::new(alloc::vec::Vec::new()),
            wait: WaitQueue::new(),
            opts: SpinIrq::new(SockOpts::fresh()),
        }))
    }

    pub fn accept(&self) -> Result<Arc<Self>, FsError> {
        loop {
            match self.try_accept() {
                Ok(s) => return Ok(s),
                Err(FsError::WouldBlock) => {
                    self.wait.park();
                    if crate::sched::current_signal_pending() {
                        return Err(FsError::Interrupted);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub fn wait_queue(&self) -> &WaitQueue {
        &self.wait
    }

    pub fn send_to(&self, buf: &[u8], peer: Option<IpEndpoint>) -> Result<usize, FsError> {
        if self.opts.lock().shut_wr {
            return Err(FsError::BrokenPipe);
        }
        let target = match peer.or_else(|| *self.peer.lock()) {
            Some(p) => p,
            None => return Err(FsError::InvalidArgument),
        };
        match self.kind {
            SockKind::Udp => {
                if self.bound_local.lock().is_none() {
                    let ep = IpListenEndpoint {
                        addr: None,
                        port: ephemeral_port(),
                    };
                    self.bind(ep)?;
                }
                super::with_stack(|s| {
                    let sock = s.sockets.get_mut::<udp::Socket>(self.handle);
                    sock.send_slice(buf, target).map_err(|_| FsError::Io)?;
                    Ok::<usize, FsError>(buf.len())
                })
                .ok_or(FsError::NotSupported)?
            }
            SockKind::Tcp => super::with_stack(|s| {
                let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
                if !sock.may_send() {
                    return Err(FsError::BrokenPipe);
                }
                sock.send_slice(buf).map_err(|_| FsError::Io)
            })
            .ok_or(FsError::NotSupported)?,
        }
    }

    pub fn try_recv_from(&self, buf: &mut [u8]) -> Result<(usize, Option<IpEndpoint>), FsError> {
        if self.opts.lock().shut_rd {
            return Ok((0, None));
        }
        match self.kind {
            SockKind::Udp => super::with_stack(|s| {
                let sock = s.sockets.get_mut::<udp::Socket>(self.handle);
                if !sock.can_recv() {
                    return Err(FsError::WouldBlock);
                }
                let (n, meta) = sock.recv_slice(buf).map_err(|_| FsError::Io)?;
                Ok((n, Some(meta.endpoint)))
            })
            .ok_or(FsError::NotSupported)?,
            SockKind::Tcp => super::with_stack(|s| {
                let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
                if !sock.can_recv() {
                    return Err(FsError::WouldBlock);
                }
                let n = sock.recv_slice(buf).map_err(|_| FsError::Io)?;
                Ok((n, None))
            })
            .ok_or(FsError::NotSupported)?,
        }
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, Option<IpEndpoint>), FsError> {
        let rcvtimeo_us = self.opts.lock().rcvtimeo_us;
        let deadline = if rcvtimeo_us != 0 {
            Some(
                frame::cpu::clock::nanos_since_boot()
                    .saturating_add(rcvtimeo_us.saturating_mul(1_000)),
            )
        } else {
            None
        };
        let pid = crate::sched::current_pid();
        loop {
            match self.try_recv_from(buf) {
                Ok(x) => {
                    if deadline.is_some() {
                        let _ = crate::timeout::unregister(pid);
                    }
                    return Ok(x);
                }
                Err(FsError::WouldBlock) => {
                    if let Some(d) = deadline {
                        if frame::cpu::clock::nanos_since_boot() >= d {
                            let _ = crate::timeout::unregister(pid);
                            return Err(FsError::WouldBlock);
                        }
                        crate::timeout::register(d, pid);
                    }
                    self.wait.park();
                    self.wait.dequeue(pid);
                    if crate::sched::current_signal_pending() {
                        if deadline.is_some() {
                            let _ = crate::timeout::unregister(pid);
                        }
                        return Err(FsError::Interrupted);
                    }
                }
                Err(e) => {
                    if deadline.is_some() {
                        let _ = crate::timeout::unregister(pid);
                    }
                    return Err(e);
                }
            }
        }
    }

    fn poll_mask(&self) -> PollMask {
        let opts = *self.opts.lock();
        if opts.shut_rd && opts.shut_wr {
            return PollMask::HUP | PollMask::IN;
        }
        if self.kind == SockKind::Tcp && *self.listening.lock() {
            let pool = self.listeners.lock().clone();
            let any_active = super::with_stack(|s| {
                pool.iter()
                    .any(|h| s.sockets.get::<tcp::Socket>(*h).is_active())
            })
            .unwrap_or(false);
            return if any_active {
                PollMask::IN
            } else {
                PollMask::empty()
            };
        }
        let (mask, established) = super::with_stack(|s| {
            let mut m = PollMask::empty();
            let mut est = false;
            match self.kind {
                SockKind::Udp => {
                    let sock = s.sockets.get_mut::<udp::Socket>(self.handle);
                    if sock.can_recv() {
                        m |= PollMask::IN;
                    }
                    if sock.can_send() {
                        m |= PollMask::OUT;
                    }
                }
                SockKind::Tcp => {
                    let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
                    est = tcp_established_or_past(sock.state());
                    if sock.can_recv() || opts.shut_rd {
                        m |= PollMask::IN;
                    }
                    if sock.can_send() && !opts.shut_wr {
                        m |= PollMask::OUT;
                    }
                    if !sock.is_open() {
                        m |= PollMask::HUP;
                    }
                }
            }
            (m, est)
        })
        .unwrap_or((PollMask::empty(), false));
        if established {
            self.opts.lock().ever_established = true;
        }
        mask
    }

    pub fn wake(&self) {
        self.wait.wake_all();
    }

    pub fn sock_type(&self) -> u32 {
        match self.kind {
            SockKind::Tcp => SOCK_STREAM,
            SockKind::Udp => SOCK_DGRAM,
        }
    }

    pub fn proto(&self) -> u32 {
        match self.kind {
            SockKind::Tcp => 6,
            SockKind::Udp => 17,
        }
    }

    pub fn is_tcp(&self) -> bool {
        self.kind == SockKind::Tcp
    }

    pub fn local_name(&self) -> IpEndpoint {
        let unspec = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(0, 0, 0, 0)), 0);
        match self.kind {
            SockKind::Udp => {
                let le =
                    super::with_stack(|s| s.sockets.get::<udp::Socket>(self.handle).endpoint());
                match le {
                    Some(le) if le.port != 0 => listen_to_endpoint(le),
                    _ => match *self.bound_local.lock() {
                        Some(le) => listen_to_endpoint(le),
                        None => unspec,
                    },
                }
            }
            SockKind::Tcp => {
                let smol = super::with_stack(|s| {
                    s.sockets.get::<tcp::Socket>(self.handle).local_endpoint()
                });
                match smol {
                    Some(Some(ep)) => ep,
                    _ => match *self.bound_local.lock() {
                        Some(le) => listen_to_endpoint(le),
                        None => unspec,
                    },
                }
            }
        }
    }

    pub fn peer_endpoint(&self) -> Option<IpEndpoint> {
        match self.kind {
            SockKind::Udp => *self.peer.lock(),
            SockKind::Tcp => {
                let remote = super::with_stack(|s| {
                    s.sockets.get::<tcp::Socket>(self.handle).remote_endpoint()
                })
                .flatten();
                remote.or_else(|| *self.peer.lock())
            }
        }
    }

    pub fn take_so_error(&self) -> u16 {
        self.latch_connect_error();
        let mut o = self.opts.lock();
        let e = o.so_error;
        o.so_error = 0;
        if e != 0 {
            o.so_error_seen = true;
        }
        e
    }

    fn latch_connect_error(&self) {
        if self.kind != SockKind::Tcp {
            return;
        }
        if self.peer.lock().is_none() {
            return;
        }
        if *self.listening.lock() {
            return;
        }
        {
            let o = self.opts.lock();
            if o.so_error_seen || o.ever_established {
                return;
            }
        }
        let st = super::with_stack(|s| s.sockets.get::<tcp::Socket>(self.handle).state())
            .unwrap_or(tcp::State::Closed);
        if tcp_established_or_past(st) {
            self.opts.lock().ever_established = true;
        } else if st == tcp::State::Closed {
            let mut o = self.opts.lock();
            if o.so_error == 0 {
                o.so_error = 111;
            }
        }
    }

    pub fn shutdown(&self, how: i32) -> Result<(), FsError> {
        const SHUT_RD: i32 = 0;
        const SHUT_WR: i32 = 1;
        const SHUT_RDWR: i32 = 2;
        if !matches!(how, SHUT_RD | SHUT_WR | SHUT_RDWR) {
            return Err(FsError::InvalidArgument);
        }
        let mut o = self.opts.lock();
        if how == SHUT_RD || how == SHUT_RDWR {
            o.shut_rd = true;
        }
        if how == SHUT_WR || how == SHUT_RDWR {
            o.shut_wr = true;
            if self.kind == SockKind::Tcp {
                super::with_stack(|s| {
                    let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
                    sock.close();
                });
            }
        }
        drop(o);
        self.wait.wake_all();
        Ok(())
    }

    pub fn apply_smoltcp_sockopt(&self, kind: SmoltcpOpt, val: u64) {
        super::with_stack(|s| match self.kind {
            SockKind::Tcp => {
                let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
                match kind {
                    SmoltcpOpt::TcpNoDelay => sock.set_nagle_enabled(val == 0),
                    SmoltcpOpt::Keepalive => {
                        sock.set_keep_alive(if val != 0 {
                            Some(smoltcp::time::Duration::from_secs(60))
                        } else {
                            None
                        });
                    }
                    SmoltcpOpt::HopLimit => sock.set_hop_limit(Some(val as u8)),
                }
            }
            SockKind::Udp => {
                let _ = (kind, val);
            }
        });
    }
}

#[derive(Copy, Clone)]
pub enum SmoltcpOpt {
    TcpNoDelay,
    Keepalive,
    HopLimit,
}

pub fn wake_all_sockets() {
    let socks: alloc::vec::Vec<Arc<InetSocket>> = REGISTRY.lock().values().cloned().collect();
    for s in socks {
        s.wake();
    }
}

impl Inode for InetSocket {
    fn kind(&self) -> InodeKind {
        InodeKind::Pipe
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Pipe, 0, 0o600)
    }

    fn read_at(&self, _off: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let (n, _peer) = self.recv_from(buf)?;
        Ok(n)
    }

    fn write_at(&self, _off: u64, buf: &[u8]) -> Result<usize, FsError> {
        self.send_to(buf, None)
    }

    fn poll(&self) -> PollMask {
        self.poll_mask()
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&self.wait);
    }

    fn on_close(&self, _flags: OpenFlags) {
        let key = (self as *const Self) as *const () as usize;
        REGISTRY.lock().remove(&key);
        let pool: alloc::vec::Vec<SocketHandle> = self.listeners.lock().drain(..).collect();
        let _ = super::with_stack(|s| {
            s.sockets.remove(self.handle);
            for h in pool {
                s.sockets.remove(h);
            }
        });
    }
}

fn tcp_established_or_past(st: tcp::State) -> bool {
    use tcp::State;
    matches!(
        st,
        State::Established
            | State::CloseWait
            | State::FinWait1
            | State::FinWait2
            | State::Closing
            | State::LastAck
            | State::TimeWait
    )
}

fn listen_to_endpoint(le: IpListenEndpoint) -> IpEndpoint {
    let addr = le
        .addr
        .unwrap_or(IpAddress::Ipv4(Ipv4Address::new(0, 0, 0, 0)));
    IpEndpoint::new(addr, le.port)
}

fn ephemeral_port() -> u16 {
    use core::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(32768);
    let p = NEXT.fetch_add(1, Ordering::Relaxed);
    if p < 32768 {
        NEXT.store(32768, Ordering::Relaxed);
        return 32768;
    }
    p
}

pub fn parse_sockaddr_in(buf: &[u8]) -> Result<IpEndpoint, FsError> {
    if buf.len() < 8 {
        return Err(FsError::InvalidArgument);
    }
    let fam = u16::from_le_bytes([buf[0], buf[1]]);
    if fam != 2 {
        return Err(FsError::InvalidArgument);
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let addr = Ipv4Address::new(buf[4], buf[5], buf[6], buf[7]);
    Ok(IpEndpoint::new(IpAddress::Ipv4(addr), port))
}

pub fn write_sockaddr_in(ep: &IpEndpoint, out: &mut [u8]) -> usize {
    out[0..2].copy_from_slice(&2u16.to_le_bytes());
    out[2..4].copy_from_slice(&ep.port.to_be_bytes());
    let IpAddress::Ipv4(a) = ep.addr;
    out[4..8].copy_from_slice(a.as_bytes());
    16
}
