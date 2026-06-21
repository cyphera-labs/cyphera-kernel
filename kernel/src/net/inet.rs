extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;

use frame::sync::SpinIrq;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address};

use crate::vfs::{FsError, Inode, InodeKind, OpenFlags, PollMask, Stat};
use crate::wait::WaitQueue;

pub fn register(s: &Arc<InetSocket>) {
    s.ns.register_inet(s);
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Family {
    Inet,
    Inet6,
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
    pub connect_initiated: bool,
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
    family: Family,
    ns: Arc<crate::net::NetNamespace>,
    peer: SpinIrq<Option<IpEndpoint>>,
    bound_local: SpinIrq<Option<IpListenEndpoint>>,
    listening: SpinIrq<bool>,
    listeners: SpinIrq<alloc::vec::Vec<SocketHandle>>,
    wait: WaitQueue,
    pub opts: SpinIrq<SockOpts>,
}

impl InetSocket {
    pub fn new_udp(family: Family) -> Result<Arc<Self>, FsError> {
        let metadata_storage = vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS];
        let payload_storage = vec![0u8; UDP_BUFFER_BYTES];
        let metadata_storage_2 = metadata_storage.clone();
        let payload_storage_2 = payload_storage.clone();
        let rx = udp::PacketBuffer::new(metadata_storage, payload_storage);
        let tx = udp::PacketBuffer::new(metadata_storage_2, payload_storage_2);
        let socket = udp::Socket::new(rx, tx);
        let ns = crate::sched::current_net_ns();
        let handle = ns.with_stack(|s| s.sockets.add(socket));
        Ok(Arc::new(Self {
            handle,
            kind: SockKind::Udp,
            family,
            ns,
            peer: SpinIrq::new(None),
            bound_local: SpinIrq::new(None),
            listening: SpinIrq::new(false),
            listeners: SpinIrq::new(alloc::vec::Vec::new()),
            wait: WaitQueue::new(),
            opts: SpinIrq::new(SockOpts::fresh()),
        }))
    }

    pub fn new_tcp(family: Family) -> Result<Arc<Self>, FsError> {
        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let socket = tcp::Socket::new(rx, tx);
        let ns = crate::sched::current_net_ns();
        let handle = ns.with_stack(|s| s.sockets.add(socket));
        Ok(Arc::new(Self {
            handle,
            kind: SockKind::Tcp,
            family,
            ns,
            peer: SpinIrq::new(None),
            bound_local: SpinIrq::new(None),
            listening: SpinIrq::new(false),
            listeners: SpinIrq::new(alloc::vec::Vec::new()),
            wait: WaitQueue::new(),
            opts: SpinIrq::new(SockOpts::fresh()),
        }))
    }

    fn new_tcp_listener(
        ns: &Arc<crate::net::NetNamespace>,
        local: IpListenEndpoint,
    ) -> Result<SocketHandle, FsError> {
        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let socket = tcp::Socket::new(rx, tx);
        ns.with_stack(|s| {
            let h = s.sockets.add(socket);
            let sock = s.sockets.get_mut::<tcp::Socket>(h);
            sock.listen(local)
                .map(|_| h)
                .map_err(|_| FsError::InvalidArgument)
        })
    }

    pub fn handle(&self) -> SocketHandle {
        self.handle
    }

    pub fn bind_endpoint(&self, ep: IpListenEndpoint) -> Result<(), FsError> {
        let ep = match self.kind {
            SockKind::Udp => {
                let ep = if ep.port == 0 {
                    IpListenEndpoint {
                        addr: ep.addr,
                        port: self.ns.next_ephemeral_port(),
                    }
                } else {
                    ep
                };
                self.ns.with_stack(|s| {
                    let sock = s.sockets.get_mut::<udp::Socket>(self.handle);
                    sock.bind(ep).map_err(|_| FsError::InvalidArgument)
                })?;
                ep
            }
            SockKind::Tcp => ep,
        };
        *self.bound_local.lock() = Some(ep);
        Ok(())
    }

    pub fn connect_endpoint(&self, ep: IpEndpoint) -> Result<(), FsError> {
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
                    .unwrap_or_else(|| self.ns.next_ephemeral_port());
                self.ns.with_stack(|s| {
                    let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
                    let is_loop = match ep.addr {
                        IpAddress::Ipv4(a) => a.is_loopback(),
                        IpAddress::Ipv6(a) => a == Ipv6Address::LOOPBACK,
                    };
                    let ctx = match (is_loop, s.iface.as_mut()) {
                        (false, Some(iface)) => iface.context(),
                        _ => s.loop_iface.context(),
                    };
                    sock.connect(ctx, ep, local)
                        .map_err(|_| FsError::InvalidArgument)
                })?;
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
                    o.connect_initiated = true;
                }
                *self.peer.lock() = Some(ep);
                Ok(())
            }
        }
    }

    fn tcp_state(&self) -> tcp::State {
        self.ns
            .with_stack(|s| s.sockets.get::<tcp::Socket>(self.handle).state())
    }

    pub fn tcp_connect(&self, ep: IpEndpoint, nonblock: bool) -> i64 {
        use crate::errno::{EALREADY, ECONNREFUSED, EINPROGRESS, EISCONN};
        let st = self.tcp_state();
        if tcp_established_or_past(st) {
            self.opts.lock().ever_established = true;
            return EISCONN;
        }
        if matches!(st, tcp::State::SynSent | tcp::State::SynReceived) {
            return if nonblock {
                EALREADY
            } else {
                self.wait_connected()
            };
        }
        {
            let o = self.opts.lock();
            if o.ever_established {
                return EISCONN;
            }
            if o.connect_initiated {
                return ECONNREFUSED;
            }
        }
        if let Err(e) = self.connect_endpoint(ep) {
            return e.errno();
        }
        if nonblock {
            EINPROGRESS
        } else {
            self.wait_connected()
        }
    }

    pub fn wait_connected(&self) -> i64 {
        if self.kind != SockKind::Tcp {
            return 0;
        }
        use crate::vfs::blocking::IoAttempt;
        let r =
            crate::vfs::blocking::block_io::<i64>("inet_connect", &self.wait, false, None, || {
                let st = self
                    .ns
                    .with_stack(|s| s.sockets.get::<tcp::Socket>(self.handle).state());
                if tcp_established_or_past(st) {
                    self.opts.lock().ever_established = true;
                    IoAttempt::Ready(0)
                } else if st == tcp::State::Closed {
                    IoAttempt::Ready(crate::errno::ECONNREFUSED)
                } else {
                    IoAttempt::WouldBlock
                }
            });
        match r {
            Ok(status) => status,
            Err(FsError::Interrupted) => crate::errno::EINTR,
            Err(e) => e.errno(),
        }
    }

    pub fn listen_stream(&self, backlog: i32) -> Result<(), FsError> {
        match self.kind {
            SockKind::Udp => Err(FsError::InvalidArgument),
            SockKind::Tcp => {
                let local = self.bound_local.lock().ok_or(FsError::InvalidArgument)?;
                let n = (backlog.max(1) as usize).min(MAX_LISTEN_BACKLOG);
                let mut pool = alloc::vec::Vec::with_capacity(n);
                for _ in 0..n {
                    pool.push(Self::new_tcp_listener(&self.ns, local)?);
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
            let active = self.ns.with_stack(|s| {
                let sock = s.sockets.get::<tcp::Socket>(h);
                sock.is_active()
            });
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
        let replacement = Self::new_tcp_listener(&self.ns, local)?;
        pool[idx] = replacement;
        drop(pool);

        let remote = self.ns.with_stack(|s| {
            s.sockets
                .get::<tcp::Socket>(accepted_handle)
                .remote_endpoint()
        });

        Ok(Arc::new(InetSocket {
            handle: accepted_handle,
            kind: SockKind::Tcp,
            family: self.family,
            ns: self.ns.clone(),
            peer: SpinIrq::new(remote),
            bound_local: SpinIrq::new(Some(local)),
            listening: SpinIrq::new(false),
            listeners: SpinIrq::new(alloc::vec::Vec::new()),
            wait: WaitQueue::new(),
            opts: SpinIrq::new(SockOpts {
                ever_established: true,
                ..SockOpts::fresh()
            }),
        }))
    }

    pub fn send_payload(
        &self,
        buf: &[u8],
        peer: Option<IpEndpoint>,
        nonblock: bool,
    ) -> Result<usize, FsError> {
        use crate::vfs::blocking::IoAttempt;
        if self.opts.lock().shut_wr {
            return Err(FsError::BrokenPipe);
        }
        let target = match peer.or_else(|| *self.peer.lock()) {
            Some(p) => p,
            None => return Err(FsError::InvalidArgument),
        };
        if self.kind == SockKind::Udp && self.bound_local.lock().is_none() {
            let ep = IpListenEndpoint {
                addr: None,
                port: self.ns.next_ephemeral_port(),
            };
            self.bind_endpoint(ep)?;
        }
        let site = match self.kind {
            SockKind::Udp => "inet_send_udp",
            SockKind::Tcp => "inet_send_tcp",
        };
        crate::vfs::blocking::block_io(site, &self.wait, nonblock, None, || {
            self.ns.with_stack(|s| match self.kind {
                SockKind::Udp => {
                    let sock = s.sockets.get_mut::<udp::Socket>(self.handle);
                    match sock.send_slice(buf, target) {
                        Ok(()) => IoAttempt::Ready(buf.len()),
                        Err(udp::SendError::BufferFull) => IoAttempt::WouldBlock,
                        Err(_) => IoAttempt::Err(FsError::Io),
                    }
                }
                SockKind::Tcp => {
                    let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
                    if !sock.may_send() {
                        return IoAttempt::Err(FsError::BrokenPipe);
                    }
                    match sock.send_slice(buf) {
                        Ok(0) if !buf.is_empty() => IoAttempt::WouldBlock,
                        Ok(n) => IoAttempt::Ready(n),
                        Err(_) => IoAttempt::Err(FsError::Io),
                    }
                }
            })
        })
    }

    pub fn try_recv_from(&self, buf: &mut [u8]) -> Result<(usize, Option<IpEndpoint>), FsError> {
        if self.opts.lock().shut_rd {
            return Ok((0, None));
        }
        match self.kind {
            SockKind::Udp => self.ns.with_stack(|s| {
                let sock = s.sockets.get_mut::<udp::Socket>(self.handle);
                if !sock.can_recv() {
                    return Err(FsError::WouldBlock);
                }
                let (n, meta) = sock.recv_slice(buf).map_err(|_| FsError::Io)?;
                Ok((n, Some(meta.endpoint)))
            }),
            SockKind::Tcp => {
                let ever_established = self.opts.lock().ever_established;
                self.ns.with_stack(|s| {
                    let sock = s.sockets.get_mut::<tcp::Socket>(self.handle);
                    if !sock.can_recv() {
                        if !sock.may_recv()
                            && (ever_established || tcp_established_or_past(sock.state()))
                        {
                            return Ok((0, None));
                        }
                        return Err(FsError::WouldBlock);
                    }
                    let n = sock.recv_slice(buf).map_err(|_| FsError::Io)?;
                    Ok((n, None))
                })
            }
        }
    }

    pub fn recv(
        &self,
        buf: &mut [u8],
        nonblock: bool,
    ) -> Result<(usize, Option<IpEndpoint>), FsError> {
        let rcvtimeo_us = self.opts.lock().rcvtimeo_us;
        let deadline = if !nonblock && rcvtimeo_us != 0 {
            Some(
                frame::cpu::clock::nanos_since_boot()
                    .saturating_add(rcvtimeo_us.saturating_mul(1_000)),
            )
        } else {
            None
        };
        crate::vfs::blocking::block_io("inet_recv", &self.wait, nonblock, deadline, || {
            match self.try_recv_from(buf) {
                Ok(x) => crate::vfs::blocking::IoAttempt::Ready(x),
                Err(FsError::WouldBlock) => crate::vfs::blocking::IoAttempt::WouldBlock,
                Err(e) => crate::vfs::blocking::IoAttempt::Err(e),
            }
        })
    }

    fn poll_mask(&self) -> PollMask {
        let opts = *self.opts.lock();
        if opts.shut_rd && opts.shut_wr {
            return PollMask::HUP | PollMask::IN;
        }
        if self.kind == SockKind::Tcp && *self.listening.lock() {
            let pool = self.listeners.lock().clone();
            let any_active = self.ns.with_stack(|s| {
                pool.iter()
                    .any(|h| s.sockets.get::<tcp::Socket>(*h).is_active())
            });
            return if any_active {
                PollMask::IN
            } else {
                PollMask::empty()
            };
        }
        let (mask, established) = self.ns.with_stack(|s| {
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
        });
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
        let unspec = match self.family {
            Family::Inet => IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::new(0, 0, 0, 0)), 0),
            Family::Inet6 => IpEndpoint::new(IpAddress::Ipv6(Ipv6Address::UNSPECIFIED), 0),
        };
        let le_to_ep =
            |le: IpListenEndpoint| IpEndpoint::new(le.addr.unwrap_or(unspec.addr), le.port);
        match self.kind {
            SockKind::Udp => {
                let le = self
                    .ns
                    .with_stack(|s| s.sockets.get::<udp::Socket>(self.handle).endpoint());
                if le.port != 0 {
                    le_to_ep(le)
                } else {
                    match *self.bound_local.lock() {
                        Some(le) => le_to_ep(le),
                        None => unspec,
                    }
                }
            }
            SockKind::Tcp => {
                let smol = self
                    .ns
                    .with_stack(|s| s.sockets.get::<tcp::Socket>(self.handle).local_endpoint());
                match smol {
                    Some(ep) => ep,
                    None => match *self.bound_local.lock() {
                        Some(le) => le_to_ep(le),
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
                let remote = self
                    .ns
                    .with_stack(|s| s.sockets.get::<tcp::Socket>(self.handle).remote_endpoint());
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
        let st = self
            .ns
            .with_stack(|s| s.sockets.get::<tcp::Socket>(self.handle).state());
        if tcp_established_or_past(st) {
            self.opts.lock().ever_established = true;
        } else if st == tcp::State::Closed {
            let mut o = self.opts.lock();
            if o.so_error == 0 {
                o.so_error = 111;
            }
        }
    }

    pub fn do_shutdown(&self, how: i32) -> Result<(), FsError> {
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
                self.ns.with_stack(|s| {
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
        self.ns.with_stack(|s| match self.kind {
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

impl Inode for InetSocket {
    fn kind(&self) -> InodeKind {
        InodeKind::Pipe
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Pipe, 0, 0o600)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        self.read_at_with_flags(offset, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(
        &self,
        _off: u64,
        buf: &mut [u8],
        flags: OpenFlags,
    ) -> Result<usize, FsError> {
        let (n, _peer) = self.recv(buf, flags.contains(OpenFlags::NONBLOCK))?;
        Ok(n)
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
        self.send_payload(buf, None, flags.contains(OpenFlags::NONBLOCK))
    }

    fn poll(&self) -> PollMask {
        self.poll_mask()
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&self.wait);
    }

    fn as_socket(&self) -> Option<&dyn super::Socket> {
        Some(self)
    }

    fn on_close(&self, _flags: OpenFlags) {
        self.ns.unregister_inet(self);
        let pool: alloc::vec::Vec<SocketHandle> = self.listeners.lock().drain(..).collect();
        self.ns.with_stack(|s| {
            if self.kind == SockKind::Tcp {
                s.sockets.get_mut::<tcp::Socket>(self.handle).abort();
                for h in &pool {
                    s.sockets.get_mut::<tcp::Socket>(*h).abort();
                }
            }
        });
        self.ns.with_stack(|s| {
            s.sockets.remove(self.handle);
            for h in pool {
                s.sockets.remove(h);
            }
        });
    }
}

impl super::Socket for InetSocket {
    fn bind(&self, addr: &[u8]) -> i64 {
        let ep = match parse_sockaddr(addr) {
            Ok(e) => e,
            Err(e) => return e.errno(),
        };
        if ep.port != 0
            && ep.port < 1024
            && !crate::security::capable(crate::process::CAP_NET_BIND_SERVICE)
        {
            return crate::errno::EACCES;
        }
        let listen = IpListenEndpoint {
            addr: if ep.addr.is_unspecified() {
                None
            } else {
                Some(ep.addr)
            },
            port: ep.port,
        };
        match self.bind_endpoint(listen) {
            Ok(()) => 0,
            Err(e) => e.errno(),
        }
    }

    fn listen(&self, backlog: i32) -> i64 {
        match self.listen_stream(backlog) {
            Ok(()) => 0,
            Err(e) => e.errno(),
        }
    }

    fn accept(&self, peer_out: Option<(u64, u64)>, nonblock: bool) -> Result<Arc<dyn Inode>, i64> {
        let new_sock = crate::vfs::blocking::block_io::<Arc<InetSocket>>(
            "inet_accept",
            &self.wait,
            nonblock,
            None,
            || match self.try_accept() {
                Ok(s) => crate::vfs::blocking::IoAttempt::Ready(s),
                Err(FsError::WouldBlock) => crate::vfs::blocking::IoAttempt::WouldBlock,
                Err(e) => crate::vfs::blocking::IoAttempt::Err(e),
            },
        )
        .map_err(|e| e.errno())?;
        register(&new_sock);
        if let Some((addr, addrlen)) = peer_out {
            if addr != 0 && addrlen != 0 {
                if let Some(ep) = new_sock.peer_endpoint() {
                    let mut cap = [0u8; 4];
                    if frame::user::copy_from_user(addrlen, &mut cap).is_ok() {
                        let cap = u32::from_le_bytes(cap) as usize;
                        let mut ab = [0u8; SOCKADDR_MAX];
                        let full = write_sockaddr_in(&ep, &mut ab);
                        let n = full.min(cap);
                        let _ = frame::user::copy_to_user(addr, &ab[..n]);
                        let _ = frame::user::copy_to_user(addrlen, &(full as u32).to_le_bytes());
                    }
                }
            }
        }
        Ok(new_sock)
    }

    fn connect(&self, addr: &[u8], nonblock: bool) -> i64 {
        let ep = match parse_sockaddr(addr) {
            Ok(e) => e,
            Err(e) => return e.errno(),
        };
        if self.is_tcp() {
            return self.tcp_connect(ep, nonblock);
        }
        match self.connect_endpoint(ep) {
            Ok(()) => 0,
            Err(e) => e.errno(),
        }
    }

    fn send_to(&self, buf: &[u8], addr: Option<&[u8]>, nonblock: bool) -> i64 {
        let peer = match addr {
            Some(ab) => match parse_sockaddr(ab) {
                Ok(e) => Some(e),
                Err(e) => return e.errno(),
            },
            None => None,
        };
        match self.send_payload(buf, peer, nonblock) {
            Ok(w) => w as i64,
            Err(e) => e.errno(),
        }
    }

    fn recv_from(&self, buf: &mut [u8], peer_out: Option<(u64, u64)>, nonblock: bool) -> i64 {
        let (read, peer) = match self.recv(buf, nonblock) {
            Ok(r) => r,
            Err(e) => return e.errno(),
        };
        if let Some((addr, addrlen_ptr)) = peer_out {
            if addr != 0 && addrlen_ptr != 0 {
                if let Some(ep) = peer {
                    let mut ab = [0u8; SOCKADDR_MAX];
                    let len = write_sockaddr_in(&ep, &mut ab);
                    let _ = frame::user::copy_to_user(addr, &ab[..len]);
                    let _ = frame::user::copy_to_user(addrlen_ptr, &(len as u32).to_le_bytes());
                }
            }
        }
        read as i64
    }

    fn shutdown(&self, how: i32) -> i64 {
        match self.do_shutdown(how) {
            Ok(()) => 0,
            Err(e) => e.errno(),
        }
    }

    fn getsockname(&self, addr_out: u64, len_out: u64) -> i64 {
        copy_sockaddr_to_user(&self.local_name(), addr_out, len_out)
    }

    fn getpeername(&self, addr_out: u64, len_out: u64) -> i64 {
        match self.peer_endpoint() {
            Some(ep) => copy_sockaddr_to_user(&ep, addr_out, len_out),
            None => crate::errno::ENOTCONN,
        }
    }

    fn setsockopt(&self, level: i32, opt: i32, optval: u64, optlen: u64) -> i64 {
        use crate::errno::{EFAULT, EINVAL, ENOPROTOOPT};
        let level = level as u64;
        let opt = opt as u64;
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
                self.opts.lock().reuseaddr = v != 0;
                0
            }
            (SOL_SOCKET, SO_REUSEPORT) => {
                let v = match read_int() {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                self.opts.lock().reuseport = v != 0;
                0
            }
            (SOL_SOCKET, SO_KEEPALIVE) => {
                let v = match read_int() {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                self.opts.lock().keepalive = v != 0;
                if self.is_tcp() {
                    self.apply_smoltcp_sockopt(SmoltcpOpt::Keepalive, if v != 0 { 1 } else { 0 });
                }
                0
            }
            (SOL_SOCKET, SO_BROADCAST) => {
                let v = match read_int() {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                self.opts.lock().broadcast = v != 0;
                0
            }
            (SOL_SOCKET, SO_RCVBUF) => {
                let v = match read_int() {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                self.opts.lock().rcvbuf = (v.max(0) as u32).saturating_mul(2);
                0
            }
            (SOL_SOCKET, SO_SNDBUF) => {
                let v = match read_int() {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                self.opts.lock().sndbuf = (v.max(0) as u32).saturating_mul(2);
                0
            }
            (SOL_SOCKET, SO_RCVTIMEO) => {
                let us = match read_timeval_us() {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                self.opts.lock().rcvtimeo_us = us;
                0
            }
            (SOL_SOCKET, SO_SNDTIMEO) => {
                let us = match read_timeval_us() {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                self.opts.lock().sndtimeo_us = us;
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
                let mut o = self.opts.lock();
                o.linger_on = onoff != 0;
                o.linger_seconds = secs;
                0
            }
            (SOL_SOCKET, SO_DEBUG | SO_DONTROUTE | SO_OOBINLINE) => {
                let _ = read_int();
                0
            }
            (IPPROTO_TCP, TCP_NODELAY) => {
                if !self.is_tcp() {
                    return ENOPROTOOPT;
                }
                let v = match read_int() {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                self.opts.lock().nodelay = v != 0;
                self.apply_smoltcp_sockopt(SmoltcpOpt::TcpNoDelay, if v != 0 { 1 } else { 0 });
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
                self.opts.lock().ip_ttl = ttl;
                if self.is_tcp() {
                    self.apply_smoltcp_sockopt(SmoltcpOpt::HopLimit, ttl as u64);
                }
                0
            }
            (IPPROTO_IP, IP_TOS | IP_PKTINFO) => {
                let _ = read_int();
                0
            }
            (IPPROTO_IPV6, IPV6_V6ONLY | IPV6_UNICAST_HOPS | IPV6_TCLASS | IPV6_RECVPKTINFO) => {
                let _ = read_int();
                0
            }
            _ => ENOPROTOOPT,
        }
    }

    fn getsockopt(&self, level: i32, opt: i32, optval: u64, optlen_ptr: u64) -> i64 {
        use crate::errno::{EFAULT, EINVAL, ENOPROTOOPT};
        let level = level as u64;
        let opt = opt as u64;
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

        let opts = *self.opts.lock();
        match (level, opt) {
            (SOL_SOCKET, SO_TYPE) => write_int(self.sock_type() as i32),
            (SOL_SOCKET, SO_PROTOCOL) => write_int(self.proto() as i32),
            (SOL_SOCKET, SO_DOMAIN) => write_int(match self.family {
                Family::Inet => 2,
                Family::Inet6 => 10,
            }),
            (SOL_SOCKET, SO_ERROR) => write_int(self.take_so_error() as i32),
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
            (IPPROTO_IPV6, IPV6_V6ONLY) => write_int(1),
            (IPPROTO_IPV6, IPV6_UNICAST_HOPS) => write_int(opts.ip_ttl as i32),
            (IPPROTO_IPV6, IPV6_TCLASS | IPV6_RECVPKTINFO) => write_int(0),
            _ => {
                user_len = user_len.min(4);
                let zeroes = [0u8; 4];
                let _ = frame::user::copy_to_user(optval, &zeroes[..user_len]);
                ENOPROTOOPT
            }
        }
    }
}

const SOL_SOCKET: u64 = 1;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_IP: u64 = 0;
const IPPROTO_IPV6: u64 = 41;

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

const IPV6_UNICAST_HOPS: u64 = 16;
const IPV6_V6ONLY: u64 = 26;
const IPV6_RECVPKTINFO: u64 = 49;
const IPV6_TCLASS: u64 = 67;

fn copy_sockaddr_to_user(ep: &IpEndpoint, addr: u64, addrlen_ptr: u64) -> i64 {
    if addr == 0 || addrlen_ptr == 0 {
        return crate::errno::EFAULT;
    }
    let mut cap = [0u8; 4];
    if frame::user::copy_from_user(addrlen_ptr, &mut cap).is_err() {
        return crate::errno::EFAULT;
    }
    let cap = u32::from_le_bytes(cap) as usize;
    let mut ab = [0u8; SOCKADDR_MAX];
    let full = write_sockaddr_in(ep, &mut ab);
    let n = full.min(cap);
    if n > 0 && frame::user::copy_to_user(addr, &ab[..n]).is_err() {
        return crate::errno::EFAULT;
    }
    if frame::user::copy_to_user(addrlen_ptr, &(full as u32).to_le_bytes()).is_err() {
        return crate::errno::EFAULT;
    }
    0
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

pub const SOCKADDR_MAX: usize = 28;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

pub fn parse_sockaddr(buf: &[u8]) -> Result<IpEndpoint, FsError> {
    if buf.len() < 2 {
        return Err(FsError::InvalidArgument);
    }
    match u16::from_le_bytes([buf[0], buf[1]]) {
        AF_INET => parse_sockaddr_in(buf),
        AF_INET6 => parse_sockaddr_in6(buf),
        _ => Err(FsError::InvalidArgument),
    }
}

pub fn parse_sockaddr_in(buf: &[u8]) -> Result<IpEndpoint, FsError> {
    if buf.len() < 8 {
        return Err(FsError::InvalidArgument);
    }
    let fam = u16::from_le_bytes([buf[0], buf[1]]);
    if fam != AF_INET {
        return Err(FsError::InvalidArgument);
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let addr = Ipv4Address::new(buf[4], buf[5], buf[6], buf[7]);
    Ok(IpEndpoint::new(IpAddress::Ipv4(addr), port))
}

pub fn parse_sockaddr_in6(buf: &[u8]) -> Result<IpEndpoint, FsError> {
    if buf.len() < 24 {
        return Err(FsError::InvalidArgument);
    }
    let fam = u16::from_le_bytes([buf[0], buf[1]]);
    if fam != AF_INET6 {
        return Err(FsError::InvalidArgument);
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let addr = Ipv6Address::from_bytes(&buf[8..24]);
    Ok(IpEndpoint::new(IpAddress::Ipv6(addr), port))
}

pub fn write_sockaddr_in(ep: &IpEndpoint, out: &mut [u8]) -> usize {
    out[2..4].copy_from_slice(&ep.port.to_be_bytes());
    match ep.addr {
        IpAddress::Ipv4(a) => {
            out[0..2].copy_from_slice(&AF_INET.to_le_bytes());
            out[4..8].copy_from_slice(a.as_bytes());
            16
        }
        IpAddress::Ipv6(a) => {
            out[0..2].copy_from_slice(&AF_INET6.to_le_bytes());
            out[4..8].copy_from_slice(&0u32.to_le_bytes());
            out[8..24].copy_from_slice(a.as_bytes());
            out[24..28].copy_from_slice(&0u32.to_le_bytes());
            28
        }
    }
}
