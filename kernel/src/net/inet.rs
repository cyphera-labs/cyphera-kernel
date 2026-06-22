extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;

use frame::sync::SpinIrq;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::{tcp, udp};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address};

use cyphera_kapi::{Errno, KResult};

use crate::core::wait::WaitQueue;
use crate::vfs::{Inode, InodeKind, OpenFlags, PollMask, Stat};

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
enum Realm {
    Ext,
    Loop,
    Both,
}

pub(crate) fn addr_is_loop(addr: IpAddress) -> bool {
    match addr {
        IpAddress::Ipv4(a) => a.is_loopback(),
        IpAddress::Ipv6(a) => a == Ipv6Address::LOCALHOST,
    }
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
    handle: SpinIrq<SocketHandle>,
    loop_handle: SpinIrq<Option<SocketHandle>>,
    realm: SpinIrq<Realm>,
    kind: SockKind,
    family: Family,
    ns: Arc<crate::net::NetNamespace>,
    peer: SpinIrq<Option<IpEndpoint>>,
    bound_local: SpinIrq<Option<IpListenEndpoint>>,
    listening: SpinIrq<bool>,
    listeners: SpinIrq<alloc::vec::Vec<(SocketHandle, bool)>>,
    wait: WaitQueue,
    pub opts: SpinIrq<SockOpts>,
}

impl InetSocket {
    fn new_udp_socket() -> udp::Socket<'static> {
        let metadata_storage = vec![udp::PacketMetadata::EMPTY; UDP_META_SLOTS];
        let payload_storage = vec![0u8; UDP_BUFFER_BYTES];
        let metadata_storage_2 = metadata_storage.clone();
        let payload_storage_2 = payload_storage.clone();
        let rx = udp::PacketBuffer::new(metadata_storage, payload_storage);
        let tx = udp::PacketBuffer::new(metadata_storage_2, payload_storage_2);
        udp::Socket::new(rx, tx)
    }

    pub fn new_udp(family: Family) -> KResult<Arc<Self>> {
        let ns = crate::core::current_net_ns();
        let (handle, loop_handle) = ns.with_stack(|s| {
            let ext = s.sockets.add(Self::new_udp_socket());
            let lp = s.loop_sockets.add(Self::new_udp_socket());
            (ext, lp)
        });
        Ok(Arc::new(Self {
            handle: SpinIrq::new(handle),
            loop_handle: SpinIrq::new(Some(loop_handle)),
            realm: SpinIrq::new(Realm::Both),
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

    pub fn new_tcp(family: Family) -> KResult<Arc<Self>> {
        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let socket = tcp::Socket::new(rx, tx);
        let ns = crate::core::current_net_ns();
        let handle = ns.with_stack(|s| s.sockets.add(socket));
        Ok(Arc::new(Self {
            handle: SpinIrq::new(handle),
            loop_handle: SpinIrq::new(None),
            realm: SpinIrq::new(Realm::Ext),
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
        is_loop: bool,
    ) -> KResult<SocketHandle> {
        let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUFFER_BYTES]);
        let socket = tcp::Socket::new(rx, tx);
        ns.with_stack(|s| {
            let h = s.set(is_loop).add(socket);
            let sock = s.set(is_loop).get_mut::<tcp::Socket>(h);
            sock.listen(local).map(|_| h).map_err(|_| Errno::INVAL)
        })
    }

    pub fn handle(&self) -> SocketHandle {
        *self.handle.lock()
    }

    fn primary_loop(&self) -> bool {
        *self.realm.lock() == Realm::Loop
    }

    fn udp_endpoints(&self) -> alloc::vec::Vec<(SocketHandle, bool)> {
        let mut v = alloc::vec![(*self.handle.lock(), false)];
        if let Some(h) = *self.loop_handle.lock() {
            v.push((h, true));
        }
        v
    }

    fn udp_handle_for(&self, is_loop: bool) -> SocketHandle {
        if is_loop {
            self.loop_handle.lock().unwrap_or(*self.handle.lock())
        } else {
            *self.handle.lock()
        }
    }

    fn place_tcp_handle(&self, is_loop: bool) {
        let target = if is_loop { Realm::Loop } else { Realm::Ext };
        if *self.realm.lock() == target {
            return;
        }
        let old = *self.handle.lock();
        let from_loop = self.primary_loop();
        let moved = self.ns.with_stack(|s| {
            let sock = s.set(from_loop).remove(old);
            s.set(is_loop).add(sock)
        });
        *self.handle.lock() = moved;
        *self.realm.lock() = target;
    }

    pub fn bind_endpoint(&self, ep: IpListenEndpoint) -> KResult<()> {
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
                for (h, is_loop) in self.udp_endpoints() {
                    self.ns.with_stack(|s| {
                        let sock = s.set(is_loop).get_mut::<udp::Socket>(h);
                        sock.bind(ep).map_err(|_| Errno::INVAL)
                    })?;
                }
                ep
            }
            SockKind::Tcp => ep,
        };
        *self.bound_local.lock() = Some(ep);
        Ok(())
    }

    pub fn connect_endpoint(&self, ep: IpEndpoint) -> KResult<()> {
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
                let is_loop = addr_is_loop(ep.addr);
                self.place_tcp_handle(is_loop);
                let handle = *self.handle.lock();
                self.ns.with_stack(|s| {
                    match (is_loop, s.iface.as_mut()) {
                        (false, Some(iface)) => {
                            let ctx = iface.context();
                            let sock = s.sockets.get_mut::<tcp::Socket>(handle);
                            sock.connect(ctx, ep, local)
                        }
                        _ => {
                            let ctx = s.loop_iface.context();
                            let sock = s.loop_sockets.get_mut::<tcp::Socket>(handle);
                            sock.connect(ctx, ep, local)
                        }
                    }
                    .map_err(|_| Errno::INVAL)
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
        let (h, is_loop) = (*self.handle.lock(), self.primary_loop());
        self.ns
            .with_stack(|s| s.set(is_loop).get::<tcp::Socket>(h).state())
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
            return e.as_neg_i64();
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
                let (h, is_loop) = (*self.handle.lock(), self.primary_loop());
                let st = self
                    .ns
                    .with_stack(|s| s.set(is_loop).get::<tcp::Socket>(h).state());
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
            Err(Errno::INTR) => crate::errno::EINTR,
            Err(e) => e.as_neg_i64(),
        }
    }

    pub fn listen_stream(&self, backlog: i32) -> KResult<()> {
        match self.kind {
            SockKind::Udp => Err(Errno::INVAL),
            SockKind::Tcp => {
                let local = self.bound_local.lock().ok_or(Errno::INVAL)?;
                let n = (backlog.max(1) as usize).min(MAX_LISTEN_BACKLOG);
                let realms: &[bool] = match local.addr {
                    None => &[false, true],
                    Some(addr) if addr_is_loop(addr) => &[true],
                    Some(_) => &[false],
                };
                let mut pool = alloc::vec::Vec::with_capacity(n * realms.len());
                for _ in 0..n {
                    for &is_loop in realms {
                        pool.push((Self::new_tcp_listener(&self.ns, local, is_loop)?, is_loop));
                    }
                }
                *self.realm.lock() = match local.addr {
                    None => Realm::Both,
                    Some(addr) if addr_is_loop(addr) => Realm::Loop,
                    Some(_) => Realm::Ext,
                };
                *self.listeners.lock() = pool;
                *self.listening.lock() = true;
                Ok(())
            }
        }
    }

    pub fn try_accept(&self) -> KResult<Arc<Self>> {
        if self.kind != SockKind::Tcp || !*self.listening.lock() {
            return Err(Errno::INVAL);
        }
        let local = self.bound_local.lock().ok_or(Errno::INVAL)?;

        let mut pool = self.listeners.lock();
        if pool.is_empty() {
            return Err(Errno::INVAL);
        }

        let mut active_idx = None;
        for (i, &(h, is_loop)) in pool.iter().enumerate() {
            let active = self.ns.with_stack(|s| {
                let sock = s.set(is_loop).get::<tcp::Socket>(h);
                sock.is_active()
            });
            if active {
                active_idx = Some(i);
                break;
            }
        }
        let idx = match active_idx {
            Some(i) => i,
            None => return Err(Errno::AGAIN),
        };
        let (accepted_handle, accepted_loop) = pool[idx];
        let replacement = Self::new_tcp_listener(&self.ns, local, accepted_loop)?;
        pool[idx] = (replacement, accepted_loop);
        drop(pool);

        let remote = self.ns.with_stack(|s| {
            s.set(accepted_loop)
                .get::<tcp::Socket>(accepted_handle)
                .remote_endpoint()
        });

        Ok(Arc::new(InetSocket {
            handle: SpinIrq::new(accepted_handle),
            loop_handle: SpinIrq::new(None),
            realm: SpinIrq::new(if accepted_loop {
                Realm::Loop
            } else {
                Realm::Ext
            }),
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
    ) -> KResult<usize> {
        use crate::vfs::blocking::IoAttempt;
        if self.opts.lock().shut_wr {
            return Err(Errno::PIPE);
        }
        let target = match peer.or_else(|| *self.peer.lock()) {
            Some(p) => p,
            None => return Err(Errno::INVAL),
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
        let dst_loop = addr_is_loop(target.addr);
        crate::vfs::blocking::block_io(site, &self.wait, nonblock, None, || {
            self.ns.with_stack(|s| match self.kind {
                SockKind::Udp => {
                    let h = self.udp_handle_for(dst_loop);
                    let sock = s.set(dst_loop).get_mut::<udp::Socket>(h);
                    match sock.send_slice(buf, target) {
                        Ok(()) => IoAttempt::Ready(buf.len()),
                        Err(udp::SendError::BufferFull) => IoAttempt::WouldBlock,
                        Err(_) => IoAttempt::Err(Errno::IO),
                    }
                }
                SockKind::Tcp => {
                    let (h, is_loop) = (*self.handle.lock(), self.primary_loop());
                    let sock = s.set(is_loop).get_mut::<tcp::Socket>(h);
                    if !sock.may_send() {
                        return IoAttempt::Err(Errno::PIPE);
                    }
                    match sock.send_slice(buf) {
                        Ok(0) if !buf.is_empty() => IoAttempt::WouldBlock,
                        Ok(n) => IoAttempt::Ready(n),
                        Err(_) => IoAttempt::Err(Errno::IO),
                    }
                }
            })
        })
    }

    pub fn try_recv_from(&self, buf: &mut [u8]) -> KResult<(usize, Option<IpEndpoint>)> {
        if self.opts.lock().shut_rd {
            return Ok((0, None));
        }
        match self.kind {
            SockKind::Udp => {
                for (h, is_loop) in self.udp_endpoints() {
                    let got: KResult<Option<(usize, Option<IpEndpoint>)>> =
                        self.ns.with_stack(|s| {
                            let sock = s.set(is_loop).get_mut::<udp::Socket>(h);
                            if !sock.can_recv() {
                                return Ok(None);
                            }
                            let (n, meta) = sock.recv_slice(buf).map_err(|_| Errno::IO)?;
                            Ok(Some((n, Some(meta.endpoint))))
                        });
                    if let Some(r) = got? {
                        return Ok(r);
                    }
                }
                Err(Errno::AGAIN)
            }
            SockKind::Tcp => {
                let ever_established = self.opts.lock().ever_established;
                let (h, is_loop) = (*self.handle.lock(), self.primary_loop());
                self.ns.with_stack(|s| {
                    let sock = s.set(is_loop).get_mut::<tcp::Socket>(h);
                    if !sock.can_recv() {
                        if !sock.may_recv()
                            && (ever_established || tcp_established_or_past(sock.state()))
                        {
                            return Ok((0, None));
                        }
                        return Err(Errno::AGAIN);
                    }
                    let n = sock.recv_slice(buf).map_err(|_| Errno::IO)?;
                    Ok((n, None))
                })
            }
        }
    }

    pub fn recv(&self, buf: &mut [u8], nonblock: bool) -> KResult<(usize, Option<IpEndpoint>)> {
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
                Err(Errno::AGAIN) => crate::vfs::blocking::IoAttempt::WouldBlock,
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
                    .any(|(h, is_loop)| s.set(*is_loop).get::<tcp::Socket>(*h).is_active())
            });
            return if any_active {
                PollMask::IN
            } else {
                PollMask::empty()
            };
        }
        if self.kind == SockKind::Udp {
            let mut m = PollMask::empty();
            for (h, is_loop) in self.udp_endpoints() {
                self.ns.with_stack(|s| {
                    let sock = s.set(is_loop).get_mut::<udp::Socket>(h);
                    if sock.can_recv() {
                        m |= PollMask::IN;
                    }
                    if sock.can_send() {
                        m |= PollMask::OUT;
                    }
                });
            }
            return m;
        }
        let (h, is_loop) = (*self.handle.lock(), self.primary_loop());
        let (mask, established) = self.ns.with_stack(|s| {
            let mut m = PollMask::empty();
            let mut est = false;
            match self.kind {
                SockKind::Udp => {}
                SockKind::Tcp => {
                    let sock = s.set(is_loop).get_mut::<tcp::Socket>(h);
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
                let h = *self.handle.lock();
                let le = self
                    .ns
                    .with_stack(|s| s.sockets.get::<udp::Socket>(h).endpoint());
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
                let (h, is_loop) = (*self.handle.lock(), self.primary_loop());
                let smol = self
                    .ns
                    .with_stack(|s| s.set(is_loop).get::<tcp::Socket>(h).local_endpoint());
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
                let (h, is_loop) = (*self.handle.lock(), self.primary_loop());
                let remote = self
                    .ns
                    .with_stack(|s| s.set(is_loop).get::<tcp::Socket>(h).remote_endpoint());
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
        let (h, is_loop) = (*self.handle.lock(), self.primary_loop());
        let st = self
            .ns
            .with_stack(|s| s.set(is_loop).get::<tcp::Socket>(h).state());
        if tcp_established_or_past(st) {
            self.opts.lock().ever_established = true;
        } else if st == tcp::State::Closed {
            let mut o = self.opts.lock();
            if o.so_error == 0 {
                o.so_error = 111;
            }
        }
    }

    pub fn do_shutdown(&self, how: i32) -> KResult<()> {
        const SHUT_RD: i32 = 0;
        const SHUT_WR: i32 = 1;
        const SHUT_RDWR: i32 = 2;
        if !matches!(how, SHUT_RD | SHUT_WR | SHUT_RDWR) {
            return Err(Errno::INVAL);
        }
        let mut o = self.opts.lock();
        if how == SHUT_RD || how == SHUT_RDWR {
            o.shut_rd = true;
        }
        if how == SHUT_WR || how == SHUT_RDWR {
            o.shut_wr = true;
            if self.kind == SockKind::Tcp {
                let (h, is_loop) = (*self.handle.lock(), self.primary_loop());
                self.ns.with_stack(|s| {
                    let sock = s.set(is_loop).get_mut::<tcp::Socket>(h);
                    sock.close();
                });
            }
        }
        drop(o);
        self.wait.wake_all();
        Ok(())
    }

    pub fn apply_smoltcp_sockopt(&self, kind: SmoltcpOpt, val: u64) {
        let (h, is_loop) = (*self.handle.lock(), self.primary_loop());
        self.ns.with_stack(|s| match self.kind {
            SockKind::Tcp => {
                let sock = s.set(is_loop).get_mut::<tcp::Socket>(h);
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

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_at_with_flags(offset, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(&self, _off: u64, buf: &mut [u8], flags: OpenFlags) -> KResult<usize> {
        let (n, _peer) = self.recv(buf, flags.contains(OpenFlags::NONBLOCK))?;
        Ok(n)
    }

    fn write_at(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        self.write_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn write_at_with_flags(&self, _off: u64, buf: &[u8], flags: OpenFlags) -> KResult<usize> {
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
        let pool: alloc::vec::Vec<(SocketHandle, bool)> = self.listeners.lock().drain(..).collect();
        let primary = (*self.handle.lock(), self.primary_loop());
        let loop_udp = *self.loop_handle.lock();
        self.ns.with_stack(|s| {
            if self.kind == SockKind::Tcp {
                s.set(primary.1).get_mut::<tcp::Socket>(primary.0).abort();
                for (h, is_loop) in &pool {
                    s.set(*is_loop).get_mut::<tcp::Socket>(*h).abort();
                }
            }
        });
        self.ns.with_stack(|s| {
            s.set(primary.1).remove(primary.0);
            if let Some(h) = loop_udp {
                s.loop_sockets.remove(h);
            }
            for (h, is_loop) in pool {
                s.set(is_loop).remove(h);
            }
        });
    }
}

impl super::Socket for InetSocket {
    fn bind(&self, addr: &[u8]) -> i64 {
        let ep = match parse_sockaddr(addr) {
            Ok(e) => e,
            Err(e) => return e.as_neg_i64(),
        };
        if ep.port != 0
            && ep.port < 1024
            && !crate::security::capable(crate::process_model::CAP_NET_BIND_SERVICE)
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
            Err(e) => e.as_neg_i64(),
        }
    }

    fn listen(&self, backlog: i32) -> i64 {
        match self.listen_stream(backlog) {
            Ok(()) => 0,
            Err(e) => e.as_neg_i64(),
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
                Err(Errno::AGAIN) => crate::vfs::blocking::IoAttempt::WouldBlock,
                Err(e) => crate::vfs::blocking::IoAttempt::Err(e),
            },
        )
        .map_err(|e| e.as_neg_i64())?;
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
            Err(e) => return e.as_neg_i64(),
        };
        if self.is_tcp() {
            return self.tcp_connect(ep, nonblock);
        }
        match self.connect_endpoint(ep) {
            Ok(()) => 0,
            Err(e) => e.as_neg_i64(),
        }
    }

    fn send_to(&self, buf: &[u8], addr: Option<&[u8]>, nonblock: bool) -> i64 {
        let peer = match addr {
            Some(ab) => match parse_sockaddr(ab) {
                Ok(e) => Some(e),
                Err(e) => return e.as_neg_i64(),
            },
            None => None,
        };
        match self.send_payload(buf, peer, nonblock) {
            Ok(w) => w as i64,
            Err(e) => e.as_neg_i64(),
        }
    }

    fn recv_from(&self, buf: &mut [u8], peer_out: Option<(u64, u64)>, nonblock: bool) -> i64 {
        let (read, peer) = match self.recv(buf, nonblock) {
            Ok(r) => r,
            Err(e) => return e.as_neg_i64(),
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
            Err(e) => e.as_neg_i64(),
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

pub fn parse_sockaddr(buf: &[u8]) -> KResult<IpEndpoint> {
    if buf.len() < 2 {
        return Err(Errno::INVAL);
    }
    match u16::from_le_bytes([buf[0], buf[1]]) {
        AF_INET => parse_sockaddr_in(buf),
        AF_INET6 => parse_sockaddr_in6(buf),
        _ => Err(Errno::INVAL),
    }
}

pub fn parse_sockaddr_in(buf: &[u8]) -> KResult<IpEndpoint> {
    if buf.len() < 8 {
        return Err(Errno::INVAL);
    }
    let fam = u16::from_le_bytes([buf[0], buf[1]]);
    if fam != AF_INET {
        return Err(Errno::INVAL);
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let addr = Ipv4Address::new(buf[4], buf[5], buf[6], buf[7]);
    Ok(IpEndpoint::new(IpAddress::Ipv4(addr), port))
}

pub fn parse_sockaddr_in6(buf: &[u8]) -> KResult<IpEndpoint> {
    if buf.len() < 24 {
        return Err(Errno::INVAL);
    }
    let fam = u16::from_le_bytes([buf[0], buf[1]]);
    if fam != AF_INET6 {
        return Err(Errno::INVAL);
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let mut o6 = [0u8; 16];
    o6.copy_from_slice(&buf[8..24]);
    let addr = Ipv6Address::from(o6);
    Ok(IpEndpoint::new(IpAddress::Ipv6(addr), port))
}

pub fn write_sockaddr_in(ep: &IpEndpoint, out: &mut [u8]) -> usize {
    out[2..4].copy_from_slice(&ep.port.to_be_bytes());
    match ep.addr {
        IpAddress::Ipv4(a) => {
            out[0..2].copy_from_slice(&AF_INET.to_le_bytes());
            out[4..8].copy_from_slice(&a.octets());
            16
        }
        IpAddress::Ipv6(a) => {
            out[0..2].copy_from_slice(&AF_INET6.to_le_bytes());
            out[4..8].copy_from_slice(&0u32.to_le_bytes());
            out[8..24].copy_from_slice(&a.octets());
            out[24..28].copy_from_slice(&0u32.to_le_bytes());
            28
        }
    }
}
