extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;

use frame::sync::SpinIrq;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::icmp;
use smoltcp::wire::{IpAddress, IpEndpoint};

use crate::vfs::{FsError, Inode, InodeKind, OpenFlags, PollMask, Stat};
use crate::wait::WaitQueue;

pub fn register(s: &Arc<IcmpSocket>) {
    s.ns.register_icmp(s);
}

const RX_BYTES: usize = 16 * 1024;
const META_SLOTS: usize = 16;

pub struct IcmpSocket {
    handle: SocketHandle,
    ns: Arc<crate::net::NetNamespace>,
    bound: SpinIrq<bool>,
    peer: SpinIrq<Option<IpAddress>>,
    wait: WaitQueue,
}

impl IcmpSocket {
    pub fn new() -> Result<Arc<Self>, FsError> {
        let rx = icmp::PacketBuffer::new(
            vec![icmp::PacketMetadata::EMPTY; META_SLOTS],
            vec![0u8; RX_BYTES],
        );
        let tx = icmp::PacketBuffer::new(
            vec![icmp::PacketMetadata::EMPTY; META_SLOTS],
            vec![0u8; RX_BYTES],
        );
        let socket = icmp::Socket::new(rx, tx);
        let ns = crate::sched::current_net_ns();
        let handle = ns.with_stack(|s| s.sockets.add(socket));
        Ok(Arc::new(Self {
            handle,
            ns,
            bound: SpinIrq::new(false),
            peer: SpinIrq::new(None),
            wait: WaitQueue::new(),
        }))
    }

    pub fn wake(&self) {
        self.wait.wake_all();
    }

    fn ensure_bound(&self, ident: u16) -> Result<(), FsError> {
        let mut b = self.bound.lock();
        if !*b {
            self.ns.with_stack(|s| {
                let sock = s.sockets.get_mut::<icmp::Socket>(self.handle);
                sock.bind(icmp::Endpoint::Ident(ident))
                    .map_err(|_| FsError::InvalidArgument)
            })?;
            *b = true;
        }
        Ok(())
    }

    fn try_send(&self, buf: &[u8], dst: IpAddress) -> Result<usize, FsError> {
        if buf.len() < 8 {
            return Err(FsError::InvalidArgument);
        }
        let ident = u16::from_be_bytes([buf[4], buf[5]]);
        self.ensure_bound(ident)?;
        self.ns.with_stack(|s| {
            let sock = s.sockets.get_mut::<icmp::Socket>(self.handle);
            if !sock.can_send() {
                return Err(FsError::WouldBlock);
            }
            sock.send_slice(buf, dst).map_err(|_| FsError::Io)?;
            Ok(buf.len())
        })
    }

    fn try_recv(&self, buf: &mut [u8]) -> Result<(usize, IpAddress), FsError> {
        self.ns.with_stack(|s| {
            let sock = s.sockets.get_mut::<icmp::Socket>(self.handle);
            if !sock.can_recv() {
                return Err(FsError::WouldBlock);
            }
            sock.recv_slice(buf).map_err(|_| FsError::Io)
        })
    }

    fn recv_loop(&self, buf: &mut [u8], nonblock: bool) -> Result<(usize, IpAddress), FsError> {
        crate::vfs::blocking::block_io("icmp_recv", &self.wait, nonblock, None, || {
            match self.try_recv(buf) {
                Ok(r) => crate::vfs::blocking::IoAttempt::Ready(r),
                Err(FsError::WouldBlock) => crate::vfs::blocking::IoAttempt::WouldBlock,
                Err(e) => crate::vfs::blocking::IoAttempt::Err(e),
            }
        })
    }
}

impl super::Socket for IcmpSocket {
    fn connect(&self, addr: &[u8], _nonblock: bool) -> i64 {
        match super::inet::parse_sockaddr(addr) {
            Ok(ep) => {
                *self.peer.lock() = Some(ep.addr);
                0
            }
            Err(e) => e.errno(),
        }
    }

    fn send_to(&self, buf: &[u8], addr: Option<&[u8]>, _nonblock: bool) -> i64 {
        let dst = match addr {
            Some(ab) => match super::inet::parse_sockaddr(ab) {
                Ok(ep) => ep.addr,
                Err(e) => return e.errno(),
            },
            None => match *self.peer.lock() {
                Some(a) => a,
                None => return crate::errno::EDESTADDRREQ,
            },
        };
        match self.try_send(buf, dst) {
            Ok(n) => n as i64,
            Err(e) => e.errno(),
        }
    }

    fn recv_from(&self, buf: &mut [u8], peer_out: Option<(u64, u64)>, nonblock: bool) -> i64 {
        match self.recv_loop(buf, nonblock) {
            Ok((n, src)) => {
                if let Some((addr, addrlen_ptr)) = peer_out {
                    if addr != 0 && addrlen_ptr != 0 {
                        let mut ab = [0u8; super::inet::SOCKADDR_MAX];
                        let len = super::inet::write_sockaddr_in(&IpEndpoint::new(src, 0), &mut ab);
                        let _ = frame::user::copy_to_user(addr, &ab[..len]);
                        let _ = frame::user::copy_to_user(addrlen_ptr, &(len as u32).to_le_bytes());
                    }
                }
                n as i64
            }
            Err(e) => e.errno(),
        }
    }
}

impl Inode for IcmpSocket {
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
        self.recv_loop(buf, flags.contains(OpenFlags::NONBLOCK))
            .map(|(n, _)| n)
    }

    fn write_at(&self, _off: u64, buf: &[u8]) -> Result<usize, FsError> {
        let dst = self.peer.lock().ok_or(FsError::InvalidArgument)?;
        self.try_send(buf, dst)
    }

    fn poll(&self) -> PollMask {
        self.ns.with_stack(|s| {
            let sock = s.sockets.get_mut::<icmp::Socket>(self.handle);
            let mut m = PollMask::empty();
            if sock.can_recv() {
                m |= PollMask::IN;
            }
            if sock.can_send() {
                m |= PollMask::OUT;
            }
            m
        })
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&self.wait);
    }

    fn as_socket(&self) -> Option<&dyn super::Socket> {
        Some(self)
    }

    fn on_close(&self, _flags: OpenFlags) {
        self.ns.unregister_icmp(self);
        self.ns.with_stack(|s| s.sockets.remove(self.handle));
    }
}
