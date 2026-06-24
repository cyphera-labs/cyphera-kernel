extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;

use frame::sync::SpinIrq;
use smoltcp::socket::icmp;
use smoltcp::wire::{IpAddress, IpEndpoint};

use cyphera_kapi::{Errno, KResult};

use super::SockRef;
use crate::core::wait::WaitQueue;
use crate::vfs::{Inode, InodeKind, OpenFlags, PollMask, Stat};

pub fn register(s: &Arc<IcmpSocket>) {
    s.ns.register_icmp(s);
}

const RX_BYTES: usize = 16 * 1024;
const META_SLOTS: usize = 16;

pub struct IcmpSocket {
    handle: SockRef,
    loop_handle: SockRef,
    ns: Arc<crate::net::NetNamespace>,
    bound: SpinIrq<bool>,
    peer: SpinIrq<Option<IpAddress>>,
    wait: WaitQueue,
}

impl IcmpSocket {
    fn new_icmp_socket() -> icmp::Socket<'static> {
        let rx = icmp::PacketBuffer::new(
            vec![icmp::PacketMetadata::EMPTY; META_SLOTS],
            vec![0u8; RX_BYTES],
        );
        let tx = icmp::PacketBuffer::new(
            vec![icmp::PacketMetadata::EMPTY; META_SLOTS],
            vec![0u8; RX_BYTES],
        );
        icmp::Socket::new(rx, tx)
    }

    pub fn new() -> KResult<Arc<Self>> {
        let ns = crate::core::current_net_ns();
        let (handle, loop_handle) = ns.with_stack(|s| {
            let ext = s.add_socket(false, Self::new_icmp_socket());
            let lp = s.add_socket(true, Self::new_icmp_socket());
            (ext, lp)
        });
        Ok(Arc::new(Self {
            handle,
            loop_handle,
            ns,
            bound: SpinIrq::new(false),
            peer: SpinIrq::new(None),
            wait: WaitQueue::new(),
        }))
    }

    pub fn wake(&self) {
        self.wait.wake_all();
    }

    fn endpoints(&self) -> [SockRef; 2] {
        [self.handle, self.loop_handle]
    }

    fn ref_for(&self, is_loop: bool) -> SockRef {
        if is_loop {
            self.loop_handle
        } else {
            self.handle
        }
    }

    fn ensure_bound(&self, ident: u16) -> KResult<()> {
        let mut b = self.bound.lock();
        if !*b {
            for r in self.endpoints() {
                self.ns.with_stack(|s| {
                    s.icmp_mut(r)
                        .bind(icmp::Endpoint::Ident(ident))
                        .map_err(|_| Errno::INVAL)
                })?;
            }
            *b = true;
        }
        Ok(())
    }

    fn try_send(&self, buf: &[u8], dst: IpAddress) -> KResult<usize> {
        if buf.len() < 8 {
            return Err(Errno::INVAL);
        }
        let ident = u16::from_be_bytes([buf[4], buf[5]]);
        self.ensure_bound(ident)?;
        let r = self.ref_for(super::inet::addr_is_loop(dst));
        self.ns.with_stack(|s| {
            let sock = s.icmp_mut(r);
            if !sock.can_send() {
                return Err(Errno::AGAIN);
            }
            sock.send_slice(buf, dst).map_err(|_| Errno::IO)?;
            Ok(buf.len())
        })
    }

    fn try_recv(&self, buf: &mut [u8]) -> KResult<(usize, IpAddress)> {
        for rf in self.endpoints() {
            let got: KResult<Option<(usize, IpAddress)>> = self.ns.with_stack(|s| {
                let sock = s.icmp_mut(rf);
                if !sock.can_recv() {
                    return Ok(None);
                }
                sock.recv_slice(buf).map(Some).map_err(|_| Errno::IO)
            });
            if let Some(r) = got? {
                return Ok(r);
            }
        }
        Err(Errno::AGAIN)
    }

    fn recv_loop(&self, buf: &mut [u8], nonblock: bool) -> KResult<(usize, IpAddress)> {
        crate::vfs::blocking::block_io("icmp_recv", &self.wait, nonblock, None, || {
            match self.try_recv(buf) {
                Ok(r) => crate::vfs::blocking::IoAttempt::Ready(r),
                Err(Errno::AGAIN) => crate::vfs::blocking::IoAttempt::WouldBlock,
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
            Err(e) => e.as_neg_i64(),
        }
    }

    fn send_to(&self, buf: &[u8], addr: Option<&[u8]>, _nonblock: bool) -> i64 {
        let dst = match addr {
            Some(ab) => match super::inet::parse_sockaddr(ab) {
                Ok(ep) => ep.addr,
                Err(e) => return e.as_neg_i64(),
            },
            None => match *self.peer.lock() {
                Some(a) => a,
                None => return crate::errno::EDESTADDRREQ,
            },
        };
        match self.try_send(buf, dst) {
            Ok(n) => n as i64,
            Err(e) => e.as_neg_i64(),
        }
    }

    fn recv_from(&self, buf: &mut [u8], peer_out: Option<(u64, u64)>, nonblock: bool) -> i64 {
        match self.recv_loop(buf, nonblock) {
            Ok((n, src)) => {
                if let Some((addr, addrlen_ptr)) = peer_out {
                    if addr != 0 && addrlen_ptr != 0 {
                        let _ = super::inet::copy_sockaddr_to_user(
                            &IpEndpoint::new(src, 0),
                            addr,
                            addrlen_ptr,
                        );
                    }
                }
                n as i64
            }
            Err(e) => e.as_neg_i64(),
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

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(&self, _off: u64, buf: &mut [u8], flags: OpenFlags) -> KResult<usize> {
        self.recv_loop(buf, flags.contains(OpenFlags::NONBLOCK))
            .map(|(n, _)| n)
    }

    fn write_at(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        let dst = self.peer.lock().ok_or(Errno::INVAL)?;
        self.try_send(buf, dst)
    }

    fn poll(&self) -> PollMask {
        let mut m = PollMask::empty();
        for r in self.endpoints() {
            self.ns.with_stack(|s| {
                let sock = s.icmp_mut(r);
                if sock.can_recv() {
                    m |= PollMask::IN;
                }
                if sock.can_send() {
                    m |= PollMask::OUT;
                }
            });
        }
        m
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&self.wait);
    }

    fn as_socket(&self) -> Option<&dyn super::Socket> {
        Some(self)
    }

    fn on_close(&self, _flags: OpenFlags) {
        self.ns.unregister_icmp(self);
        self.ns.with_stack(|s| {
            s.remove_socket(self.handle);
            s.remove_socket(self.loop_handle);
        });
    }
}
