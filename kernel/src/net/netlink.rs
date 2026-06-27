extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use frame::sync::SpinIrq;

use smoltcp::wire::IpCidr;

use cyphera_kapi::KResult;

use crate::core::wait::WaitQueue;
use crate::vfs::blocking::IoAttempt;
use crate::vfs::{Inode, InodeKind, OpenFlags, PollMask, Stat};

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const NLMSG_DONE: u16 = 3;
const NLM_F_MULTI: u16 = 2;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const ARPHRD_LOOPBACK: u16 = 772;
const ARPHRD_ETHER: u16 = 1;

const NETLINK_ROUTE: i32 = 0;
const NETLINK_KOBJECT_UEVENT: i32 = 15;

const SOL_NETLINK: i32 = 270;
const NETLINK_ADD_MEMBERSHIP: i32 = 1;
const NETLINK_DROP_MEMBERSHIP: i32 = 2;
const SOL_SOCKET: i32 = 1;
const SO_PASSCRED: i32 = 16;

const UEVENT_GROUP: u32 = 1;

static UEVENT_LISTENERS: SpinIrq<Vec<Weak<NetlinkSocket>>> = SpinIrq::new(Vec::new());
static UEVENT_SEQ: AtomicU64 = AtomicU64::new(1);

pub struct NetlinkSocket {
    protocol: i32,
    queue: SpinIrq<VecDeque<Vec<u8>>>,
    waiters: WaitQueue,
    passcred: AtomicBool,
    groups: AtomicU32,
}

impl NetlinkSocket {
    pub fn new(protocol: i32) -> Arc<Self> {
        let s = Arc::new(Self {
            protocol,
            queue: SpinIrq::new(VecDeque::new()),
            waiters: WaitQueue::new(),
            passcred: AtomicBool::new(false),
            groups: AtomicU32::new(0),
        });
        if protocol == NETLINK_KOBJECT_UEVENT {
            UEVENT_LISTENERS.lock().push(Arc::downgrade(&s));
        }
        s
    }

    fn group_bit(group: u32) -> u32 {
        if group == 0 || group > 32 {
            0
        } else {
            1u32 << (group - 1)
        }
    }

    fn add_membership(&self, group: u32) {
        let bit = Self::group_bit(group);
        if bit != 0 {
            self.groups.fetch_or(bit, Ordering::Relaxed);
        }
    }

    fn drop_membership(&self, group: u32) {
        let bit = Self::group_bit(group);
        if bit != 0 {
            self.groups.fetch_and(!bit, Ordering::Relaxed);
        }
    }

    fn in_group(&self, group: u32) -> bool {
        let bit = Self::group_bit(group);
        bit != 0 && self.groups.load(Ordering::Relaxed) & bit != 0
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        if self.protocol == NETLINK_KOBJECT_UEVENT {
            let me = self as *const NetlinkSocket;
            UEVENT_LISTENERS
                .lock()
                .retain(|w| !core::ptr::eq(w.as_ptr(), me));
        }
    }
}

pub fn emit_uevent(action: &str, devpath: &str, props: &[(&str, &str)]) {
    fn put(msg: &mut Vec<u8>, k: &str, v: &str) {
        msg.extend_from_slice(k.as_bytes());
        msg.push(b'=');
        msg.extend_from_slice(v.as_bytes());
        msg.push(0);
    }
    let seq = UEVENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut msg: Vec<u8> = Vec::new();
    msg.extend_from_slice(action.as_bytes());
    msg.push(b'@');
    msg.extend_from_slice(devpath.as_bytes());
    msg.push(0);
    put(&mut msg, "ACTION", action);
    put(&mut msg, "DEVPATH", devpath);
    for (k, v) in props {
        put(&mut msg, k, v);
    }
    let seq_s: String = alloc::format!("{seq}");
    put(&mut msg, "SEQNUM", &seq_s);

    let targets: Vec<Arc<NetlinkSocket>> = {
        let mut listeners = UEVENT_LISTENERS.lock();
        listeners.retain(|w| w.strong_count() > 0);
        listeners.iter().filter_map(|w| w.upgrade()).collect()
    };
    for s in targets {
        if s.groups.load(Ordering::Relaxed) != 0 && !s.in_group(UEVENT_GROUP) {
            continue;
        }
        s.queue.lock().push_back(msg.clone());
        s.waiters.wake_all();
    }
}

impl Inode for NetlinkSocket {
    fn kind(&self) -> InodeKind {
        InodeKind::Pipe
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Pipe, 0, 0o600)
    }

    fn write_at(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        if self.protocol != NETLINK_ROUTE || buf.len() < 16 {
            return Ok(buf.len());
        }
        let msg_type = u16::from_le_bytes([buf[4], buf[5]]);
        let seq = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if msg_type == RTM_GETLINK {
            let mut q = self.queue.lock();
            q.push_back(build_link_msg(
                seq,
                1,
                "lo",
                &[0; 6],
                65536,
                ARPHRD_LOOPBACK,
            ));
            if crate::core::current_net_ns().has_iface() {
                let mac = virtio::net_mac().unwrap_or([0; 6]);
                q.push_back(build_link_msg(seq, 2, "eth0", &mac, 1500, ARPHRD_ETHER));
            }
            q.push_back(build_done(seq));
            drop(q);
            self.waiters.wake_all();
        } else if msg_type == RTM_GETADDR {
            let mut q = self.queue.lock();
            for (ifindex, cidr) in interface_addrs() {
                q.push_back(build_addr_msg(seq, ifindex, &cidr));
            }
            q.push_back(build_done(seq));
            drop(q);
            self.waiters.wake_all();
        }
        Ok(buf.len())
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_at_with_flags(off, buf, OpenFlags::empty())
    }

    fn read_at_with_flags(&self, _off: u64, buf: &mut [u8], flags: OpenFlags) -> KResult<usize> {
        let nonblock = flags.contains(OpenFlags::NONBLOCK);
        crate::vfs::blocking::block_io("netlink_read", &self.waiters, nonblock, None, || {
            let mut q = self.queue.lock();
            match q.pop_front() {
                Some(msg) => {
                    let n = msg.len().min(buf.len());
                    buf[..n].copy_from_slice(&msg[..n]);
                    IoAttempt::Ready(n)
                }
                None => IoAttempt::WouldBlock,
            }
        })
    }

    fn read_with_fds(
        &self,
        buf: &mut [u8],
        nonblock: bool,
    ) -> KResult<(usize, Vec<alloc::sync::Arc<crate::vfs::OpenFile>>)> {
        let flags = if nonblock {
            OpenFlags::NONBLOCK
        } else {
            OpenFlags::empty()
        };
        let n = self.read_at_with_flags(0, buf, flags)?;
        Ok((n, Vec::new()))
    }

    fn poll(&self) -> PollMask {
        let mut mask = PollMask::OUT;
        if !self.queue.lock().is_empty() {
            mask |= PollMask::IN;
        }
        mask
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&self.waiters);
    }

    fn as_socket(&self) -> Option<&dyn super::Socket> {
        Some(self)
    }
}

fn build_link_msg(
    seq: u32,
    ifindex: i32,
    name: &str,
    mac: &[u8],
    mtu: u32,
    ifi_type: u16,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(&RTM_NEWLINK.to_le_bytes());
    buf.extend_from_slice(&NLM_F_MULTI.to_le_bytes());
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    buf.push(0);
    buf.push(0);
    buf.extend_from_slice(&ifi_type.to_le_bytes());
    buf.extend_from_slice(&ifindex.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    push_attr(&mut buf, IFLA_IFNAME, name.as_bytes(), true);
    push_attr(&mut buf, IFLA_ADDRESS, mac, false);
    push_attr(&mut buf, IFLA_MTU, &mtu.to_le_bytes(), false);

    let total = buf.len() as u32;
    buf[0..4].copy_from_slice(&total.to_le_bytes());
    buf
}

fn push_attr(buf: &mut Vec<u8>, kind: u16, data: &[u8], add_nul: bool) {
    let payload_len = data.len() + if add_nul { 1 } else { 0 };
    let attr_len = 4 + payload_len;
    buf.extend_from_slice(&(attr_len as u16).to_le_bytes());
    buf.extend_from_slice(&kind.to_le_bytes());
    buf.extend_from_slice(data);
    if add_nul {
        buf.push(0);
    }
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

fn build_done(seq: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&20u32.to_le_bytes());
    buf.extend_from_slice(&NLMSG_DONE.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf
}

fn interface_addrs() -> Vec<(i32, IpCidr)> {
    crate::core::current_net_ns().with_stack(|s| {
        let mut v: Vec<(i32, IpCidr)> = Vec::new();
        for c in s.loop_iface.ip_addrs() {
            v.push((1, *c));
        }
        if let Some(eth) = s.iface.as_ref() {
            for c in eth.ip_addrs() {
                v.push((2, *c));
            }
        }
        v
    })
}

fn build_addr_msg(seq: u32, ifindex: i32, cidr: &IpCidr) -> Vec<u8> {
    let (family, prefix, addr): (u8, u8, Vec<u8>) = match cidr {
        IpCidr::Ipv4(c) => (2, c.prefix_len(), c.address().octets().to_vec()),
        IpCidr::Ipv6(c) => (10, c.prefix_len(), c.address().octets().to_vec()),
    };
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(&RTM_NEWADDR.to_le_bytes());
    buf.extend_from_slice(&NLM_F_MULTI.to_le_bytes());
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    buf.push(family);
    buf.push(prefix);
    buf.push(0);
    buf.push(0);
    buf.extend_from_slice(&(ifindex as u32).to_le_bytes());

    push_attr(&mut buf, IFA_ADDRESS, &addr, false);
    push_attr(&mut buf, IFA_LOCAL, &addr, false);

    let total = buf.len() as u32;
    buf[0..4].copy_from_slice(&total.to_le_bytes());
    buf
}

impl super::Socket for NetlinkSocket {
    fn bind(&self, addr: &[u8]) -> i64 {
        if addr.len() >= 12 {
            let nl_groups = u32::from_le_bytes([addr[8], addr[9], addr[10], addr[11]]);
            self.groups.store(nl_groups, Ordering::Relaxed);
        }
        0
    }
    fn setsockopt(&self, level: i32, opt: i32, optval: u64, optlen: u64) -> i64 {
        if level == SOL_SOCKET && opt == SO_PASSCRED {
            self.passcred.store(true, Ordering::Relaxed);
            return 0;
        }
        if level == SOL_NETLINK && matches!(opt, NETLINK_ADD_MEMBERSHIP | NETLINK_DROP_MEMBERSHIP) {
            if optlen < 4 {
                return crate::errno::EINVAL;
            }
            let mut buf = [0u8; 4];
            if frame::user::copy_from_user(optval, &mut buf).is_err() {
                return crate::errno::EFAULT;
            }
            let group = u32::from_le_bytes(buf);
            if opt == NETLINK_ADD_MEMBERSHIP {
                self.add_membership(group);
            } else {
                self.drop_membership(group);
            }
        }
        0
    }
    fn recv_creds(&self) -> Option<(i32, u32, u32)> {
        if self.protocol == NETLINK_KOBJECT_UEVENT && self.passcred.load(Ordering::Relaxed) {
            Some((0, 0, 0))
        } else {
            None
        }
    }
    fn recv_src_addr(&self) -> Option<Vec<u8>> {
        if self.protocol == NETLINK_KOBJECT_UEVENT {
            let mut a = alloc::vec![0u8; 12];
            a[0..2].copy_from_slice(&16u16.to_le_bytes());
            a[8..12].copy_from_slice(&1u32.to_le_bytes());
            Some(a)
        } else {
            None
        }
    }
}
