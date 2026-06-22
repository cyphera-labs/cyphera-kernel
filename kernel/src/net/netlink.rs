extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::sync::SpinIrq;

use smoltcp::wire::IpCidr;

use cyphera_kapi::{Errno, KResult};

use crate::vfs::{Inode, InodeKind, PollMask, Stat};

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

pub struct NetlinkSocket {
    queue: SpinIrq<VecDeque<Vec<u8>>>,
}

impl NetlinkSocket {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            queue: SpinIrq::new(VecDeque::new()),
        })
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
        if buf.len() < 16 {
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
        } else if msg_type == RTM_GETADDR {
            let mut q = self.queue.lock();
            for (ifindex, cidr) in interface_addrs() {
                q.push_back(build_addr_msg(seq, ifindex, &cidr));
            }
            q.push_back(build_done(seq));
        }
        Ok(buf.len())
    }

    fn read_at(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut q = self.queue.lock();
        let msg = match q.pop_front() {
            Some(m) => m,
            None => return Err(Errno::AGAIN),
        };
        let n = msg.len().min(buf.len());
        buf[..n].copy_from_slice(&msg[..n]);
        Ok(n)
    }

    fn poll(&self) -> PollMask {
        let mut mask = PollMask::OUT;
        if !self.queue.lock().is_empty() {
            mask |= PollMask::IN;
        }
        mask
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
    fn bind(&self, _addr: &[u8]) -> i64 {
        0
    }
}
