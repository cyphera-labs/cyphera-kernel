extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::sync::SpinIrq;

use crate::vfs::{FsError, Inode, InodeKind, Stat};

const RTM_GETLINK: u16 = 18;
const RTM_NEWLINK: u16 = 16;
const NLMSG_DONE: u16 = 3;
const NLM_F_MULTI: u16 = 2;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;

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

    fn write_at(&self, _off: u64, buf: &[u8]) -> Result<usize, FsError> {
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
            if let Some(mac) = virtio::net_mac() {
                q.push_back(build_link_msg(seq, 2, "eth0", &mac, 1500, ARPHRD_ETHER));
            }
            q.push_back(build_done(seq));
        }
        Ok(buf.len())
    }

    fn read_at(&self, _off: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let mut q = self.queue.lock();
        let msg = match q.pop_front() {
            Some(m) => m,
            None => return Err(FsError::WouldBlock),
        };
        let n = msg.len().min(buf.len());
        buf[..n].copy_from_slice(&msg[..n]);
        Ok(n)
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
