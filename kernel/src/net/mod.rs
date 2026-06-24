extern crate alloc;

pub mod device;
pub mod epoll;
pub mod icmp;
pub mod inet;
pub mod netlink;
pub mod unix;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use frame::sync::SpinIrq;
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::socket::{AnySocket, tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::IpEndpoint;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address,
};

use device::VirtioNetDevice;

use crate::core::wait::WaitQueue;

pub trait Socket {
    fn bind(&self, addr: &[u8]) -> i64 {
        let _ = addr;
        crate::errno::EOPNOTSUPP
    }
    fn listen(&self, backlog: i32) -> i64 {
        let _ = backlog;
        crate::errno::EOPNOTSUPP
    }
    fn accept(
        &self,
        peer_out: Option<(u64, u64)>,
        nonblock: bool,
    ) -> Result<alloc::sync::Arc<dyn crate::vfs::Inode>, i64> {
        let _ = (peer_out, nonblock);
        Err(crate::errno::EOPNOTSUPP)
    }
    fn connect(&self, addr: &[u8], nonblock: bool) -> i64 {
        let _ = (addr, nonblock);
        crate::errno::EOPNOTSUPP
    }
    fn send_to(&self, buf: &[u8], addr: Option<&[u8]>, nonblock: bool) -> i64 {
        let _ = (buf, addr, nonblock);
        crate::errno::EOPNOTSUPP
    }
    fn recv_from(&self, buf: &mut [u8], peer_out: Option<(u64, u64)>, nonblock: bool) -> i64 {
        let _ = (buf, peer_out, nonblock);
        crate::errno::EOPNOTSUPP
    }
    fn shutdown(&self, how: i32) -> i64 {
        let _ = how;
        crate::errno::EOPNOTSUPP
    }
    fn setsockopt(&self, level: i32, opt: i32, optval: u64, optlen: u64) -> i64 {
        let _ = (level, opt, optval, optlen);
        crate::errno::EOPNOTSUPP
    }
    fn getsockopt(&self, level: i32, opt: i32, val_out: u64, len_out: u64) -> i64 {
        let _ = (level, opt, val_out, len_out);
        crate::errno::EOPNOTSUPP
    }
    fn getsockname(&self, addr_out: u64, len_out: u64) -> i64 {
        let _ = (addr_out, len_out);
        crate::errno::EOPNOTSUPP
    }
    fn getpeername(&self, addr_out: u64, len_out: u64) -> i64 {
        let _ = (addr_out, len_out);
        crate::errno::EOPNOTSUPP
    }
}

pub struct NetStack {
    pub device: Option<VirtioNetDevice>,
    pub iface: Option<Interface>,
    pub loop_device: Loopback,
    pub loop_iface: Interface,
    pub sockets: SocketSet<'static>,
    pub loop_sockets: SocketSet<'static>,
    socket_gen: alloc::vec::Vec<(bool, SocketHandle, u64)>,
    gen_ctr: u64,
}

#[derive(Copy, Clone)]
pub struct SockRef {
    handle: SocketHandle,
    loopback: bool,
    generation: u64,
}

impl SockRef {
    pub(crate) fn is_loop(&self) -> bool {
        self.loopback
    }
}

impl NetStack {
    fn set_for(&mut self, loopback: bool) -> &mut SocketSet<'static> {
        if loopback {
            &mut self.loop_sockets
        } else {
            &mut self.sockets
        }
    }

    fn set_ref(&self, loopback: bool) -> &SocketSet<'static> {
        if loopback {
            &self.loop_sockets
        } else {
            &self.sockets
        }
    }

    fn assert_member(&self, r: SockRef) {
        assert!(
            self.socket_gen
                .iter()
                .any(|&(lb, h, g)| lb == r.loopback && h == r.handle && g == r.generation),
            "SockRef used against the wrong socket set or a reused slot"
        );
    }

    pub fn add_socket<T: AnySocket<'static>>(&mut self, loopback: bool, sock: T) -> SockRef {
        let handle = self.set_for(loopback).add(sock);
        let generation = self.gen_ctr;
        self.gen_ctr = self.gen_ctr.wrapping_add(1);
        self.socket_gen.push((loopback, handle, generation));
        SockRef {
            handle,
            loopback,
            generation,
        }
    }

    pub fn remove_socket(&mut self, r: SockRef) -> smoltcp::socket::Socket<'static> {
        self.assert_member(r);
        self.socket_gen
            .retain(|&(lb, h, g)| !(lb == r.loopback && h == r.handle && g == r.generation));
        self.set_for(r.loopback).remove(r.handle)
    }

    pub fn tcp(&self, r: SockRef) -> &tcp::Socket<'static> {
        self.assert_member(r);
        self.set_ref(r.loopback).get::<tcp::Socket>(r.handle)
    }

    pub fn tcp_mut(&mut self, r: SockRef) -> &mut tcp::Socket<'static> {
        self.assert_member(r);
        self.set_for(r.loopback).get_mut::<tcp::Socket>(r.handle)
    }

    pub fn udp(&self, r: SockRef) -> &udp::Socket<'static> {
        self.assert_member(r);
        self.set_ref(r.loopback).get::<udp::Socket>(r.handle)
    }

    pub fn udp_mut(&mut self, r: SockRef) -> &mut udp::Socket<'static> {
        self.assert_member(r);
        self.set_for(r.loopback).get_mut::<udp::Socket>(r.handle)
    }

    pub fn icmp_mut(&mut self, r: SockRef) -> &mut smoltcp::socket::icmp::Socket<'static> {
        self.assert_member(r);
        self.set_for(r.loopback)
            .get_mut::<smoltcp::socket::icmp::Socket>(r.handle)
    }

    pub fn connect_tcp(
        &mut self,
        r: SockRef,
        ep: IpEndpoint,
        local: u16,
    ) -> Result<(), tcp::ConnectError> {
        self.assert_member(r);
        if r.loopback {
            let ctx = self.loop_iface.context();
            self.loop_sockets
                .get_mut::<tcp::Socket>(r.handle)
                .connect(ctx, ep, local)
        } else if let Some(iface) = self.iface.as_mut() {
            let ctx = iface.context();
            self.sockets
                .get_mut::<tcp::Socket>(r.handle)
                .connect(ctx, ep, local)
        } else {
            let ctx = self.loop_iface.context();
            self.sockets
                .get_mut::<tcp::Socket>(r.handle)
                .connect(ctx, ep, local)
        }
    }
}

pub struct NetNamespace {
    stack: SpinIrq<NetStack>,
    inet_registry: SpinIrq<BTreeMap<usize, Arc<inet::InetSocket>>>,
    icmp_registry: SpinIrq<BTreeMap<usize, Arc<icmp::IcmpSocket>>>,
    abstract_bound: SpinIrq<BTreeMap<String, Weak<unix::UnixSocket>>>,
    ephemeral_next: AtomicU16,
    owner_user_ns: Option<Arc<crate::process_model::UserNamespace>>,
}

impl NetNamespace {
    fn new(
        stack: NetStack,
        owner_user_ns: Option<Arc<crate::process_model::UserNamespace>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            stack: SpinIrq::new(stack),
            inet_registry: SpinIrq::new(BTreeMap::new()),
            icmp_registry: SpinIrq::new(BTreeMap::new()),
            abstract_bound: SpinIrq::new(BTreeMap::new()),
            ephemeral_next: AtomicU16::new(32768),
            owner_user_ns,
        })
    }

    pub fn owner_user_ns(&self) -> Option<Arc<crate::process_model::UserNamespace>> {
        self.owner_user_ns.clone()
    }

    pub fn with_stack<R>(&self, f: impl FnOnce(&mut NetStack) -> R) -> R {
        let (r, changed) = {
            let mut guard = self.stack.lock();
            let stack: &mut NetStack = &mut guard;
            let r = f(stack);
            let now = smoltcp_now();
            let mut changed = false;
            if let (Some(iface), Some(device)) = (stack.iface.as_mut(), stack.device.as_mut()) {
                changed |=
                    iface.poll(now, device, &mut stack.sockets) == PollResult::SocketStateChanged;
            }
            changed |= stack
                .loop_iface
                .poll(now, &mut stack.loop_device, &mut stack.loop_sockets)
                == PollResult::SocketStateChanged;
            (r, changed)
        };
        if changed {
            self.wake_inet();
            self.wake_icmp();
        }
        r
    }

    pub fn register_inet(&self, s: &Arc<inet::InetSocket>) {
        let key = Arc::as_ptr(s) as *const () as usize;
        self.inet_registry.lock().insert(key, s.clone());
    }

    pub fn unregister_inet(&self, s: &inet::InetSocket) {
        let key = (s as *const inet::InetSocket) as *const () as usize;
        self.inet_registry.lock().remove(&key);
    }

    fn wake_inet(&self) {
        let socks: Vec<Arc<inet::InetSocket>> =
            self.inet_registry.lock().values().cloned().collect();
        for s in socks {
            s.wake();
        }
    }

    pub fn register_icmp(&self, s: &Arc<icmp::IcmpSocket>) {
        let key = Arc::as_ptr(s) as *const () as usize;
        self.icmp_registry.lock().insert(key, s.clone());
    }

    pub fn unregister_icmp(&self, s: &icmp::IcmpSocket) {
        let key = (s as *const icmp::IcmpSocket) as *const () as usize;
        self.icmp_registry.lock().remove(&key);
    }

    fn wake_icmp(&self) {
        let socks: Vec<Arc<icmp::IcmpSocket>> =
            self.icmp_registry.lock().values().cloned().collect();
        for s in socks {
            s.wake();
        }
    }

    pub fn try_bind_abstract(&self, name: String, sock: Weak<unix::UnixSocket>) -> bool {
        let mut t = self.abstract_bound.lock();
        if t.get(&name).and_then(|w| w.upgrade()).is_some() {
            return false;
        }
        t.insert(name, sock);
        true
    }

    pub fn lookup_abstract(&self, name: &str) -> Option<Arc<unix::UnixSocket>> {
        self.abstract_bound
            .lock()
            .get(name)
            .and_then(|w| w.upgrade())
    }

    pub fn unbind_abstract(&self, name: &str) {
        self.abstract_bound.lock().remove(name);
    }

    pub fn next_ephemeral_port(&self) -> u16 {
        let p = self.ephemeral_next.fetch_add(1, Ordering::Relaxed);
        if p < 32768 {
            self.ephemeral_next.store(32768, Ordering::Relaxed);
            return 32768;
        }
        p
    }

    pub fn has_iface(&self) -> bool {
        self.stack.lock().iface.is_some()
    }
}

static HOST_NS: SpinIrq<Option<Arc<NetNamespace>>> = SpinIrq::new(None);
static NET_NS_LIST: SpinIrq<Vec<Weak<NetNamespace>>> = SpinIrq::new(Vec::new());
static PUMP_WAIT: WaitQueue = WaitQueue::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);

fn register_ns(ns: &Arc<NetNamespace>) {
    NET_NS_LIST.lock().push(Arc::downgrade(ns));
}

fn build_loopback() -> (Loopback, Interface) {
    let mut loop_device = Loopback::new(Medium::Ip);
    let loop_config = Config::new(HardwareAddress::Ip);
    let mut loop_iface = Interface::new(loop_config, &mut loop_device, smoltcp_now());
    loop_iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::new(127, 0, 0, 1)),
                8,
            ))
            .ok();
        addrs
            .push(IpCidr::new(IpAddress::Ipv6(Ipv6Address::LOCALHOST), 128))
            .ok();
        addrs
            .push(IpCidr::new(
                IpAddress::Ipv6(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                64,
            ))
            .ok();
    });
    (loop_device, loop_iface)
}

pub fn init() {
    let (loop_device, loop_iface) = build_loopback();

    let (device, iface) = match virtio::net_mac() {
        Some(mac) => {
            let mut device = VirtioNetDevice;
            let hw_addr = HardwareAddress::Ethernet(EthernetAddress(mac));
            let config = Config::new(hw_addr);
            let mut iface = Interface::new(config, &mut device, smoltcp_now());
            iface.update_ip_addrs(|addrs| {
                addrs
                    .push(IpCidr::new(
                        IpAddress::Ipv4(Ipv4Address::new(10, 0, 2, 15)),
                        24,
                    ))
                    .ok();
                addrs
                    .push(IpCidr::new(
                        IpAddress::Ipv6(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x15)),
                        64,
                    ))
                    .ok();
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(10, 0, 2, 2))
                .ok();
            frame::println!(
                "net: smoltcp up; ip 10.0.2.15/24 via 10.0.2.2 (mac {:02x?}) + lo 127.0.0.1/8 + ::1/128",
                mac
            );
            (Some(device), Some(iface))
        }
        None => {
            frame::println!("net: smoltcp up; lo 127.0.0.1/8 + ::1/128 only (no virtio-net)");
            (None, None)
        }
    };

    let stack = NetStack {
        device,
        iface,
        loop_device,
        loop_iface,
        sockets: SocketSet::new(Vec::new()),
        loop_sockets: SocketSet::new(Vec::new()),
        socket_gen: Vec::new(),
        gen_ctr: 0,
    };
    let ns = NetNamespace::new(stack, None);
    register_ns(&ns);
    *HOST_NS.lock() = Some(ns);
    INITIALIZED.store(true, Ordering::Release);
}

pub fn host_net_ns() -> Arc<NetNamespace> {
    HOST_NS
        .lock()
        .as_ref()
        .expect("net: host namespace not initialized")
        .clone()
}

pub fn new_namespace() -> Arc<NetNamespace> {
    new_namespace_with_owner(None)
}

pub fn new_namespace_with_owner(
    owner_user_ns: Option<Arc<crate::process_model::UserNamespace>>,
) -> Arc<NetNamespace> {
    let (loop_device, loop_iface) = build_loopback();
    let stack = NetStack {
        device: None,
        iface: None,
        loop_device,
        loop_iface,
        sockets: SocketSet::new(Vec::new()),
        loop_sockets: SocketSet::new(Vec::new()),
        socket_gen: Vec::new(),
        gen_ctr: 0,
    };
    let ns = NetNamespace::new(stack, owner_user_ns);
    register_ns(&ns);
    ns
}

pub fn signal_pump_tick() {
    PUMP_WAIT.wake_all();
}

fn pump_all() {
    let nss: Vec<Arc<NetNamespace>> = {
        let mut list = NET_NS_LIST.lock();
        list.retain(|w| w.strong_count() > 0);
        list.iter().filter_map(|w| w.upgrade()).collect()
    };
    for ns in nss {
        ns.with_stack(|_| {});
    }
}

extern "C" fn smoltcp_pump() -> ! {
    loop {
        if INITIALIZED.load(Ordering::Acquire) {
            pump_all();
        }
        PUMP_WAIT.park();
    }
}

pub fn start_pump_kthread() {
    let _pid = crate::process_model::spawn_kthread("smoltcp-pump", smoltcp_pump);
}

fn smoltcp_now() -> Instant {
    let nanos = frame::cpu::nanos_since_boot();
    Instant::from_micros((nanos / 1000) as i64)
}
