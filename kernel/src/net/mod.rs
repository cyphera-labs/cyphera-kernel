extern crate alloc;

pub mod device;
pub mod epoll;
pub mod inet;
pub mod netlink;
pub mod unix;

use alloc::vec::Vec;

use frame::sync::SpinIrq;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Loopback, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use device::VirtioNetDevice;

use crate::wait::WaitQueue;

pub struct NetStack {
    pub device: Option<VirtioNetDevice>,
    pub iface: Option<Interface>,
    pub loop_device: Loopback,
    pub loop_iface: Interface,
    pub sockets: SocketSet<'static>,
}

static NET: SpinIrq<Option<NetStack>> = SpinIrq::new(None);

static PUMP_WAIT: WaitQueue = WaitQueue::new();

pub fn init() {
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
    });

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
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(10, 0, 2, 2))
                .ok();
            frame::println!(
                "net: smoltcp up; ip 10.0.2.15/24 via 10.0.2.2 (mac {:02x?}) + lo 127.0.0.1/8",
                mac
            );
            (Some(device), Some(iface))
        }
        None => {
            frame::println!("net: smoltcp up; lo 127.0.0.1/8 only (no virtio-net)");
            (None, None)
        }
    };

    *NET.lock() = Some(NetStack {
        device,
        iface,
        loop_device,
        loop_iface,
        sockets: SocketSet::new(Vec::new()),
    });
}

pub fn with_stack<R>(f: impl FnOnce(&mut NetStack) -> R) -> Option<R> {
    let r = {
        let mut g = NET.lock();
        let stack = g.as_mut()?;
        let r = f(stack);
        let now = smoltcp_now();
        if let (Some(iface), Some(device)) = (stack.iface.as_mut(), stack.device.as_mut()) {
            iface.poll(now, device, &mut stack.sockets);
        }
        stack
            .loop_iface
            .poll(now, &mut stack.loop_device, &mut stack.sockets);
        Some(r)
    };
    if r.is_some() {
        inet::wake_all_sockets();
    }
    r
}

pub fn available() -> bool {
    NET.lock().is_some()
}

pub fn signal_pump_tick() {
    PUMP_WAIT.wake_all();
}

extern "C" fn smoltcp_pump() -> ! {
    loop {
        if available() {
            let _ = with_stack(|_| {});
        }
        PUMP_WAIT.park();
    }
}

pub fn start_pump_kthread() {
    if !available() {
        return;
    }
    let _pid = crate::sched::spawn_kthread("smoltcp-pump", smoltcp_pump);
}

fn smoltcp_now() -> Instant {
    let nanos = frame::cpu::nanos_since_boot();
    Instant::from_micros((nanos / 1000) as i64)
}
