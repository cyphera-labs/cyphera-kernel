#![no_main]

use libfuzzer_sys::fuzz_target;
use smoltcp::wire::{
    ArpPacket, EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(eth) = EthernetFrame::new_checked(data) {
        let _ = eth.src_addr();
        let _ = eth.dst_addr();
        let ethertype = eth.ethertype();
        let payload = eth.payload();

        match ethertype {
            EthernetProtocol::Ipv4 => walk_ipv4(payload),
            EthernetProtocol::Arp => {
                if let Ok(arp) = ArpPacket::new_checked(payload) {
                    let _ = arp.operation();
                    let _ = arp.source_hardware_addr();
                    let _ = arp.source_protocol_addr();
                    let _ = arp.target_hardware_addr();
                    let _ = arp.target_protocol_addr();
                }
            }
            _ => {}
        }
    }

    walk_ipv4(data);
    if let Ok(udp) = UdpPacket::new_checked(data) {
        let _ = udp.src_port();
        let _ = udp.dst_port();
        let _ = udp.len();
        let _ = udp.checksum();
        let _ = udp.payload();
    }
    if let Ok(tcp) = TcpPacket::new_checked(data) {
        let _ = tcp.src_port();
        let _ = tcp.dst_port();
        let _ = tcp.seq_number();
        let _ = tcp.ack_number();
        let _ = tcp.window_len();
        let _ = tcp.urgent_at();
        let _ = tcp.options();
        let _ = tcp.payload();
    }
});

fn walk_ipv4(bytes: &[u8]) {
    let Ok(ip) = Ipv4Packet::new_checked(bytes) else {
        return;
    };
    let _ = ip.version();
    let _ = ip.header_len();
    let _ = ip.dscp();
    let _ = ip.ecn();
    let _ = ip.total_len();
    let _ = ip.ident();
    let _ = ip.frag_offset();
    let _ = ip.hop_limit();
    let _ = ip.src_addr();
    let _ = ip.dst_addr();
    let _ = ip.checksum();
    let proto = ip.next_header();
    let payload = ip.payload();

    match proto {
        IpProtocol::Tcp => {
            if let Ok(tcp) = TcpPacket::new_checked(payload) {
                let _ = tcp.src_port();
                let _ = tcp.dst_port();
                let _ = tcp.options();
                let _ = tcp.payload();
            }
        }
        IpProtocol::Udp => {
            if let Ok(udp) = UdpPacket::new_checked(payload) {
                let _ = udp.src_port();
                let _ = udp.dst_port();
                let _ = udp.payload();
            }
        }
        _ => {}
    }
}
