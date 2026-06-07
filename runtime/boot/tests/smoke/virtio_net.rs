#![no_std]
#![no_main]

use frame::{boot::parse_hvm_start_info, io::uart, println};

const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const OUR_IP: [u8; 4] = [10, 0, 2, 15];
const TARGET_IP: [u8; 4] = [10, 0, 2, 2];

const ETHER_BCAST: [u8; 6] = [0xff; 6];
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const ARP_REQUEST: [u8; 2] = [0x00, 0x01];
const ARP_REPLY: [u8; 2] = [0x00, 0x02];

fn build_arp_request() -> [u8; 60] {
    let mut frame = [0u8; 60];

    frame[..6].copy_from_slice(&ETHER_BCAST);
    frame[6..12].copy_from_slice(&OUR_MAC);
    frame[12..14].copy_from_slice(&ETHERTYPE_ARP);

    frame[14..16].copy_from_slice(&[0x00, 0x01]);
    frame[16..18].copy_from_slice(&[0x08, 0x00]);
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&ARP_REQUEST);
    frame[22..28].copy_from_slice(&OUR_MAC);
    frame[28..32].copy_from_slice(&OUR_IP);
    frame[32..38].copy_from_slice(&[0; 6]);
    frame[38..42].copy_from_slice(&TARGET_IP);
    frame
}

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] virtio_net: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };
    virtio::init();

    let mac = virtio::net_mac().expect("no virtio-net found");
    println!(
        "[test] virtio_net: MAC = {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    assert_eq!(mac, OUR_MAC, "MAC mismatch");

    let frame = build_arp_request();
    virtio::net_send(&frame).expect("net_send ARP");
    println!("[test] virtio_net: ARP request sent (60 bytes)");

    let mut buf = [0u8; 2048];
    let mut got_reply = false;
    for _ in 0..1_000_000 {
        match virtio::net_try_recv(&mut buf) {
            Ok(n) if n >= 42 => {
                let etype = &buf[12..14];
                let arp_op = &buf[20..22];
                if etype == ETHERTYPE_ARP && arp_op == ARP_REPLY {
                    let sender_mac = &buf[22..28];
                    let sender_ip = &buf[28..32];
                    println!(
                        "[test] virtio_net: ARP reply from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ip {}.{}.{}.{}",
                        sender_mac[0],
                        sender_mac[1],
                        sender_mac[2],
                        sender_mac[3],
                        sender_mac[4],
                        sender_mac[5],
                        sender_ip[0],
                        sender_ip[1],
                        sender_ip[2],
                        sender_ip[3],
                    );
                    assert_eq!(sender_ip, &TARGET_IP, "ARP sender_ip mismatch");
                    got_reply = true;
                    break;
                }
            }
            _ => {}
        }
    }

    assert!(got_reply, "no ARP reply received within poll budget");
    println!("[test] virtio_net: PASS");
    frame::io::qemu_exit::exit(frame::io::qemu_exit::ExitCode::Success)
}
