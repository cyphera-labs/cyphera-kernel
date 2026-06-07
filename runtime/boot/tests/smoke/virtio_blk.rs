#![no_std]
#![no_main]

use frame::{boot::parse_hvm_start_info, io::uart, println};

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] virtio_blk: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    virtio::init();

    let cap = virtio::block_capacity_sectors().expect("no virtio-blk found");
    println!("[test] virtio_blk: capacity = {cap} sectors");
    assert!(cap > 0);

    let mut sector = [0u8; 512];
    virtio::read_block_sector(0, &mut sector).expect("read sector 0");
    let magic = &sector[..11];
    assert_eq!(magic, b"CYPHERA-BLK", "sector 0 magic mismatch");

    println!(
        "[test] virtio_blk: sector 0 magic OK ({:?})",
        core::str::from_utf8(magic).unwrap()
    );

    let mut payload = [0u8; 512];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }
    virtio::write_block_sector(1, &payload).expect("write sector 1");

    let mut readback = [0u8; 512];
    virtio::read_block_sector(1, &mut readback).expect("readback sector 1");
    assert_eq!(payload, readback, "sector 1 round-trip mismatch");
    println!("[test] virtio_blk: sector 1 round-trip OK");

    let mut multi = [0u8; 512 * 4];
    for (i, b) in multi.iter_mut().enumerate() {
        *b = ((i * 7 + 3) & 0xff) as u8;
    }
    virtio::write_block_sector(8, &multi).expect("multi-sector write");
    let mut readback4 = [0u8; 512 * 4];
    virtio::read_block_sector(8, &mut readback4).expect("multi-sector readback");
    assert_eq!(multi, readback4, "multi-sector round-trip mismatch");
    let mut bad = [0u8; 500];
    assert!(
        virtio::read_block_sector(0, &mut bad).is_err(),
        "non-multiple-of-512 must be rejected, not panic"
    );
    let mut empty: [u8; 0] = [];
    assert!(
        virtio::read_block_sector(0, &mut empty).is_err(),
        "empty buffer must be rejected, not panic"
    );
    println!("[test] virtio_blk: multi-sector round-trip OK");

    println!("[test] virtio_blk: PASS");
    frame::io::qemu_exit::exit(frame::io::qemu_exit::ExitCode::Success)
}
