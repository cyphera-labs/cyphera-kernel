#![no_std]
#![no_main]

extern crate alloc;

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

    // Heap-allocate test buffers so they don't inflate the kernel_main
    // stack frame. In debug/coverage builds (opt-level < 3) the compiler
    // reserves space for every local in the enclosing frame before the
    // first statement executes — including before virtio::init() is
    // called above. The ~6 KiB of buffers below, combined with the deep
    // uninlined call chain inside VirtIOSound::new() (4 virtqueues, each
    // with DMA descriptor tables), overflows the 64 KiB bootstrap stack
    // and causes a silent triple fault. Boxing moves the storage onto the
    // heap and keeps the kernel_main frame small.
    let mut sector = alloc::boxed::Box::new([0u8; 512]);
    virtio::read_block_sector(0, sector.as_mut()).expect("read sector 0");
    let magic = &sector[..11];
    assert_eq!(magic, b"CYPHERA-BLK", "sector 0 magic mismatch");

    println!(
        "[test] virtio_blk: sector 0 magic OK ({:?})",
        core::str::from_utf8(magic).unwrap()
    );

    let mut payload = alloc::boxed::Box::new([0u8; 512]);
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }
    virtio::write_block_sector(1, payload.as_ref()).expect("write sector 1");

    let mut readback = alloc::boxed::Box::new([0u8; 512]);
    virtio::read_block_sector(1, readback.as_mut()).expect("readback sector 1");
    assert_eq!(*payload, *readback, "sector 1 round-trip mismatch");
    println!("[test] virtio_blk: sector 1 round-trip OK");

    let mut multi = alloc::boxed::Box::new([0u8; 512 * 4]);
    for (i, b) in multi.iter_mut().enumerate() {
        *b = ((i * 7 + 3) & 0xff) as u8;
    }
    virtio::write_block_sector(8, multi.as_ref()).expect("multi-sector write");
    let mut readback4 = alloc::boxed::Box::new([0u8; 512 * 4]);
    virtio::read_block_sector(8, readback4.as_mut()).expect("multi-sector readback");
    assert_eq!(*multi, *readback4, "multi-sector round-trip mismatch");
    let mut bad = alloc::boxed::Box::new([0u8; 500]);
    assert!(
        virtio::read_block_sector(0, bad.as_mut()).is_err(),
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
