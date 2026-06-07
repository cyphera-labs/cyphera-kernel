#![no_std]
#![no_main]

use frame::{boot::parse_hvm_start_info, io::uart, println};

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] virtio_rng: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    println!("[test] virtio_rng: probing virtio-mmio bus");
    virtio::init();

    let mut buf = [0u8; 32];
    let n = virtio::fill_random(&mut buf).expect("virtio-rng fill");
    assert_eq!(n, buf.len(), "rng returned partial buffer");

    print_hex("random bytes", &buf);

    assert!(
        buf.iter().any(|&b| b != 0),
        "rng returned all zeros — device not delivering bytes"
    );

    println!("[test] virtio_rng: PASS");
    frame::io::qemu_exit::exit(frame::io::qemu_exit::ExitCode::Success)
}

fn print_hex(label: &str, bytes: &[u8]) {
    use core::fmt::Write;
    let mut uart = frame::io::uart::UART.lock();
    let _ = write!(uart, "{label}: ");
    for b in bytes {
        let _ = write!(uart, "{:02x}", b);
    }
    let _ = writeln!(uart);
}
