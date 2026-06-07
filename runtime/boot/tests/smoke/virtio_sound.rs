#![no_std]
#![no_main]

use frame::{boot::parse_hvm_start_info, io::uart, println};

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] virtio_sound: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    println!("[test] virtio_sound: probing virtio-mmio bus");
    virtio::init();

    let (jacks, streams, chmaps) =
        virtio::sound_topology().expect("virtio-sound device not detected on the mmio bus");
    println!(
        "[test] virtio_sound: jacks={} streams={} chmaps={}",
        jacks, streams, chmaps
    );
    assert_eq!(jacks, 1, "expected jacks=1 from run-qemu.sh");
    assert_eq!(streams, 2, "expected streams=2 from run-qemu.sh");
    assert_eq!(chmaps, 1, "expected chmaps=1 from run-qemu.sh");

    let outputs = virtio::sound_output_streams().expect("enumerate output streams");
    println!("[test] virtio_sound: output_streams={:?}", outputs);
    assert!(
        !outputs.is_empty(),
        "device advertises no playback streams — a client would have nowhere to send PCM"
    );

    println!("[test] virtio_sound: PASS");
    frame::io::qemu_exit::exit(frame::io::qemu_exit::ExitCode::Success)
}
