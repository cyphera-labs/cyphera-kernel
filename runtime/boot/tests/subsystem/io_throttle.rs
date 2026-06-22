#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;

use frame::{boot::parse_hvm_start_info, io::qemu_exit, io::uart, println};

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] io_throttle: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };
    kernel::init();

    println!("[test] io_throttle: running tests");

    let root: Arc<kernel::cgroup::Cgroup> = kernel::cgroup::root();
    {
        let mut io = root.io.lock();
        io.max_wbps = Some(4 * 1024);
    }
    println!("[test] io_throttle: io.max wbps=4KiB/s on root cgroup");

    kernel::process_model::spawn_kthread("io_throttle_worker", io_worker_entry);

    kernel::core::start_first()
}

extern "C" fn io_worker_entry() -> ! {
    let cg = kernel::core::current_cgroup();
    let expected_root = kernel::cgroup::root();
    if cg.is_none() || !Arc::ptr_eq(&cg.unwrap(), &expected_root) {
        println!("[test] io_throttle: kthread not in root cgroup — fail");
        qemu_exit::exit(qemu_exit::ExitCode::Failed);
    }

    let start = frame::cpu::clock::nanos_since_boot();

    let payload = [0xAAu8; 512];
    for i in 0..16u64 {
        if let Err(e) = kernel::io::block_write(1024 + i, &payload) {
            println!("[test] io_throttle: block_write failed: {:?}", e);
            qemu_exit::exit(qemu_exit::ExitCode::Failed);
        }
    }

    let end = frame::cpu::clock::nanos_since_boot();
    let elapsed_ms = (end - start) / 1_000_000;
    println!(
        "[test] io_throttle: 16 x 512B writes elapsed {} ms",
        elapsed_ms
    );

    if elapsed_ms < 500 {
        println!(
            "[test] io_throttle: too fast ({} ms) — io.max not enforced",
            elapsed_ms
        );
        qemu_exit::exit(qemu_exit::ExitCode::Failed);
    }

    println!("IO_THROTTLE_OK");
    qemu_exit::exit(qemu_exit::ExitCode::Success);
}
