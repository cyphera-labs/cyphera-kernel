#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

use frame::{
    boot::{BootProtocol, parse_hvm_start_info, parse_multiboot2_info},
    cpu, println,
};

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32, protocol_raw: u32) -> ! {
    frame::io::uart::init();

    let protocol = BootProtocol::from_raw(protocol_raw);
    match protocol {
        BootProtocol::Pvh => {
            println!("Cyphera Kernel booting (PVH; hvm_start_info @ {boot_info_ptr:#x})")
        }
        BootProtocol::Multiboot2 => {
            println!("Cyphera Kernel booting (multiboot2; info @ {boot_info_ptr:#x})")
        }
    }

    // SAFETY: the boot stub guarantees `boot_info_ptr` matches the
    // selected protocol's info struct, and we're called exactly once
    // before anything has touched the bootloader-placed memory region.
    let boot_info = unsafe {
        match protocol {
            BootProtocol::Pvh => parse_hvm_start_info(boot_info_ptr),
            BootProtocol::Multiboot2 => parse_multiboot2_info(boot_info_ptr),
        }
    };
    println!("memory map: {} regions", boot_info.memory_map.len());
    for region in boot_info.memory_map {
        println!(
            "  [{:#016x}-{:#016x}] {:?} ({} KiB)",
            region.start,
            region.end,
            region.kind,
            region.size() / 1024
        );
    }
    println!("boot modules: {} found", boot_info.modules.len());
    for (i, m) in boot_info.modules.iter().enumerate() {
        println!(
            "  module[{}]: paddr={:#x} size={} KiB cmdline={}",
            i,
            m.paddr,
            m.size / 1024,
            m.cmdline_paddr.map(|p| p as i64).unwrap_or(-1),
        );
    }

    // SAFETY: invoked once, on the BSP, IRQs are off (we never enabled
    // them since boot.s).
    unsafe { frame::init(&boot_info) };

    println!("frame online");

    kernel::init();
    kernel::boot_banner();

    if frame::boot::modules().is_empty() {
        println!(
            "init: no initrd module supplied; halting (boot kernel with `-initrd ...` or a GRUB module2 entry)"
        );
        cpu::halt();
    }
    println!("init: handing off to PID 1 via exec_init");
    kernel::init_exec::exec_init();
}
