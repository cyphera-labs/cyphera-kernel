#![no_std]
#![no_main]

use frame::{
    boot::{KERNEL_VMA_OFFSET, parse_hvm_start_info},
    io::{
        qemu_exit::{ExitCode, exit},
        uart,
    },
    mm::{direct_map, frame_alloc},
    println,
};

const SENTINEL: u64 = 0xDEAD_BEEF_CAFE_F00D;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] direct_map_alias: bringing up frame");

    let boot_info = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&boot_info) };

    let end = direct_map::end();
    assert!(end > 0, "direct map not live after frame::init");
    println!("[test] direct_map_alias: direct map live, end = {:#x}", end);

    let f = frame_alloc::alloc_frame().expect("alloc_frame");
    let pa = f.start_address().as_u64();
    let va = direct_map::phys_to_virt(pa);
    // SAFETY: `f` is a frame we exclusively own; the direct map aliases it
    // writable at `va`, and a u64 write at the page-aligned start is in bounds.
    unsafe { core::ptr::write_volatile(va as *mut u64, SENTINEL) };
    let va2 = direct_map::phys_to_virt(pa);
    // SAFETY: `va2` is the same frame's direct-map alias re-derived from `pa`;
    // reading the u64 just written is in bounds.
    let readback = unsafe { core::ptr::read_volatile(va2 as *const u64) };
    assert_eq!(readback, SENTINEL, "direct-map alias is not coherent");
    assert_eq!(
        direct_map::virt_to_phys(va),
        pa,
        "phys->virt->phys round-trip"
    );
    assert!(direct_map::is_mapped(pa), "owned RAM frame must be mapped");
    const PCI_HOLE_PA: u64 = 0xc000_0000;
    if end > PCI_HOLE_PA {
        assert!(
            !direct_map::is_mapped(PCI_HOLE_PA),
            "PCI-hole PA below end() must be unmapped"
        );
    }
    frame_alloc::free_frame(f);
    println!("[test] direct_map_alias: owned-frame alias + round-trip + is_mapped OK (pa {pa:#x})");

    let hi = end / 2;
    assert_eq!(
        direct_map::virt_to_phys(direct_map::phys_to_virt(hi)),
        hi,
        "high-PA round-trip"
    );
    println!("[test] direct_map_alias: high-PA round-trip OK ({hi:#x})");

    let img_va = kernel_main as *const () as usize as u64;
    assert!(
        img_va >= KERNEL_VMA_OFFSET,
        "kernel_main must be an image VA"
    );
    assert_eq!(
        direct_map::virt_to_phys(img_va),
        img_va - KERNEL_VMA_OFFSET,
        "image-VA branch of virt_to_phys"
    );
    println!("[test] direct_map_alias: image-VA branch OK");

    println!("[test] direct_map_alias: PASS");
    exit(ExitCode::Success)
}
