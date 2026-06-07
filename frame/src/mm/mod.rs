pub mod addr;
pub mod frame_alloc;
pub mod heap;
pub mod mmio_map;
pub mod vm;

pub use addr::{PAGE_SIZE, Page, PhysAddr, PhysFrame, Size4KiB, VirtAddr};

pub fn zero_frame(frame: PhysFrame<x86_64::structures::paging::Size4KiB>) {
    use crate::boot::KERNEL_VMA_OFFSET;
    let kva = frame.start_address().as_u64() | KERNEL_VMA_OFFSET;
    // SAFETY: `frame` is a freshly-allocated RAM frame. On the supported
    // microvm configuration all usable DRAM is phys < 1 GiB, so it lies in
    // the boot stub's PDPT_high[510] window (phys [0,1 GiB) mapped
    // writable/write-back at KERNEL_VMA_OFFSET) and `pa | KERNEL_VMA_OFFSET`
    // is its unique high-half alias — 4 KiB-aligned and naming exactly these
    // 4096 bytes. (This is a 1 GiB high-half window, not a full physical
    // map; for phys >= 1 GiB the OR-aliasing lands in a device window or on
    // phys 0 — the allocator relies on RAM staying under 1 GiB, see vm.rs.)
    // Writing 4096 bytes from the page-aligned start stays inside the frame
    // and touches no other Rust-visible allocation.
    unsafe {
        core::ptr::write_bytes(kva as *mut u8, 0, 4096);
    }
}

pub fn write_to_frame(
    frame: PhysFrame<x86_64::structures::paging::Size4KiB>,
    offset: usize,
    data: &[u8],
) {
    use crate::boot::KERNEL_VMA_OFFSET;
    let end = offset
        .checked_add(data.len())
        .expect("write_to_frame: offset+len overflow");
    assert!(end <= 4096, "write_to_frame: would overflow page");
    let kva = frame.start_address().as_u64() | KERNEL_VMA_OFFSET;
    // SAFETY: the checked_add + `assert!(end <= 4096)` above guarantee
    // `[offset, offset+data.len())` lies within this frame's 4096 bytes.
    // `frame` is a RAM frame in phys [0,1 GiB), which the boot stub's
    // PDPT_high[510] window maps writable/write-back at `pa |
    // KERNEL_VMA_OFFSET` — the supported microvm config keeps all DRAM under
    // 1 GiB (see vm.rs), so this is its unique high-half-window alias, not a
    // full physical map. Hence the destination `kva + offset` is a valid
    // writable destination for `data.len()` bytes. `data` is a live `&[u8]`
    // valid for that many reads, and the kernel mapping and the caller's
    // slice are disjoint allocations, so source and destination do not
    // overlap.
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), (kva as *mut u8).add(offset), data.len());
    }
}

pub fn read_from_frame(
    frame: PhysFrame<x86_64::structures::paging::Size4KiB>,
    offset: usize,
    buf: &mut [u8],
) {
    use crate::boot::KERNEL_VMA_OFFSET;
    let end = offset
        .checked_add(buf.len())
        .expect("read_from_frame: offset+len overflow");
    assert!(end <= 4096, "read_from_frame: would overflow page");
    let kva = frame.start_address().as_u64() | KERNEL_VMA_OFFSET;
    // SAFETY: the checked_add + `assert!(end <= 4096)` above guarantee
    // `[offset, offset+buf.len())` lies within this frame's 4096 bytes.
    // `frame` is a RAM frame in phys [0,1 GiB), readable via the boot stub's
    // PDPT_high[510] window at `pa | KERNEL_VMA_OFFSET` — the supported
    // microvm config keeps all DRAM under 1 GiB (see vm.rs), so this is its
    // unique high-half-window alias, not a full physical map. Hence the
    // source `kva + offset` is a valid source for `buf.len()` reads. `buf` is
    // a live `&mut [u8]` valid for that many writes, and the kernel mapping
    // and the caller's slice are disjoint allocations, so source and
    // destination do not overlap.
    unsafe {
        core::ptr::copy_nonoverlapping((kva as *const u8).add(offset), buf.as_mut_ptr(), buf.len());
    }
}
