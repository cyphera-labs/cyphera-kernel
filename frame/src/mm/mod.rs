pub mod addr;
pub mod direct_map;
pub mod frame_alloc;
pub mod heap;
pub mod mmio_map;
pub mod vm;

pub use addr::{PAGE_SIZE, Page, PhysAddr, PhysFrame, Size4KiB, VirtAddr};
pub use vm::AddrSpaceRoot;

pub fn zero_frame(frame: PhysFrame<x86_64::structures::paging::Size4KiB>) {
    let kva = crate::mm::direct_map::phys_to_virt(frame.start_address().as_u64());
    // SAFETY: the direct map aliases all physical RAM writable/write-back at
    // DIRECT_MAP_BASE, so phys_to_virt(pa) is the frame's unique alias; the
    // 4096-byte write from its page-aligned start stays within the frame.
    unsafe {
        core::ptr::write_bytes(kva as *mut u8, 0, 4096);
    }
}

pub fn write_to_frame(
    frame: PhysFrame<x86_64::structures::paging::Size4KiB>,
    offset: usize,
    data: &[u8],
) {
    let end = offset
        .checked_add(data.len())
        .expect("write_to_frame: offset+len overflow");
    assert!(end <= 4096, "write_to_frame: would overflow page");
    let kva = crate::mm::direct_map::phys_to_virt(frame.start_address().as_u64());
    // SAFETY: the checked bound keeps [offset, offset+data.len()) within the
    // frame, which the direct map aliases writable at DIRECT_MAP_BASE; `data`
    // is a live slice valid for that many reads and disjoint from the mapping.
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), (kva as *mut u8).add(offset), data.len());
    }
}

pub fn read_from_frame(
    frame: PhysFrame<x86_64::structures::paging::Size4KiB>,
    offset: usize,
    buf: &mut [u8],
) {
    let end = offset
        .checked_add(buf.len())
        .expect("read_from_frame: offset+len overflow");
    assert!(end <= 4096, "read_from_frame: would overflow page");
    let kva = crate::mm::direct_map::phys_to_virt(frame.start_address().as_u64());
    // SAFETY: the checked bound keeps [offset, offset+buf.len()) within the
    // frame, which the direct map aliases readable at DIRECT_MAP_BASE; `buf`
    // is a live slice valid for that many writes and disjoint from the mapping.
    unsafe {
        core::ptr::copy_nonoverlapping((kva as *const u8).add(offset), buf.as_mut_ptr(), buf.len());
    }
}
