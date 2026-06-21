use core::ptr::NonNull;

use frame::boot::KERNEL_VMA_OFFSET;
use frame::mm::frame_alloc;
use virtio_drivers::{BufferDirection, Hal, PhysAddr};

pub struct FrameHal;

// SAFETY: the four `Hal` translations are mutually consistent. `dma_alloc`
// returns contiguous DRAM frames aliased through the direct map
// (`phys_to_virt`); `share` inverts that with the branching `virt_to_phys`
// (DRAM/heap buffers live in the direct map, stack/static buffers in the
// kernel-image map); `mmio_phys_to_virt` maps device PAs through the boot
// stub's PDPT[509]/[511] device windows or a fresh uncacheable mapping. The
// direct map covers all of physical RAM, so every DRAM PA/VA pair these
// methods produce names live, kernel-owned memory.
unsafe impl Hal for FrameHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        let frame = frame_alloc::alloc_contiguous(pages)
            .expect("dma_alloc: frame_alloc out of contiguous frames");
        let paddr = frame.start_address().as_u64() as PhysAddr;
        let kva = frame::mm::direct_map::phys_to_virt(paddr as u64);
        let vaddr = NonNull::new(kva as *mut u8).expect("dma_alloc: vaddr non-zero");
        // SAFETY: `vaddr` is the direct-map alias of the `pages` contiguous
        // frames just returned by `alloc_contiguous` — non-null, page-aligned,
        // the only outstanding reference to exactly `pages * 4096` bytes of
        // freshly-allocated writable DRAM, the full span we write_bytes over.
        unsafe {
            core::ptr::write_bytes(vaddr.as_ptr(), 0, pages * 4096);
        }
        (paddr, vaddr)
    }

    unsafe fn dma_dealloc(paddr: PhysAddr, _vaddr: NonNull<u8>, pages: usize) -> i32 {
        use frame::mm::{PhysAddr as FramePhysAddr, PhysFrame, Size4KiB};
        let frame = match PhysFrame::<Size4KiB>::from_start_address(FramePhysAddr::new(paddr)) {
            Ok(f) => f,
            Err(_) => return -1,
        };
        frame_alloc::free_contiguous(frame, pages);
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, size: usize) -> NonNull<u8> {
        let pa = paddr;
        let kva = if (0xC000_0000..0x1_0000_0000).contains(&pa) {
            pa | KERNEL_VMA_OFFSET
        } else if (0x8000_0000..0xC000_0000).contains(&pa) {
            0xffff_ffff_4000_0000_u64 + (pa - 0x8000_0000)
        } else {
            // SAFETY: `paddr`/`size` come from the virtio bus probe and
            // name a real device-MMIO window outside the boot-stub-covered
            // ranges; `map_mmio_into_kernel` maps that span uncacheable into
            // the kernel high half and returns its VA.
            unsafe { frame::mm::mmio_map::map_mmio_into_kernel(pa, size) }
        };
        NonNull::new(kva as *mut u8).expect("mmio_phys_to_virt: kva non-zero")
    }

    unsafe fn share(buffer: NonNull<[u8]>, _direction: BufferDirection) -> PhysAddr {
        let va = buffer.as_ptr() as *const u8 as u64;
        frame::mm::direct_map::virt_to_phys(va) as PhysAddr
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {}
}
