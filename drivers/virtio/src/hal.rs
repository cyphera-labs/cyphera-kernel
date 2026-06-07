use core::ptr::NonNull;

use frame::boot::KERNEL_VMA_OFFSET;
use frame::mm::frame_alloc;
use virtio_drivers::{BufferDirection, Hal, PhysAddr};

pub struct FrameHal;

// SAFETY: the `Hal` contract requires that the four address translations
// be mutually consistent and that `dma_alloc` hand back a page-aligned,
// physically-contiguous region the device may DMA into. `dma_alloc` pulls
// `pages` contiguous frames from `frame_alloc` and returns the matching
// high-half VA via the fixed `pa | KERNEL_VMA_OFFSET` mapping; `share`
// inverts exactly that mapping (`va - KERNEL_VMA_OFFSET`) for DRAM
// buffers; `mmio_phys_to_virt` maps device PAs through the boot stub's
// PDPT[509]/PDPT[511] device windows (or a fresh kernel mapping). The
// boot stub maps only phys [0, 1 GiB) of DRAM writable/WB via PDPT[510],
// so `pa | KERNEL_VMA_OFFSET` is a valid DRAM alias only for pa < 1 GiB;
// this holds because the supported microvm config keeps all guest DRAM
// under 1 GiB, and `frame_alloc` therefore only ever hands back frames
// inside that window. Under that precondition every PA/VA pair these
// methods produce names live, kernel-owned memory (DRAM in the PDPT[510]
// window, devices in the PDPT[509]/[511] windows), so the implementation
// upholds the trait's translation and ownership invariants.
unsafe impl Hal for FrameHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        let frame = frame_alloc::alloc_contiguous(pages)
            .expect("dma_alloc: frame_alloc out of contiguous frames");
        let paddr = frame.start_address().as_u64() as PhysAddr;
        let kva = (paddr as u64) | KERNEL_VMA_OFFSET;
        let vaddr = NonNull::new(kva as *mut u8).expect("dma_alloc: vaddr non-zero");
        // SAFETY: `vaddr` is the `pa | KERNEL_VMA_OFFSET` alias of the `pages`
        // contiguous frames just returned by `frame_alloc::alloc_contiguous`,
        // so it is non-null, page-aligned, and the only outstanding reference
        // to exactly `pages * 4096` bytes of freshly-allocated DRAM. Those
        // bytes are writable because the supported microvm config keeps all
        // guest DRAM under 1 GiB, so `paddr` lies in the boot stub's PDPT[510]
        // phys [0, 1 GiB) writable/WB window and the alias is a live mapping —
        // the full span we write_bytes over.
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
        (va.wrapping_sub(KERNEL_VMA_OFFSET)) as PhysAddr
    }

    unsafe fn unshare(_paddr: PhysAddr, _buffer: NonNull<[u8]>, _direction: BufferDirection) {
    }
}
