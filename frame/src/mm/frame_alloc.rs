use core::sync::atomic::{AtomicUsize, Ordering};

use buddy_system_allocator::FrameAllocator as BuddyFrameAllocator;
use x86_64::PhysAddr;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::boot::{BootInfo, MemoryRegion};
use crate::sync::SpinIrq;

const RESERVED_LOW_END: u64 = 0x10_0000;

static FRAME_ALLOCATOR: SpinIrq<Option<BuddyFrameAllocator<32>>> = SpinIrq::new(None);

static TOTAL_FRAMES: AtomicUsize = AtomicUsize::new(0);
static FRAMES_IN_USE: AtomicUsize = AtomicUsize::new(0);

/// # Safety
///
/// Caller must ensure (1) `boot_info.memory_map` accurately reflects
/// physical memory, (2) the kernel image is in fact in
/// `[__kernel_image_phys_start, __kernel_image_phys_end]`, and
/// (3) this is called exactly once.
pub unsafe fn init(boot_info: &BootInfo) {
    let kernel_start = core::ptr::addr_of!(crate::boot::__kernel_image_phys_start) as u64;
    let kernel_end = core::ptr::addr_of!(crate::boot::__kernel_image_phys_end) as u64;

    let mut reserved_buf: [(u64, u64); 16] = [(0, 0); 16];
    let mut reserved_len = 0usize;
    reserved_buf[reserved_len] = (kernel_start, kernel_end);
    reserved_len += 1;
    for m in boot_info.modules {
        if reserved_len == reserved_buf.len() {
            crate::println!(
                "frame_alloc: more modules than reserved-buf slots ({}); ignoring the rest",
                boot_info.modules.len(),
            );
            break;
        }
        let s = align_down(m.paddr, 4096);
        let e = align_up(m.paddr + m.size, 4096);
        reserved_buf[reserved_len] = (s, e);
        reserved_len += 1;
    }
    let reserved = &reserved_buf[..reserved_len];

    let mut slot = FRAME_ALLOCATOR.lock();
    assert!(slot.is_none(), "frame_alloc::init called twice");
    *slot = Some(BuddyFrameAllocator::new());
    let alloc = slot.as_mut().expect("just inserted");

    let mut total_donated_frames: usize = 0;
    for region in boot_info.memory_map {
        if !region.is_usable() {
            continue;
        }
        for sub in subtract_reserved(region, reserved) {
            let start = align_up(sub.0, 4096);
            let end = align_down(sub.1, 4096);
            if end <= start {
                continue;
            }
            let start_frame = (start / 4096) as usize;
            let end_frame = (end / 4096) as usize;
            alloc.add_frame(start_frame, end_frame);
            total_donated_frames += end_frame - start_frame;
        }
    }

    TOTAL_FRAMES.store(total_donated_frames, Ordering::SeqCst);

    crate::println!(
        "frame_alloc: donated {} frames ({} MiB) to buddy allocator",
        total_donated_frames,
        (total_donated_frames * 4096) / (1024 * 1024)
    );
}

#[derive(Copy, Clone, Debug)]
pub struct Stats {
    pub total: usize,
    pub in_use: usize,
}

pub fn stats() -> Stats {
    Stats {
        total: TOTAL_FRAMES.load(Ordering::Relaxed),
        in_use: FRAMES_IN_USE.load(Ordering::Relaxed),
    }
}

fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

fn subtract_reserved(
    region: &MemoryRegion,
    reserved: &[(u64, u64)],
) -> alloc::vec::Vec<(u64, u64)> {
    let mut surviving: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::new();
    let r0 = region.start.max(RESERVED_LOW_END);
    if region.end > r0 {
        surviving.push((r0, region.end));
    }

    for &(rs, re) in reserved {
        if re <= rs {
            continue;
        }
        let mut next: alloc::vec::Vec<(u64, u64)> = alloc::vec::Vec::with_capacity(surviving.len());
        for (s, e) in surviving.drain(..) {
            if re <= s || rs >= e {
                next.push((s, e));
            } else {
                if s < rs {
                    next.push((s, rs));
                }
                if re < e {
                    next.push((re, e));
                }
            }
        }
        surviving = next;
    }
    surviving
}

pub fn alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    let mut g = FRAME_ALLOCATOR.lock();
    let alloc = g.as_mut().expect("frame_alloc::init not called");
    let frame_idx = alloc.alloc(1)?;
    let addr = PhysAddr::new((frame_idx as u64) * 4096);
    let frame = PhysFrame::from_start_address(addr).ok()?;
    FRAMES_IN_USE.fetch_add(1, Ordering::Relaxed);
    Some(frame)
}

pub fn alloc_contiguous(count: usize) -> Option<PhysFrame<Size4KiB>> {
    if count == 0 {
        return None;
    }
    let mut g = FRAME_ALLOCATOR.lock();
    let alloc = g.as_mut().expect("frame_alloc::init not called");
    let frame_idx = alloc.alloc(count)?;
    let addr = PhysAddr::new((frame_idx as u64) * 4096);
    let frame = PhysFrame::from_start_address(addr).ok()?;
    FRAMES_IN_USE.fetch_add(count.next_power_of_two(), Ordering::Relaxed);
    Some(frame)
}

pub fn free_frame(frame: PhysFrame<Size4KiB>) {
    let idx = (frame.start_address().as_u64() / 4096) as usize;
    let mut g = FRAME_ALLOCATOR.lock();
    let alloc = g.as_mut().expect("frame_alloc::init not called");
    alloc.dealloc(idx, 1);
    FRAMES_IN_USE.fetch_sub(1, Ordering::Relaxed);
}

pub fn free_contiguous(frame: PhysFrame<Size4KiB>, count: usize) {
    let idx = (frame.start_address().as_u64() / 4096) as usize;
    let mut g = FRAME_ALLOCATOR.lock();
    let alloc = g.as_mut().expect("frame_alloc::init not called");
    alloc.dealloc(idx, count);
    FRAMES_IN_USE.fetch_sub(count.next_power_of_two(), Ordering::Relaxed);
}
