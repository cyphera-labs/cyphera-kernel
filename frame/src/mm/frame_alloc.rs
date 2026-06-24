use core::sync::atomic::{AtomicPtr, AtomicU16, AtomicUsize, Ordering};

use buddy_system_allocator::FrameAllocator as BuddyFrameAllocator;
use x86_64::PhysAddr;
use x86_64::structures::paging::{PhysFrame, Size4KiB};

use crate::boot::{BootInfo, MemoryRegion};
use crate::sync::SpinIrq;

const RESERVED_LOW_END: u64 = 0x10_0000;

const LOW_LIMIT: u64 = 1024 * 1024 * 1024;
const LOW_POOL_CAP: usize = 520;

static FRAME_ALLOCATOR: SpinIrq<Option<BuddyFrameAllocator<32>>> = SpinIrq::new(None);

static TOTAL_FRAMES: AtomicUsize = AtomicUsize::new(0);
static FRAMES_IN_USE: AtomicUsize = AtomicUsize::new(0);

static REFCOUNT_TABLE: AtomicPtr<AtomicU16> = AtomicPtr::new(core::ptr::null_mut());
static REFCOUNT_LEN: AtomicUsize = AtomicUsize::new(0);

static MAX_FRAME_EXCL: AtomicUsize = AtomicUsize::new(0);

struct LowPool {
    frames: [u64; LOW_POOL_CAP],
    len: usize,
}

static LOW_POOL: SpinIrq<LowPool> = SpinIrq::new(LowPool {
    frames: [0; LOW_POOL_CAP],
    len: 0,
});

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
    let mut max_frame_excl: usize = 0;
    for region in boot_info.memory_map {
        if !region.is_usable() {
            continue;
        }
        let region_end_frame = (align_down(region.end, 4096) / 4096) as usize;
        max_frame_excl = max_frame_excl.max(region_end_frame);
        for sub in subtract_reserved(region, reserved) {
            let mut start = align_up(sub.0, 4096);
            let end = align_down(sub.1, 4096);
            if end <= start {
                continue;
            }
            {
                let mut pool = LOW_POOL.lock();
                while pool.len < LOW_POOL_CAP && start < LOW_LIMIT && start + 4096 <= end {
                    let n = pool.len;
                    pool.frames[n] = start;
                    pool.len = n + 1;
                    start += 4096;
                }
            }
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
    MAX_FRAME_EXCL.store(max_frame_excl, Ordering::SeqCst);

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
    if let Some(slot) = refcount_slot(frame) {
        slot.store(1, Ordering::Release);
    }
    FRAMES_IN_USE.fetch_add(1, Ordering::Relaxed);
    Some(frame)
}

pub fn alloc_low_frame() -> Option<u64> {
    let mut pool = LOW_POOL.lock();
    let n = pool.len.checked_sub(1)?;
    pool.len = n;
    Some(pool.frames[n])
}

pub fn release_low_pool() {
    let mut slot = FRAME_ALLOCATOR.lock();
    let alloc = slot.as_mut().expect("frame_alloc::init not called");
    let mut pool = LOW_POOL.lock();
    let mut released = 0usize;
    for i in 0..pool.len {
        let frame = (pool.frames[i] / 4096) as usize;
        alloc.add_frame(frame, frame + 1);
        released += 1;
    }
    pool.len = 0;
    TOTAL_FRAMES.fetch_add(released, Ordering::SeqCst);
}

/// # Safety
///
/// Caller must invoke this exactly once, on the BSP, after `frame_alloc::init`
/// and `direct_map::init` (the table is backed by buddy frames addressed
/// through the direct map) and before any other CPU is online. Allocations
/// made before this runs (page-table frames, the heap's first chunk) are not
/// refcount-tracked; that is sound because those allocations are permanent —
/// they are never freed, so no count ever needs to reach 0 for them.
pub unsafe fn init_refcounts() {
    let len = MAX_FRAME_EXCL.load(Ordering::SeqCst);
    if len == 0 {
        return;
    }
    let bytes = len
        .checked_mul(core::mem::size_of::<AtomicU16>())
        .expect("frame_alloc: refcount table size overflow");
    let pages = bytes.div_ceil(4096);
    let backing =
        alloc_contiguous(pages).expect("frame_alloc: out of frames for the refcount table");
    let pa = backing.start_address().as_u64();
    let va = crate::mm::direct_map::phys_to_virt(pa) as *mut AtomicU16;
    // SAFETY: `va` is the direct-map alias of `pages` contiguous frames just
    // handed out by `alloc_contiguous` (page-aligned, the only outstanding
    // reference, writable). `pages * 4096 >= len * 2`, so the `len`-element
    // `AtomicU16` array fits within the backing span. AtomicU16 is
    // zero-initializable (a 0 count means "not allocated"), so writing zero
    // bytes is a valid initial state; the write stays within the frames.
    unsafe {
        core::ptr::write_bytes(va as *mut u8, 0, pages * 4096);
    }
    REFCOUNT_LEN.store(len, Ordering::SeqCst);
    REFCOUNT_TABLE.store(va, Ordering::SeqCst);
}

#[inline]
fn refcount_slot(frame: PhysFrame<Size4KiB>) -> Option<&'static AtomicU16> {
    let table = REFCOUNT_TABLE.load(Ordering::Acquire);
    if table.is_null() {
        return None;
    }
    let len = REFCOUNT_LEN.load(Ordering::Relaxed);
    let idx = (frame.start_address().as_u64() / 4096) as usize;
    if idx >= len {
        return None;
    }
    // SAFETY: `table` is the published, non-null base of the `len`-element
    // `AtomicU16` array built once in `init_refcounts` and never moved or
    // freed (`'static`); `idx < len` keeps the offset in bounds, and
    // `AtomicU16` is the element type, so the produced reference is to a
    // live, properly-aligned array element.
    unsafe { Some(&*table.add(idx)) }
}

pub fn frame_ref_inc(frame: PhysFrame<Size4KiB>) {
    if let Some(slot) = refcount_slot(frame) {
        let mut cur = slot.load(Ordering::Relaxed);
        loop {
            if cur == u16::MAX {
                return;
            }
            match slot.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }
}

pub fn frame_ref_count(frame: PhysFrame<Size4KiB>) -> u32 {
    refcount_slot(frame).map_or(0, |slot| slot.load(Ordering::Acquire) as u32)
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
    if let Some(slot) = refcount_slot(frame) {
        slot.store(1, Ordering::Release);
    }
    FRAMES_IN_USE.fetch_add(count.next_power_of_two(), Ordering::Relaxed);
    Some(frame)
}

pub fn free_frame(frame: PhysFrame<Size4KiB>) {
    if let Some(slot) = refcount_slot(frame) {
        let mut cur = slot.load(Ordering::Acquire);
        loop {
            debug_assert!(cur != 0, "frame_alloc: free of a frame with refcount 0");
            if cur == 0 || cur == u16::MAX {
                return;
            }
            match slot.compare_exchange_weak(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) if cur == 1 => break,
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }
    let idx = (frame.start_address().as_u64() / 4096) as usize;
    let mut g = FRAME_ALLOCATOR.lock();
    let alloc = g.as_mut().expect("frame_alloc::init not called");
    alloc.dealloc(idx, 1);
    FRAMES_IN_USE.fetch_sub(1, Ordering::Relaxed);
}

pub fn reclaim_module(paddr: u64, size: u64) -> usize {
    let start = align_up(paddr, 4096);
    let end = align_down(paddr.saturating_add(size), 4096);
    if end <= start {
        return 0;
    }
    let start_frame = (start / 4096) as usize;
    let end_frame = (end / 4096) as usize;
    {
        let mut g = FRAME_ALLOCATOR.lock();
        let alloc = g.as_mut().expect("frame_alloc::init not called");
        alloc.add_frame(start_frame, end_frame);
    }
    let added = end_frame - start_frame;
    TOTAL_FRAMES.fetch_add(added, Ordering::SeqCst);
    added
}

pub fn free_contiguous(frame: PhysFrame<Size4KiB>, count: usize) {
    if let Some(slot) = refcount_slot(frame) {
        let mut cur = slot.load(Ordering::Acquire);
        loop {
            if cur == u16::MAX || cur == 0 {
                return;
            }
            match slot.compare_exchange_weak(cur, 0, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    debug_assert!(
                        cur == 1,
                        "frame_alloc: free_contiguous of a head with refcount != 1"
                    );
                    break;
                }
                Err(observed) => cur = observed,
            }
        }
    }
    let idx = (frame.start_address().as_u64() / 4096) as usize;
    let mut g = FRAME_ALLOCATOR.lock();
    let alloc = g.as_mut().expect("frame_alloc::init not called");
    alloc.dealloc(idx, count);
    FRAMES_IN_USE.fetch_sub(count.next_power_of_two(), Ordering::Relaxed);
}
