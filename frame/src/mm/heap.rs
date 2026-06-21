use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use linked_list_allocator::Heap;

use crate::sync::SpinIrq;

const BOOTSTRAP_SIZE: usize = 1024 * 1024;

const TARGET_HEAP_BYTES: usize = 128 * 1024 * 1024;

const PHASE1_HEAP_BYTES: usize = 32 * 1024 * 1024;

const FIRST_CHUNK_BYTES: usize = 64 * 1024 * 1024;

const MIN_CHUNK_BYTES: usize = 1024 * 1024;

const MAX_REGIONS: usize = 16;

#[repr(C, align(4096))]
struct BootstrapStorage([u8; BOOTSTRAP_SIZE]);

static mut BOOTSTRAP_STORAGE: BootstrapStorage = BootstrapStorage([0; BOOTSTRAP_SIZE]);

struct Region {
    start: AtomicUsize,
    end: AtomicUsize,
    heap: SpinIrq<Heap>,
}

#[allow(clippy::declare_interior_mutable_const)]
const REGION_INIT: Region = Region {
    start: AtomicUsize::new(0),
    end: AtomicUsize::new(0),
    heap: SpinIrq::new(Heap::empty()),
};

struct GrowableHeap {
    bootstrap: SpinIrq<Heap>,
    bootstrap_start: AtomicUsize,
    bootstrap_end: AtomicUsize,
    regions: [Region; MAX_REGIONS],
    region_count: AtomicUsize,
}

// SAFETY: this honors the `GlobalAlloc` contract. `alloc` only ever returns
// either a pointer minted by a per-region or bootstrap `Heap::allocate_first_fit`
// (so it satisfies `layout`'s size+alignment and points into storage that
// region exclusively owns) or null on exhaustion. `dealloc` routes a pointer
// back to the single `Heap` whose published `[start, end)` range contains it,
// so a block is always freed to the same allocator that produced it with the
// matching `layout`; null and out-of-range pointers are skipped rather than
// misrouted. Every `Heap` is guarded by its own `SpinIrq`, which disables IRQs
// for the critical section, so concurrent alloc/dealloc from other CPUs or from
// an IRQ-context allocation are serialized per region without deadlock, keeping
// each linked-list heap's internal state race-free.
unsafe impl GlobalAlloc for GrowableHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let n = self.region_count.load(Ordering::Acquire);
        for i in 0..n {
            if let Ok(p) = self.regions[i].heap.lock().allocate_first_fit(layout) {
                return p.as_ptr();
            }
        }
        match self.bootstrap.lock().allocate_first_fit(layout) {
            Ok(p) => p.as_ptr(),
            Err(_) => ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let addr = ptr as usize;

        let n = self.region_count.load(Ordering::Acquire);
        for i in 0..n {
            let s = self.regions[i].start.load(Ordering::Relaxed);
            let e = self.regions[i].end.load(Ordering::Relaxed);
            if addr >= s && addr < e {
                self.regions[i]
                    .heap
                    .lock()
                    .deallocate(NonNull::new_unchecked(ptr), layout);
                return;
            }
        }

        let bs = self.bootstrap_start.load(Ordering::Relaxed);
        let be = self.bootstrap_end.load(Ordering::Relaxed);
        if addr >= bs && addr < be {
            self.bootstrap
                .lock()
                .deallocate(NonNull::new_unchecked(ptr), layout);
        }
    }
}

#[global_allocator]
static HEAP: GrowableHeap = GrowableHeap {
    bootstrap: SpinIrq::new(Heap::empty()),
    bootstrap_start: AtomicUsize::new(0),
    bootstrap_end: AtomicUsize::new(0),
    regions: [REGION_INIT; MAX_REGIONS],
    region_count: AtomicUsize::new(0),
};

/// # Safety
///
/// Caller must invoke this exactly once, on the BSP, before any
/// allocation. Concurrent allocations during init are UB.
pub unsafe fn init() {
    let storage_ptr = core::ptr::addr_of_mut!(BOOTSTRAP_STORAGE) as *mut u8;
    HEAP.bootstrap.lock().init(storage_ptr, BOOTSTRAP_SIZE);
    HEAP.bootstrap_start
        .store(storage_ptr as usize, Ordering::Relaxed);
    HEAP.bootstrap_end
        .store(storage_ptr as usize + BOOTSTRAP_SIZE, Ordering::Relaxed);
    crate::println!(
        "heap: bootstrap initialized at {:#x}, size {} KiB",
        storage_ptr as usize,
        BOOTSTRAP_SIZE / 1024
    );
}

pub fn expand_initial() {
    // SAFETY: invoked once during single-threaded boot, after
    // frame_alloc::init and before any other CPU is online.
    unsafe { expand_main(PHASE1_HEAP_BYTES, PHASE1_HEAP_BYTES) }
}

pub fn expand_full() {
    // SAFETY: invoked once during single-threaded boot, after
    // expand_initial + the module reclaim and before any AP is online.
    unsafe { expand_main(TARGET_HEAP_BYTES, FIRST_CHUNK_BYTES) }
}

/// # Safety
///
/// Caller must invoke this only after `frame_alloc::init`, and must not
/// run it concurrently with allocations on other CPUs (boot-time only).
unsafe fn expand_main(target_bytes: usize, first_chunk_bytes: usize) {
    use crate::mm::frame_alloc;

    let mut regions_used = HEAP.region_count.load(Ordering::Acquire);
    let mut claimed: usize = (0..regions_used)
        .map(|i| {
            HEAP.regions[i].end.load(Ordering::Relaxed)
                - HEAP.regions[i].start.load(Ordering::Relaxed)
        })
        .sum();
    let mut chunk_bytes: usize = first_chunk_bytes;

    while claimed < target_bytes && regions_used < MAX_REGIONS {
        if chunk_bytes < MIN_CHUNK_BYTES {
            break;
        }
        let pages = chunk_bytes / 4096;
        let frame = match frame_alloc::alloc_contiguous(pages) {
            Some(f) => f,
            None => {
                chunk_bytes /= 2;
                continue;
            }
        };
        let phys = frame.start_address().as_u64();
        let va = crate::mm::direct_map::phys_to_virt(phys) as *mut u8;

        let slot = &HEAP.regions[regions_used];
        slot.heap.lock().init(va, chunk_bytes);
        slot.start.store(va as usize, Ordering::Relaxed);
        slot.end.store(va as usize + chunk_bytes, Ordering::Relaxed);
        HEAP.region_count.store(regions_used + 1, Ordering::Release);
        regions_used += 1;
        claimed += chunk_bytes;
    }

    crate::println!(
        "heap: expanded — {} region(s), {} MiB total",
        regions_used,
        claimed / (1024 * 1024)
    );

    if claimed == 0 {
        panic!("heap::expand_main: buddy could not satisfy any chunk");
    }
}

#[alloc_error_handler]
fn alloc_error(layout: core::alloc::Layout) -> ! {
    panic!(
        "heap allocation failed: size={} align={}",
        layout.size(),
        layout.align()
    );
}
