use core::sync::atomic::{AtomicU64, Ordering};

use crate::mm::vm::{Perms, VmSpace};

const MMIO_VA_BASE: u64 = 0xffff_fc00_0000_0000;
const MMIO_VA_LIMIT: u64 = 0xffff_ffc0_0000_0000;

const PAGE_SIZE: u64 = 4096;

static NEXT_MMIO_VA: AtomicU64 = AtomicU64::new(MMIO_VA_BASE);

/// # Safety
///
/// `pa` must be a valid CPU-accessible MMIO range; mapping arbitrary
/// physical addresses can fault the CPU or corrupt device state.
pub unsafe fn map_mmio_into_kernel(pa: u64, size: usize) -> u64 {
    if size == 0 {
        return MMIO_VA_BASE;
    }

    let pa_page = pa & !(PAGE_SIZE - 1);
    let pa_offset = pa - pa_page;
    let total = pa_offset as usize + size;
    let pages = total.div_ceil(PAGE_SIZE as usize);
    let bytes = (pages as u64) * PAGE_SIZE;

    let va_page = NEXT_MMIO_VA.fetch_add(bytes, Ordering::Relaxed);
    let va_end = va_page + bytes;
    if va_end > MMIO_VA_LIMIT {
        panic!(
            "map_mmio_into_kernel: arena exhausted (asked for {} bytes, base {:#x}, limit {:#x})",
            size, va_page, MMIO_VA_LIMIT,
        );
    }

    let mut vmspace = VmSpace::current();
    let vaddr = x86_64::VirtAddr::new(va_page);
    vmspace
        .map_mmio(vaddr, pa_page, pages, Perms::READ | Perms::WRITE)
        .expect("map_mmio_into_kernel: page-table install failed");

    va_page + pa_offset
}
