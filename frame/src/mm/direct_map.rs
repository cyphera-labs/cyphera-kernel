extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::registers::control::Cr3;

use crate::boot::BootInfo;
use crate::mm::frame_alloc;

pub const DIRECT_MAP_BASE: u64 = 0xffff_8880_0000_0000;

const PML4_INDEX: usize = ((DIRECT_MAP_BASE >> 39) & 0x1ff) as usize;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const HUGE: u64 = 1 << 7;
const NX: u64 = 1 << 63;

const GIB: u64 = 1024 * 1024 * 1024;
const MIB2: u64 = 2 * 1024 * 1024;
const FRAME_MASK: u64 = 0x000f_ffff_ffff_f000;

static DIRECT_MAP_END: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn phys_to_virt(pa: u64) -> u64 {
    debug_assert!(
        pa < end(),
        "phys_to_virt: {:#x} is outside the direct map [0, {:#x})",
        pa,
        end()
    );
    pa + DIRECT_MAP_BASE
}

#[inline]
pub fn virt_to_phys(va: u64) -> u64 {
    if va >= crate::boot::KERNEL_VMA_OFFSET {
        va - crate::boot::KERNEL_VMA_OFFSET
    } else {
        debug_assert!(
            va >= DIRECT_MAP_BASE && va < DIRECT_MAP_BASE + end(),
            "virt_to_phys: {:#x} is neither an image nor a direct-map VA",
            va
        );
        va - DIRECT_MAP_BASE
    }
}

pub fn end() -> u64 {
    DIRECT_MAP_END.load(Ordering::Acquire)
}

pub fn is_mapped(pa: u64) -> bool {
    let span = end();
    debug_assert!(span != 0, "is_mapped queried before direct_map::init");
    if span == 0 || pa >= span {
        return false;
    }
    let pml4_pa = Cr3::read().0.start_address().as_u64();
    // SAFETY: page-table frames are RAM the direct map covers, so phys_to_virt
    // yields valid aliases; PML4_INDEX and the GiB/2 MiB indices are < 512 by
    // construction, so each `.add` stays within its 512-entry table. The
    // direct-map tables are built once at init and never mutated, so this
    // lock-free read races nothing.
    unsafe {
        let pml4e = (phys_to_virt(pml4_pa) as *const u64).add(PML4_INDEX).read();
        if pml4e & PRESENT == 0 {
            return false;
        }
        let pdpte = (phys_to_virt(pml4e & FRAME_MASK) as *const u64)
            .add((pa / GIB) as usize)
            .read();
        if pdpte & PRESENT == 0 {
            return false;
        }
        if pdpte & HUGE != 0 {
            return true;
        }
        let pde = (phys_to_virt(pdpte & FRAME_MASK) as *const u64)
            .add(((pa % GIB) / MIB2) as usize)
            .read();
        pde & PRESENT != 0
    }
}

fn one_gib_pages() -> bool {
    let leaf = core::arch::x86_64::__cpuid(0x8000_0001);
    leaf.edx & (1 << 26) != 0
}

fn ram_overlaps(boot_info: &BootInfo, lo: u64, hi: u64) -> bool {
    for r in boot_info.memory_map {
        if r.is_usable() && r.start < hi && r.end > lo {
            return true;
        }
    }
    for m in boot_info.modules {
        if m.paddr < hi && m.paddr + m.size > lo {
            return true;
        }
    }
    false
}

fn alloc_low_table() -> u64 {
    let pa =
        frame_alloc::alloc_low_frame().expect("direct_map: sub-1 GiB table-frame pool exhausted");
    let kva = pa | crate::boot::KERNEL_VMA_OFFSET;
    // SAFETY: alloc_low_frame only returns frames < 1 GiB, which the boot
    // stub's PDPT[510] window aliases writable at `pa | KERNEL_VMA_OFFSET`;
    // zeroing its 4096 bytes stays within the frame.
    unsafe { core::ptr::write_bytes(kva as *mut u8, 0, 4096) };
    pa
}

fn table(pa: u64) -> *mut u64 {
    (pa | crate::boot::KERNEL_VMA_OFFSET) as *mut u64
}

/// # Safety
///
/// Must run once on the BSP after `frame_alloc::init` and before any
/// consumer addresses RAM through `phys_to_virt`, with no other CPU online.
pub unsafe fn init(boot_info: &BootInfo) {
    let mut span_end: u64 = 0;
    for r in boot_info.memory_map {
        if r.is_usable() {
            span_end = span_end.max(r.end);
        }
    }
    for m in boot_info.modules {
        span_end = span_end.max(m.paddr + m.size);
    }
    span_end = (span_end + GIB - 1) & !(GIB - 1);
    assert!(
        span_end <= 512 * GIB,
        "direct_map: RAM span {:#x} exceeds the 512 GiB single-PDPT ceiling",
        span_end
    );

    let gib_pages = one_gib_pages();
    let pdpt_pa = alloc_low_table();

    let mut g = 0u64;
    while g < span_end {
        let idx = (g / GIB) as usize;
        let full = (0..512).all(|c| ram_overlaps(boot_info, g + c * MIB2, g + (c + 1) * MIB2));
        if full && gib_pages {
            // SAFETY: `idx < 512` indexes the freshly-zeroed PDPT; a present
            // 1 GiB leaf for an all-RAM gigabyte is in bounds.
            unsafe {
                table(pdpt_pa)
                    .add(idx)
                    .write(g | PRESENT | WRITABLE | HUGE | NX)
            };
        } else if ram_overlaps(boot_info, g, g + GIB) {
            let pd_pa = alloc_low_table();
            for c in 0..512u64 {
                let pa = g + c * MIB2;
                if ram_overlaps(boot_info, pa, pa + MIB2) {
                    // SAFETY: `c < 512` indexes the freshly-zeroed PD; a
                    // present 2 MiB leaf mapping RAM, write is in bounds.
                    unsafe {
                        table(pd_pa)
                            .add(c as usize)
                            .write(pa | PRESENT | WRITABLE | HUGE | NX)
                    };
                }
            }
            // SAFETY: `idx < 512`; a non-huge PDPT entry pointing at the PD.
            unsafe {
                table(pdpt_pa)
                    .add(idx)
                    .write(pd_pa | PRESENT | WRITABLE | NX)
            };
        }
        g += GIB;
    }

    let pml4_pa = Cr3::read().0.start_address().as_u64();
    // SAFETY: `PML4_INDEX` (273) is an unused kernel-half slot; the active
    // PML4 is reachable via the bootstrap window. Installing the PDPT makes
    // the direct map visible, and `VmSpace::new_user` shares the kernel-half
    // slots into every address space.
    unsafe {
        table(pml4_pa)
            .add(PML4_INDEX)
            .write(pdpt_pa | PRESENT | WRITABLE | NX)
    };

    let (frame, flags) = Cr3::read();
    // SAFETY: rewriting CR3 with the same root flushes non-global TLB
    // entries so the new PML4 slot takes effect; the root is unchanged.
    unsafe { Cr3::write(frame, flags) };

    DIRECT_MAP_END.store(span_end, Ordering::Release);
    crate::println!(
        "direct_map: RAM aliased up to {:#x} at {:#x} ({} leaves)",
        span_end,
        DIRECT_MAP_BASE,
        if gib_pages { "1 GiB" } else { "2 MiB" }
    );
}
