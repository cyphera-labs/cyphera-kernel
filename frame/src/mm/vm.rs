use bitflags::bitflags;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::{MapToError, Mapper};
use x86_64::structures::paging::page::PageRange;
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame,
    Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::mm::frame_alloc;

static PT_MUTATION_LOCK: crate::sync::SpinIrq<()> = crate::sync::SpinIrq::new(());

bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct Perms: u32 {
        const READ    = 1 << 0;
        const WRITE   = 1 << 1;
        const EXECUTE = 1 << 2;
        const USER    = 1 << 3;
    }
}

impl Perms {
    pub const KERNEL_RW: Perms = Perms::READ.union(Perms::WRITE);
    pub const KERNEL_RX: Perms = Perms::READ.union(Perms::EXECUTE);
    pub const USER_RW: Perms = Perms::READ.union(Perms::WRITE).union(Perms::USER);
    pub const USER_RX: Perms = Perms::READ.union(Perms::EXECUTE).union(Perms::USER);

    fn to_pte_flags(self) -> PageTableFlags {
        let mut f = PageTableFlags::PRESENT;
        if self.contains(Perms::WRITE) {
            f |= PageTableFlags::WRITABLE;
        }
        if !self.contains(Perms::EXECUTE) {
            f |= PageTableFlags::NO_EXECUTE;
        }
        if self.contains(Perms::USER)
            && self.intersects(Perms::READ.union(Perms::WRITE).union(Perms::EXECUTE))
        {
            f |= PageTableFlags::USER_ACCESSIBLE;
        }
        f
    }
}

struct PhysFrameAdapter;

// SAFETY: the trait requires that `allocate_frame` hand out a frame not
// already in use. `frame_alloc::alloc_frame` returns a buddy-allocated
// physical frame removed from the free list, so no two outstanding
// allocations alias the same frame; it returns `None` rather than a
// bogus frame when exhausted.
unsafe impl FrameAllocator<Size4KiB> for PhysFrameAdapter {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        use crate::boot::KERNEL_VMA_OFFSET;
        let f = frame_alloc::alloc_frame()?;
        let kva = f.start_address().as_u64() | KERNEL_VMA_OFFSET;
        // SAFETY: `f` is a freshly-allocated 4 KiB frame. `frame_alloc`
        // hands out frames in low DRAM (< 1 GiB), the range PDPT_high
        // [510] maps writable/write-back, so ORing the kernel
        // high-mapping offset yields a writable VA into that frame; the
        // kernel-half PML4 entry is shared by every address space, so
        // the VA resolves under any CR3. We own the frame exclusively
        // (just allocated), and the full 4096-byte span is exactly one
        // page, so the write stays in bounds.
        unsafe {
            core::ptr::write_bytes(kva as *mut u8, 0, 4096);
        }
        Some(f)
    }
}

impl FrameDeallocator<Size4KiB> for PhysFrameAdapter {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        frame_alloc::free_frame(frame);
    }
}

pub struct VmSpace {
    root: PhysFrame<Size4KiB>,
    owned: bool,
}

impl VmSpace {
    pub fn current() -> Self {
        let (root, _) = Cr3::read();
        Self { root, owned: false }
    }

    pub fn root_frame(&self) -> PhysFrame<Size4KiB> {
        self.root
    }

    pub fn activate_root(root: PhysFrame<Size4KiB>) {
        let (_, flags) = Cr3::read();
        // SAFETY: caller asserts the frame is a valid PML4 with the
        // kernel high-half mirrored. Same rationale as
        // `activate_for_task`.
        unsafe { Cr3::write(root, flags) };
    }

    pub fn new() -> Result<Self, MapError> {
        use crate::boot::KERNEL_VMA_OFFSET;
        let root = frame_alloc::alloc_frame().ok_or(MapError::OutOfFrames)?;
        let kva = root.start_address().as_u64() | KERNEL_VMA_OFFSET;
        // SAFETY: `root` was just allocated and is owned solely by this
        // VmSpace; its high-mapping VA is a writable single-page region
        // reachable under any CR3. Zeroing all 4096 bytes stays within
        // that one frame and gives a clean PML4 with no user-half
        // entries.
        unsafe {
            core::ptr::write_bytes(kva as *mut u8, 0, 4096);
        }
        Ok(Self { root, owned: true })
    }

    pub fn new_user() -> Result<Self, MapError> {
        use crate::boot::KERNEL_VMA_OFFSET;
        let new = Self::new()?;
        let parent_kva = Cr3::read().0.start_address().as_u64() | KERNEL_VMA_OFFSET;
        let child_kva = new.root.start_address().as_u64() | KERNEL_VMA_OFFSET;
        // SAFETY: `parent_kva`/`child_kva` are the high-mapping VAs of
        // two distinct 4 KiB PML4 frames (the child was just allocated
        // by `Self::new()`, so it does not alias the active root). `i`
        // ranges over 256..512, so each access is at byte offset
        // 2048..4096 — within the page. The reads/writes are 8-byte
        // aligned (i*8 of an aligned page base) and each VA is a live,
        // properly-aligned `u64` slot in a page-table frame. The source
        // is the active root's kernel half (entries 256..512): those
        // top-level entries are fixed after boot and shared by every
        // address space, so the unsynchronized copy reads stable values.
        unsafe {
            for i in 256..512 {
                let entry = ((parent_kva + i * 8) as *const u64).read();
                ((child_kva + i * 8) as *mut u64).write(entry);
            }
        }
        Ok(new)
    }

    pub fn id(&self) -> u64 {
        self.root.start_address().as_u64()
    }

    fn mapper(&mut self) -> OffsetPageTable<'static> {
        use crate::boot::KERNEL_VMA_OFFSET;
        let pml4_va = self.root.start_address().as_u64() | KERNEL_VMA_OFFSET;
        // SAFETY: `pml4_va` is the kernel-high-mapping VA of this
        // VmSpace's root frame — a live, page-aligned `PageTable`
        // reachable under any CR3. `&mut self` excludes only other Rust
        // borrows of THIS VmSpace; a CLONE_VM/vfork peer wrapping the
        // SAME root frame in its own VmSpace could fabricate a second
        // `&mut PageTable` to this table from another CPU. The mapper /
        // `&mut PageTable` is therefore sound to *use* only while
        // `PT_MUTATION_LOCK` is held — that lock serializes the
        // otherwise-aliasing structure accesses from peer CPUs sharing
        // this root. Every mutating caller in this module takes the lock
        // around the mapper; callers must not retain the mapper or touch
        // the tree outside it. The `'static` is a lint-silencing
        // convenience, sound only because each caller drops the mapper
        // before returning.
        let l4 = unsafe { &mut *(pml4_va as *mut PageTable) };
        // SAFETY: `KERNEL_VMA_OFFSET` is the constant physical-to-virtual
        // offset of the identity-style kernel high mapping, so every
        // frame referenced from `l4` (intermediate tables and leaves in
        // low DRAM) is reachable at `PA | offset` — exactly the
        // contract `OffsetPageTable::new` requires of its physical
        // memory offset.
        unsafe { OffsetPageTable::new(l4, VirtAddr::new(KERNEL_VMA_OFFSET)) }
    }

    pub fn map(
        &mut self,
        vaddr: VirtAddr,
        frame: PhysFrame<Size4KiB>,
        perms: Perms,
    ) -> Result<MappedRegion, MapError> {
        let page = Page::<Size4KiB>::from_start_address(vaddr).map_err(|_| MapError::Misaligned)?;
        let flags = perms.to_pte_flags();
        let mut alloc = PhysFrameAdapter;
        {
            let _g = PT_MUTATION_LOCK.lock();
            // SAFETY: `map_to` is unsound only under concurrent mutation
            // of this address space's table tree; `PT_MUTATION_LOCK` is
            // held across the call (and its INVLPG), serializing all
            // structure mutations across CPUs. `page`/`frame` are valid
            // 4 KiB units and `alloc` zeroes any intermediate table it
            // creates, so no stale entries are materialized.
            let flush = unsafe {
                self.mapper()
                    .map_to(page, frame, flags, &mut alloc)
                    .map_err(MapError::from_x86_64)?
            };
            flush.flush();
        }
        Ok(MappedRegion {
            start: vaddr,
            pages: 1,
            owned_frames: alloc::vec::Vec::new(),
        })
    }

    pub fn map_mmio(
        &mut self,
        vaddr: VirtAddr,
        paddr: u64,
        pages: usize,
        perms: Perms,
    ) -> Result<(), MapError> {
        let mut alloc = PhysFrameAdapter;
        let start_page =
            Page::<Size4KiB>::from_start_address(vaddr).map_err(|_| MapError::Misaligned)?;
        let mut flags = perms.to_pte_flags();
        flags |=
            PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH | PageTableFlags::NO_EXECUTE;

        let _g = PT_MUTATION_LOCK.lock();
        let mut mapper = self.mapper();
        for i in 0..pages {
            let page = start_page + i as u64;
            let phys = PhysAddr::new(paddr + (i as u64) * 4096);
            let frame = PhysFrame::<Size4KiB>::from_start_address(phys)
                .map_err(|_| MapError::Misaligned)?;
            // SAFETY: `PT_MUTATION_LOCK` is held for the whole loop, so
            // no peer CPU mutates this table tree concurrently; `page`
            // and `frame` are start-address-aligned 4 KiB units and
            // `alloc` zeroes new intermediate tables; the
            // NO_CACHE/WRITE_THROUGH flags suit device registers. This is
            // a safe fn driving an unsafe `map_to`, so the caller MUST
            // pass a `paddr`/`pages` naming a real device-MMIO window
            // that does not alias live DRAM or another live mapping — the
            // driver-side caller upholds that.
            unsafe {
                mapper
                    .map_to(page, frame, flags, &mut alloc)
                    .map_err(MapError::from_x86_64)?
                    .flush();
            }
        }
        Ok(())
    }

    pub fn map_one_frame(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        perms: Perms,
    ) -> Result<(), MapError> {
        let mut alloc = PhysFrameAdapter;
        let flags = perms.to_pte_flags();
        let _g = PT_MUTATION_LOCK.lock();
        let mut mapper = self.mapper();
        // SAFETY: `PT_MUTATION_LOCK` is held, serializing this single
        // mapping against peer-CPU table mutation. `page` and `frame`
        // are caller-provided valid 4 KiB units (lazy fault-in /
        // shared-frame clone); `alloc` zeroes any intermediate table.
        // Frame ownership stays with the caller, as documented.
        unsafe {
            mapper
                .map_to(page, frame, flags, &mut alloc)
                .map_err(MapError::from_x86_64)?
                .flush();
        }
        Ok(())
    }

    pub fn map_anon(
        &mut self,
        vaddr: VirtAddr,
        pages: usize,
        perms: Perms,
    ) -> Result<MappedRegion, MapError> {
        let mut alloc = PhysFrameAdapter;
        let start_page =
            Page::<Size4KiB>::from_start_address(vaddr).map_err(|_| MapError::Misaligned)?;
        let flags = perms.to_pte_flags();
        let mut owned_frames: alloc::vec::Vec<PhysFrame<Size4KiB>> =
            alloc::vec::Vec::with_capacity(pages);
        let mut failed: Option<MapError> = None;
        let mut orphan: Option<PhysFrame<Size4KiB>> = None;
        {
            let _g = PT_MUTATION_LOCK.lock();
            let mut mapper = self.mapper();
            for i in 0..pages {
                let page = start_page + i as u64;
                let frame = match frame_alloc::alloc_frame() {
                    Some(f) => f,
                    None => {
                        failed = Some(MapError::OutOfFrames);
                        break;
                    }
                };
                // SAFETY: `PT_MUTATION_LOCK` is held for the whole alloc
                // loop, so no peer CPU mutates this tree concurrently.
                // `page` is `start_page + i` (in bounds of the request)
                // and `frame` was just freshly allocated, so it aliases
                // no existing mapping; `alloc` zeroes new intermediate
                // tables. A failure leaves `frame` un-entered (handled
                // as `orphan`), keeping alloc/teardown symmetric.
                match unsafe { mapper.map_to(page, frame, flags, &mut alloc) } {
                    Ok(flush) => {
                        flush.flush();
                        owned_frames.push(frame);
                    }
                    Err(e) => {
                        orphan = Some(frame);
                        failed = Some(MapError::from_x86_64(e));
                        break;
                    }
                }
            }
            if failed.is_some() {
                for j in 0..owned_frames.len() {
                    let page = start_page + j as u64;
                    if let Ok((_f, flush)) = mapper.unmap(page) {
                        flush.flush();
                    }
                }
            }
        }

        if let Some(e) = failed {
            if !owned_frames.is_empty() {
                crate::cpu::tlb::shootdown_all();
            }
            for frame in &owned_frames {
                frame_alloc::free_frame(*frame);
            }
            if let Some(f) = orphan {
                frame_alloc::free_frame(f);
            }
            return Err(e);
        }

        Ok(MappedRegion {
            start: vaddr,
            pages,
            owned_frames,
        })
    }

    pub fn translate(&mut self, vaddr: VirtAddr) -> Option<PhysAddr> {
        self.mapper().translate_addr(vaddr)
    }

    pub fn page_flags(&mut self, vaddr: VirtAddr) -> Option<(bool, bool, bool)> {
        use x86_64::structures::paging::mapper::TranslateResult;
        match self.mapper().translate(vaddr) {
            TranslateResult::Mapped { flags, .. } => Some((
                flags.contains(PageTableFlags::PRESENT),
                flags.contains(PageTableFlags::USER_ACCESSIBLE),
                flags.contains(PageTableFlags::WRITABLE),
            )),
            _ => None,
        }
    }

    pub fn unmap(&mut self, region: MappedRegion) {
        let start = Page::<Size4KiB>::from_start_address(region.start).unwrap();
        let range = PageRange {
            start,
            end: start + region.pages as u64,
        };
        let mut any_unmapped = false;
        {
            let _g = PT_MUTATION_LOCK.lock();
            let mut mapper = self.mapper();
            for page in range {
                if let Ok((_frame, flush)) = mapper.unmap(page) {
                    flush.flush();
                    any_unmapped = true;
                }
            }
        }
        if any_unmapped {
            crate::cpu::tlb::shootdown_all();
        }
        for frame in &region.owned_frames {
            frame_alloc::free_frame(*frame);
        }
        core::mem::forget(region);
    }

    pub fn change_perms(
        &mut self,
        vaddr: VirtAddr,
        pages: usize,
        perms: Perms,
    ) -> Result<usize, MapError> {
        let start = match Page::<Size4KiB>::from_start_address(vaddr) {
            Ok(p) => p,
            Err(_) => return Err(MapError::Misaligned),
        };
        let new_flags = perms.to_pte_flags();
        let mut any_changed = false;
        let mut not_present = 0usize;
        {
            let _g = PT_MUTATION_LOCK.lock();
            let mut mapper = self.mapper();
            for i in 0..pages {
                let page = start + i as u64;
                // SAFETY: `PT_MUTATION_LOCK` is held (above) for the whole
                // loop, so no peer CPU mutates this table tree concurrently.
                // `update_flags` only rewrites an existing leaf PTE — it
                // doesn't re-map or free anything. Failure (page not present)
                // is non-destructive; we count and continue.
                let res = unsafe { mapper.update_flags(page, new_flags) };
                if let Ok(flush) = res {
                    flush.flush();
                    any_changed = true;
                } else {
                    not_present += 1;
                }
            }
        }
        if any_changed {
            crate::cpu::tlb::shootdown_all();
        }
        Ok(not_present)
    }

    pub fn unmap_keep_frame(&mut self, vaddr: VirtAddr) {
        let page = match Page::<Size4KiB>::from_start_address(vaddr) {
            Ok(p) => p,
            Err(_) => return,
        };
        let unmapped = {
            let _g = PT_MUTATION_LOCK.lock();
            let mut mapper = self.mapper();
            if let Ok((_frame, flush)) = mapper.unmap(page) {
                flush.flush();
                true
            } else {
                false
            }
        };
        if unmapped {
            crate::cpu::tlb::shootdown_all();
        }
    }

    pub fn unmap_pages(&mut self, vaddr: VirtAddr, pages: usize) {
        let start = match Page::<Size4KiB>::from_start_address(vaddr) {
            Ok(p) => p,
            Err(_) => return,
        };
        let mut freed: alloc::vec::Vec<PhysFrame<Size4KiB>> = alloc::vec::Vec::new();
        {
            let _g = PT_MUTATION_LOCK.lock();
            let mut mapper = self.mapper();
            for i in 0..pages {
                let page = start + i as u64;
                if let Ok((frame, flush)) = mapper.unmap(page) {
                    flush.flush();
                    freed.push(frame);
                }
            }
        }
        if !freed.is_empty() {
            crate::cpu::tlb::shootdown_all();
            for frame in freed {
                frame_alloc::free_frame(frame);
            }
        }
    }

    /// # Safety
    ///
    /// Switching CR3 invalidates all virtual addresses the caller's
    /// code is currently using. Caller must ensure this `VmSpace`
    /// maps the kernel's currently-executing code, current stack, and
    /// any data the caller is about to touch.
    pub unsafe fn activate_with_prev(&self) -> PhysFrame<Size4KiB> {
        let (prev, flags) = Cr3::read();
        Cr3::write(self.root, flags);
        prev
    }

    pub fn activate_for_task(&self) {
        let (_, flags) = Cr3::read();
        // SAFETY: see method-doc rationale.
        unsafe { Cr3::write(self.root, flags) };
    }

    pub fn with_active<R>(&self, f: impl FnOnce() -> R) -> R {
        // SAFETY: see method-doc rationale; kernel-half PML4 entries
        // are shared, and we restore the original CR3 before
        // returning so any pre-swap caller's view is unchanged.
        let prev = unsafe { self.activate_with_prev() };
        let result = f();
        let (_, flags) = Cr3::read();
        // SAFETY: `prev` is the exact CR3 root captured on entry by
        // `activate_with_prev`; restoring it returns the CPU to the
        // address space that was active before this call, so the
        // caller's code, stack, and data remain mapped. `flags`
        // preserves the current PCID/PWT/PCD bits.
        unsafe { Cr3::write(prev, flags) };
        result
    }

    pub fn is_active(&self) -> bool {
        Cr3::read().0 == self.root
    }

    pub fn clone_user_half(&mut self) -> Result<VmSpace, MapError> {
        self.clone_user_half_with_shared(&[]).map(|(vm, _)| vm)
    }

    pub fn clone_user_half_with_shared(
        &mut self,
        shared_ranges: &[(u64, u64)],
    ) -> Result<(VmSpace, alloc::vec::Vec<u64>), MapError> {
        use crate::boot::KERNEL_VMA_OFFSET;
        const PRESENT: u64 = 1 << 0;
        const WRITABLE: u64 = 1 << 1;
        const USER: u64 = 1 << 2;
        const HUGE: u64 = 1 << 7;
        const NX: u64 = 1 << 63;
        const FRAME_MASK: u64 = 0x000f_ffff_ffff_f000;

        let mut child = Self::new_user()?;
        let mut shared_vaddrs: alloc::vec::Vec<u64> = alloc::vec::Vec::new();

        let parent_pml4_pa = self.root.start_address().as_u64();
        // SAFETY: page-table frames live in low DRAM (< 1 GiB); the
        // kernel high mapping covers that range, and the kernel-half
        // PML4 entry is shared across every per-process VmSpace, so
        // the high VA is reachable regardless of CR3.
        let parent_pml4 = (parent_pml4_pa | KERNEL_VMA_OFFSET) as *const u64;

        let mut walk_err: Option<MapError> = None;
        'walk: for i4 in 0usize..256 {
            // SAFETY: `parent_pml4` points at the parent's PML4 frame via
            // the kernel high mapping; `i4 < 256` keeps the offset inside
            // the 512-entry table, and each slot is an aligned `u64`, so
            // this read is in-bounds and well-aligned.
            //
            // CONCURRENCY (NOT fully serialized — see flag): this raw
            // walk does NOT hold `PT_MUTATION_LOCK`. The fork caller
            // holds the per-AddressSpace vmspace lock, but the mm
            // syscalls (mmap/munmap/mprotect on a CLONE_VM peer) take
            // only `PT_MUTATION_LOCK`, a disjoint lock — so a peer CPU
            // sharing this root can mutate these entries (and free the
            // intermediate frames whose `pa | KERNEL_VMA_OFFSET` aliases
            // the l3/l2/l1 reads below) mid-walk. Soundness today rests
            // on no CLONE_VM-peer mmap/munmap running concurrently with
            // this fork; that is not enforced here.
            let l4_e = unsafe { parent_pml4.add(i4).read() };
            if l4_e & PRESENT == 0 {
                continue;
            }
            let l3 = ((l4_e & FRAME_MASK) | KERNEL_VMA_OFFSET) as *const u64;
            for i3 in 0usize..512 {
                // SAFETY: `l3` is the high-mapping VA of the PDPT frame
                // named by the present (checked above) L4 entry; the
                // frame lives in low DRAM covered by the kernel high
                // mapping. `i3 < 512` keeps the aligned `u64` read inside
                // the table. (Same unserialized-peer-mutation caveat as
                // the L4 read above: a concurrent peer munmap could free
                // this PDPT frame mid-walk.)
                let l3_e = unsafe { l3.add(i3).read() };
                if l3_e & PRESENT == 0 || l3_e & HUGE != 0 {
                    continue;
                }
                let l2 = ((l3_e & FRAME_MASK) | KERNEL_VMA_OFFSET) as *const u64;
                for i2 in 0usize..512 {
                    // SAFETY: `l2` is the high-mapping VA of the PD frame
                    // named by the present, non-huge (checked above) L3
                    // entry, in kernel-mapped low DRAM. `i2 < 512` keeps
                    // the aligned `u64` read in bounds.
                    let l2_e = unsafe { l2.add(i2).read() };
                    if l2_e & PRESENT == 0 || l2_e & HUGE != 0 {
                        continue;
                    }
                    let l1 = ((l2_e & FRAME_MASK) | KERNEL_VMA_OFFSET) as *const u64;
                    for i1 in 0usize..512 {
                        // SAFETY: `l1` is the high-mapping VA of the PT
                        // frame named by the present, non-huge (checked
                        // above) L2 entry, in kernel-mapped low DRAM.
                        // `i1 < 512` keeps the aligned `u64` leaf read in
                        // bounds.
                        let l1_e = unsafe { l1.add(i1).read() };
                        if l1_e & PRESENT == 0 {
                            continue;
                        }

                        let parent_frame_pa = l1_e & FRAME_MASK;
                        let vaddr = ((i4 as u64) << 39)
                            | ((i3 as u64) << 30)
                            | ((i2 as u64) << 21)
                            | ((i1 as u64) << 12);

                        let mut perms = Perms::READ;
                        if l1_e & WRITABLE != 0 {
                            perms |= Perms::WRITE;
                        }
                        if l1_e & USER != 0 {
                            perms |= Perms::USER;
                        }
                        if l1_e & NX == 0 {
                            perms |= Perms::EXECUTE;
                        }

                        let is_shared = shared_ranges
                            .iter()
                            .any(|&(lo, hi)| vaddr >= lo && vaddr < hi);

                        let page = match Page::<Size4KiB>::from_start_address(VirtAddr::new(vaddr))
                        {
                            Ok(p) => p,
                            Err(_) => {
                                walk_err = Some(MapError::Misaligned);
                                break 'walk;
                            }
                        };

                        if is_shared {
                            let parent_frame = match PhysFrame::<Size4KiB>::from_start_address(
                                PhysAddr::new(parent_frame_pa),
                            ) {
                                Ok(f) => f,
                                Err(_) => {
                                    walk_err = Some(MapError::Misaligned);
                                    break 'walk;
                                }
                            };
                            if let Err(e) = child.map_one_frame(page, parent_frame, perms) {
                                walk_err = Some(e);
                                break 'walk;
                            }
                            shared_vaddrs.push(vaddr);
                        } else {
                            let child_frame = match frame_alloc::alloc_frame() {
                                Some(f) => f,
                                None => {
                                    walk_err = Some(MapError::OutOfFrames);
                                    break 'walk;
                                }
                            };
                            let child_frame_pa = child_frame.start_address().as_u64();
                            // SAFETY: source and dest are valid page-aligned
                            // 4 KiB frames in low DRAM, both reachable via the
                            // kernel high mapping. Non-overlapping by
                            // construction (alloc_frame returned a fresh frame).
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    (parent_frame_pa | KERNEL_VMA_OFFSET) as *const u8,
                                    (child_frame_pa | KERNEL_VMA_OFFSET) as *mut u8,
                                    4096,
                                );
                            }
                            if let Err(e) = child.map(VirtAddr::new(vaddr), child_frame, perms) {
                                frame_alloc::free_frame(child_frame);
                                walk_err = Some(e);
                                break 'walk;
                            }
                        }
                    }
                }
            }
        }

        if let Some(e) = walk_err {
            for &v in &shared_vaddrs {
                child.unmap_keep_frame(VirtAddr::new(v));
            }
            return Err(e);
        }

        Ok((child, shared_vaddrs))
    }

    pub fn clear_user(&mut self) {
        use crate::boot::KERNEL_VMA_OFFSET;
        const PRESENT: u64 = 1 << 0;
        const HUGE: u64 = 1 << 7;
        const FRAME_MASK: u64 = 0x000f_ffff_ffff_f000;

        let pml4_pa = self.root.start_address().as_u64();
        let pml4 = (pml4_pa | KERNEL_VMA_OFFSET) as *mut u64;

        let mut any_unmapped = false;
        for i4 in 0usize..256 {
            // SAFETY: `pml4` is the high-mapping VA of this VmSpace's root
            // frame (kernel-mapped low DRAM); `i4 < 256` keeps the aligned
            // `u64` read in the user half of the 512-entry table. clear_user
            // runs only at terminal teardown — VmSpace `Drop`, or `execve`
            // after the caller has SIGKILL'd/reaped every CLONE_VM peer — so
            // no peer CPU is walking this root concurrently. (`&mut self`
            // alone would NOT establish that: a peer sharing this root holds
            // its own VmSpace; cross-CPU structure access is serialized by
            // PT_MUTATION_LOCK, which clear_user need not take because the
            // peers are already gone.)
            let l4_e = unsafe { pml4.add(i4).read() };
            if l4_e & PRESENT == 0 {
                continue;
            }
            if l4_e & HUGE != 0 {
                // SAFETY: same user-half PML4 slot just read, under the
                // teardown precondition above (no peer CPU touches this root);
                // zeroing the entry drops the defensively-handled huge mapping.
                unsafe { pml4.add(i4).write(0) };
                any_unmapped = true;
                continue;
            }
            let l3_pa = l4_e & FRAME_MASK;
            let l3 = (l3_pa | KERNEL_VMA_OFFSET) as *mut u64;
            for i3 in 0usize..512 {
                // SAFETY: `l3` is the high-mapping VA of the PDPT frame
                // named by the present, non-huge L4 entry above, in
                // kernel-mapped low DRAM. `i3 < 512` keeps the aligned
                // `u64` read in bounds.
                let l3_e = unsafe { l3.add(i3).read() };
                if l3_e & PRESENT == 0 || l3_e & HUGE != 0 {
                    continue;
                }
                let l2_pa = l3_e & FRAME_MASK;
                let l2 = (l2_pa | KERNEL_VMA_OFFSET) as *mut u64;
                for i2 in 0usize..512 {
                    // SAFETY: `l2` is the high-mapping VA of the PD frame
                    // named by the present, non-huge L3 entry above, in
                    // kernel-mapped low DRAM. `i2 < 512` keeps the
                    // aligned `u64` read in bounds.
                    let l2_e = unsafe { l2.add(i2).read() };
                    if l2_e & PRESENT == 0 || l2_e & HUGE != 0 {
                        continue;
                    }
                    let l1_pa = l2_e & FRAME_MASK;
                    let l1 = (l1_pa | KERNEL_VMA_OFFSET) as *mut u64;
                    for i1 in 0usize..512 {
                        // SAFETY: `l1` is the high-mapping VA of the PT
                        // frame named by the present, non-huge L2 entry
                        // above, in kernel-mapped low DRAM. `i1 < 512`
                        // keeps the aligned `u64` leaf read in bounds.
                        let l1_e = unsafe { l1.add(i1).read() };
                        if l1_e & PRESENT == 0 {
                            continue;
                        }
                        let leaf_pa = l1_e & FRAME_MASK;
                        if let Ok(f) =
                            PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(leaf_pa))
                        {
                            frame_alloc::free_frame(f);
                        }
                        // SAFETY: same PT slot just read, under the teardown
                        // precondition above (no peer CPU touches this root);
                        // the leaf frame was already returned to the allocator
                        // above, so zeroing the entry removes the only mapping
                        // that referenced it.
                        unsafe { l1.add(i1).write(0) };
                        any_unmapped = true;
                    }
                    if let Ok(f) = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(l1_pa)) {
                        frame_alloc::free_frame(f);
                    }
                    // SAFETY: in-bounds (`i2 < 512`) PD slot, under the
                    // teardown precondition above (no peer CPU touches this
                    // root); the L1 frame it pointed to was just freed, so
                    // zeroing the entry drops its last reference.
                    unsafe { l2.add(i2).write(0) };
                }
                if let Ok(f) = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(l2_pa)) {
                    frame_alloc::free_frame(f);
                }
                // SAFETY: in-bounds (`i3 < 512`) PDPT slot, under the teardown
                // precondition above (no peer CPU touches this root); the L2
                // frame it pointed to was just freed, so zeroing the entry
                // drops its last reference.
                unsafe { l3.add(i3).write(0) };
            }
            if let Ok(f) = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(l3_pa)) {
                frame_alloc::free_frame(f);
            }
            // SAFETY: in-bounds (`i4 < 256`, user half) PML4 slot, under the
            // teardown precondition above (no peer CPU touches this root); the
            // L3 frame it pointed to was just freed, so zeroing the entry drops
            // its last reference while leaving the kernel half (256..512)
            // untouched.
            unsafe { pml4.add(i4).write(0) };
        }

        if any_unmapped {
            crate::cpu::tlb::shootdown_all();
        }
    }
}

impl Drop for VmSpace {
    fn drop(&mut self) {
        if self.owned {
            self.clear_user();
            frame_alloc::free_frame(self.root);
        }
    }
}

pub struct MappedRegion {
    start: VirtAddr,
    pages: usize,
    owned_frames: alloc::vec::Vec<PhysFrame<Size4KiB>>,
}

impl MappedRegion {
    pub fn start(&self) -> VirtAddr {
        self.start
    }

    pub fn pages(&self) -> usize {
        self.pages
    }

    pub fn size_bytes(&self) -> usize {
        self.pages * 4096
    }
}

impl Drop for MappedRegion {
    fn drop(&mut self) {}
}

#[derive(Debug)]
pub enum MapError {
    OutOfFrames,
    Misaligned,
    AlreadyMapped,
    ParentTableHugePage,
}

impl MapError {
    fn from_x86_64(err: MapToError<Size4KiB>) -> Self {
        match err {
            MapToError::FrameAllocationFailed => Self::OutOfFrames,
            MapToError::ParentEntryHugePage => Self::ParentTableHugePage,
            MapToError::PageAlreadyMapped(_) => Self::AlreadyMapped,
        }
    }
}
