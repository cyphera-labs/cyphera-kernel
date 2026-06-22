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

#[cfg(cow_fork_forced_window)]
const COW_FORCED_WINDOW_LO: u64 = 0x4000_0000;
#[cfg(cow_fork_forced_window)]
const COW_FORCED_WINDOW_HI: u64 = COW_FORCED_WINDOW_LO + 64 * 4096;
#[cfg(cow_fork_forced_window)]
const COW_FORCED_WINDOW_BUDGET: u64 = 2_000_000;
#[cfg(cow_fork_forced_window)]
static COW_FORCED_WINDOW_DONE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[cfg(cow_fork_forced_window)]
#[inline(never)]
fn cow_fork_forced_window_after_leaf_read(parent_pml4: *const u64, vaddr: u64, expected: [u64; 4]) {
    if !(COW_FORCED_WINDOW_LO..COW_FORCED_WINDOW_HI).contains(&vaddr) {
        return;
    }
    if COW_FORCED_WINDOW_DONE.swap(true, core::sync::atomic::Ordering::AcqRel) {
        return;
    }
    const FW_PRESENT: u64 = 1 << 0;
    const FW_HUGE: u64 = 1 << 7;
    const FW_FRAME_MASK: u64 = 0x000f_ffff_ffff_f000;
    let i4 = ((vaddr >> 39) & 0x1ff) as usize;
    let i3 = ((vaddr >> 30) & 0x1ff) as usize;
    let i2 = ((vaddr >> 21) & 0x1ff) as usize;
    let i1 = ((vaddr >> 12) & 0x1ff) as usize;
    let mut n = 0u64;
    while n < COW_FORCED_WINDOW_BUDGET {
        // SAFETY: re-walks the parent tree exactly as the fork walk above —
        // `parent_pml4` is the parent PML4 direct-map alias, each index is masked
        // to one 512-entry table, and a deeper level is dereferenced only after
        // its parent entry is confirmed present AND unchanged. A freed table
        // clears its parent entry, so a freed frame is caught at the parent level
        // and never read through. Reads are volatile so the loop re-reads memory
        // each pass and observes a peer-CPU mutation instead of caching the first.
        unsafe {
            let l4_e = core::ptr::read_volatile(parent_pml4.add(i4));
            if l4_e & FW_PRESENT == 0 || l4_e != expected[0] {
                panic!("cow_fork_forced_window: L4 entry changed/freed under the window");
            }
            let l3 = crate::mm::direct_map::phys_to_virt(l4_e & FW_FRAME_MASK) as *const u64;
            let l3_e = core::ptr::read_volatile(l3.add(i3));
            if l3_e & FW_PRESENT == 0 || l3_e & FW_HUGE != 0 || l3_e != expected[1] {
                panic!("cow_fork_forced_window: L3 entry changed/freed under the window");
            }
            let l2 = crate::mm::direct_map::phys_to_virt(l3_e & FW_FRAME_MASK) as *const u64;
            let l2_e = core::ptr::read_volatile(l2.add(i2));
            if l2_e & FW_PRESENT == 0 || l2_e & FW_HUGE != 0 || l2_e != expected[2] {
                panic!("cow_fork_forced_window: L2 entry changed/freed under the window");
            }
            let l1 = crate::mm::direct_map::phys_to_virt(l2_e & FW_FRAME_MASK) as *const u64;
            let l1_e = core::ptr::read_volatile(l1.add(i1));
            if l1_e & FW_PRESENT == 0 || l1_e != expected[3] {
                panic!("cow_fork_forced_window: L1 leaf changed/freed under the window");
            }
        }
        core::hint::spin_loop();
        n += 1;
    }
}

#[cfg(not(cow_fork_forced_window))]
#[inline(always)]
fn cow_fork_forced_window_after_leaf_read(
    _parent_pml4: *const u64,
    _vaddr: u64,
    _expected: [u64; 4],
) {
}

const COW_PTE: PageTableFlags = PageTableFlags::BIT_9;

const PTE_PRESENT: u64 = 1 << 0;
const PTE_HUGE: u64 = 1 << 7;
const PTE_FRAME_MASK: u64 = 0x000f_ffff_ffff_f000;

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
        let f = frame_alloc::alloc_frame()?;
        let kva = crate::mm::direct_map::phys_to_virt(f.start_address().as_u64());
        // SAFETY: `f` is a freshly-allocated 4 KiB frame; the direct map
        // aliases all RAM writable at phys_to_virt(pa) and is shared into
        // every address space, so this is a valid writable VA for the
        // frame. We own it exclusively and the 4096-byte write stays in it.
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

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AddrSpaceRoot(PhysFrame<Size4KiB>);

impl AddrSpaceRoot {
    pub fn as_phys(&self) -> u64 {
        self.0.start_address().as_u64()
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

    pub fn root(&self) -> AddrSpaceRoot {
        AddrSpaceRoot(self.root)
    }

    pub fn activate_root(root: AddrSpaceRoot) {
        let (_, flags) = Cr3::read();
        // SAFETY: caller asserts the frame is a valid PML4 with the
        // kernel high-half mirrored. Same rationale as
        // `activate_for_task`.
        unsafe { Cr3::write(root.0, flags) };
    }

    pub fn new() -> Result<Self, MapError> {
        let root = frame_alloc::alloc_frame().ok_or(MapError::OutOfFrames)?;
        let kva = crate::mm::direct_map::phys_to_virt(root.start_address().as_u64());
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
        let new = Self::new()?;
        let parent_kva =
            crate::mm::direct_map::phys_to_virt(Cr3::read().0.start_address().as_u64());
        let child_kva = crate::mm::direct_map::phys_to_virt(new.root.start_address().as_u64());
        // SAFETY: `parent_kva`/`child_kva` are the direct-map VAs of
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
        let pml4_va = crate::mm::direct_map::phys_to_virt(self.root.start_address().as_u64());
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
        // SAFETY: the direct map aliases all physical RAM at a constant
        // offset (DIRECT_MAP_BASE), so every page-table frame reachable
        // from `l4` is addressable at `pa + DIRECT_MAP_BASE` — exactly the
        // physical-memory-offset contract `OffsetPageTable::new` requires.
        unsafe { OffsetPageTable::new(l4, VirtAddr::new(crate::mm::direct_map::DIRECT_MAP_BASE)) }
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

    pub fn map_one_frame_fork_anon(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        perms: Perms,
        cow: bool,
    ) -> Result<(), MapError> {
        let mut alloc = PhysFrameAdapter;
        let leaf_flags = if cow {
            (perms.to_pte_flags() & !PageTableFlags::WRITABLE) | COW_PTE
        } else {
            perms.to_pte_flags()
        };
        let parent_flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
        let _g = PT_MUTATION_LOCK.lock();
        let mut mapper = self.mapper();
        // SAFETY: `PT_MUTATION_LOCK` is held, serializing this single mapping
        // against peer-CPU table mutation. `page` is caller-provided and
        // `frame` is the parent's existing leaf frame being shared into the
        // child; `alloc` zeroes any intermediate table. The frame stays owned
        // by the refcount layer, not this mapping — the caller bumps its
        // refcount.
        unsafe {
            mapper
                .map_to_with_table_flags(page, frame, leaf_flags, parent_flags, &mut alloc)
                .map_err(MapError::from_x86_64)?
                .flush();
        }
        Ok(())
    }

    fn downgrade_leaf_to_cow_and_inc_locked(
        &mut self,
        vaddr: u64,
        parent_frame: PhysFrame<Size4KiB>,
    ) -> bool {
        match self.leaf_pte_ptr(vaddr) {
            Some(p) => {
                frame_alloc::frame_ref_inc(parent_frame);
                // SAFETY: `p` is the direct-map VA of a present leaf PTE; the
                // lock is held, so this is the only writer. Clearing WRITABLE
                // and setting the COW bit downgrades the parent's own mapping
                // to read-only-COW so its next write also copies. The refcount
                // was bumped above, under this same lock, before the leaf
                // becomes observably read-only-COW.
                unsafe {
                    let e = p.read();
                    p.write((e & !PageTableFlags::WRITABLE.bits()) | COW_PTE.bits());
                }
                true
            }
            None => false,
        }
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
                crate::mm::zero_frame(frame);
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

    fn leaf_pte_ptr(&mut self, vaddr: u64) -> Option<*mut u64> {
        let mut table_pa = self.root.start_address().as_u64();
        let shifts = [39u32, 30, 21, 12];
        for (level, shift) in shifts.iter().enumerate() {
            let idx = ((vaddr >> shift) & 0x1ff) as usize;
            let entry_va = crate::mm::direct_map::phys_to_virt(table_pa) + (idx as u64) * 8;
            // SAFETY: `table_pa` starts at this VmSpace's root frame and is
            // replaced each level by the next table's frame number masked out
            // of a present (checked below) non-huge entry; every such frame is
            // RAM aliased by the direct map. `idx < 512` keeps the aligned
            // `u64` read inside the 512-entry table. The caller holds
            // PT_MUTATION_LOCK, serializing this walk against peer-CPU
            // structure mutation.
            let entry = unsafe { (entry_va as *const u64).read() };
            if entry & PTE_PRESENT == 0 {
                return None;
            }
            if level == 3 {
                return Some(entry_va as *mut u64);
            }
            if entry & PTE_HUGE != 0 {
                return None;
            }
            table_pa = entry & PTE_FRAME_MASK;
        }
        None
    }

    pub fn page_is_cow(&mut self, vaddr: VirtAddr) -> bool {
        let _g = PT_MUTATION_LOCK.lock();
        match self.leaf_pte_ptr(vaddr.as_u64() & !0xfff) {
            // SAFETY: `leaf_pte_ptr` returned the direct-map VA of a present
            // leaf PTE; reading the `u64` is in-bounds and the lock is held.
            Some(p) => (unsafe { p.read() } & COW_PTE.bits()) != 0,
            None => false,
        }
    }

    pub fn break_cow(
        &mut self,
        vaddr: VirtAddr,
        new_perms: Option<Perms>,
    ) -> Result<CowBreak, MapError> {
        let page_va = vaddr.as_u64() & !0xfff;
        let _g = PT_MUTATION_LOCK.lock();
        let pte_ptr = match self.leaf_pte_ptr(page_va) {
            Some(p) => p,
            None => return Ok(CowBreak::NotPresent),
        };
        // SAFETY: `pte_ptr` is the direct-map VA of a present leaf PTE; under
        // PT_MUTATION_LOCK (held here, the lock every PTE mutation takes) no
        // one else mutates it, so this read observes the live entry.
        let entry = unsafe { pte_ptr.read() };
        if entry & PageTableFlags::WRITABLE.bits() != 0 {
            return Ok(CowBreak::AlreadyWritable);
        }
        if entry & COW_PTE.bits() == 0 {
            return Ok(CowBreak::NotCow);
        }
        let old_pa = entry & PTE_FRAME_MASK;
        let old_frame = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(old_pa))
            .map_err(|_| MapError::Misaligned)?;
        if frame_alloc::frame_ref_count(old_frame) == 0 {
            return Ok(CowBreak::NotCow);
        }
        let perm_bits = match new_perms {
            Some(p) => p.to_pte_flags().bits() & !PTE_FRAME_MASK & !COW_PTE.bits(),
            None => entry & !PTE_FRAME_MASK & !COW_PTE.bits(),
        };
        if frame_alloc::frame_ref_count(old_frame) == 1 {
            let new_flags = perm_bits | PageTableFlags::WRITABLE.bits();
            // SAFETY: same present leaf PTE read above; PT_MUTATION_LOCK is
            // held, so this is the only writer. Keeping the frame and clearing
            // COW + setting WRITABLE upgrades the sole owner's mapping in place.
            unsafe {
                pte_ptr.write((entry & PTE_FRAME_MASK) | new_flags);
            }
            crate::cpu::tlb::flush_local_page(page_va);
            Ok(CowBreak::BrokenInPlace)
        } else {
            let new_frame = frame_alloc::alloc_frame().ok_or(MapError::OutOfFrames)?;
            let new_pa = new_frame.start_address().as_u64();
            // SAFETY: `old_pa`/`new_pa` are page-aligned 4 KiB frames, both
            // aliased writable by the direct map; the copy is non-overlapping
            // (`new_frame` was just freshly allocated, so it does not alias
            // `old_frame`).
            unsafe {
                core::ptr::copy_nonoverlapping(
                    crate::mm::direct_map::phys_to_virt(old_pa) as *const u8,
                    crate::mm::direct_map::phys_to_virt(new_pa) as *mut u8,
                    4096,
                );
            }
            let new_flags = perm_bits | PageTableFlags::WRITABLE.bits();
            // SAFETY: same present leaf PTE read above; PT_MUTATION_LOCK is
            // held, so this is the only writer. Pointing the entry at `new_pa`
            // (the just-copied private frame) with WRITABLE set and the COW bit
            // cleared is remap-then-free: the mapping is swapped here; the
            // caller frees `old_frame` only after its post-lock shootdown.
            unsafe {
                pte_ptr.write(new_pa | new_flags);
            }
            crate::cpu::tlb::flush_local_page(page_va);
            Ok(CowBreak::Broken { old_frame })
        }
    }

    fn restamp_perms(&mut self, page_va: u64, perms: Perms) -> bool {
        let _g = PT_MUTATION_LOCK.lock();
        let pte_ptr = match self.leaf_pte_ptr(page_va) {
            Some(p) => p,
            None => return false,
        };
        let perm_bits = perms.to_pte_flags().bits() & !PTE_FRAME_MASK & !COW_PTE.bits();
        // SAFETY: `pte_ptr` is the direct-map VA of a present leaf PTE;
        // PT_MUTATION_LOCK is held, so this is the only writer. The new entry
        // reuses the existing frame number (read out verbatim) and keeps it
        // writable, rewriting only the perm/NX flags and clearing COW.
        unsafe {
            let entry = pte_ptr.read();
            let new_flags = perm_bits | PageTableFlags::WRITABLE.bits();
            pte_ptr.write((entry & PTE_FRAME_MASK) | new_flags);
        }
        crate::cpu::tlb::flush_local_page(page_va);
        true
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
    ) -> Result<ProtectResult, MapError> {
        let start = match Page::<Size4KiB>::from_start_address(vaddr) {
            Ok(p) => p,
            Err(_) => return Err(MapError::Misaligned),
        };
        let new_flags = perms.to_pte_flags();
        let want_write = perms.contains(Perms::WRITE);
        let mut any_changed = false;
        let mut not_present = 0usize;
        let mut cow_break_pages: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        {
            let _g = PT_MUTATION_LOCK.lock();
            for i in 0..pages {
                let page = start + i as u64;
                let page_va = page.start_address().as_u64();
                let pte = match self.leaf_pte_ptr(page_va) {
                    Some(p) => p,
                    None => {
                        not_present += 1;
                        continue;
                    }
                };
                // SAFETY: `pte` is the direct-map VA of a present leaf PTE;
                // PT_MUTATION_LOCK is held, so this is the only writer. The new
                // entry reuses the existing frame number (preserved verbatim
                // out of the read), so this rewrites only the permission flags.
                unsafe {
                    let entry = pte.read();
                    let is_cow = entry & COW_PTE.bits() != 0;
                    if is_cow && want_write {
                        if frame_alloc::frame_ref_count(PhysFrame::<Size4KiB>::containing_address(
                            PhysAddr::new(entry & PTE_FRAME_MASK),
                        )) > 1
                        {
                            let ro = (entry & !PTE_FRAME_MASK & !PageTableFlags::WRITABLE.bits())
                                | COW_PTE.bits();
                            pte.write((entry & PTE_FRAME_MASK) | ro);
                            cow_break_pages.push(page_va);
                        } else {
                            let flags = new_flags.bits() & !COW_PTE.bits();
                            pte.write((entry & PTE_FRAME_MASK) | flags);
                        }
                    } else {
                        let mut flags = new_flags.bits();
                        if is_cow {
                            flags = (flags & !PageTableFlags::WRITABLE.bits()) | COW_PTE.bits();
                        }
                        pte.write((entry & PTE_FRAME_MASK) | flags);
                    }
                }
                any_changed = true;
            }
        }
        if any_changed {
            crate::cpu::tlb::shootdown_all();
        }
        let mut copied = 0usize;
        let mut any_broken = false;
        let mut freed: alloc::vec::Vec<PhysFrame<Size4KiB>> = alloc::vec::Vec::new();
        for page_va in cow_break_pages {
            match self.break_cow(VirtAddr::new(page_va), Some(perms)) {
                Ok(CowBreak::Broken { old_frame }) => {
                    copied += 1;
                    any_broken = true;
                    freed.push(old_frame);
                }
                Ok(CowBreak::BrokenInPlace) => any_broken = true,
                Ok(CowBreak::AlreadyWritable) => {
                    any_broken |= self.restamp_perms(page_va, perms);
                }
                _ => {}
            }
        }
        if any_broken {
            crate::cpu::tlb::shootdown_all();
            for f in freed {
                frame_alloc::free_frame(f);
            }
        }
        Ok(ProtectResult {
            not_present,
            copied,
        })
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
        let freed = self.unmap_pages_collect(vaddr, pages);
        if !freed.is_empty() {
            crate::cpu::tlb::shootdown_all();
            for frame in freed {
                frame_alloc::free_frame(frame);
            }
        }
    }

    pub fn unmap_pages_collect(
        &mut self,
        vaddr: VirtAddr,
        pages: usize,
    ) -> alloc::vec::Vec<PhysFrame<Size4KiB>> {
        let start = match Page::<Size4KiB>::from_start_address(vaddr) {
            Ok(p) => p,
            Err(_) => return alloc::vec::Vec::new(),
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
        freed
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

    pub fn clone_user_half_phase1(
        &mut self,
        shared_ranges: &[(u64, u64)],
    ) -> Result<CowClone, MapError> {
        const PRESENT: u64 = 1 << 0;
        const WRITABLE: u64 = 1 << 1;
        const USER: u64 = 1 << 2;
        const HUGE: u64 = 1 << 7;
        const NX: u64 = 1 << 63;
        const FRAME_MASK: u64 = 0x000f_ffff_ffff_f000;
        let cow_bit = COW_PTE.bits();

        let mut child = Self::new_user()?;
        let mut shared_vaddrs: alloc::vec::Vec<u64> = alloc::vec::Vec::new();
        let mut cow_vaddrs: alloc::vec::Vec<(u64, PhysFrame<Size4KiB>, Perms)> =
            alloc::vec::Vec::new();
        let mut child_installed: alloc::vec::Vec<(u64, PhysFrame<Size4KiB>, bool)> =
            alloc::vec::Vec::new();

        #[derive(Clone, Copy)]
        enum DeferredMap {
            SharedFile,
            ReadonlyShare,
            EagerCopy,
        }
        let mut deferred: alloc::vec::Vec<(u64, PhysFrame<Size4KiB>, Perms, DeferredMap)> =
            alloc::vec::Vec::new();

        let parent_pml4_pa = self.root.start_address().as_u64();
        // SAFETY: page-table frames live in RAM, which the direct map
        // aliases at phys_to_virt(pa); the kernel-half PML4 entry is
        // shared across every per-process VmSpace, so the VA is
        // reachable regardless of CR3.
        let parent_pml4 = (crate::mm::direct_map::phys_to_virt(parent_pml4_pa)) as *const u64;

        let mut walk_err: Option<MapError> = None;
        let _pt = PT_MUTATION_LOCK.lock();
        'walk: for i4 in 0usize..256 {
            // SAFETY: `parent_pml4` is the parent PML4 frame's direct-map
            // alias; `i4 < 256` keeps the offset inside the 512-entry table,
            // and each slot is an aligned `u64`, so this read is in-bounds and
            // well-aligned. PT_MUTATION_LOCK (held) excludes the mutators that
            // could free this frame, so it stays a live page table for the walk.
            let l4_e = unsafe { parent_pml4.add(i4).read() };
            if l4_e & PRESENT == 0 {
                continue;
            }
            let l3 = (crate::mm::direct_map::phys_to_virt(l4_e & FRAME_MASK)) as *const u64;
            for i3 in 0usize..512 {
                // SAFETY: `l3` is the direct-map VA of the PDPT frame
                // named by the present (checked above) L4 entry; the
                // frame lives in RAM aliased by the direct mapping.
                // `i3 < 512` keeps the aligned `u64` read inside the
                // table. PT_MUTATION_LOCK (held across the walk) excludes
                // the peer munmap that could free this PDPT frame.
                let l3_e = unsafe { l3.add(i3).read() };
                if l3_e & PRESENT == 0 || l3_e & HUGE != 0 {
                    continue;
                }
                let l2 = (crate::mm::direct_map::phys_to_virt(l3_e & FRAME_MASK)) as *const u64;
                for i2 in 0usize..512 {
                    // SAFETY: `l2` is the direct-map VA of the PD frame
                    // named by the present, non-huge (checked above) L3
                    // entry, in RAM (direct-mapped). `i2 < 512` keeps
                    // the aligned `u64` read in bounds.
                    let l2_e = unsafe { l2.add(i2).read() };
                    if l2_e & PRESENT == 0 || l2_e & HUGE != 0 {
                        continue;
                    }
                    let l1 = (crate::mm::direct_map::phys_to_virt(l2_e & FRAME_MASK)) as *const u64;
                    for i1 in 0usize..512 {
                        // SAFETY: `l1` is the direct-map VA of the PT
                        // frame named by the present, non-huge (checked
                        // above) L2 entry, in RAM (direct-mapped).
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

                        cow_fork_forced_window_after_leaf_read(
                            parent_pml4,
                            vaddr,
                            [l4_e, l3_e, l2_e, l1_e],
                        );

                        let parent_is_cow = l1_e & cow_bit != 0;
                        let mut perms = Perms::READ;
                        if l1_e & WRITABLE != 0 || parent_is_cow {
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

                        let parent_frame = match PhysFrame::<Size4KiB>::from_start_address(
                            PhysAddr::new(parent_frame_pa),
                        ) {
                            Ok(f) => f,
                            Err(_) => {
                                walk_err = Some(MapError::Misaligned);
                                break 'walk;
                            }
                        };

                        if is_shared {
                            deferred.push((vaddr, parent_frame, perms, DeferredMap::SharedFile));
                        } else {
                            let is_writable = perms.contains(Perms::WRITE);
                            let tracked = frame_alloc::frame_ref_count(parent_frame) != 0;
                            if is_writable && tracked {
                                if self.downgrade_leaf_to_cow_and_inc_locked(vaddr, parent_frame) {
                                    cow_vaddrs.push((vaddr, parent_frame, perms));
                                }
                            } else if !is_writable && tracked {
                                frame_alloc::frame_ref_inc(parent_frame);
                                deferred.push((
                                    vaddr,
                                    parent_frame,
                                    perms,
                                    DeferredMap::ReadonlyShare,
                                ));
                            } else {
                                let new_frame = match frame_alloc::alloc_frame() {
                                    Some(f) => f,
                                    None => {
                                        walk_err = Some(MapError::OutOfFrames);
                                        break 'walk;
                                    }
                                };
                                let src = parent_frame.start_address().as_u64();
                                let dst = new_frame.start_address().as_u64();
                                // SAFETY: `src`/`dst` are page-aligned 4 KiB
                                // frames both aliased writable by the direct
                                // map; `new_frame` was just freshly allocated so
                                // it does not alias `parent_frame`, making the
                                // 4096-byte copy non-overlapping. PT_MUTATION_LOCK
                                // is held, so `parent_frame` cannot be freed under
                                // the copy.
                                unsafe {
                                    core::ptr::copy_nonoverlapping(
                                        crate::mm::direct_map::phys_to_virt(src) as *const u8,
                                        crate::mm::direct_map::phys_to_virt(dst) as *mut u8,
                                        4096,
                                    );
                                }
                                deferred.push((vaddr, new_frame, perms, DeferredMap::EagerCopy));
                            }
                        }
                    }
                }
            }
        }

        drop(_pt);

        if let Some(e) = walk_err {
            self.unwind_cow_share(&mut child, &shared_vaddrs, &child_installed, &cow_vaddrs, 0);
            for &(_, f, _, kind) in &deferred {
                if matches!(kind, DeferredMap::ReadonlyShare | DeferredMap::EagerCopy) {
                    frame_alloc::free_frame(f);
                }
            }
            return Err(e);
        }

        for i in 0..deferred.len() {
            let (vaddr, frame, perms, kind) = deferred[i];
            let install = match Page::<Size4KiB>::from_start_address(VirtAddr::new(vaddr)) {
                Ok(page) => match kind {
                    DeferredMap::SharedFile => child.map_one_frame(page, frame, perms),
                    DeferredMap::ReadonlyShare => {
                        child.map_one_frame_fork_anon(page, frame, perms, false)
                    }
                    DeferredMap::EagerCopy => child.map_one_frame(page, frame, perms),
                },
                Err(_) => Err(MapError::Misaligned),
            };
            if let Err(e) = install {
                self.unwind_cow_share(&mut child, &shared_vaddrs, &child_installed, &cow_vaddrs, 0);
                for &(_, f, _, k) in &deferred[i..] {
                    if matches!(k, DeferredMap::ReadonlyShare | DeferredMap::EagerCopy) {
                        frame_alloc::free_frame(f);
                    }
                }
                return Err(e);
            }
            match kind {
                DeferredMap::SharedFile => shared_vaddrs.push(vaddr),
                DeferredMap::ReadonlyShare => child_installed.push((vaddr, frame, false)),
                DeferredMap::EagerCopy => child_installed.push((vaddr, frame, true)),
            }
        }

        let needs_shootdown = !cow_vaddrs.is_empty();
        Ok(CowClone {
            child,
            shared_vaddrs,
            child_installed,
            cow_vaddrs,
            needs_shootdown,
        })
    }

    pub fn finish_cow_clone(
        &mut self,
        clone: CowClone,
    ) -> Result<(VmSpace, alloc::vec::Vec<u64>), MapError> {
        let CowClone {
            mut child,
            shared_vaddrs,
            child_installed,
            cow_vaddrs,
            needs_shootdown: _,
        } = clone;
        for idx in 0..cow_vaddrs.len() {
            let (vaddr, parent_frame, perms) = cow_vaddrs[idx];
            let page = match Page::<Size4KiB>::from_start_address(VirtAddr::new(vaddr)) {
                Ok(p) => p,
                Err(_) => {
                    self.unwind_cow_share(
                        &mut child,
                        &shared_vaddrs,
                        &child_installed,
                        &cow_vaddrs,
                        idx,
                    );
                    return Err(MapError::Misaligned);
                }
            };
            if let Err(e) = child.map_one_frame_fork_anon(page, parent_frame, perms, true) {
                self.unwind_cow_share(
                    &mut child,
                    &shared_vaddrs,
                    &child_installed,
                    &cow_vaddrs,
                    idx,
                );
                return Err(e);
            }
        }

        Ok((child, shared_vaddrs))
    }

    fn detach_child_leaf(&mut self, vaddr: VirtAddr) {
        let page = match Page::<Size4KiB>::from_start_address(vaddr) {
            Ok(p) => p,
            Err(_) => return,
        };
        let _g = PT_MUTATION_LOCK.lock();
        let mut mapper = self.mapper();
        if let Ok((_frame, flush)) = mapper.unmap(page) {
            flush.flush();
        }
    }

    fn unwind_cow_share(
        &mut self,
        child: &mut VmSpace,
        shared_vaddrs: &[u64],
        child_installed: &[(u64, PhysFrame<Size4KiB>, bool)],
        cow_vaddrs: &[(u64, PhysFrame<Size4KiB>, Perms)],
        done: usize,
    ) {
        for &v in shared_vaddrs {
            child.detach_child_leaf(VirtAddr::new(v));
        }
        for &(v, frame, _eager) in child_installed {
            child.detach_child_leaf(VirtAddr::new(v));
            frame_alloc::free_frame(frame);
        }
        for (i, &(v, frame, _p)) in cow_vaddrs.iter().enumerate() {
            if i < done {
                child.detach_child_leaf(VirtAddr::new(v));
            }
            frame_alloc::free_frame(frame);
            self.upgrade_leaf_from_cow(v);
        }
    }

    fn upgrade_leaf_from_cow(&mut self, vaddr: u64) {
        let _g = PT_MUTATION_LOCK.lock();
        if let Some(p) = self.leaf_pte_ptr(vaddr) {
            // SAFETY: `p` is the direct-map VA of a present leaf PTE; the lock
            // is held, so this is the only writer. Setting WRITABLE and
            // clearing the COW bit restores the parent's own mapping to its
            // pre-fork writable state when the clone unwinds.
            unsafe {
                let e = p.read();
                p.write((e | PageTableFlags::WRITABLE.bits()) & !COW_PTE.bits());
            }
        }
    }

    pub fn clear_user(&mut self) {
        const PRESENT: u64 = 1 << 0;
        const HUGE: u64 = 1 << 7;
        const FRAME_MASK: u64 = 0x000f_ffff_ffff_f000;

        let pml4_pa = self.root.start_address().as_u64();
        let pml4 = (crate::mm::direct_map::phys_to_virt(pml4_pa)) as *mut u64;

        let mut any_unmapped = false;
        for i4 in 0usize..256 {
            // SAFETY: `pml4` is the direct-map VA of this VmSpace's root
            // frame (RAM (direct-mapped)); `i4 < 256` keeps the aligned
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
            let l3 = (crate::mm::direct_map::phys_to_virt(l3_pa)) as *mut u64;
            for i3 in 0usize..512 {
                // SAFETY: `l3` is the direct-map VA of the PDPT frame
                // named by the present, non-huge L4 entry above, in
                // RAM (direct-mapped). `i3 < 512` keeps the aligned
                // `u64` read in bounds.
                let l3_e = unsafe { l3.add(i3).read() };
                if l3_e & PRESENT == 0 || l3_e & HUGE != 0 {
                    continue;
                }
                let l2_pa = l3_e & FRAME_MASK;
                let l2 = (crate::mm::direct_map::phys_to_virt(l2_pa)) as *mut u64;
                for i2 in 0usize..512 {
                    // SAFETY: `l2` is the direct-map VA of the PD frame
                    // named by the present, non-huge L3 entry above, in
                    // RAM (direct-mapped). `i2 < 512` keeps the
                    // aligned `u64` read in bounds.
                    let l2_e = unsafe { l2.add(i2).read() };
                    if l2_e & PRESENT == 0 || l2_e & HUGE != 0 {
                        continue;
                    }
                    let l1_pa = l2_e & FRAME_MASK;
                    let l1 = (crate::mm::direct_map::phys_to_virt(l1_pa)) as *mut u64;
                    for i1 in 0usize..512 {
                        // SAFETY: `l1` is the direct-map VA of the PT
                        // frame named by the present, non-huge L2 entry
                        // above, in RAM (direct-mapped). `i1 < 512`
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

#[derive(Debug, PartialEq, Eq)]
pub enum CowBreak {
    Broken { old_frame: PhysFrame<Size4KiB> },
    BrokenInPlace,
    AlreadyWritable,
    NotCow,
    NotPresent,
}

pub struct CowClone {
    child: VmSpace,
    shared_vaddrs: alloc::vec::Vec<u64>,
    child_installed: alloc::vec::Vec<(u64, PhysFrame<Size4KiB>, bool)>,
    cow_vaddrs: alloc::vec::Vec<(u64, PhysFrame<Size4KiB>, Perms)>,
    needs_shootdown: bool,
}

impl CowClone {
    pub fn needs_shootdown(&self) -> bool {
        self.needs_shootdown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectResult {
    pub not_present: usize,
    pub copied: usize,
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
