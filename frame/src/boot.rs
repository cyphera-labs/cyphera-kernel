use core::arch::global_asm;
use core::slice;

global_asm!(include_str!("boot.s"), options(att_syntax));

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BootProtocol {
    Pvh = 0,
    Multiboot2 = 1,
}

impl BootProtocol {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            1 => Self::Multiboot2,
            _ => Self::Pvh,
        }
    }
}

pub const HVM_START_INFO_MAGIC: u32 = 0x336e_c578;

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum E820Type {
    Usable = 1,
    Reserved = 2,
    AcpiReclaimable = 3,
    AcpiNvs = 4,
    Unusable = 5,
    PmemDisabled = 6,
    Pmem = 7,
}

impl E820Type {
    fn from_raw(raw: u32) -> Self {
        match raw {
            1 => Self::Usable,
            2 => Self::Reserved,
            3 => Self::AcpiReclaimable,
            4 => Self::AcpiNvs,
            5 => Self::Unusable,
            6 => Self::PmemDisabled,
            7 => Self::Pmem,
            _ => Self::Reserved,
        }
    }
}

#[repr(C)]
struct HvmStartInfoRaw {
    magic: u32,
    version: u32,
    flags: u32,
    nr_modules: u32,
    modlist_paddr: u64,
    cmdline_paddr: u64,
    rsdp_paddr: u64,
    memmap_paddr: u64,
    memmap_entries: u32,
    reserved: u32,
}

#[repr(C)]
struct HvmMemmapTableEntryRaw {
    addr: u64,
    size: u64,
    kind: u32,
    reserved: u32,
}

#[repr(C)]
struct Mb2InfoHeader {
    total_size: u32,
    reserved: u32,
}

#[repr(C)]
struct Mb2TagHeader {
    tag_type: u32,
    size: u32,
}

const MB2_TAG_END: u32 = 0;
const MB2_TAG_CMDLINE: u32 = 1;
const MB2_TAG_MODULE: u32 = 3;
const MB2_TAG_MMAP: u32 = 6;
const MB2_TAG_ACPI_RSDP_V1: u32 = 14;
const MB2_TAG_ACPI_RSDP_V2: u32 = 15;

#[repr(C)]
struct Mb2ModuleTag {
    tag_type: u32,
    size: u32,
    mod_start: u32,
    mod_end: u32,
}

#[repr(C)]
struct Mb2MmapTagHeader {
    tag_type: u32,
    size: u32,
    entry_size: u32,
    entry_version: u32,
}

#[repr(C)]
struct Mb2MmapEntry {
    base_addr: u64,
    length: u64,
    kind: u32,
    reserved: u32,
}

#[derive(Debug, Copy, Clone)]
pub struct Module {
    pub paddr: u64,
    pub size: u64,
    pub cmdline_paddr: Option<u64>,
}

#[derive(Debug)]
pub struct BootInfo {
    pub memory_map: &'static [MemoryRegion],
    pub rsdp_paddr: Option<u64>,
    pub cmdline_paddr: Option<u64>,
    pub modules: &'static [Module],
}

#[derive(Debug, Copy, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub kind: E820Type,
}

impl MemoryRegion {
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    pub fn is_usable(&self) -> bool {
        matches!(self.kind, E820Type::Usable)
    }
}

const MAX_MEMORY_REGIONS: usize = 64;

static mut MEMORY_MAP_STORAGE: [MemoryRegion; MAX_MEMORY_REGIONS] = [MemoryRegion {
    start: 0,
    end: 0,
    kind: E820Type::Reserved,
}; MAX_MEMORY_REGIONS];

const MAX_MODULES: usize = 8;

static mut MODULES_STORAGE: [Module; MAX_MODULES] = [Module {
    paddr: 0,
    size: 0,
    cmdline_paddr: None,
}; MAX_MODULES];

/// # Safety
///
/// Caller must supply the genuine pointer from PVH entry, and must
/// ensure the underlying memory has not been overwritten between PVH
/// entry and this call. `BootInfo` is stored in static buffers, so
/// this must be called at most once.
pub unsafe fn parse_hvm_start_info(boot_info_ptr: u32) -> BootInfo {
    if boot_info_ptr == 0 {
        return BootInfo {
            memory_map: &[],
            rsdp_paddr: None,
            cmdline_paddr: None,
            modules: &[],
        };
    }

    let raw = &*(boot_info_ptr as usize as *const HvmStartInfoRaw);
    debug_assert_eq!(raw.magic, HVM_START_INFO_MAGIC, "bad PVH magic");

    let entries = if raw.memmap_paddr != 0 && raw.memmap_entries > 0 {
        let count = (raw.memmap_entries as usize).min(MAX_MEMORY_REGIONS);
        let entries_ptr = raw.memmap_paddr as usize as *const HvmMemmapTableEntryRaw;
        let raw_entries = slice::from_raw_parts(entries_ptr, count);
        for (i, e) in raw_entries.iter().enumerate() {
            MEMORY_MAP_STORAGE[i] = MemoryRegion {
                start: e.addr,
                end: e.addr + e.size,
                kind: E820Type::from_raw(e.kind),
            };
        }
        &MEMORY_MAP_STORAGE[..count]
    } else {
        &[]
    };

    let modules: &'static [Module] = if raw.nr_modules > 0 && raw.modlist_paddr != 0 {
        #[repr(C)]
        struct HvmModlistEntryRaw {
            paddr: u64,
            size: u64,
            cmdline_paddr: u64,
            reserved: u64,
        }
        let count = (raw.nr_modules as usize).min(MAX_MODULES);
        let entries_ptr = raw.modlist_paddr as usize as *const HvmModlistEntryRaw;
        let raw_modules = slice::from_raw_parts(entries_ptr, count);
        for (i, m) in raw_modules.iter().enumerate() {
            MODULES_STORAGE[i] = Module {
                paddr: m.paddr,
                size: m.size,
                cmdline_paddr: (m.cmdline_paddr != 0).then_some(m.cmdline_paddr),
            };
        }
        &MODULES_STORAGE[..count]
    } else {
        &[]
    };

    BootInfo {
        memory_map: entries,
        rsdp_paddr: (raw.rsdp_paddr != 0).then_some(raw.rsdp_paddr),
        cmdline_paddr: (raw.cmdline_paddr != 0).then_some(raw.cmdline_paddr),
        modules,
    }
}

/// # Safety
///
/// Caller must supply the genuine multiboot2 info pointer from
/// `_start` and ensure the underlying memory is unaltered between the
/// bootloader's exit and this call. `BootInfo` is stored in static
/// buffers, so this must be called at most once.
pub unsafe fn parse_multiboot2_info(boot_info_ptr: u32) -> BootInfo {
    if boot_info_ptr == 0 {
        return BootInfo {
            memory_map: &[],
            rsdp_paddr: None,
            cmdline_paddr: None,
            modules: &[],
        };
    }

    let base = boot_info_ptr as usize;
    let info = &*(base as *const Mb2InfoHeader);
    let total = info.total_size as usize;
    let end = base.saturating_add(total);

    let mut cur = base + core::mem::size_of::<Mb2InfoHeader>();

    let mut memory_map: &'static [MemoryRegion] = &[];
    let mut rsdp_paddr: Option<u64> = None;
    let mut cmdline_paddr: Option<u64> = None;
    let mut module_count = 0usize;

    while cur + core::mem::size_of::<Mb2TagHeader>() <= end {
        let tag = &*(cur as *const Mb2TagHeader);
        if tag.tag_type == MB2_TAG_END {
            break;
        }
        if tag.size < core::mem::size_of::<Mb2TagHeader>() as u32 {
            break;
        }

        match tag.tag_type {
            MB2_TAG_MMAP => {
                let hdr = &*(cur as *const Mb2MmapTagHeader);
                let entry_size = hdr.entry_size as usize;
                if entry_size >= core::mem::size_of::<Mb2MmapEntry>() {
                    let entries_base = cur + core::mem::size_of::<Mb2MmapTagHeader>();
                    let tag_end = cur + hdr.size as usize;
                    let mut entry_cur = entries_base;
                    let mut count = 0usize;
                    while entry_cur + entry_size <= tag_end && count < MAX_MEMORY_REGIONS {
                        let entry = &*(entry_cur as *const Mb2MmapEntry);
                        MEMORY_MAP_STORAGE[count] = MemoryRegion {
                            start: entry.base_addr,
                            end: entry.base_addr + entry.length,
                            kind: E820Type::from_raw(entry.kind),
                        };
                        count += 1;
                        entry_cur += entry_size;
                    }
                    memory_map = &MEMORY_MAP_STORAGE[..count];
                }
            }
            MB2_TAG_CMDLINE => {
                let s_addr = (cur + core::mem::size_of::<Mb2TagHeader>()) as u64;
                cmdline_paddr = Some(s_addr);
            }
            MB2_TAG_MODULE if module_count < MAX_MODULES => {
                let m = &*(cur as *const Mb2ModuleTag);
                let cmdline_str_addr = if m.size as usize > core::mem::size_of::<Mb2ModuleTag>() {
                    Some((cur + core::mem::size_of::<Mb2ModuleTag>()) as u64)
                } else {
                    None
                };
                MODULES_STORAGE[module_count] = Module {
                    paddr: m.mod_start as u64,
                    size: (m.mod_end - m.mod_start) as u64,
                    cmdline_paddr: cmdline_str_addr,
                };
                module_count += 1;
            }
            MB2_TAG_ACPI_RSDP_V1 | MB2_TAG_ACPI_RSDP_V2 => {
                let rsdp_addr = (cur + core::mem::size_of::<Mb2TagHeader>()) as u64;
                rsdp_paddr = Some(rsdp_addr);
            }
            _ => {
            }
        }

        let advance = ((tag.size as usize) + 7) & !7;
        if advance == 0 {
            break;
        }
        cur = cur.saturating_add(advance);
    }

    BootInfo {
        memory_map,
        rsdp_paddr,
        cmdline_paddr,
        modules: &MODULES_STORAGE[..module_count],
    }
}

use core::sync::atomic::{AtomicU64, Ordering};

static RSDP_PADDR: AtomicU64 = AtomicU64::new(0);

pub fn set_rsdp_paddr(pa: u64) {
    RSDP_PADDR.store(pa, Ordering::Release);
}

pub fn rsdp_paddr() -> Option<u64> {
    let v = RSDP_PADDR.load(Ordering::Acquire);
    (v != 0).then_some(v)
}

static MODULES_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

pub fn set_modules(modules: &[Module]) {
    let count = modules.len().min(MAX_MODULES);
    MODULES_COUNT.store(count, Ordering::Release);
}

pub fn modules() -> &'static [Module] {
    let count = MODULES_COUNT.load(Ordering::Acquire);
    // SAFETY: `MODULES_STORAGE` is exclusively written by the
    // bootloader-info parsers (parse_hvm_start_info /
    // parse_multiboot2_info), each of which runs once before
    // anyone calls `modules()`. After parsing, the storage is
    // read-only. We hand back an immutable slice.
    unsafe {
        let ptr = &raw const MODULES_STORAGE[0];
        core::slice::from_raw_parts(ptr, count)
    }
}

pub fn module_bytes(module: &Module) -> Option<&'static [u8]> {
    let end = module.paddr.checked_add(module.size)?;
    if end > 0x4000_0000 {
        return None;
    }
    let kva = module.paddr | KERNEL_VMA_OFFSET;
    // SAFETY: `kva` is the high-half VA for a bootloader-reserved
    // memory range; the boot stub mapped phys [0, 1 GiB) at this
    // VA window. The kernel never writes to bootloader-reserved
    // memory, so the bytes are immutable for the kernel's
    // lifetime. The range fits within 1 GiB per the check above.
    let bytes = unsafe { core::slice::from_raw_parts(kva as *const u8, module.size as usize) };
    Some(bytes)
}

static ECAM_BASE: AtomicU64 = AtomicU64::new(0xB000_0000);

pub fn set_ecam_base(pa: u64) {
    ECAM_BASE.store(pa, Ordering::Release);
}

pub fn ecam_base() -> u64 {
    ECAM_BASE.load(Ordering::Acquire)
}

extern "C" {
    pub static __kernel_image_phys_start: u8;
    pub static __kernel_image_phys_end: u8;
}

pub const KERNEL_VMA_OFFSET: u64 = 0xffff_ffff_8000_0000;

#[inline]
pub fn kva_to_pa(kva: u64) -> u64 {
    kva.wrapping_sub(KERNEL_VMA_OFFSET)
}
