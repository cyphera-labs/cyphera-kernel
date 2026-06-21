use alloc::vec::Vec;
use core::mem::size_of;

const RSDP_XSDT_ADDR_OFFSET: usize = 24;
const SDT_LENGTH_OFFSET: usize = 4;
const SDT_HEADER_SIZE: usize = 36;
const MADT_ENTRIES_OFFSET: usize = SDT_HEADER_SIZE + 8;

const MADT_SIG: [u8; 4] = *b"APIC";

const ENTRY_LOCAL_APIC: u8 = 0;

const FLAG_ENABLED: u32 = 1 << 0;
const FLAG_ONLINE_CAPABLE: u32 = 1 << 1;

fn read_u32(ptr: *const u8) -> u32 {
    // SAFETY: a safe fn cannot enforce this; every (file-local) caller passes
    // a `pa_to_va` direct-map alias of a firmware-supplied (trusted,
    // unvalidated) ACPI table whose base PA the caller gated with
    // `direct_map::is_mapped`, with at least 4 bytes behind it. Unaligned read.
    unsafe { core::ptr::read_unaligned(ptr as *const u32) }
}

fn read_u64(ptr: *const u8) -> u64 {
    // SAFETY: a safe fn cannot enforce this; every (file-local) caller passes
    // a `pa_to_va` direct-map alias of a firmware-supplied (trusted,
    // unvalidated) ACPI table whose base PA the caller gated with
    // `direct_map::is_mapped`, with at least 8 bytes behind it. Unaligned read.
    unsafe { core::ptr::read_unaligned(ptr as *const u64) }
}

fn pa_to_va(pa: u64) -> *const u8 {
    crate::mm::direct_map::phys_to_virt(pa) as *const u8
}

pub fn parse_apic_ids(rsdp_paddr: Option<u64>) -> Vec<u8> {
    let rsdp_pa = match rsdp_paddr {
        Some(p) => p,
        None => return Vec::new(),
    };

    if !crate::mm::direct_map::is_mapped(rsdp_pa) {
        return Vec::new();
    }
    let rsdp = pa_to_va(rsdp_pa);
    // SAFETY: `rsdp_pa` is from trusted PVH `hvm_start_info` and gated mapped
    // above. The XSDT 64-bit pointer is the fixed field at offset 24, so `.add`
    // reads 8 bytes within that page.
    let xsdt_addr = read_u64(unsafe { rsdp.add(RSDP_XSDT_ADDR_OFFSET) });
    if xsdt_addr == 0 || !crate::mm::direct_map::is_mapped(xsdt_addr) {
        return Vec::new();
    }

    let xsdt = pa_to_va(xsdt_addr);
    // SAFETY: `xsdt_addr` is from the (trusted, unvalidated) RSDP. For a valid
    // SDT the 4-byte `length` is at offset 4 (§5.2.6), so `add(4)` reads within
    // the header.
    let xsdt_len = read_u32(unsafe { xsdt.add(SDT_LENGTH_OFFSET) }) as usize;
    if xsdt_len < SDT_HEADER_SIZE {
        return Vec::new();
    }

    let entry_count = (xsdt_len - SDT_HEADER_SIZE) / size_of::<u64>();

    for i in 0..entry_count {
        // SAFETY: entry_count = (xsdt_len - 36) / 8 from the length above, so
        // for every i the offset 36 + i*8 and its 8-byte read stay within the
        // firmware-reported xsdt_len bytes (§5.2.8).
        let ptr_pa = read_u64(unsafe { xsdt.add(SDT_HEADER_SIZE + i * size_of::<u64>()) });
        if ptr_pa == 0 || !crate::mm::direct_map::is_mapped(ptr_pa) {
            continue;
        }
        let sdt = pa_to_va(ptr_pa);
        let sig = [
            // SAFETY: `ptr_pa` is a non-zero SDT pointer from the (trusted)
            // XSDT array. The 4-byte signature is bytes 0..4 of any SDT header
            // (§5.2.6); byte 0 is in bounds.
            unsafe { *sdt },
            // SAFETY: byte 1 of the mandatory 4-byte SDT signature, same header.
            unsafe { *sdt.add(1) },
            // SAFETY: byte 2 of the mandatory 4-byte SDT signature, same header.
            unsafe { *sdt.add(2) },
            // SAFETY: byte 3 (last) of the 4-byte SDT signature, same header.
            unsafe { *sdt.add(3) },
        ];
        if sig == MADT_SIG {
            return parse_madt_lapic_entries(sdt);
        }
    }
    Vec::new()
}

fn parse_madt_lapic_entries(madt: *const u8) -> Vec<u8> {
    // SAFETY: `madt` is the SDT whose signature matched "APIC" in the walk
    // above. For a valid SDT the 4-byte `length` is at offset 4 (§5.2.6),
    // within the 36-byte header, so this read is in bounds.
    let madt_len = read_u32(unsafe { madt.add(SDT_LENGTH_OFFSET) }) as usize;
    if madt_len < MADT_ENTRIES_OFFSET {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut off = MADT_ENTRIES_OFFSET;
    while off + 2 <= madt_len {
        // SAFETY: the loop guard `off + 2 <= madt_len` holds here, so both
        // `off` and `off + 1` are < `madt_len` and address the entry header's
        // `type:u8` / `length:u8` (§5.2.12) within the table.
        let entry_type = unsafe { *madt.add(off) };
        // SAFETY: same loop-guard bound — `off + 1 < madt_len` — reads the
        // entry-header `length:u8` byte in bounds.
        let entry_len = unsafe { *madt.add(off + 1) } as usize;
        if entry_len < 2 || off + entry_len > madt_len {
            break;
        }
        if entry_type == ENTRY_LOCAL_APIC && entry_len >= 8 {
            // SAFETY: this branch requires `entry_len >= 8` and the guard above
            // ensured `off + entry_len <= madt_len`, so `off + 3` (the apic_id
            // byte of a Processor Local APIC entry, §5.2.12) is in the table.
            let apic_id = unsafe { *madt.add(off + 3) };
            // SAFETY: with `entry_len >= 8` and `off + entry_len <= madt_len`,
            // bytes `off + 4 .. off + 8` (the entry's 4-byte flags) are in the
            // table.
            let flags = read_u32(unsafe { madt.add(off + 4) });
            if flags & (FLAG_ENABLED | FLAG_ONLINE_CAPABLE) != 0 && apic_id != 0 {
                out.push(apic_id);
            }
        }
        off += entry_len;
    }
    out
}
