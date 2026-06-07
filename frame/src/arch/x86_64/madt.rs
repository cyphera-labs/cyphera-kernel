use alloc::vec::Vec;
use core::mem::size_of;

use crate::boot::KERNEL_VMA_OFFSET;

const RSDP_XSDT_ADDR_OFFSET: usize = 24;
const SDT_LENGTH_OFFSET: usize = 4;
const SDT_HEADER_SIZE: usize = 36;
const MADT_ENTRIES_OFFSET: usize = SDT_HEADER_SIZE + 8;

const MADT_SIG: [u8; 4] = *b"APIC";

const ENTRY_LOCAL_APIC: u8 = 0;

const FLAG_ENABLED: u32 = 1 << 0;
const FLAG_ONLINE_CAPABLE: u32 = 1 << 1;

fn read_u32(ptr: *const u8) -> u32 {
    // SAFETY: this is a safe `fn`, so it cannot constrain its callers; the
    // unsafe read below relies on a contract every call site must
    // uphold: `ptr` is a `pa_to_va` result for a firmware-supplied
    // (trusted, unvalidated) ACPI address in low DRAM (< 1 GiB — the
    // only range `pa_to_va` aliases as writable write-back DRAM; the
    // higher PDPT_high windows are UC device space), with >= 4
    // readable bytes behind it. The bounds are established at the
    // unsafe call sites. Read is unaligned, so alignment is
    // unconstrained.
    unsafe { core::ptr::read_unaligned(ptr as *const u32) }
}

fn read_u64(ptr: *const u8) -> u64 {
    // SAFETY: this is a safe `fn`, so it cannot constrain its callers; the
    // unsafe read below relies on a contract every call site must
    // uphold: `ptr` is a `pa_to_va` result for a firmware-supplied
    // (trusted, unvalidated) ACPI address in low DRAM (< 1 GiB — the
    // only range `pa_to_va` aliases as writable write-back DRAM; the
    // higher PDPT_high windows are UC device space), with >= 8
    // readable bytes behind it. The bounds are established at the
    // unsafe call sites. Read is unaligned, so alignment is
    // unconstrained.
    unsafe { core::ptr::read_unaligned(ptr as *const u64) }
}

fn pa_to_va(pa: u64) -> *const u8 {
    (pa | KERNEL_VMA_OFFSET) as *const u8
}

pub fn parse_apic_ids(rsdp_paddr: Option<u64>) -> Vec<u8> {
    let rsdp_pa = match rsdp_paddr {
        Some(p) => p,
        None => return Vec::new(),
    };

    let rsdp = pa_to_va(rsdp_pa);
    // SAFETY: `rsdp_pa` is supplied by trusted PVH `hvm_start_info` and is
    // assumed (not validated — no signature/checksum check) to name a valid
    // RSDP in low DRAM (< 1 GiB — the only range `pa_to_va` aliases as
    // writable write-back DRAM). The XSDT 64-bit pointer is a fixed field at
    // offset 24 of the RSDP layout, so `.add` of that constant offset reads
    // 8 bytes within that page.
    let xsdt_addr = read_u64(unsafe { rsdp.add(RSDP_XSDT_ADDR_OFFSET) });
    if xsdt_addr == 0 {
        return Vec::new();
    }

    let xsdt = pa_to_va(xsdt_addr);
    // SAFETY: `xsdt_addr` is read from the (trusted, unvalidated) RSDP and
    // assumed to name a valid XSDT in low DRAM (< 1 GiB — the only range
    // `pa_to_va` aliases as writable write-back DRAM). For a valid SDT the
    // 4-byte `length` field is at offset 4 (§5.2.6), so `add(4)` reads
    // within that page's header.
    let xsdt_len = read_u32(unsafe { xsdt.add(SDT_LENGTH_OFFSET) }) as usize;
    if xsdt_len < SDT_HEADER_SIZE {
        return Vec::new();
    }

    let entry_count = (xsdt_len - SDT_HEADER_SIZE) / size_of::<u64>();

    for i in 0..entry_count {
        // SAFETY: `entry_count` was derived as
        // `(xsdt_len - SDT_HEADER_SIZE) / 8`, so for every `i` the
        // offset `36 + i*8` and its 8-byte read stay within the
        // `xsdt_len` bytes the header reports — the pointer array the
        // XSDT carries past its header (§5.2.8).
        let ptr_pa = read_u64(unsafe { xsdt.add(SDT_HEADER_SIZE + i * size_of::<u64>()) });
        if ptr_pa == 0 {
            continue;
        }
        let sdt = pa_to_va(ptr_pa);
        let sig = [
            // SAFETY: `ptr_pa` is a non-zero SDT pointer from the (trusted,
            // unvalidated) XSDT array, assumed to lie in low DRAM (< 1 GiB —
            // the only range `pa_to_va` aliases as writable write-back DRAM).
            // The 4-byte signature occupies bytes 0..4 of any SDT header
            // (§5.2.6), so byte 0 is in bounds.
            unsafe { *sdt },
            // SAFETY: signature byte 1 — offset 1 of the SDT header,
            // still inside the mandatory 4-byte signature field.
            unsafe { *sdt.add(1) },
            // SAFETY: signature byte 2 — offset 2 of the SDT header,
            // still inside the mandatory 4-byte signature field.
            unsafe { *sdt.add(2) },
            // SAFETY: signature byte 3 — offset 3, the last byte of the
            // 4-byte signature, in bounds for any SDT header.
            unsafe { *sdt.add(3) },
        ];
        if sig == MADT_SIG {
            return parse_madt_lapic_entries(sdt);
        }
    }
    Vec::new()
}

fn parse_madt_lapic_entries(madt: *const u8) -> Vec<u8> {
    // SAFETY: `madt` is the SDT pointer whose signature matched "APIC" in
    // the XSDT walk above; like every pointer there it is firmware-supplied
    // and assumed to lie in low DRAM (< 1 GiB — the only range `pa_to_va`
    // aliases as writable write-back DRAM). For a valid SDT the 4-byte
    // `length` field is at offset 4 (§5.2.6), within the 36-byte header, so
    // this read is in bounds.
    let madt_len = read_u32(unsafe { madt.add(SDT_LENGTH_OFFSET) }) as usize;
    if madt_len < MADT_ENTRIES_OFFSET {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut off = MADT_ENTRIES_OFFSET;
    while off + 2 <= madt_len {
        // SAFETY: the loop guard `off + 2 <= madt_len` holds here, so
        // both `off` and `off + 1` are < `madt_len` and address the
        // entry header's `type:u8` / `length:u8` (§5.2.12) within the
        // table bytes that `madt_len` reported.
        let entry_type = unsafe { *madt.add(off) };
        // SAFETY: same loop-guard bound — `off + 1 < madt_len` — reads
        // the entry-header `length:u8` byte in bounds.
        let entry_len = unsafe { *madt.add(off + 1) } as usize;
        if entry_len < 2 || off + entry_len > madt_len {
            break;
        }
        if entry_type == ENTRY_LOCAL_APIC && entry_len >= 8 {
            // SAFETY: this branch requires `entry_len >= 8` and the
            // guard above ensured `off + entry_len <= madt_len`, so
            // `off + 3` (the `apic_id` byte of a Processor Local APIC
            // entry, §5.2.12) is within the table.
            let apic_id = unsafe { *madt.add(off + 3) };
            // SAFETY: with `entry_len >= 8` and `off + entry_len
            // <= madt_len`, bytes `off + 4 .. off + 8` — the entry's
            // 4-byte `flags` field — are fully inside the table.
            let flags = read_u32(unsafe { madt.add(off + 4) });
            if flags & (FLAG_ENABLED | FLAG_ONLINE_CAPABLE) != 0 && apic_id != 0 {
                out.push(apic_id);
            }
        }
        off += entry_len;
    }
    out
}
