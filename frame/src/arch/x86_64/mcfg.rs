use core::mem::size_of;

use crate::boot::KERNEL_VMA_OFFSET;

const RSDP_XSDT_ADDR_OFFSET: usize = 24;
const SDT_LENGTH_OFFSET: usize = 4;
const SDT_HEADER_SIZE: usize = 36;
const MCFG_ENTRIES_OFFSET: usize = SDT_HEADER_SIZE + 8;

const MCFG_SIG: [u8; 4] = *b"MCFG";

fn read_u32(ptr: *const u8) -> u32 {
    // SAFETY: this is a safe fn, so the read-validity precondition is NOT
    // enforced by the signature — it is relied upon, not checked. Every call
    // site is file-local and passes a `pa_to_va`-folded ACPI-table pointer
    // (firmware-supplied, trusted, assumed in low DRAM < 1 GiB — the only
    // range that aliases writable write-back DRAM via PDPT_high[510]; the
    // higher PDPT_high windows are UC device space) with at least 4 bytes of
    // table behind it. The read is unaligned, so alignment is unconstrained.
    unsafe { core::ptr::read_unaligned(ptr as *const u32) }
}

fn read_u64(ptr: *const u8) -> u64 {
    // SAFETY: this is a safe fn, so the read-validity precondition is NOT
    // enforced by the signature — it is relied upon, not checked. Every call
    // site is file-local and passes a `pa_to_va`-folded ACPI-table pointer
    // (firmware-supplied, trusted, assumed in low DRAM < 1 GiB — the only
    // range that aliases writable write-back DRAM via PDPT_high[510]; the
    // higher PDPT_high windows are UC device space) with at least 8 bytes of
    // table behind it. The read is unaligned, so alignment is unconstrained.
    unsafe { core::ptr::read_unaligned(ptr as *const u64) }
}

fn pa_to_va(pa: u64) -> *const u8 {
    (pa | KERNEL_VMA_OFFSET) as *const u8
}

pub fn parse_mcfg_ecam_base(rsdp_paddr: Option<u64>) -> Option<u64> {
    let rsdp_pa = rsdp_paddr?;

    let rsdp = pa_to_va(rsdp_pa);
    // SAFETY: `rsdp_pa` is bootloader-supplied (trusted) and assumed to point
    // at a valid, immutable RSDP in low DRAM (< 1 GiB), so `pa_to_va` folds it
    // into the PDPT_high[510] window and lands on a mapped page — a firmware-
    // placement assumption, not a checked invariant. The XSDT 64-bit pointer
    // is a fixed field at offset 24 of the RSDP layout, so reading 8 bytes
    // there stays within that structure.
    let xsdt_addr = read_u64(unsafe { rsdp.add(RSDP_XSDT_ADDR_OFFSET) });
    if xsdt_addr == 0 {
        return None;
    }

    let xsdt = pa_to_va(xsdt_addr);
    // SAFETY: `xsdt_addr` came from the (trusted, unvalidated) RSDP; we assume
    // firmware places the XSDT in low DRAM (< 1 GiB), so `pa_to_va` folds it
    // into the PDPT_high[510] window and the address is mapped — pa_to_va only
    // OR-folds the offset, it does not itself map anything. The SDT length is
    // a fixed 4-byte u32 at offset 4 within the 36-byte header any valid XSDT
    // begins with, so .add(4) stays inside that header; read_u32 does an
    // unaligned read of those 4 bytes.
    let xsdt_len = read_u32(unsafe { xsdt.add(SDT_LENGTH_OFFSET) }) as usize;
    if xsdt_len < SDT_HEADER_SIZE {
        return None;
    }

    let entry_count = (xsdt_len - SDT_HEADER_SIZE) / size_of::<u64>();

    for i in 0..entry_count {
        // SAFETY: entry_count was derived as (xsdt_len - 36) / 8 from the
        // length field read above, so for every i in 0..entry_count the
        // offset 36 + i*8 plus the 8 bytes read_u64 touches stays within
        // the firmware-reported xsdt_len bytes of the XSDT — an unvalidated
        // length, trusted not checked. Like every read here this assumes the
        // whole table (base plus xsdt_len) lies in the < 1 GiB PDPT_high[510]
        // window; a large reported length is not bounds-checked against it.
        let ptr_pa = read_u64(unsafe { xsdt.add(SDT_HEADER_SIZE + i * size_of::<u64>()) });
        if ptr_pa == 0 {
            continue;
        }
        let sdt = pa_to_va(ptr_pa);
        let sig = [
            // SAFETY: `ptr_pa` is a non-zero SDT pointer from the (trusted)
            // XSDT array, assumed to address a firmware-placed table in low
            // DRAM (< 1 GiB), so its `pa_to_va` fold lands in the mapped
            // PDPT_high[510] window — a placement assumption, not a check. The
            // 4-byte ASCII signature occupies bytes 0..4 of any SDT header
            // (§5.2.6); byte 0 is its first byte.
            unsafe { *sdt },
            // SAFETY: byte 1 of the mandatory 4-byte SDT signature field,
            // within the same assumed-mapped SDT header as the read above.
            unsafe { *sdt.add(1) },
            // SAFETY: byte 2 of the mandatory 4-byte SDT signature field,
            // within the same assumed-mapped SDT header.
            unsafe { *sdt.add(2) },
            // SAFETY: byte 3 (last) of the mandatory 4-byte SDT signature
            // field, within the same assumed-mapped SDT header.
            unsafe { *sdt.add(3) },
        ];
        if sig == MCFG_SIG {
            return parse_first_ecam_entry(sdt);
        }
    }
    None
}

fn parse_first_ecam_entry(mcfg: *const u8) -> Option<u64> {
    // SAFETY: `mcfg` is the XSDT-listed SDT whose signature the caller already
    // read as "MCFG" (so it lies in the assumed-mapped low-DRAM window and has
    // the standard 36-byte SDT header); .add(4) addresses its 4-byte length
    // field, read unaligned.
    let mcfg_len = read_u32(unsafe { mcfg.add(SDT_LENGTH_OFFSET) }) as usize;
    if mcfg_len < MCFG_ENTRIES_OFFSET + 16 {
        return None;
    }
    // SAFETY: the length check above guaranteed mcfg_len >= 44 + 16, so
    // the first 16-byte allocation entry at offset 44 (header + 8 reserved)
    // and the 8-byte base_address read_u64 takes from it both lie within
    // the firmware-reported mcfg_len extent (trusted, not validated) of this
    // mapped MCFG table.
    let entry_ptr = unsafe { mcfg.add(MCFG_ENTRIES_OFFSET) };
    let base_address = read_u64(entry_ptr);
    if base_address == 0 {
        return None;
    }
    Some(base_address)
}
