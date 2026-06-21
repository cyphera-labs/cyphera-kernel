use core::mem::size_of;

const RSDP_XSDT_ADDR_OFFSET: usize = 24;
const SDT_LENGTH_OFFSET: usize = 4;
const SDT_HEADER_SIZE: usize = 36;
const MCFG_ENTRIES_OFFSET: usize = SDT_HEADER_SIZE + 8;

const MCFG_SIG: [u8; 4] = *b"MCFG";

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

pub fn parse_mcfg_ecam_base(rsdp_paddr: Option<u64>) -> Option<u64> {
    let rsdp_pa = rsdp_paddr?;

    if !crate::mm::direct_map::is_mapped(rsdp_pa) {
        return None;
    }
    let rsdp = pa_to_va(rsdp_pa);
    // SAFETY: `rsdp_pa` is bootloader-supplied (trusted, unvalidated) and gated
    // mapped above. The XSDT 64-bit pointer is the fixed field at offset 24 of
    // the RSDP, so reading 8 bytes there stays within that structure.
    let xsdt_addr = read_u64(unsafe { rsdp.add(RSDP_XSDT_ADDR_OFFSET) });
    if xsdt_addr == 0 || !crate::mm::direct_map::is_mapped(xsdt_addr) {
        return None;
    }

    let xsdt = pa_to_va(xsdt_addr);
    // SAFETY: `xsdt_addr` came from the (trusted, unvalidated) RSDP. The SDT
    // length is the 4-byte u32 at offset 4 of the 36-byte header any valid XSDT
    // begins with, so `.add(4)` stays inside the header.
    let xsdt_len = read_u32(unsafe { xsdt.add(SDT_LENGTH_OFFSET) }) as usize;
    if xsdt_len < SDT_HEADER_SIZE {
        return None;
    }

    let entry_count = (xsdt_len - SDT_HEADER_SIZE) / size_of::<u64>();

    for i in 0..entry_count {
        // SAFETY: entry_count = (xsdt_len - 36) / 8 from the length read above,
        // so for every i the offset 36 + i*8 and its 8-byte read stay within
        // the firmware-reported xsdt_len (trusted, not bounds-checked).
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
        if sig == MCFG_SIG {
            return parse_first_ecam_entry(sdt);
        }
    }
    None
}

fn parse_first_ecam_entry(mcfg: *const u8) -> Option<u64> {
    // SAFETY: `mcfg` is the XSDT-listed SDT the caller matched as "MCFG"; it has
    // the standard 36-byte header, so `.add(4)` addresses its 4-byte length
    // field, read unaligned.
    let mcfg_len = read_u32(unsafe { mcfg.add(SDT_LENGTH_OFFSET) }) as usize;
    if mcfg_len < MCFG_ENTRIES_OFFSET + 16 {
        return None;
    }
    // SAFETY: the check above guaranteed mcfg_len >= 60, so the first 16-byte
    // allocation entry at offset 44 and the 8-byte base_address read both lie
    // within the firmware-reported mcfg_len (trusted, not validated).
    let entry_ptr = unsafe { mcfg.add(MCFG_ENTRIES_OFFSET) };
    let base_address = read_u64(entry_ptr);
    if base_address == 0 {
        return None;
    }
    Some(base_address)
}
