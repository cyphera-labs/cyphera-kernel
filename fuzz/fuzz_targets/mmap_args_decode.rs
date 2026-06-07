#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    addr: u64,
    length: u64,
    prot: u64,
    flags: u64,
}

fuzz_target!(|input: Input| {
    let result = decode_mmap_args(input.addr, input.length, input.prot, input.flags);

    match result {
        Ok(decoded) => {
            assert!(
                decoded.length_aligned >= input.length || decoded.length_aligned == 0,
                "length_aligned shrank: {} < {}",
                decoded.length_aligned,
                input.length
            );
            assert!(
                decoded.length_aligned % 4096 == 0,
                "length_aligned not page-aligned: {:#x}",
                decoded.length_aligned
            );
            assert_eq!(
                (decoded.pages as u64).wrapping_mul(4096),
                decoded.length_aligned,
                "pages × 4096 mismatch"
            );
            let allowed_perms = PERMS_USER | PERMS_READ | PERMS_WRITE | PERMS_EXECUTE;
            assert_eq!(
                decoded.perms & !allowed_perms,
                0,
                "perms leaked extra bits: {:#x}",
                decoded.perms
            );
            assert!(
                decoded.perms & PERMS_USER != 0,
                "USER bit missing from perms"
            );
            assert!(input.length != 0);
            if input.addr & 0xfff != 0 {
                assert_eq!(input.flags & (MAP_FIXED | MAP_FIXED_NOREPLACE), 0);
            }
        }
        Err(MmapError::Inval) => {
            let bad = input.length == 0
                || (input.addr & 0xfff != 0
                    && (input.flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0);
            assert!(bad, "EINVAL without trigger condition");
        }
    }
});

const PROT_READ_BIT: u64 = 1;
const PROT_WRITE_BIT: u64 = 2;
const PROT_EXEC_BIT: u64 = 4;

#[allow(dead_code)]
const MAP_SHARED: u64 = 0x01;
#[allow(dead_code)]
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
#[allow(dead_code)]
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;

const PERMS_USER: u64 = 1 << 0;
const PERMS_READ: u64 = 1 << 1;
const PERMS_WRITE: u64 = 1 << 2;
const PERMS_EXECUTE: u64 = 1 << 3;

#[derive(Debug)]
#[allow(dead_code)]
struct DecodedMmap {
    pages: usize,
    length_aligned: u64,
    perms: u64,
    is_anon: bool,
    is_shared: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
enum MmapError {
    Inval,
}

fn prot_to_perms(prot: u64) -> u64 {
    let mut p = PERMS_USER;
    if prot & PROT_READ_BIT != 0 {
        p |= PERMS_READ;
    }
    if prot & PROT_WRITE_BIT != 0 {
        p |= PERMS_WRITE;
    }
    if prot & PROT_EXEC_BIT != 0 {
        p |= PERMS_EXECUTE;
    }
    p
}

fn decode_mmap_args(addr: u64, length: u64, prot: u64, flags: u64) -> Result<DecodedMmap, MmapError> {
    if length == 0 {
        return Err(MmapError::Inval);
    }
    if addr & 0xfff != 0 {
        if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0 {
            return Err(MmapError::Inval);
        }
    }
    let pages = length.div_ceil(4096) as usize;
    let length_aligned = (pages as u64).wrapping_mul(4096);
    let perms = prot_to_perms(prot);

    let is_anon = (flags & MAP_ANONYMOUS) != 0;
    let is_shared = (flags & MAP_SHARED) != 0;

    Ok(DecodedMmap {
        pages,
        length_aligned,
        perms,
        is_anon,
        is_shared,
    })
}
