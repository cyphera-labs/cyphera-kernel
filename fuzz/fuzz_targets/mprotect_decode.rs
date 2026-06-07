#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    addr: u64,
    length: u64,
    prot: u64,
}

fuzz_target!(|input: Input| {
    let result = decode_mprotect(input.addr, input.length, input.prot);

    match result {
        Ok(decoded) => {
            assert!(input.addr & 0xfff == 0);
            assert!(input.length > 0);
            let scaled = (decoded.pages as u64).wrapping_mul(4096);
            assert!(
                scaled >= input.length || decoded.pages as u64 > input.length / 4096,
                "pages × 4096 lost data: pages={} length={}",
                decoded.pages,
                input.length
            );
            let allowed = PERMS_USER | PERMS_READ | PERMS_WRITE | PERMS_EXECUTE;
            assert_eq!(
                decoded.perms & !allowed,
                0,
                "perms leaked bits: {:#x}",
                decoded.perms
            );
            if input.prot == 0 {
                assert_eq!(decoded.perms, PERMS_USER, "PROT_NONE picked up R/W/X");
            }
            if input.prot & PROT_READ_BIT != 0 {
                assert!(decoded.perms & PERMS_READ != 0);
            }
            if input.prot & PROT_WRITE_BIT != 0 {
                assert!(decoded.perms & PERMS_WRITE != 0);
            }
            if input.prot & PROT_EXEC_BIT != 0 {
                assert!(decoded.perms & PERMS_EXECUTE != 0);
            }
            assert_eq!(input.prot & !(PROT_READ_BIT | PROT_WRITE_BIT | PROT_EXEC_BIT), 0);
        }
        Err(MprotectError::Inval) => {
            let bad = input.length == 0
                || input.addr & 0xfff != 0
                || input.prot & !(PROT_READ_BIT | PROT_WRITE_BIT | PROT_EXEC_BIT) != 0;
            assert!(bad, "EINVAL without trigger");
        }
    }
});

const PROT_READ_BIT: u64 = 1;
const PROT_WRITE_BIT: u64 = 2;
const PROT_EXEC_BIT: u64 = 4;

const PERMS_USER: u64 = 1 << 0;
const PERMS_READ: u64 = 1 << 1;
const PERMS_WRITE: u64 = 1 << 2;
const PERMS_EXECUTE: u64 = 1 << 3;

#[derive(Debug)]
#[allow(dead_code)]
struct DecodedMprotect {
    pages: usize,
    perms: u64,
}

#[derive(Debug)]
enum MprotectError {
    Inval,
}

fn decode_mprotect(addr: u64, length: u64, prot: u64) -> Result<DecodedMprotect, MprotectError> {
    if length == 0 || addr & 0xfff != 0 {
        return Err(MprotectError::Inval);
    }
    if prot & !(PROT_READ_BIT | PROT_WRITE_BIT | PROT_EXEC_BIT) != 0 {
        return Err(MprotectError::Inval);
    }
    let pages = length.div_ceil(4096) as usize;
    let mut perms = PERMS_USER;
    if prot == 0 {
    } else {
        if prot & PROT_READ_BIT != 0 {
            perms |= PERMS_READ;
        }
        if prot & PROT_WRITE_BIT != 0 {
            perms |= PERMS_WRITE;
        }
        if prot & PROT_EXEC_BIT != 0 {
            perms |= PERMS_EXECUTE;
        }
    }
    Ok(DecodedMprotect { pages, perms })
}
