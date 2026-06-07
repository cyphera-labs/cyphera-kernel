#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    old_addr: u64,
    old_size: u64,
    new_size: u64,
    flags: u64,
}

fuzz_target!(|input: Input| {
    let result = decode_mremap(input.old_addr, input.old_size, input.new_size, input.flags);

    match result {
        Ok(decoded) => {
            assert_eq!(input.old_addr & 0xfff, 0);
            assert!(input.new_size > 0);
            assert_eq!(input.flags & MREMAP_FIXED, 0);
            assert_eq!(
                decoded.old_aligned % 4096,
                0,
                "old_aligned not page-aligned: {:#x}",
                decoded.old_aligned
            );
            assert_eq!(
                decoded.new_aligned % 4096,
                0,
                "new_aligned not page-aligned: {:#x}",
                decoded.new_aligned
            );
            assert_eq!(
                (decoded.old_pages as u64).wrapping_mul(4096),
                decoded.old_aligned,
                "old_pages × 4096 ≠ old_aligned"
            );
            assert_eq!(
                (decoded.new_pages as u64).wrapping_mul(4096),
                decoded.new_aligned,
                "new_pages × 4096 ≠ new_aligned"
            );
            match decoded.direction {
                Direction::Noop => assert_eq!(decoded.new_aligned, decoded.old_aligned),
                Direction::Shrink => assert!(decoded.new_aligned < decoded.old_aligned),
                Direction::Grow => assert!(decoded.new_aligned > decoded.old_aligned),
            }
        }
        Err(MremapError::Inval) => {
            let bad = input.old_addr & 0xfff != 0
                || input.new_size == 0
                || input.flags & MREMAP_FIXED != 0;
            assert!(bad, "EINVAL without trigger");
        }
    }
});

#[allow(dead_code)]
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum Direction {
    Noop,
    Shrink,
    Grow,
}

#[derive(Debug)]
#[allow(dead_code)]
struct DecodedMremap {
    old_pages: usize,
    new_pages: usize,
    old_aligned: u64,
    new_aligned: u64,
    direction: Direction,
}

#[derive(Debug)]
enum MremapError {
    Inval,
}

fn decode_mremap(
    old_addr: u64,
    old_size: u64,
    new_size: u64,
    flags: u64,
) -> Result<DecodedMremap, MremapError> {
    if old_addr & 0xfff != 0 || new_size == 0 {
        return Err(MremapError::Inval);
    }
    if flags & MREMAP_FIXED != 0 {
        return Err(MremapError::Inval);
    }
    let old_pages = old_size.div_ceil(4096) as usize;
    let new_pages = new_size.div_ceil(4096) as usize;
    let old_aligned = (old_pages as u64).wrapping_mul(4096);
    let new_aligned = (new_pages as u64).wrapping_mul(4096);

    let direction = if new_aligned == old_aligned {
        Direction::Noop
    } else if new_aligned < old_aligned {
        Direction::Shrink
    } else {
        Direction::Grow
    };

    Ok(DecodedMremap {
        old_pages,
        new_pages,
        old_aligned,
        new_aligned,
        direction,
    })
}
