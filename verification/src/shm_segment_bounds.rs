pub const PAGE_SIZE: usize = 4096;

pub const SHM_MAX_BYTES: usize = 1 << 30;

pub const EINVAL: i64 = -22;

pub fn validate_and_page_count(size: usize) -> Result<usize, i64> {
    if size == 0 || size > SHM_MAX_BYTES {
        return Err(EINVAL);
    }
    Ok(size.div_ceil(PAGE_SIZE))
}

pub fn segment_length(pages: usize) -> u64 {
    (pages * PAGE_SIZE) as u64
}

pub fn page_vaddr(vaddr: u64, i: usize) -> u64 {
    vaddr + (i * PAGE_SIZE) as u64
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn rejects_zero_size() {
        let r = validate_and_page_count(0);
        assert!(matches!(r, Err(EINVAL)));
    }

    #[kani::proof]
    fn rejects_oversize() {
        let size: usize = kani::any();
        kani::assume(size > SHM_MAX_BYTES);
        let r = validate_and_page_count(size);
        assert!(matches!(r, Err(EINVAL)));
    }

    #[kani::proof]
    fn page_count_in_range() {
        let size: usize = kani::any();
        kani::assume(size > 0);
        kani::assume(size <= SHM_MAX_BYTES);

        let r = validate_and_page_count(size);
        match r {
            Ok(pages) => {
                assert!(pages >= 1);
                let max_pages = SHM_MAX_BYTES.div_ceil(PAGE_SIZE);
                assert!(pages <= max_pages);
            }
            Err(_) => {
                panic!("unexpected EINVAL");
            }
        }
    }

    #[kani::proof]
    fn segment_length_no_overflow() {
        let size: usize = kani::any();
        kani::assume(size > 0);
        kani::assume(size <= SHM_MAX_BYTES);

        let pages = validate_and_page_count(size).expect("validated");
        let max_pages = SHM_MAX_BYTES.div_ceil(PAGE_SIZE);
        assert!(pages <= max_pages);

        let len = segment_length(pages);
        assert!(len <= (max_pages * PAGE_SIZE) as u64);
        assert!(len > 0);
    }

    #[kani::proof]
    fn page_vaddr_no_wrap() {
        let pages: u8 = kani::any();
        let vaddr: u64 = kani::any();
        kani::assume(pages > 0);
        let length = (pages as usize * PAGE_SIZE) as u64;
        kani::assume(vaddr <= u64::MAX - length);

        let i: u8 = kani::any();
        kani::assume(i < pages);

        let addr = page_vaddr(vaddr, i as usize);
        assert!(addr >= vaddr);
        assert!(addr < vaddr + length);
        assert_eq!((addr - vaddr) % PAGE_SIZE as u64, 0);
    }

    #[kani::proof]
    fn id_monotonic_until_wrap() {
        let prev: i32 = kani::any();
        kani::assume(prev < i32::MAX);
        let next = prev.wrapping_add(1);
        assert!(next > prev);
    }
}
