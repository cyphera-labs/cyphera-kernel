pub fn map_anon_then_teardown_net(pages: u64) -> i64 {
    let allocated = pages;
    let owned_frames_len = pages;
    let freed = owned_frames_len;
    allocated as i64 - freed as i64
}

pub fn contiguous_then_per_frame_teardown_leak(pages: u64) -> u64 {
    let reserved = pages.next_power_of_two();
    let freed = pages;
    reserved - freed
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn per_frame_alloc_is_symmetric() {
        let pages: u64 = kani::any();
        kani::assume(pages >= 1 && pages <= 1024);
        assert_eq!(map_anon_then_teardown_net(pages), 0);
    }

    #[kani::proof]
    fn teardown_leaks_iff_overalloc() {
        let pages: u64 = kani::any();
        kani::assume(pages >= 1 && pages <= 1024);
        let leak = contiguous_then_per_frame_teardown_leak(pages);
        if pages.is_power_of_two() {
            assert_eq!(leak, 0);
        } else {
            assert!(leak > 0);
        }
        assert_eq!(map_anon_then_teardown_net(pages), 0);
    }
}
