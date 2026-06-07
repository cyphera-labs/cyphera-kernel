pub const USER_ADDRESS_LIMIT: u64 = 0x0000_8000_0000_0000;

pub fn user_range_inside_userspace(addr: u64, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    match addr.checked_add(len as u64) {
        Some(end) => end <= USER_ADDRESS_LIMIT,
        None => false,
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn zero_len_always_ok() {
        let addr: u64 = kani::any();
        assert!(user_range_inside_userspace(addr, 0));
    }

    #[kani::proof]
    fn accepted_implies_in_userspace() {
        let addr: u64 = kani::any();
        let len: usize = kani::any();
        kani::assume(len > 0);
        kani::assume(len <= 0x1_0000_0000);

        if user_range_inside_userspace(addr, len) {
            let end = addr
                .checked_add(len as u64)
                .expect("no overflow when accepted");
            assert!(end <= USER_ADDRESS_LIMIT);
        }
    }

    #[kani::proof]
    fn kernel_addr_rejected() {
        let addr: u64 = kani::any();
        let len: usize = kani::any();
        kani::assume(addr >= USER_ADDRESS_LIMIT);
        kani::assume(len > 0);
        kani::assume(len <= 0x1_0000_0000);

        assert!(!user_range_inside_userspace(addr, len));
    }

    #[kani::proof]
    fn overflow_rejected() {
        let addr: u64 = kani::any();
        let len: usize = kani::any();
        kani::assume(len > 0);
        kani::assume(addr > u64::MAX - (len as u64));

        assert!(!user_range_inside_userspace(addr, len));
    }
}
