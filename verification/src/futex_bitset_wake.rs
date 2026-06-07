pub const EINVAL: i64 = -22;

pub const MAX_WAITERS: usize = 4;

pub fn wake_bitset(
    waiters: &[u32; MAX_WAITERS],
    waiter_count: usize,
    n: u32,
    wake_mask: u32,
) -> (i64, [bool; MAX_WAITERS]) {
    let mut decisions = [false; MAX_WAITERS];
    if wake_mask == 0 {
        return (EINVAL, decisions);
    }
    let mut woken: u32 = 0;
    let mut i = 0;
    while i < waiter_count {
        let waiter_mask = waiters[i];
        if (waiter_mask & wake_mask) != 0 && woken < n {
            decisions[i] = true;
            woken += 1;
        }
        i += 1;
    }
    (woken as i64, decisions)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(6)]
    fn non_intersecting_never_woken() {
        let waiters: [u32; MAX_WAITERS] = kani::any();
        let waiter_count: usize = kani::any();
        kani::assume(waiter_count <= MAX_WAITERS);
        let n: u32 = kani::any();
        let wake_mask: u32 = kani::any();
        kani::assume(wake_mask != 0);

        let (_woken, decisions) = wake_bitset(&waiters, waiter_count, n, wake_mask);
        let mut i = 0;
        while i < waiter_count {
            if waiters[i] & wake_mask == 0 {
                assert!(!decisions[i]);
            }
            i += 1;
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn wake_count_bounded_by_n() {
        let waiters: [u32; MAX_WAITERS] = kani::any();
        let waiter_count: usize = kani::any();
        kani::assume(waiter_count <= MAX_WAITERS);
        let n: u32 = kani::any();
        let wake_mask: u32 = kani::any();
        kani::assume(wake_mask != 0);

        let (woken, decisions) = wake_bitset(&waiters, waiter_count, n, wake_mask);
        assert!((woken as u32) <= n);
        let mut count = 0u32;
        let mut i = 0;
        while i < waiter_count {
            if decisions[i] {
                count += 1;
            }
            i += 1;
        }
        assert_eq!(count as i64, woken);
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn wake_all_mask_wakes_nonzero_waiters() {
        let waiters: [u32; MAX_WAITERS] = kani::any();
        let waiter_count: usize = kani::any();
        kani::assume(waiter_count <= MAX_WAITERS);
        let n: u32 = MAX_WAITERS as u32 + 1;

        let (_woken, decisions) = wake_bitset(&waiters, waiter_count, n, !0u32);
        let mut i = 0;
        while i < waiter_count {
            if waiters[i] != 0 {
                assert!(decisions[i]);
            } else {
                assert!(!decisions[i]);
            }
            i += 1;
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn zero_mask_is_einval() {
        let waiters: [u32; MAX_WAITERS] = kani::any();
        let waiter_count: usize = kani::any();
        kani::assume(waiter_count <= MAX_WAITERS);
        let n: u32 = kani::any();

        let (result, decisions) = wake_bitset(&waiters, waiter_count, n, 0);
        assert_eq!(result, EINVAL);
        let mut i = 0;
        while i < MAX_WAITERS {
            assert!(!decisions[i]);
            i += 1;
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn cap_zero_wakes_nothing() {
        let waiters: [u32; MAX_WAITERS] = kani::any();
        let waiter_count: usize = kani::any();
        kani::assume(waiter_count <= MAX_WAITERS);
        let wake_mask: u32 = kani::any();
        kani::assume(wake_mask != 0);

        let (woken, decisions) = wake_bitset(&waiters, waiter_count, 0, wake_mask);
        assert_eq!(woken, 0);
        let mut i = 0;
        while i < MAX_WAITERS {
            assert!(!decisions[i]);
            i += 1;
        }
    }
}
