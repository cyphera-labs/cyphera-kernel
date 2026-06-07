pub const SA_NODEFER: u64 = 0x4000_0000;

pub fn combine_blocked(pre_blocked: u64, action_mask: u64, action_flags: u64, signal: u32) -> u64 {
    let mut new_blocked = pre_blocked | action_mask;
    if action_flags & SA_NODEFER == 0 {
        new_blocked |= 1u64 << signal;
    }
    new_blocked
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn pre_blocked_bits_preserved() {
        let pre_blocked: u64 = kani::any();
        let action_mask: u64 = kani::any();
        let action_flags: u64 = kani::any();
        let signal: u32 = kani::any();
        kani::assume(signal < 64);

        let new_blocked = combine_blocked(pre_blocked, action_mask, action_flags, signal);
        assert!(pre_blocked & new_blocked == pre_blocked);
    }

    #[kani::proof]
    fn action_mask_bits_preserved() {
        let pre_blocked: u64 = kani::any();
        let action_mask: u64 = kani::any();
        let action_flags: u64 = kani::any();
        let signal: u32 = kani::any();
        kani::assume(signal < 64);

        let new_blocked = combine_blocked(pre_blocked, action_mask, action_flags, signal);
        assert!(action_mask & new_blocked == action_mask);
    }

    #[kani::proof]
    fn self_block_when_nodefer_clear() {
        let pre_blocked: u64 = kani::any();
        let action_mask: u64 = kani::any();
        let action_flags: u64 = kani::any();
        let signal: u32 = kani::any();
        kani::assume(signal < 64);
        kani::assume(action_flags & SA_NODEFER == 0);

        let new_blocked = combine_blocked(pre_blocked, action_mask, action_flags, signal);
        assert!(new_blocked & (1u64 << signal) != 0);
    }

    #[kani::proof]
    fn no_self_block_when_nodefer_set() {
        let pre_blocked: u64 = kani::any();
        let action_mask: u64 = kani::any();
        let action_flags: u64 = kani::any();
        let signal: u32 = kani::any();
        kani::assume(signal < 64);
        kani::assume(action_flags & SA_NODEFER != 0);

        let new_blocked = combine_blocked(pre_blocked, action_mask, action_flags, signal);
        assert_eq!(new_blocked, pre_blocked | action_mask);
    }

    #[kani::proof]
    fn no_spurious_bits_set() {
        let pre_blocked: u64 = kani::any();
        let action_mask: u64 = kani::any();
        let action_flags: u64 = kani::any();
        let signal: u32 = kani::any();
        kani::assume(signal < 64);

        let new_blocked = combine_blocked(pre_blocked, action_mask, action_flags, signal);
        let upper = pre_blocked | action_mask | (1u64 << signal);
        assert!(new_blocked & !upper == 0);
    }

    #[kani::proof]
    fn nodefer_bit_isolation() {
        let pre_blocked: u64 = kani::any();
        let action_mask: u64 = kani::any();
        let flags_a: u64 = kani::any();
        let flags_b: u64 = kani::any();
        let signal: u32 = kani::any();
        kani::assume(signal < 64);
        kani::assume((flags_a & SA_NODEFER) == (flags_b & SA_NODEFER));

        assert_eq!(
            combine_blocked(pre_blocked, action_mask, flags_a, signal),
            combine_blocked(pre_blocked, action_mask, flags_b, signal),
        );
    }
}
