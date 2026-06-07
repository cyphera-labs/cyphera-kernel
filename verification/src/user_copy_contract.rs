use crate::user_range_check::user_range_inside_userspace;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UserOp {
    Ok,
    Fault,
}

pub fn copy_from_user_model(user_addr: u64, len: usize, access_ok_runtime: bool) -> (UserOp, bool) {
    if !user_range_inside_userspace(user_addr, len) {
        return (UserOp::Fault, false);
    }
    if !access_ok_runtime {
        return (UserOp::Fault, false);
    }
    let did_copy = true;
    (UserOp::Ok, did_copy)
}

pub fn copy_to_user_model(user_addr: u64, len: usize, access_ok_runtime: bool) -> (UserOp, bool) {
    if !user_range_inside_userspace(user_addr, len) {
        return (UserOp::Fault, false);
    }
    if !access_ok_runtime {
        return (UserOp::Fault, false);
    }
    let did_copy = true;
    (UserOp::Ok, did_copy)
}

pub fn cmpxchg_user_u32_alignment_ok(user_addr: u64) -> bool {
    user_addr & 0x3 == 0
}

pub fn atomic_or_user_u32_alignment_ok(user_addr: u64) -> bool {
    user_addr & 0x3 == 0
}

#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::user_range_check::USER_ADDRESS_LIMIT;

    #[kani::proof]
    fn copy_from_user_rejects_kernel_addr() {
        let user_addr: u64 = kani::any();
        let len: usize = kani::any();
        let access_ok: bool = kani::any();
        kani::assume(user_addr >= USER_ADDRESS_LIMIT);
        kani::assume(len > 0);
        kani::assume(len <= 0x1_0000_0000);

        let (outcome, did_copy) = copy_from_user_model(user_addr, len, access_ok);
        assert!(outcome == UserOp::Fault);
        assert!(!did_copy);
    }

    #[kani::proof]
    fn copy_from_user_rejects_overflow() {
        let user_addr: u64 = kani::any();
        let len: usize = kani::any();
        let access_ok: bool = kani::any();
        kani::assume(len > 0);
        kani::assume(user_addr > u64::MAX - (len as u64));

        let (outcome, did_copy) = copy_from_user_model(user_addr, len, access_ok);
        assert!(outcome == UserOp::Fault);
        assert!(!did_copy);
    }

    #[kani::proof]
    fn copy_from_user_rejects_runtime_fault() {
        let user_addr: u64 = kani::any();
        let len: usize = kani::any();

        let (outcome, did_copy) = copy_from_user_model(user_addr, len, false);
        assert!(outcome == UserOp::Fault);
        assert!(!did_copy);
    }

    #[kani::proof]
    fn copy_from_user_succeeds_iff_preconditions_hold() {
        let user_addr: u64 = kani::any();
        let len: usize = kani::any();
        let access_ok: bool = kani::any();
        kani::assume(len <= 0x1_0000_0000);

        let (outcome, did_copy) = copy_from_user_model(user_addr, len, access_ok);
        assert_eq!(outcome == UserOp::Ok, did_copy);
        assert_eq!(
            did_copy,
            user_range_inside_userspace(user_addr, len) && access_ok
        );
    }

    #[kani::proof]
    fn copy_to_user_rejects_kernel_addr() {
        let user_addr: u64 = kani::any();
        let len: usize = kani::any();
        let access_ok: bool = kani::any();
        kani::assume(user_addr >= USER_ADDRESS_LIMIT);
        kani::assume(len > 0);
        kani::assume(len <= 0x1_0000_0000);

        let (outcome, did_copy) = copy_to_user_model(user_addr, len, access_ok);
        assert!(outcome == UserOp::Fault);
        assert!(!did_copy);
    }

    #[kani::proof]
    fn copy_to_user_rejects_overflow() {
        let user_addr: u64 = kani::any();
        let len: usize = kani::any();
        let access_ok: bool = kani::any();
        kani::assume(len > 0);
        kani::assume(user_addr > u64::MAX - (len as u64));

        let (outcome, did_copy) = copy_to_user_model(user_addr, len, access_ok);
        assert!(outcome == UserOp::Fault);
        assert!(!did_copy);
    }

    #[kani::proof]
    fn cmpxchg_alignment_rejects_misaligned() {
        let user_addr: u64 = kani::any();
        kani::assume(user_addr & 0x3 != 0);
        assert!(!cmpxchg_user_u32_alignment_ok(user_addr));
    }

    #[kani::proof]
    fn cmpxchg_alignment_accepts_aligned() {
        let user_addr: u64 = kani::any();
        kani::assume(user_addr & 0x3 == 0);
        assert!(cmpxchg_user_u32_alignment_ok(user_addr));
    }

    #[kani::proof]
    fn atomic_or_alignment_rejects_misaligned() {
        let user_addr: u64 = kani::any();
        kani::assume(user_addr & 0x3 != 0);
        assert!(!atomic_or_user_u32_alignment_ok(user_addr));
    }

    #[kani::proof]
    fn atomic_or_alignment_accepts_aligned() {
        let user_addr: u64 = kani::any();
        kani::assume(user_addr & 0x3 == 0);
        assert!(atomic_or_user_u32_alignment_ok(user_addr));
    }
}
