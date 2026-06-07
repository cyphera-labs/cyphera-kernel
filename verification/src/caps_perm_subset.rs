pub const ALL_CAPS_MASK: u64 = (1u64 << 41) - 1;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CapsetError {
    PermEscalation,
    EffExceedsPerm,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CapsetOk {
    pub stored_eff: u64,
    pub stored_perm: u64,
}

pub fn capset_eff_perm(
    old_perm: u64,
    new_perm: u64,
    new_eff: u64,
) -> Result<CapsetOk, CapsetError> {
    if (new_perm & !old_perm) != 0 {
        return Err(CapsetError::PermEscalation);
    }
    if (new_eff & !new_perm) != 0 {
        return Err(CapsetError::EffExceedsPerm);
    }
    Ok(CapsetOk {
        stored_eff: new_eff & ALL_CAPS_MASK,
        stored_perm: new_perm & ALL_CAPS_MASK,
    })
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn accept_implies_eff_subset_perm() {
        let old_perm: u64 = kani::any();
        let new_perm: u64 = kani::any();
        let new_eff: u64 = kani::any();

        if let Ok(ok) = capset_eff_perm(old_perm, new_perm, new_eff) {
            assert!(ok.stored_eff & !ok.stored_perm == 0);
        }
    }

    #[kani::proof]
    fn accept_implies_no_escalation() {
        let old_perm: u64 = kani::any();
        let new_perm: u64 = kani::any();
        let new_eff: u64 = kani::any();

        if let Ok(ok) = capset_eff_perm(old_perm, new_perm, new_eff) {
            assert!(ok.stored_perm & !old_perm == 0);
        }
    }

    #[kani::proof]
    fn stored_values_within_all_caps_mask() {
        let old_perm: u64 = kani::any();
        let new_perm: u64 = kani::any();
        let new_eff: u64 = kani::any();

        if let Ok(ok) = capset_eff_perm(old_perm, new_perm, new_eff) {
            assert!(ok.stored_eff & !ALL_CAPS_MASK == 0);
            assert!(ok.stored_perm & !ALL_CAPS_MASK == 0);
        }
    }

    #[kani::proof]
    fn above_mask_bits_never_stored() {
        let old_perm: u64 = kani::any();
        let new_perm: u64 = kani::any();
        let new_eff: u64 = kani::any();
        let high_bit: u64 = kani::any();
        kani::assume(high_bit >= 41);
        kani::assume(high_bit < 64);

        if let Ok(ok) = capset_eff_perm(old_perm, new_perm, new_eff) {
            assert!(ok.stored_eff & (1u64 << high_bit) == 0);
            assert!(ok.stored_perm & (1u64 << high_bit) == 0);
        }
    }

    #[kani::proof]
    fn escalation_takes_precedence() {
        let old_perm: u64 = kani::any();
        let new_perm: u64 = kani::any();
        let new_eff: u64 = kani::any();
        kani::assume(new_perm & !old_perm != 0);

        assert_eq!(
            capset_eff_perm(old_perm, new_perm, new_eff),
            Err(CapsetError::PermEscalation)
        );
    }

    #[kani::proof]
    fn eff_exceeds_perm_when_rule_one_passes() {
        let old_perm: u64 = kani::any();
        let new_perm: u64 = kani::any();
        let new_eff: u64 = kani::any();
        kani::assume(new_perm & !old_perm == 0);
        kani::assume(new_eff & !new_perm != 0);

        assert_eq!(
            capset_eff_perm(old_perm, new_perm, new_eff),
            Err(CapsetError::EffExceedsPerm)
        );
    }

    #[kani::proof]
    fn accept_when_both_rules_pass() {
        let old_perm: u64 = kani::any();
        let new_perm: u64 = kani::any();
        let new_eff: u64 = kani::any();
        kani::assume(new_perm & !old_perm == 0);
        kani::assume(new_eff & !new_perm == 0);

        assert!(capset_eff_perm(old_perm, new_perm, new_eff).is_ok());
    }
}
