pub const PERM_READ: u32 = 1 << 0;
pub const PERM_WRITE: u32 = 1 << 1;
pub const PERM_EXECUTE: u32 = 1 << 2;
pub const PERM_USER: u32 = 1 << 3;

pub const PTE_PRESENT: u64 = 1 << 0;
pub const PTE_WRITABLE: u64 = 1 << 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_NO_EXECUTE: u64 = 1 << 63;

pub fn to_pte_flags(perms: u32) -> u64 {
    let mut f = PTE_PRESENT;
    if perms & PERM_WRITE != 0 {
        f |= PTE_WRITABLE;
    }
    if perms & PERM_EXECUTE == 0 {
        f |= PTE_NO_EXECUTE;
    }
    if perms & PERM_USER != 0 {
        f |= PTE_USER;
    }
    f
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn always_present() {
        let perms: u32 = kani::any();
        let f = to_pte_flags(perms);
        assert!(f & PTE_PRESENT != 0);
    }

    #[kani::proof]
    fn write_perm_sets_writable() {
        let perms: u32 = kani::any();
        let f = to_pte_flags(perms);
        if perms & PERM_WRITE != 0 {
            assert!(f & PTE_WRITABLE != 0);
        } else {
            assert!(f & PTE_WRITABLE == 0);
        }
    }

    #[kani::proof]
    fn user_perm_sets_user() {
        let perms: u32 = kani::any();
        let f = to_pte_flags(perms);
        if perms & PERM_USER != 0 {
            assert!(f & PTE_USER != 0);
        } else {
            assert!(f & PTE_USER == 0);
        }
    }

    #[kani::proof]
    fn execute_perm_clears_nx() {
        let perms: u32 = kani::any();
        let f = to_pte_flags(perms);
        if perms & PERM_EXECUTE != 0 {
            assert!(f & PTE_NO_EXECUTE == 0);
        } else {
            assert!(f & PTE_NO_EXECUTE != 0);
        }
    }

    #[kani::proof]
    fn write_bit_independent() {
        let perms: u32 = kani::any();
        let toggled = perms ^ PERM_WRITE;

        let f1 = to_pte_flags(perms);
        let f2 = to_pte_flags(toggled);
        let other_mask = PTE_PRESENT | PTE_USER | PTE_NO_EXECUTE;
        assert_eq!(f1 & other_mask, f2 & other_mask);
        assert_ne!(f1 & PTE_WRITABLE, f2 & PTE_WRITABLE);
    }

    #[kani::proof]
    fn user_bit_independent() {
        let perms: u32 = kani::any();
        let toggled = perms ^ PERM_USER;

        let f1 = to_pte_flags(perms);
        let f2 = to_pte_flags(toggled);
        let other_mask = PTE_PRESENT | PTE_WRITABLE | PTE_NO_EXECUTE;
        assert_eq!(f1 & other_mask, f2 & other_mask);
        assert_ne!(f1 & PTE_USER, f2 & PTE_USER);
    }

    #[kani::proof]
    fn execute_bit_independent() {
        let perms: u32 = kani::any();
        let toggled = perms ^ PERM_EXECUTE;

        let f1 = to_pte_flags(perms);
        let f2 = to_pte_flags(toggled);
        let other_mask = PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        assert_eq!(f1 & other_mask, f2 & other_mask);
        assert_ne!(f1 & PTE_NO_EXECUTE, f2 & PTE_NO_EXECUTE);
    }

    #[kani::proof]
    fn read_bit_has_no_pte_effect() {
        let perms: u32 = kani::any();
        let toggled = perms ^ PERM_READ;
        assert_eq!(to_pte_flags(perms), to_pte_flags(toggled));
    }
}
