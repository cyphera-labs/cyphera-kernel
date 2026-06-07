pub const MAX_VMAS: usize = 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Vma {
    pub start: u32,
    pub end: u32,
}

impl Vma {
    pub const fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct VmaList {
    pub vmas: [Vma; MAX_VMAS],
    pub count: u32,
}

impl VmaList {
    pub const fn empty() -> Self {
        Self {
            vmas: [Vma::new(0, 0); MAX_VMAS],
            count: 0,
        }
    }

    pub fn is_well_formed(&self) -> bool {
        let n = self.count as usize;
        if n > MAX_VMAS {
            return false;
        }
        let mut i = 0;
        while i < n {
            let v = self.vmas[i];
            if v.start >= v.end {
                return false;
            }
            if i > 0 {
                let prev = self.vmas[i - 1];
                if prev.end > v.start {
                    return false;
                }
                if prev.start >= v.start {
                    return false;
                }
            }
            i += 1;
        }
        true
    }

    pub fn overlaps(&self, lo: u32, hi: u32) -> bool {
        if lo >= hi {
            return false;
        }
        let n = self.count as usize;
        let mut i = 0;
        while i < n {
            let v = self.vmas[i];
            if v.start < hi && v.end > lo {
                return true;
            }
            i += 1;
        }
        false
    }

    pub fn try_insert(&mut self, v: Vma) -> bool {
        if v.start >= v.end {
            return false;
        }
        if (self.count as usize) >= MAX_VMAS {
            return false;
        }
        if self.overlaps(v.start, v.end) {
            return false;
        }
        let n = self.count as usize;
        let mut pos = n;
        let mut i = 0;
        while i < n {
            if self.vmas[i].start > v.start {
                pos = i;
                break;
            }
            i += 1;
        }
        let mut j = n;
        while j > pos {
            self.vmas[j] = self.vmas[j - 1];
            j -= 1;
        }
        self.vmas[pos] = v;
        self.count += 1;
        true
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn empty_is_well_formed() {
        let l = VmaList::empty();
        assert!(l.is_well_formed());
    }

    #[kani::proof]
    fn adjacent_does_not_overlap() {
        let mut l = VmaList::empty();
        assert!(l.try_insert(Vma::new(0, 5)));
        assert!(l.try_insert(Vma::new(5, 10)));
        assert!(l.is_well_formed());
        assert_eq!(l.count, 2);
        let mut l2 = VmaList::empty();
        assert!(l2.try_insert(Vma::new(5, 10)));
        assert!(l2.try_insert(Vma::new(0, 5)));
        assert!(l2.is_well_formed());
        assert_eq!(l2.count, 2);
        assert_eq!(l2.vmas[0].start, 0);
        assert_eq!(l2.vmas[1].start, 5);
    }

    #[kani::proof]
    fn single_insert_preserves_invariant() {
        let s: u8 = kani::any();
        let e: u8 = kani::any();
        kani::assume(s < e);

        let mut l = VmaList::empty();
        assert!(l.try_insert(Vma::new(s as u32, e as u32)));
        assert!(l.is_well_formed());
        assert_eq!(l.count, 1);
        assert_eq!(l.vmas[0].start, s as u32);
        assert_eq!(l.vmas[0].end, e as u32);
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn empty_range_rejected() {
        let s: u8 = kani::any();
        let mut l = VmaList::empty();
        assert!(!l.try_insert(Vma::new(s as u32, s as u32)));
        let e: u8 = kani::any();
        kani::assume(e < s);
        assert!(!l.try_insert(Vma::new(s as u32, e as u32)));
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn insert_preserves_invariant_one_existing() {
        let s1: u8 = kani::any();
        let e1: u8 = kani::any();
        let s2: u8 = kani::any();
        let e2: u8 = kani::any();
        kani::assume(s1 < e1);
        kani::assume(s2 < e2);

        let mut l = VmaList::empty();
        assert!(l.try_insert(Vma::new(s1 as u32, e1 as u32)));
        assert!(l.is_well_formed());

        let new_vma = Vma::new(s2 as u32, e2 as u32);
        let pre_overlaps = l.overlaps(new_vma.start, new_vma.end);
        let ok = l.try_insert(new_vma);

        assert_eq!(ok, !pre_overlaps);
        assert!(l.is_well_formed());
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn fully_contained_overlap_rejected() {
        let s1: u8 = kani::any();
        let e1: u8 = kani::any();
        kani::assume(s1 < e1);
        kani::assume(s1 < u8::MAX);
        let inner_s = s1 + 1;
        kani::assume(inner_s < e1);

        let mut l = VmaList::empty();
        assert!(l.try_insert(Vma::new(s1 as u32, e1 as u32)));
        assert!(!l.try_insert(Vma::new(inner_s as u32, e1 as u32)));
        assert!(l.is_well_formed());
        assert_eq!(l.count, 1);
    }

    #[kani::proof]
    fn capacity_bound() {
        let mut l = VmaList::empty();
        assert!(l.try_insert(Vma::new(0, 1)));
        assert!(l.try_insert(Vma::new(2, 3)));
        assert!(l.try_insert(Vma::new(4, 5)));
        assert!(l.try_insert(Vma::new(6, 7)));
        assert_eq!(l.count, MAX_VMAS as u32);
        assert!(!l.try_insert(Vma::new(8, 9)));
        assert!(l.is_well_formed());
    }
}
