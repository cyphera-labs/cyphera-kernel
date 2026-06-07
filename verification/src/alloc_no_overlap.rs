pub const N: usize = 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub start: u32,
    pub len: u32,
    pub allocated: bool,
}

pub fn overlaps(a_start: u32, a_len: u32, b_start: u32, b_len: u32) -> bool {
    if a_len == 0 || b_len == 0 {
        return false;
    }
    let a_end = a_start.saturating_add(a_len);
    let b_end = b_start.saturating_add(b_len);
    a_start < b_end && b_start < a_end
}

#[derive(Copy, Clone, Debug)]
pub struct Tracker {
    pub regions: [Region; N],
    pub count: u32,
}

impl Tracker {
    pub const fn empty() -> Self {
        Self {
            regions: [Region {
                start: 0,
                len: 0,
                allocated: false,
            }; N],
            count: 0,
        }
    }

    /// Invariant: no two currently-allocated regions overlap.
    pub fn no_overlap_invariant(&self) -> bool {
        let mut i = 0;
        while i < self.count as usize && i < N {
            if self.regions[i].allocated {
                let mut j = i + 1;
                while j < self.count as usize && j < N {
                    if self.regions[j].allocated
                        && overlaps(
                            self.regions[i].start,
                            self.regions[i].len,
                            self.regions[j].start,
                            self.regions[j].len,
                        )
                    {
                        return false;
                    }
                    j += 1;
                }
            }
            i += 1;
        }
        true
    }

    pub fn try_alloc(&mut self, start: u32, len: u32) -> bool {
        if len == 0 {
            return false;
        }
        let mut i = 0;
        while i < self.count as usize && i < N {
            if self.regions[i].allocated
                && overlaps(self.regions[i].start, self.regions[i].len, start, len)
            {
                return false;
            }
            i += 1;
        }
        if (self.count as usize) >= N {
            return false;
        }
        let slot = self.count as usize;
        self.regions[slot] = Region {
            start,
            len,
            allocated: true,
        };
        self.count += 1;
        true
    }

    pub fn dealloc(&mut self, idx: u32) {
        let i = idx as usize;
        if i < N && i < self.count as usize {
            self.regions[i].allocated = false;
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn overlaps_symmetric() {
        let a_start: u32 = kani::any();
        let a_len: u32 = kani::any();
        let b_start: u32 = kani::any();
        let b_len: u32 = kani::any();
        assert_eq!(
            overlaps(a_start, a_len, b_start, b_len),
            overlaps(b_start, b_len, a_start, a_len),
        );
    }

    #[kani::proof]
    fn empty_never_overlaps() {
        let a_start: u32 = kani::any();
        let b_start: u32 = kani::any();
        let b_len: u32 = kani::any();
        assert!(!overlaps(a_start, 0, b_start, b_len));
        assert!(!overlaps(a_start, b_len, b_start, 0));
    }

    #[kani::proof]
    fn adjacent_does_not_overlap() {
        let start: u32 = kani::any();
        let len_a: u32 = kani::any();
        let len_b: u32 = kani::any();
        kani::assume(len_a > 0);
        kani::assume(len_b > 0);
        kani::assume(start <= u32::MAX - len_a);

        assert!(!overlaps(start, len_a, start + len_a, len_b));
    }

    #[kani::proof]
    fn empty_tracker_satisfies_invariant() {
        let t = Tracker::empty();
        assert!(t.no_overlap_invariant());
    }

    fn one_region_tracker() -> Tracker {
        let s: u8 = kani::any();
        let l: u8 = kani::any();
        let a: bool = kani::any();
        let mut regions = [Region {
            start: 0,
            len: 0,
            allocated: false,
        }; N];
        regions[0] = Region {
            start: s as u32,
            len: l as u32,
            allocated: a,
        };
        Tracker { regions, count: 1 }
    }

    #[kani::proof]
    fn try_alloc_preserves_no_overlap_one_region() {
        let mut t = one_region_tracker();
        assert!(t.no_overlap_invariant());

        let req_start: u8 = kani::any();
        let req_len: u8 = kani::any();
        let ok = t.try_alloc(req_start as u32, req_len as u32);

        assert!(t.no_overlap_invariant());

        if ok {
            let pre = t.regions[0];
            if pre.allocated {
                assert!(!overlaps(
                    pre.start,
                    pre.len,
                    req_start as u32,
                    req_len as u32
                ));
            }
        }
    }

    #[kani::proof]
    fn try_alloc_on_empty_succeeds() {
        let mut t = Tracker::empty();
        let req_start: u32 = kani::any();
        let req_len: u32 = kani::any();
        kani::assume(req_len > 0);

        let ok = t.try_alloc(req_start, req_len);
        assert!(ok);
        assert!(t.no_overlap_invariant());
        assert_eq!(t.count, 1);
        assert!(t.regions[0].allocated);
        assert_eq!(t.regions[0].start, req_start);
        assert_eq!(t.regions[0].len, req_len);
    }

    #[kani::proof]
    fn dealloc_preserves_no_overlap_one_region() {
        let mut t = one_region_tracker();
        assert!(t.no_overlap_invariant());

        let idx: u32 = kani::any();
        t.dealloc(idx);

        assert!(t.no_overlap_invariant());
    }

    #[kani::proof]
    fn zero_len_alloc_rejected() {
        let mut t = Tracker::empty();
        let start: u32 = kani::any();
        assert!(!t.try_alloc(start, 0));
    }
}
