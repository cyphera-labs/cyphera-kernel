#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LockId {
    Global = 0,
    CpuQueue = 1,
    Vmspace = 2,
    FutexTable = 3,
    BitsetMasks = 4,
    Epoll = 5,
    Pagecache = 6,
}

impl LockId {
    pub fn from_u8(v: u8) -> Option<LockId> {
        match v {
            0 => Some(LockId::Global),
            1 => Some(LockId::CpuQueue),
            2 => Some(LockId::Vmspace),
            3 => Some(LockId::FutexTable),
            4 => Some(LockId::BitsetMasks),
            5 => Some(LockId::Epoll),
            6 => Some(LockId::Pagecache),
            _ => None,
        }
    }

    pub fn rank(self) -> u8 {
        self as u8
    }
}

pub const HELD_CAP: usize = 7;

#[derive(Copy, Clone, Debug)]
pub struct HeldSet {
    locks: [LockId; HELD_CAP],
    count: u8,
}

impl HeldSet {
    pub const fn empty() -> Self {
        Self {
            locks: [LockId::Global; HELD_CAP],
            count: 0,
        }
    }

    pub fn is_ordered(&self) -> bool {
        let mut i = 1;
        while i < self.count as usize {
            if self.locks[i - 1].rank() >= self.locks[i].rank() {
                return false;
            }
            i += 1;
        }
        true
    }

    pub fn can_acquire(&self, lock: LockId) -> bool {
        if self.count == 0 {
            return true;
        }
        let top = self.locks[(self.count - 1) as usize];
        lock.rank() > top.rank()
    }

    pub fn try_acquire(&mut self, lock: LockId) -> bool {
        if !self.can_acquire(lock) {
            return false;
        }
        if (self.count as usize) >= HELD_CAP {
            return false;
        }
        self.locks[self.count as usize] = lock;
        self.count += 1;
        true
    }

    pub fn release_top(&mut self) {
        if self.count > 0 {
            self.count -= 1;
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn empty_is_ordered() {
        let h = HeldSet::empty();
        assert!(h.is_ordered());
    }

    #[kani::proof]
    fn empty_accepts_anything() {
        let h = HeldSet::empty();
        let v: u8 = kani::any();
        kani::assume(v <= 6);
        let lock = LockId::from_u8(v).expect("v <= 6");
        assert!(h.can_acquire(lock));
    }

    #[kani::proof]
    fn try_acquire_preserves_ordered() {
        let count: u8 = kani::any();
        kani::assume(count <= 1);

        let mut h = HeldSet::empty();
        if count == 1 {
            let v: u8 = kani::any();
            kani::assume(v <= 6);
            let first = LockId::from_u8(v).expect("v <= 6");
            assert!(h.try_acquire(first));
        }
        assert!(h.is_ordered());

        let v2: u8 = kani::any();
        kani::assume(v2 <= 6);
        let next = LockId::from_u8(v2).expect("v2 <= 6");
        let _ = h.try_acquire(next);

        assert!(h.is_ordered());
    }

    #[kani::proof]
    fn lower_or_equal_rank_rejected() {
        let v_top: u8 = kani::any();
        let v_next: u8 = kani::any();
        kani::assume(v_top <= 6);
        kani::assume(v_next <= 6);
        kani::assume(v_next <= v_top);

        let mut h = HeldSet::empty();
        let top = LockId::from_u8(v_top).expect("v_top <= 6");
        assert!(h.try_acquire(top));

        let next = LockId::from_u8(v_next).expect("v_next <= 6");
        assert!(!h.try_acquire(next));
    }

    #[kani::proof]
    fn strictly_higher_rank_accepted() {
        let v_top: u8 = kani::any();
        let v_next: u8 = kani::any();
        kani::assume(v_top <= 6);
        kani::assume(v_next <= 6);
        kani::assume(v_next > v_top);

        let mut h = HeldSet::empty();
        let top = LockId::from_u8(v_top).expect("v_top <= 6");
        assert!(h.try_acquire(top));

        let next = LockId::from_u8(v_next).expect("v_next <= 6");
        assert!(h.try_acquire(next));
        assert!(h.is_ordered());
    }

    #[kani::proof]
    fn vmspace_then_global_rejected() {
        let mut h = HeldSet::empty();
        assert!(h.try_acquire(LockId::Vmspace));
        assert!(!h.try_acquire(LockId::Global));
    }

    #[kani::proof]
    fn global_then_vmspace_accepted() {
        let mut h = HeldSet::empty();
        assert!(h.try_acquire(LockId::Global));
        assert!(h.try_acquire(LockId::Vmspace));
        assert!(h.is_ordered());
        assert_eq!(h.count, 2);
    }

    #[kani::proof]
    fn rejection_is_monotonic() {
        let v_top: u8 = kani::any();
        let v_rejected: u8 = kani::any();
        let v_grow: u8 = kani::any();
        kani::assume(v_top <= 6);
        kani::assume(v_rejected <= 6);
        kani::assume(v_grow <= 6);
        kani::assume(v_rejected <= v_top);
        kani::assume(v_grow > v_top);

        let mut h = HeldSet::empty();
        let top = LockId::from_u8(v_top).expect("v_top <= 6");
        assert!(h.try_acquire(top));

        let rejected = LockId::from_u8(v_rejected).expect("v_rejected <= 6");
        assert!(!h.can_acquire(rejected));

        let grow = LockId::from_u8(v_grow).expect("v_grow <= 6");
        assert!(h.try_acquire(grow));

        assert!(!h.can_acquire(rejected));
    }

    #[kani::proof]
    fn release_top_preserves_ordered() {
        let v_first: u8 = kani::any();
        let v_second: u8 = kani::any();
        kani::assume(v_first <= 6);
        kani::assume(v_second <= 6);
        kani::assume(v_second > v_first);

        let mut h = HeldSet::empty();
        let first = LockId::from_u8(v_first).expect("v_first <= 6");
        let second = LockId::from_u8(v_second).expect("v_second <= 6");
        assert!(h.try_acquire(first));
        assert!(h.try_acquire(second));

        h.release_top();
        assert!(h.is_ordered());

        let v_re: u8 = kani::any();
        kani::assume(v_re <= 6);
        kani::assume(v_re > v_first);
        let re = LockId::from_u8(v_re).expect("v_re <= 6");
        assert!(h.try_acquire(re));
        assert!(h.is_ordered());
    }
}
