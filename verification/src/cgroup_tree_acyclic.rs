pub const N: usize = 8;

pub const NO_PARENT: u8 = u8::MAX;

#[derive(Copy, Clone, Debug)]
pub struct Forest {
    pub parent: [u8; N],
}

impl Forest {
    pub const fn empty() -> Self {
        Self {
            parent: [NO_PARENT; N],
        }
    }

    pub fn is_ancestor(&self, ancestor: u8, start: u8) -> bool {
        if start == NO_PARENT || (start as usize) >= N {
            return false;
        }
        let mut cur = start;
        let mut hops = 0;
        while hops < N {
            if cur == NO_PARENT {
                return false;
            }
            if cur == ancestor {
                return true;
            }
            cur = self.parent[cur as usize];
            hops += 1;
        }
        false
    }

    pub fn is_acyclic(&self) -> bool {
        let mut id: usize = 0;
        while id < N {
            let mut cur = self.parent[id];
            let mut hops = 0;
            while hops < N + 1 {
                if cur == NO_PARENT {
                    break;
                }
                if (cur as usize) >= N {
                    return false;
                }
                cur = self.parent[cur as usize];
                hops += 1;
            }
            if cur != NO_PARENT {
                return false;
            }
            id += 1;
        }
        true
    }

    pub fn add_child(&mut self, parent: u8, child: u8) -> bool {
        if (parent as usize) >= N || (child as usize) >= N {
            return false;
        }
        if parent == child {
            return false;
        }
        if self.parent[child as usize] != NO_PARENT {
            return false;
        }
        if self.is_ancestor(child, parent) {
            return false;
        }
        self.parent[child as usize] = parent;
        true
    }

    pub fn remove_child(&mut self, child: u8) {
        if (child as usize) < N {
            self.parent[child as usize] = NO_PARENT;
        }
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn empty_is_acyclic() {
        let f = Forest::empty();
        assert!(f.is_acyclic());
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn two_adds_preserve_acyclic_from_empty() {
        let p1: u8 = kani::any();
        let c1: u8 = kani::any();
        let p2: u8 = kani::any();
        let c2: u8 = kani::any();
        kani::assume((p1 as usize) < N);
        kani::assume((c1 as usize) < N);
        kani::assume((p2 as usize) < N);
        kani::assume((c2 as usize) < N);

        let mut f = Forest::empty();
        let _ = f.add_child(p1, c1);
        assert!(f.is_acyclic());
        let _ = f.add_child(p2, c2);
        assert!(f.is_acyclic());
    }

    #[kani::proof]
    fn self_loop_rejected() {
        let mut f = Forest::empty();
        let id: u8 = kani::any();
        kani::assume((id as usize) < N);
        assert!(!f.add_child(id, id));
        assert_eq!(f.parent[id as usize], NO_PARENT);
    }

    #[kani::proof]
    fn at_most_one_parent() {
        let p1: u8 = kani::any();
        let p2: u8 = kani::any();
        let c: u8 = kani::any();
        kani::assume((p1 as usize) < N);
        kani::assume((p2 as usize) < N);
        kani::assume((c as usize) < N);
        kani::assume(p1 != c);
        kani::assume(p2 != c);
        kani::assume(p1 != p2);

        let mut f = Forest::empty();
        assert!(f.add_child(p1, c));
        assert!(!f.add_child(p2, c));
        assert_eq!(f.parent[c as usize], p1);
    }

    #[kani::proof]
    fn back_edge_rejected() {
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        kani::assume((a as usize) < N);
        kani::assume((b as usize) < N);
        kani::assume(a != b);

        let mut f = Forest::empty();
        assert!(f.add_child(a, b));
        assert!(!f.add_child(b, a));
        assert!(f.is_acyclic());
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn remove_preserves_acyclic() {
        let p: u8 = kani::any();
        let c: u8 = kani::any();
        kani::assume((p as usize) < N);
        kani::assume((c as usize) < N);

        let mut f = Forest::empty();
        let _ = f.add_child(p, c);
        assert!(f.is_acyclic());

        let target: u8 = kani::any();
        kani::assume((target as usize) < N);
        f.remove_child(target);
        assert!(f.is_acyclic());
    }

    #[kani::proof]
    fn detach_then_reattach() {
        let p1: u8 = kani::any();
        let p2: u8 = kani::any();
        let c: u8 = kani::any();
        kani::assume((p1 as usize) < N);
        kani::assume((p2 as usize) < N);
        kani::assume((c as usize) < N);
        kani::assume(p1 != c);
        kani::assume(p2 != c);
        kani::assume(p1 != p2);

        let mut f = Forest::empty();
        assert!(f.add_child(p1, c));
        f.remove_child(c);
        assert_eq!(f.parent[c as usize], NO_PARENT);
        assert!(f.add_child(p2, c));
        assert_eq!(f.parent[c as usize], p2);
        assert!(f.is_acyclic());
    }
}
