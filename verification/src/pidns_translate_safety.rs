pub const MAX_ENTRIES: usize = 4;

pub const NOT_VISIBLE: u8 = 0;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: u8,
    pub val: u8,
}

#[derive(Copy, Clone, Debug)]
pub struct PidNs {
    pub h2l: [Entry; MAX_ENTRIES],
    pub h2l_count: u8,
    pub l2h: [Entry; MAX_ENTRIES],
    pub l2h_count: u8,
    pub next_local: u8,
}

impl Default for PidNs {
    fn default() -> Self {
        Self::new()
    }
}

fn map_get(map: &[Entry; MAX_ENTRIES], count: u8, key: u8) -> Option<u8> {
    let mut i = 0;
    while i < count as usize && i < MAX_ENTRIES {
        if map[i].key == key {
            return Some(map[i].val);
        }
        i += 1;
    }
    None
}

fn map_insert(map: &mut [Entry; MAX_ENTRIES], count: &mut u8, key: u8, val: u8) {
    map[*count as usize] = Entry { key, val };
    *count += 1;
}

fn map_remove(map: &mut [Entry; MAX_ENTRIES], count: &mut u8, key: u8) -> Option<u8> {
    let mut i = 0;
    while i < *count as usize && i < MAX_ENTRIES {
        if map[i].key == key {
            let val = map[i].val;
            let last = (*count - 1) as usize;
            map[i] = map[last];
            map[last] = Entry { key: 0, val: 0 };
            *count -= 1;
            return Some(val);
        }
        i += 1;
    }
    None
}

impl PidNs {
    pub const fn new() -> Self {
        Self {
            h2l: [Entry { key: 0, val: 0 }; MAX_ENTRIES],
            h2l_count: 0,
            l2h: [Entry { key: 0, val: 0 }; MAX_ENTRIES],
            l2h_count: 0,
            next_local: 1,
        }
    }

    pub fn host_to_local(&self, host: u8) -> u8 {
        map_get(&self.h2l, self.h2l_count, host).unwrap_or(NOT_VISIBLE)
    }

    pub fn local_to_host(&self, local: u8) -> Option<u8> {
        if local == 0 {
            return None;
        }
        map_get(&self.l2h, self.l2h_count, local)
    }

    pub fn assign(&mut self, host: u8) -> u8 {
        if let Some(existing) = map_get(&self.h2l, self.h2l_count, host) {
            return existing;
        }
        if self.h2l_count as usize >= MAX_ENTRIES || self.l2h_count as usize >= MAX_ENTRIES {
            return 0;
        }
        if self.next_local == 0 {
            return 0;
        }
        let local = self.next_local;
        self.next_local = self.next_local.wrapping_add(1);
        map_insert(&mut self.h2l, &mut self.h2l_count, host, local);
        map_insert(&mut self.l2h, &mut self.l2h_count, local, host);
        local
    }

    pub fn drop_host(&mut self, host: u8) {
        if let Some(local) = map_remove(&mut self.h2l, &mut self.h2l_count, host) {
            let _ = map_remove(&mut self.l2h, &mut self.l2h_count, local);
        }
    }

    pub fn in_sync(&self) -> bool {
        if self.h2l_count != self.l2h_count {
            return false;
        }
        let mut i = 0;
        while i < self.h2l_count as usize && i < MAX_ENTRIES {
            let (host, local) = (self.h2l[i].key, self.h2l[i].val);
            if map_get(&self.l2h, self.l2h_count, local) != Some(host) {
                return false;
            }
            i += 1;
        }
        let mut j = 0;
        while j < self.l2h_count as usize && j < MAX_ENTRIES {
            let (local, host) = (self.l2h[j].key, self.l2h[j].val);
            if map_get(&self.h2l, self.h2l_count, host) != Some(local) {
                return false;
            }
            j += 1;
        }
        true
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(6)]
    fn empty_returns_zero() {
        let ns = PidNs::new();
        let host: u8 = kani::any();
        assert_eq!(ns.host_to_local(host), NOT_VISIBLE);
        assert!(ns.in_sync());
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn assign_idempotent() {
        let mut ns = PidNs::new();
        let host: u8 = kani::any();
        kani::assume(host != 0);
        let l1 = ns.assign(host);
        let l2 = ns.assign(host);
        assert_eq!(l1, l2);
        assert_eq!(ns.host_to_local(host), l1);
        assert_eq!(ns.local_to_host(l1), Some(host));
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn host_to_local_safe_or_zero() {
        let mut ns = PidNs::new();
        let assigned: u8 = kani::any();
        kani::assume(assigned != 0);
        let _ = ns.assign(assigned);

        let query: u8 = kani::any();
        let result = ns.host_to_local(query);
        if result != NOT_VISIBLE {
            assert_eq!(ns.local_to_host(result), Some(query));
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn local_zero_never_resolves() {
        let mut ns = PidNs::new();
        let h: u8 = kani::any();
        kani::assume(h != 0);
        let _ = ns.assign(h);
        assert_eq!(ns.local_to_host(0), None);
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn drop_removes_both_directions() {
        let mut ns = PidNs::new();
        let host: u8 = kani::any();
        kani::assume(host != 0);
        let local = ns.assign(host);
        kani::assume(local != 0);
        assert_eq!(ns.host_to_local(host), local);
        assert_eq!(ns.local_to_host(local), Some(host));

        ns.drop_host(host);
        assert_eq!(ns.host_to_local(host), NOT_VISIBLE);
        assert_eq!(ns.local_to_host(local), None);
        assert!(ns.in_sync());
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn round_trip_after_assign() {
        let mut ns = PidNs::new();
        let host: u8 = kani::any();
        kani::assume(host != 0);
        let local = ns.assign(host);
        kani::assume(local != 0);
        assert_eq!(local, ns.host_to_local(host));
        assert_eq!(ns.local_to_host(local), Some(host));
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn maps_stay_in_sync() {
        let mut ns = PidNs::new();
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        let d: u8 = kani::any();
        kani::assume(a != 0 && b != 0);

        let _ = ns.assign(a);
        assert!(ns.in_sync());
        let _ = ns.assign(b);
        assert!(ns.in_sync());
        ns.drop_host(d);
        assert!(ns.in_sync());
    }
}
