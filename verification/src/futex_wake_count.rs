pub const MAX_Q: usize = 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Queue {
    pub pids: [u32; MAX_Q],
    pub count: u8,
}

impl Queue {
    pub const fn empty() -> Self {
        Self {
            pids: [0; MAX_Q],
            count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count as usize
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WakeResult {
    pub woken: [u32; MAX_Q],
    pub woken_count: u8,
    pub dropped_count: u8,
    pub requeue_start: u8,
    pub post_queue: Queue,
}

pub fn wake(q: &Queue, n: u32, success: &[bool; MAX_Q]) -> WakeResult {
    let mut woken = [0u32; MAX_Q];
    let mut woken_count: u8 = 0;
    let mut dropped_count: u8 = 0;
    let mut post = Queue::empty();
    let total = q.count as usize;
    let mut requeue_start: u8 = q.count;
    let mut i: usize = 0;
    while i < total && i < MAX_Q {
        let pid = q.pids[i];
        if (woken_count as u32) >= n {
            if (requeue_start as usize) > i {
                requeue_start = i as u8;
            }
            post.pids[post.count as usize] = pid;
            post.count += 1;
        } else if success[i] {
            woken[woken_count as usize] = pid;
            woken_count += 1;
        } else {
            dropped_count += 1;
        }
        i += 1;
    }
    WakeResult {
        woken,
        woken_count,
        dropped_count,
        requeue_start,
        post_queue: post,
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_queue() -> Queue {
        let q = Queue {
            pids: kani::any(),
            count: kani::any(),
        };
        kani::assume((q.count as usize) <= MAX_Q);
        q
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn n_zero_wakes_nothing() {
        let q = any_queue();
        let success: [bool; MAX_Q] = kani::any();

        let r = wake(&q, 0, &success);
        assert_eq!(r.woken_count, 0);
        assert_eq!(r.dropped_count, 0);
        assert_eq!(r.post_queue.count, q.count);
        let mut i = 0;
        while i < q.count as usize {
            assert_eq!(r.post_queue.pids[i], q.pids[i]);
            i += 1;
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn cap_honored() {
        let q = any_queue();
        let n: u32 = kani::any();
        let success: [bool; MAX_Q] = kani::any();

        let r = wake(&q, n, &success);
        assert!((r.woken_count as u32) <= n);
        assert!((r.woken_count as usize) <= q.count as usize);
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn no_waiter_unaccounted() {
        let q = any_queue();
        let n: u32 = kani::any();
        let success: [bool; MAX_Q] = kani::any();

        let r = wake(&q, n, &success);
        assert_eq!(
            r.woken_count as u32 + r.dropped_count as u32 + r.post_queue.count as u32,
            q.count as u32
        );
        assert!(r.requeue_start <= q.count);
        assert_eq!(
            r.woken_count as u32 + r.dropped_count as u32,
            r.requeue_start as u32
        );
        assert_eq!(
            r.post_queue.count as u32,
            q.count as u32 - r.requeue_start as u32
        );
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn requeue_preserves_relative_order() {
        let q = any_queue();
        let n: u32 = kani::any();
        let success: [bool; MAX_Q] = kani::any();

        let r = wake(&q, n, &success);
        let start = r.requeue_start as usize;
        let mut i = 0;
        while i < r.post_queue.count as usize {
            assert_eq!(r.post_queue.pids[i], q.pids[start + i]);
            i += 1;
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn wake_all_drains_queue() {
        let q = any_queue();
        let n: u32 = kani::any();
        kani::assume(n >= q.count as u32);
        let success: [bool; MAX_Q] = kani::any();

        let r = wake(&q, n, &success);
        assert_eq!(r.post_queue.count, 0);
        assert_eq!(r.woken_count + r.dropped_count, q.count);
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn all_success_is_clean_prefix() {
        let q = any_queue();
        let n: u32 = kani::any();
        let success = [true; MAX_Q];

        let r = wake(&q, n, &success);
        assert_eq!(r.dropped_count, 0);
        let expected = core::cmp::min(n as usize, q.count as usize);
        assert_eq!(r.woken_count as usize, expected);
        let mut i = 0;
        while i < r.woken_count as usize {
            assert_eq!(r.woken[i], q.pids[i]);
            i += 1;
        }
    }
}
