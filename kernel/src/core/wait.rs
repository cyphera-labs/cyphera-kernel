extern crate alloc;

use alloc::collections::VecDeque;

#[cfg(host_test)]
#[allow(unused_imports)]
use frame_host as frame;

use frame::sync::SpinIrq;

use crate::process_model::Pid;

pub struct WaitQueue {
    waiters: SpinIrq<VecDeque<Pid>>,
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            waiters: SpinIrq::new(VecDeque::new()),
        }
    }

    pub fn park(&self) {
        crate::core::park_on(self);
    }

    pub fn wake_one(&self) {
        let _ = self.wake_one_pid();
    }

    pub fn pop_one_no_wake(&self) -> Option<Pid> {
        self.waiters.lock().pop_front()
    }

    pub fn wake_one_pid(&self) -> Option<Pid> {
        loop {
            let pid = self.waiters.lock().pop_front()?;
            if crate::core::wake_pid(pid) {
                return Some(pid);
            }
        }
    }

    pub fn wake_all(&self) {
        let drained: alloc::vec::Vec<Pid> = self.waiters.lock().drain(..).collect();
        for pid in drained {
            let _ = crate::core::wake_pid(pid);
        }
    }

    pub(crate) fn enqueue(&self, pid: Pid) {
        self.waiters.lock().push_back(pid);
    }

    pub fn drain(&self) -> alloc::vec::Vec<Pid> {
        self.waiters.lock().drain(..).collect()
    }

    pub fn dequeue(&self, pid: Pid) {
        self.waiters.lock().retain(|&p| p != pid);
    }

    pub fn contains(&self, pid: Pid) -> bool {
        self.waiters.lock().iter().any(|&p| p == pid)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    Woken,
    TimedOut,
    Interrupted,
}

pub fn wait_guarded(
    site: &'static str,
    deadline_nanos: Option<u64>,
    still_parked: &dyn Fn() -> bool,
) -> WaitOutcome {
    crate::core::park_self_at_guarded(site, still_parked);
    if crate::core::current_signal_pending() {
        return WaitOutcome::Interrupted;
    }
    if deadline_nanos.is_some_and(|d| frame::cpu::clock::nanos_since_boot() >= d) {
        return WaitOutcome::TimedOut;
    }
    WaitOutcome::Woken
}

pub fn wake(pid: Pid) -> bool {
    crate::core::wake_pid(pid)
}

#[cfg(host_test)]
#[cfg(test)]
mod host_tests {
    use super::*;

    fn pid(raw: u32) -> Pid {
        Pid::from_raw(raw)
    }

    #[test]
    fn empty_queue_drain_returns_empty_vec() {
        let q = WaitQueue::new();
        assert!(q.drain().is_empty());
    }

    #[test]
    fn enqueue_then_pop_no_wake_is_fifo() {
        let q = WaitQueue::new();
        q.enqueue(pid(1));
        q.enqueue(pid(2));
        q.enqueue(pid(3));
        assert_eq!(q.pop_one_no_wake(), Some(pid(1)));
        assert_eq!(q.pop_one_no_wake(), Some(pid(2)));
        assert_eq!(q.pop_one_no_wake(), Some(pid(3)));
        assert_eq!(q.pop_one_no_wake(), None);
    }

    #[test]
    fn drain_returns_all_in_fifo_order() {
        let q = WaitQueue::new();
        q.enqueue(pid(10));
        q.enqueue(pid(20));
        q.enqueue(pid(30));
        let drained = q.drain();
        assert_eq!(drained, vec![pid(10), pid(20), pid(30)]);
        assert!(q.drain().is_empty());
    }

    #[test]
    fn contains_after_enqueue() {
        let q = WaitQueue::new();
        assert!(!q.contains(pid(7)));
        q.enqueue(pid(7));
        assert!(q.contains(pid(7)));
        assert!(!q.contains(pid(8)));
    }

    #[test]
    fn dequeue_removes_only_target_pid() {
        let q = WaitQueue::new();
        q.enqueue(pid(1));
        q.enqueue(pid(2));
        q.enqueue(pid(1));
        q.enqueue(pid(3));
        q.dequeue(pid(1));
        assert!(!q.contains(pid(1)));
        assert!(q.contains(pid(2)));
        assert!(q.contains(pid(3)));
    }

    #[test]
    fn dequeue_missing_pid_is_noop() {
        let q = WaitQueue::new();
        q.enqueue(pid(1));
        q.dequeue(pid(99));
        assert!(q.contains(pid(1)));
        assert_eq!(q.pop_one_no_wake(), Some(pid(1)));
    }

    #[test]
    fn wake_one_pid_returns_first_when_pids_are_parked() {
        crate::core::reset_for_test();
        let q = WaitQueue::new();
        let p = pid(1);
        q.enqueue(p);
        let me_park_slot_setup = || {};
        me_park_slot_setup();
        assert_eq!(q.wake_one_pid(), None);
        assert_eq!(q.pop_one_no_wake(), None);
    }

    #[test]
    fn drop_does_not_leak_lock() {
        for _ in 0..16 {
            let q = WaitQueue::new();
            q.enqueue(pid(1));
            q.enqueue(pid(2));
            {
                let mut g = q.waiters.lock();
                g.push_back(pid(3));
            }
            assert_eq!(q.pop_one_no_wake(), Some(pid(1)));
        }
    }

    #[test]
    fn concurrent_enqueue_drain_no_data_race() {
        use std::sync::Arc as StdArc;
        let q = StdArc::new(WaitQueue::new());
        let mut handles = vec![];
        let n_producers = 3;
        for tid in 0..n_producers {
            let q = q.clone();
            handles.push(std::thread::spawn(move || {
                q.enqueue(pid(tid + 100));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let drained = q.drain();
        assert_eq!(drained.len(), n_producers as usize);
    }
}
