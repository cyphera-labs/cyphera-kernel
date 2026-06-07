use alloc::vec::Vec;

#[cfg(host_test)]
#[allow(unused_imports)]
use frame_host as frame;

use frame::sync::SpinIrq;

use crate::process::Pid;

static DEADLINES: SpinIrq<Vec<(u64, Pid)>> = SpinIrq::new(Vec::new());

pub fn register(deadline_nanos: u64, pid: Pid) {
    let mut g = DEADLINES.lock();
    g.retain(|&(_, p)| p != pid);
    let pos = g
        .binary_search_by_key(&deadline_nanos, |&(d, _)| d)
        .unwrap_or_else(|p| p);
    g.insert(pos, (deadline_nanos, pid));
}

pub fn unregister(pid: Pid) -> bool {
    let mut g = DEADLINES.lock();
    let before = g.len();
    g.retain(|&(_, p)| p != pid);
    g.len() != before
}

pub fn next_deadline_ns() -> Option<u64> {
    DEADLINES.lock().first().map(|&(d, _)| d)
}

pub fn wake_expired(now_nanos: u64) {
    let expired: Vec<Pid> = {
        let mut g = DEADLINES.lock();
        let mut out = Vec::new();
        while let Some(&(d, _)) = g.first() {
            if d > now_nanos {
                break;
            }
            out.push(g.remove(0).1);
        }
        out
    };
    for pid in expired {
        let _ = crate::sched::wake_pid(pid);
    }
}

pub fn drop_pid(pid: Pid) {
    DEADLINES.lock().retain(|&(_, p)| p != pid);
}

use alloc::sync::Arc;

type CallbackFn = fn(u64);

#[derive(Copy, Clone)]
struct CallbackEntry {
    deadline: u64,
    key: u64,
    callback: CallbackFn,
}

static CALLBACK_DEADLINES: SpinIrq<Vec<CallbackEntry>> = SpinIrq::new(Vec::new());

pub fn register_callback(deadline_nanos: u64, key: u64, callback: CallbackFn) {
    let mut g = CALLBACK_DEADLINES.lock();
    g.retain(|e| e.key != key);
    let pos = g
        .binary_search_by_key(&deadline_nanos, |e| e.deadline)
        .unwrap_or_else(|p| p);
    g.insert(
        pos,
        CallbackEntry {
            deadline: deadline_nanos,
            key,
            callback,
        },
    );
}

pub fn cancel_callback(key: u64) {
    CALLBACK_DEADLINES.lock().retain(|e| e.key != key);
}

pub fn wake_expired_callbacks(now_nanos: u64) {
    let expired: Vec<CallbackEntry> = {
        let mut g = CALLBACK_DEADLINES.lock();
        let mut out = Vec::new();
        while let Some(e) = g.first() {
            if e.deadline > now_nanos {
                break;
            }
            out.push(g.remove(0));
        }
        out
    };
    for e in expired {
        (e.callback)(e.key);
    }
}

#[allow(dead_code)]
fn _arc_anchor<T>(a: &Arc<T>) -> u64 {
    Arc::as_ptr(a) as *const () as u64
}

#[cfg(host_test)]
#[cfg(test)]
mod host_tests {
    use super::*;

    fn pid(raw: u32) -> Pid {
        Pid::from_raw(raw)
    }

    fn reset_globals() {
        DEADLINES.lock().clear();
        CALLBACK_DEADLINES.lock().clear();
        crate::sched::reset_for_test();
    }

    #[test]
    fn register_inserts_in_ascending_deadline_order() {
        reset_globals();
        register(300, pid(1));
        register(100, pid(2));
        register(200, pid(3));
        let g = DEADLINES.lock();
        assert_eq!(g.len(), 3);
        assert_eq!(g[0].0, 100);
        assert_eq!(g[1].0, 200);
        assert_eq!(g[2].0, 300);
    }

    #[test]
    fn register_replaces_existing_pid_entry() {
        reset_globals();
        register(500, pid(1));
        register(200, pid(1));
        let g = DEADLINES.lock();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].0, 200);
    }

    #[test]
    fn unregister_returns_true_when_present() {
        reset_globals();
        register(100, pid(1));
        assert!(unregister(pid(1)));
        assert!(!unregister(pid(1)));
    }

    #[test]
    fn unregister_returns_false_when_missing() {
        reset_globals();
        assert!(!unregister(pid(99)));
    }

    #[test]
    fn next_deadline_ns_empty_is_none() {
        reset_globals();
        assert_eq!(next_deadline_ns(), None);
    }

    #[test]
    fn next_deadline_ns_returns_earliest() {
        reset_globals();
        register(500, pid(1));
        register(100, pid(2));
        register(300, pid(3));
        assert_eq!(next_deadline_ns(), Some(100));
    }

    #[test]
    fn wake_expired_drains_only_past_deadlines() {
        reset_globals();
        register(100, pid(1));
        register(200, pid(2));
        register(300, pid(3));
        wake_expired(200);
        let remaining = DEADLINES.lock();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, 300);
    }

    #[test]
    fn wake_expired_with_now_zero_is_noop() {
        reset_globals();
        register(100, pid(1));
        register(200, pid(2));
        wake_expired(0);
        assert_eq!(DEADLINES.lock().len(), 2);
    }

    #[test]
    fn wake_expired_with_huge_now_drains_all() {
        reset_globals();
        for i in 1..=10 {
            register(i * 100, pid(i as u32));
        }
        wake_expired(u64::MAX);
        assert!(DEADLINES.lock().is_empty());
    }

    #[test]
    fn drop_pid_removes_all_entries_for_pid() {
        reset_globals();
        register(100, pid(1));
        register(200, pid(2));
        drop_pid(pid(1));
        let g = DEADLINES.lock();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].1, pid(2));
    }

    #[test]
    fn callback_register_and_cancel() {
        reset_globals();
        fn dummy(_: u64) {}
        register_callback(100, 0xaa, dummy);
        register_callback(200, 0xbb, dummy);
        assert_eq!(CALLBACK_DEADLINES.lock().len(), 2);
        cancel_callback(0xaa);
        let g = CALLBACK_DEADLINES.lock();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].key, 0xbb);
    }

    #[test]
    fn callback_fire_invokes_with_key() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static FIRED_WITH_KEY: AtomicU64 = AtomicU64::new(0);
        fn record(k: u64) {
            FIRED_WITH_KEY.store(k, Ordering::SeqCst);
        }
        reset_globals();
        FIRED_WITH_KEY.store(0, Ordering::SeqCst);
        register_callback(100, 0xc0ffee, record);
        wake_expired_callbacks(200);
        assert_eq!(FIRED_WITH_KEY.load(Ordering::SeqCst), 0xc0ffee);
        assert!(CALLBACK_DEADLINES.lock().is_empty());
    }

    #[test]
    fn concurrent_register_and_wake_no_data_race() {
        reset_globals();
        let producers: Vec<_> = (0..3)
            .map(|i| {
                std::thread::spawn(move || {
                    register(100 + i * 10, pid(100 + i as u32));
                    register(500 + i * 10, pid(200 + i as u32));
                })
            })
            .collect();
        for _ in 0..4 {
            wake_expired(150);
            std::thread::yield_now();
        }
        for h in producers {
            h.join().unwrap();
        }
        wake_expired(u64::MAX);
        assert!(DEADLINES.lock().is_empty());
    }
}
