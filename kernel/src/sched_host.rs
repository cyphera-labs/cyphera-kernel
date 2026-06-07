extern crate alloc;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;

use crate::process::Pid;
use crate::wait::WaitQueue;

static NEXT_PID: AtomicU32 = AtomicU32::new(1);

fn pid_table() -> &'static Mutex<HashMap<ThreadId, u32>> {
    static TABLE: OnceLock<Mutex<HashMap<ThreadId, u32>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

struct ParkSlot {
    parked: AtomicBool,
}

fn park_table() -> &'static Mutex<HashMap<u32, alloc::sync::Arc<ParkSlot>>> {
    static TABLE: OnceLock<Mutex<HashMap<u32, alloc::sync::Arc<ParkSlot>>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn slot_for(pid: Pid) -> alloc::sync::Arc<ParkSlot> {
    let mut g = park_table().lock().unwrap();
    g.entry(pid.raw())
        .or_insert_with(|| {
            alloc::sync::Arc::new(ParkSlot {
                parked: AtomicBool::new(false),
            })
        })
        .clone()
}

pub fn current_pid() -> Pid {
    let tid = std::thread::current().id();
    let mut g = pid_table().lock().unwrap();
    let raw = *g
        .entry(tid)
        .or_insert_with(|| NEXT_PID.fetch_add(1, Ordering::Relaxed));
    Pid::from_raw(raw)
}

pub fn current_local_pid() -> u32 {
    current_pid().raw()
}

pub fn wake_pid(pid: Pid) -> bool {
    let slot = slot_for(pid);
    slot.parked
        .compare_exchange(true, false, Ordering::Release, Ordering::Acquire)
        .is_ok()
}

pub fn park_on(wq: &WaitQueue) {
    let me = current_pid();
    let slot = slot_for(me);
    slot.parked.store(true, Ordering::Release);
    wq.enqueue(me);
    spin_until_unparked(&slot);
    wq.dequeue(me);
}

#[allow(dead_code)]
pub fn park_on_pre_enqueued(wq: &WaitQueue) {
    let _ = wq;
    let me = current_pid();
    let slot = slot_for(me);
    slot.parked.store(true, Ordering::Release);
    spin_until_unparked(&slot);
}

pub fn park_self() {
    let me = current_pid();
    let slot = slot_for(me);
    slot.parked.store(true, Ordering::Release);
    spin_until_unparked(&slot);
}

pub fn park_self_at(_site: &str) {
    let me = current_pid();
    let slot = slot_for(me);
    slot.parked.store(true, Ordering::Release);
    spin_until_unparked(&slot);
}

pub fn park_self_at_guarded(_site: &str, still_queued: &dyn Fn() -> bool) {
    if !still_queued() {
        return;
    }
    let me = current_pid();
    let slot = slot_for(me);
    slot.parked.store(true, Ordering::Release);
    spin_until_unparked(&slot);
}

fn spin_until_unparked(slot: &ParkSlot) {
    let mut spins: u32 = 0;
    while slot.parked.load(Ordering::Acquire) {
        std::hint::spin_loop();
        spins = spins.saturating_add(1);
        if spins > 64 {
            std::thread::yield_now();
            if spins > 4_000_000 {
                slot.parked.store(false, Ordering::Release);
                return;
            }
        }
    }
}

pub fn current_signal_pending() -> bool {
    false
}

#[allow(dead_code)]
pub fn reset_for_test() {
    park_table().lock().unwrap().clear();
    pid_table().lock().unwrap().clear();
    NEXT_PID.store(1, Ordering::Relaxed);
}

#[allow(dead_code)]
pub fn is_parked(pid: Pid) -> bool {
    slot_for(pid).parked.load(Ordering::Acquire)
}
