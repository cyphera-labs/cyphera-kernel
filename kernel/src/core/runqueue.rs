extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};

use crate::process_model::{Pid, SchedClass};

pub const SCHED_LATENCY_NS: u64 = 24_000_000;

pub const SCHED_MIN_GRANULARITY_NS: u64 = 3_000_000;

pub const SCHED_WAKEUP_VRUNTIME_THRESH_NS: u64 = SCHED_LATENCY_NS / 2;

pub const RT_PRIO_COUNT: usize = 99;
pub const RT_PRIO_MIN: u8 = 1;
pub const RT_PRIO_MAX: u8 = 99;

pub const DL_BW_SCALE: u64 = 1_000_000;
pub const DL_BW_MAX: u64 = 950_000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CfsPlace {
    New,
    Wake,
    Continuing,
}

#[derive(Copy, Clone, Debug)]
pub struct EnqueueData {
    pub class: SchedClass,
    pub vruntime: u64,
    pub weight: u64,
    pub dl_deadline: u64,
}

pub struct RunQueues {
    cfs: BTreeMap<(u64, u32), u64>,
    cfs_min_vruntime: u64,
    cfs_load: u64,
    rt: [VecDeque<Pid>; RT_PRIO_COUNT],
    rt_count: usize,
    deadline: BTreeMap<(u64, u32), ()>,
    dl_total_bw: u64,
}

impl RunQueues {
    pub const fn new() -> Self {
        const EMPTY_BAND: VecDeque<Pid> = VecDeque::new();
        Self {
            cfs: BTreeMap::new(),
            cfs_min_vruntime: 0,
            cfs_load: 0,
            rt: [EMPTY_BAND; RT_PRIO_COUNT],
            rt_count: 0,
            deadline: BTreeMap::new(),
            dl_total_bw: 0,
        }
    }

    fn enqueue_cfs(&mut self, pid: Pid, vruntime: u64, weight: u64, kind: CfsPlace) -> u64 {
        let placed = match kind {
            CfsPlace::New => vruntime.max(self.cfs_min_vruntime),
            CfsPlace::Wake => vruntime.max(
                self.cfs_min_vruntime
                    .saturating_sub(SCHED_WAKEUP_VRUNTIME_THRESH_NS),
            ),
            CfsPlace::Continuing => vruntime,
        };
        let prev = self.cfs.insert((placed, pid.raw()), weight);
        self.cfs_load = self
            .cfs_load
            .saturating_add(weight)
            .saturating_sub(prev.unwrap_or(0));
        if let Some((&(left, _), _)) = self.cfs.iter().next() {
            if left > self.cfs_min_vruntime {
                self.cfs_min_vruntime = left;
            }
        }
        placed
    }

    pub fn cfs_slice_for(&self, weight: u64) -> u64 {
        let total = self.cfs_load.saturating_add(weight);
        if total == 0 {
            return SCHED_LATENCY_NS;
        }
        let raw = SCHED_LATENCY_NS.saturating_mul(weight) / total;
        raw.max(SCHED_MIN_GRANULARITY_NS)
    }

    fn enqueue_rt(&mut self, pid: Pid, priority: u8) {
        let p = priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX);
        self.rt[(p - 1) as usize].push_back(pid);
        self.rt_count += 1;
    }

    pub fn rt_top_priority(&self) -> Option<u8> {
        if self.rt_count == 0 {
            return None;
        }
        for (i, band) in self.rt.iter().enumerate().rev() {
            if !band.is_empty() {
                return Some((i + 1) as u8);
            }
        }
        None
    }

    fn enqueue_deadline(&mut self, pid: Pid, absolute_deadline: u64) {
        self.deadline.insert((absolute_deadline, pid.raw()), ());
    }

    pub fn admit_dl_bandwidth(&mut self, runtime_ns: u64, period_ns: u64) -> bool {
        if period_ns == 0 || runtime_ns > period_ns {
            return false;
        }
        let bw = runtime_ns.saturating_mul(DL_BW_SCALE) / period_ns;
        if self.dl_total_bw.saturating_add(bw) > DL_BW_MAX {
            return false;
        }
        self.dl_total_bw = self.dl_total_bw.saturating_add(bw);
        true
    }

    pub fn release_dl_bandwidth(&mut self, runtime_ns: u64, period_ns: u64) {
        if period_ns == 0 {
            return;
        }
        let bw = runtime_ns.saturating_mul(DL_BW_SCALE) / period_ns;
        self.dl_total_bw = self.dl_total_bw.saturating_sub(bw);
    }

    pub fn enqueue(&mut self, pid: Pid, data: EnqueueData, kind: CfsPlace) -> u64 {
        match data.class {
            SchedClass::Cfs => self.enqueue_cfs(pid, data.vruntime, data.weight, kind),
            SchedClass::Rt { priority, .. } => {
                self.enqueue_rt(pid, priority);
                data.vruntime
            }
            SchedClass::Deadline { .. } => {
                self.enqueue_deadline(pid, data.dl_deadline);
                data.vruntime
            }
        }
    }

    pub fn pick_next(&mut self, rt_ok: bool) -> Option<Pid> {
        if rt_ok {
            if let Some(((_dl, raw), _)) = self.deadline.pop_first() {
                let pid = Pid::from_raw(raw);
                return Some(pid);
            }
            if self.rt_count > 0 {
                for band in self.rt.iter_mut().rev() {
                    if let Some(p) = band.pop_front() {
                        self.rt_count -= 1;
                        return Some(p);
                    }
                }
            }
        }
        self.cfs.pop_first().map(|((vr, raw), w)| {
            self.cfs_load = self.cfs_load.saturating_sub(w);
            if let Some((&(new_left, _), _)) = self.cfs.iter().next() {
                if new_left > self.cfs_min_vruntime {
                    self.cfs_min_vruntime = new_left;
                }
            } else {
                self.cfs_min_vruntime = self.cfs_min_vruntime.max(vr);
            }
            Pid::from_raw(raw)
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rt_count == 0 && self.deadline.is_empty() && self.cfs.is_empty()
    }

    pub fn contains_pid(&self, target: Pid) -> bool {
        let raw = target.raw();
        if self.cfs.iter().any(|(&(_, p), _)| p == raw) {
            return true;
        }
        if self.deadline.iter().any(|(&(_, p), _)| p == raw) {
            return true;
        }
        if self.rt_count > 0 {
            for band in self.rt.iter() {
                if band.iter().any(|p| *p == target) {
                    return true;
                }
            }
        }
        false
    }

    pub fn remove_pid(&mut self, target: Pid) -> (usize, usize, usize) {
        let mut rt_removed = 0usize;
        for band in self.rt.iter_mut() {
            let before = band.len();
            band.retain(|p| *p != target);
            let diff = before - band.len();
            self.rt_count -= diff;
            rt_removed += diff;
        }
        let raw = target.raw();
        let dl_key = self
            .deadline
            .iter()
            .find_map(|(&k, _)| if k.1 == raw { Some(k) } else { None });
        let dl_removed = if let Some(k) = dl_key {
            self.deadline.remove(&k);
            1
        } else {
            0
        };
        let key = self
            .cfs
            .iter()
            .find_map(|(&k, _)| if k.1 == raw { Some(k) } else { None });
        let cfs_removed = if let Some(k) = key {
            if let Some(w) = self.cfs.remove(&k) {
                self.cfs_load = self.cfs_load.saturating_sub(w);
            }
            1
        } else {
            0
        };
        (rt_removed, dl_removed, cfs_removed)
    }

    #[allow(dead_code)]
    pub fn cfs_leftmost_vruntime(&self) -> u64 {
        self.cfs
            .iter()
            .next()
            .map(|(&(v, _), _)| v)
            .unwrap_or(self.cfs_min_vruntime)
    }

    pub fn cfs_min_vruntime(&self) -> u64 {
        self.cfs_min_vruntime
    }

    pub fn cfs_leftmost_vruntime_pub(&self) -> u64 {
        self.cfs
            .iter()
            .next()
            .map(|(&(v, _), _)| v)
            .unwrap_or(self.cfs_min_vruntime)
    }

    #[cfg(host_test)]
    pub fn cfs_len(&self) -> usize {
        self.cfs.len()
    }

    #[cfg(host_test)]
    pub fn cfs_load(&self) -> u64 {
        self.cfs_load
    }

    #[cfg(host_test)]
    pub fn rt_count(&self) -> usize {
        self.rt_count
    }

    #[cfg(host_test)]
    pub fn rt_band_len(&self, priority: u8) -> usize {
        let p = priority.clamp(RT_PRIO_MIN, RT_PRIO_MAX);
        self.rt[(p - 1) as usize].len()
    }

    #[cfg(host_test)]
    pub fn deadline_len(&self) -> usize {
        self.deadline.len()
    }

    #[cfg(host_test)]
    pub fn dl_total_bw(&self) -> u64 {
        self.dl_total_bw
    }
}

impl Default for RunQueues {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(host_test)]
#[cfg(test)]
mod host_tests {
    use super::*;
    use crate::process_model::{Pid, SchedClass};

    fn cfs_data(vruntime: u64, weight: u64) -> EnqueueData {
        EnqueueData {
            class: SchedClass::Cfs,
            vruntime,
            weight,
            dl_deadline: 0,
        }
    }

    fn rt_data(priority: u8, round_robin: bool) -> EnqueueData {
        EnqueueData {
            class: SchedClass::Rt {
                priority,
                round_robin,
            },
            vruntime: 0,
            weight: 0,
            dl_deadline: 0,
        }
    }

    fn dl_data(absolute_deadline: u64, runtime_ns: u64, period_ns: u64) -> EnqueueData {
        EnqueueData {
            class: SchedClass::Deadline {
                runtime_ns,
                deadline_ns: absolute_deadline,
                period_ns,
            },
            vruntime: 0,
            weight: 0,
            dl_deadline: absolute_deadline,
        }
    }

    #[test]
    fn new_runqueue_is_empty() {
        let rq = RunQueues::new();
        assert!(rq.is_empty());
        assert_eq!(rq.cfs_len(), 0);
        assert_eq!(rq.rt_count(), 0);
        assert_eq!(rq.deadline_len(), 0);
        assert_eq!(rq.cfs_load(), 0);
        assert_eq!(rq.dl_total_bw(), 0);
        assert_eq!(rq.rt_top_priority(), None);
    }

    #[test]
    fn pick_next_on_empty_returns_none() {
        let mut rq = RunQueues::new();
        assert_eq!(rq.pick_next(true), None);
        assert_eq!(rq.pick_next(false), None);
    }

    #[test]
    fn cfs_enqueue_new_clamps_to_min_vruntime() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), cfs_data(100, 1024), CfsPlace::Continuing);
        rq.pick_next(true);
        assert_eq!(rq.cfs_min_vruntime(), 100);
        let placed = rq.enqueue(Pid::from_raw(2), cfs_data(0, 1024), CfsPlace::New);
        assert_eq!(placed, 100);
    }

    #[test]
    fn cfs_enqueue_continuing_keeps_input_vruntime() {
        let mut rq = RunQueues::new();
        let placed = rq.enqueue(Pid::from_raw(1), cfs_data(50, 1024), CfsPlace::Continuing);
        assert_eq!(placed, 50);
    }

    #[test]
    fn cfs_enqueue_wake_clamps_to_min_vruntime_minus_thresh() {
        let mut rq = RunQueues::new();
        rq.enqueue(
            Pid::from_raw(1),
            cfs_data(SCHED_WAKEUP_VRUNTIME_THRESH_NS * 4, 1024),
            CfsPlace::Continuing,
        );
        rq.pick_next(true);
        let floor = rq.cfs_min_vruntime();
        let placed = rq.enqueue(Pid::from_raw(2), cfs_data(0, 1024), CfsPlace::Wake);
        assert_eq!(
            placed,
            floor.saturating_sub(SCHED_WAKEUP_VRUNTIME_THRESH_NS)
        );
    }

    #[test]
    fn cfs_pick_next_returns_smallest_vruntime() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(10), cfs_data(500, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(20), cfs_data(100, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(30), cfs_data(300, 1024), CfsPlace::Continuing);
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(20)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(30)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(10)));
    }

    #[test]
    fn cfs_pid_breaks_vruntime_ties_deterministically() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(99), cfs_data(100, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(7), cfs_data(100, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(50), cfs_data(100, 1024), CfsPlace::Continuing);
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(7)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(50)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(99)));
    }

    #[test]
    fn cfs_load_tracks_sum_of_enqueued_weights() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), cfs_data(0, 1024), CfsPlace::Continuing);
        assert_eq!(rq.cfs_load(), 1024);
        rq.enqueue(Pid::from_raw(2), cfs_data(0, 512), CfsPlace::Continuing);
        assert_eq!(rq.cfs_load(), 1024 + 512);
        rq.enqueue(Pid::from_raw(3), cfs_data(0, 2048), CfsPlace::Continuing);
        assert_eq!(rq.cfs_load(), 1024 + 512 + 2048);
        rq.pick_next(true);
        let pre = rq.cfs_load();
        let picked = rq.pick_next(true);
        assert!(picked.is_some());
        assert!(rq.cfs_load() < pre || pre == 0);
    }

    #[test]
    fn cfs_slice_with_no_runnables_returns_full_latency() {
        let rq = RunQueues::new();
        assert_eq!(rq.cfs_slice_for(0), SCHED_LATENCY_NS);
    }

    #[test]
    fn cfs_slice_clamps_below_to_min_granularity() {
        let mut rq = RunQueues::new();
        for pid in 1..200u32 {
            rq.enqueue(Pid::from_raw(pid), cfs_data(0, 1024), CfsPlace::Continuing);
        }
        let slice = rq.cfs_slice_for(1024);
        assert!(slice >= SCHED_MIN_GRANULARITY_NS);
    }

    #[test]
    fn cfs_min_vruntime_is_monotonic_under_pick() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), cfs_data(100, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(2), cfs_data(300, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(3), cfs_data(500, 1024), CfsPlace::Continuing);
        let mut prev = rq.cfs_min_vruntime();
        for _ in 0..3 {
            rq.pick_next(true);
            let now = rq.cfs_min_vruntime();
            assert!(
                now >= prev,
                "cfs_min_vruntime went backward: {prev} -> {now}"
            );
            prev = now;
        }
    }

    #[test]
    fn rt_enqueue_clamps_priority_into_range() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), rt_data(0, false), CfsPlace::New);
        assert_eq!(rq.rt_band_len(RT_PRIO_MIN), 1);
        rq.enqueue(Pid::from_raw(2), rt_data(200, false), CfsPlace::New);
        assert_eq!(rq.rt_band_len(RT_PRIO_MAX), 1);
    }

    #[test]
    fn rt_top_priority_picks_highest_non_empty_band() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), rt_data(10, false), CfsPlace::New);
        rq.enqueue(Pid::from_raw(2), rt_data(50, false), CfsPlace::New);
        rq.enqueue(Pid::from_raw(3), rt_data(30, false), CfsPlace::New);
        assert_eq!(rq.rt_top_priority(), Some(50));
    }

    #[test]
    fn rt_pick_next_is_fifo_within_band() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(7), rt_data(50, false), CfsPlace::New);
        rq.enqueue(Pid::from_raw(2), rt_data(50, false), CfsPlace::New);
        rq.enqueue(Pid::from_raw(99), rt_data(50, false), CfsPlace::New);
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(7)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(2)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(99)));
    }

    #[test]
    fn rt_pick_next_walks_bands_high_to_low() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(10), rt_data(10, false), CfsPlace::New);
        rq.enqueue(Pid::from_raw(50), rt_data(50, false), CfsPlace::New);
        rq.enqueue(Pid::from_raw(99), rt_data(99, false), CfsPlace::New);
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(99)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(50)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(10)));
    }

    #[test]
    fn rt_count_tracks_sum_of_band_lens() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), rt_data(10, false), CfsPlace::New);
        rq.enqueue(Pid::from_raw(2), rt_data(20, false), CfsPlace::New);
        rq.enqueue(Pid::from_raw(3), rt_data(20, false), CfsPlace::New);
        assert_eq!(rq.rt_count(), 3);
        rq.pick_next(true);
        assert_eq!(rq.rt_count(), 2);
        rq.pick_next(true);
        rq.pick_next(true);
        assert_eq!(rq.rt_count(), 0);
        assert_eq!(rq.rt_top_priority(), None);
    }

    #[test]
    fn dl_admit_under_cap_succeeds() {
        let mut rq = RunQueues::new();
        assert!(rq.admit_dl_bandwidth(10_000_000, 100_000_000));
        let bw_after = rq.dl_total_bw();
        assert!(bw_after > 0);
        assert!(bw_after <= DL_BW_MAX);
    }

    #[test]
    fn dl_admit_over_cap_fails() {
        let mut rq = RunQueues::new();
        assert!(rq.admit_dl_bandwidth(95_000_000, 100_000_000));
        assert!(!rq.admit_dl_bandwidth(10_000_000, 100_000_000));
    }

    #[test]
    fn dl_admit_rejects_runtime_gt_period() {
        let mut rq = RunQueues::new();
        assert!(!rq.admit_dl_bandwidth(200_000_000, 100_000_000));
    }

    #[test]
    fn dl_admit_rejects_zero_period() {
        let mut rq = RunQueues::new();
        assert!(!rq.admit_dl_bandwidth(10_000_000, 0));
    }

    #[test]
    fn dl_release_subtracts_bandwidth() {
        let mut rq = RunQueues::new();
        rq.admit_dl_bandwidth(50_000_000, 100_000_000);
        let after_admit = rq.dl_total_bw();
        rq.release_dl_bandwidth(50_000_000, 100_000_000);
        assert!(rq.dl_total_bw() < after_admit);
    }

    #[test]
    fn dl_pick_next_is_edf() {
        let mut rq = RunQueues::new();
        rq.enqueue(
            Pid::from_raw(10),
            dl_data(2000, 0, 100_000_000),
            CfsPlace::New,
        );
        rq.enqueue(
            Pid::from_raw(20),
            dl_data(1000, 0, 100_000_000),
            CfsPlace::New,
        );
        rq.enqueue(
            Pid::from_raw(30),
            dl_data(3000, 0, 100_000_000),
            CfsPlace::New,
        );
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(20)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(10)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(30)));
    }

    #[test]
    fn pick_next_dl_beats_rt_beats_cfs() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), cfs_data(0, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(2), rt_data(50, false), CfsPlace::New);
        rq.enqueue(
            Pid::from_raw(3),
            dl_data(1000, 0, 100_000_000),
            CfsPlace::New,
        );
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(3)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(2)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(1)));
        assert_eq!(rq.pick_next(true), None);
    }

    #[test]
    fn pick_next_throttled_skips_rt_and_dl() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), cfs_data(0, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(2), rt_data(50, false), CfsPlace::New);
        rq.enqueue(
            Pid::from_raw(3),
            dl_data(1000, 0, 100_000_000),
            CfsPlace::New,
        );
        assert_eq!(rq.pick_next(false), Some(Pid::from_raw(1)));
        assert_eq!(rq.pick_next(false), None);
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(3)));
        assert_eq!(rq.pick_next(true), Some(Pid::from_raw(2)));
    }

    #[test]
    fn contains_pid_finds_across_classes() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), cfs_data(100, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(2), rt_data(50, false), CfsPlace::New);
        rq.enqueue(
            Pid::from_raw(3),
            dl_data(1000, 0, 100_000_000),
            CfsPlace::New,
        );
        assert!(rq.contains_pid(Pid::from_raw(1)));
        assert!(rq.contains_pid(Pid::from_raw(2)));
        assert!(rq.contains_pid(Pid::from_raw(3)));
        assert!(!rq.contains_pid(Pid::from_raw(99)));
    }

    #[test]
    fn remove_pid_removes_from_correct_class_only() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), cfs_data(100, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(2), rt_data(50, false), CfsPlace::New);
        let (rt, dl, cfs) = rq.remove_pid(Pid::from_raw(1));
        assert_eq!((rt, dl, cfs), (0, 0, 1));
        assert!(!rq.contains_pid(Pid::from_raw(1)));
        assert!(rq.contains_pid(Pid::from_raw(2)));
        let (rt, dl, cfs) = rq.remove_pid(Pid::from_raw(2));
        assert_eq!((rt, dl, cfs), (1, 0, 0));
        assert!(!rq.contains_pid(Pid::from_raw(2)));
    }

    #[test]
    fn remove_pid_missing_is_noop_zero_zero_zero() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), cfs_data(100, 1024), CfsPlace::Continuing);
        let (rt, dl, cfs) = rq.remove_pid(Pid::from_raw(99));
        assert_eq!((rt, dl, cfs), (0, 0, 0));
        assert!(rq.contains_pid(Pid::from_raw(1)));
    }

    #[test]
    fn remove_pid_deducts_cfs_load() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), cfs_data(100, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(2), cfs_data(200, 512), CfsPlace::Continuing);
        assert_eq!(rq.cfs_load(), 1024 + 512);
        rq.remove_pid(Pid::from_raw(1));
        assert_eq!(rq.cfs_load(), 512);
        rq.remove_pid(Pid::from_raw(2));
        assert_eq!(rq.cfs_load(), 0);
    }

    #[test]
    fn remove_pid_decrements_rt_count() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), rt_data(50, false), CfsPlace::New);
        rq.enqueue(Pid::from_raw(2), rt_data(50, false), CfsPlace::New);
        rq.enqueue(Pid::from_raw(3), rt_data(40, false), CfsPlace::New);
        assert_eq!(rq.rt_count(), 3);
        rq.remove_pid(Pid::from_raw(2));
        assert_eq!(rq.rt_count(), 2);
        rq.remove_pid(Pid::from_raw(3));
        assert_eq!(rq.rt_count(), 1);
    }

    #[test]
    fn churn_does_not_leak_cfs_load() {
        let mut rq = RunQueues::new();
        for round in 0..32 {
            for pid in 1..=10u32 {
                rq.enqueue(
                    Pid::from_raw(pid),
                    cfs_data((round * 100 + pid) as u64, 1024),
                    CfsPlace::Continuing,
                );
            }
            while rq.pick_next(true).is_some() {}
        }
        assert_eq!(rq.cfs_load(), 0);
        assert_eq!(rq.cfs_len(), 0);
    }

    #[test]
    fn churn_does_not_leak_rt_count() {
        let mut rq = RunQueues::new();
        for round in 0..16 {
            for prio in (1..=99u8).step_by(7) {
                rq.enqueue(
                    Pid::from_raw(round * 100 + prio as u32 + 1),
                    rt_data(prio, false),
                    CfsPlace::New,
                );
            }
            while rq.pick_next(true).is_some() {}
        }
        assert_eq!(rq.rt_count(), 0);
        assert_eq!(rq.rt_top_priority(), None);
    }

    #[test]
    fn remove_then_pick_is_consistent() {
        let mut rq = RunQueues::new();
        rq.enqueue(Pid::from_raw(1), cfs_data(100, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(2), cfs_data(200, 1024), CfsPlace::Continuing);
        rq.enqueue(Pid::from_raw(3), cfs_data(300, 1024), CfsPlace::Continuing);
        rq.remove_pid(Pid::from_raw(2));
        let p1 = rq.pick_next(true);
        let p2 = rq.pick_next(true);
        let p3 = rq.pick_next(true);
        assert_ne!(p1, Some(Pid::from_raw(2)));
        assert_ne!(p2, Some(Pid::from_raw(2)));
        assert_eq!(p3, None);
    }

    #[test]
    fn drop_with_outstanding_entries_does_not_leak() {
        let mut rq = RunQueues::new();
        for i in 1..50u32 {
            rq.enqueue(
                Pid::from_raw(i),
                cfs_data(i as u64 * 10, 1024),
                CfsPlace::Continuing,
            );
        }
        for i in 50..70u32 {
            rq.enqueue(
                Pid::from_raw(i),
                rt_data((i % 99 + 1) as u8, false),
                CfsPlace::New,
            );
        }
        for i in 70..90u32 {
            rq.enqueue(
                Pid::from_raw(i),
                dl_data(i as u64 * 1000, 0, 100_000_000),
                CfsPlace::New,
            );
        }
        drop(rq);
    }
}
