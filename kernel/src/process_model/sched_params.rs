#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedClass {
    Cfs,
    Rt {
        priority: u8,
        round_robin: bool,
    },
    Deadline {
        runtime_ns: u64,
        deadline_ns: u64,
        period_ns: u64,
    },
}

impl SchedClass {
    pub const fn default_cfs() -> Self {
        SchedClass::Cfs
    }

    pub fn band(self) -> u16 {
        match self {
            SchedClass::Deadline { .. } => 300,
            SchedClass::Rt { priority, .. } => 200 + priority as u16,
            SchedClass::Cfs => 0,
        }
    }
}

pub const NICE_0_LOAD: u64 = 1024;

pub const PRIO_TO_WEIGHT: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

pub fn nice_to_weight(nice: i8) -> u64 {
    let idx = (nice as i32 + 20) as usize;
    if idx < PRIO_TO_WEIGHT.len() {
        PRIO_TO_WEIGHT[idx]
    } else {
        NICE_0_LOAD
    }
}

pub use crate::sched_state::{ProcessState, SchedOwner};
