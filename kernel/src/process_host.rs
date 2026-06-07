#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pid(pub u32);

impl Pid {
    pub fn raw(self) -> u32 {
        self.0
    }

    pub const fn from_raw(raw: u32) -> Self {
        Pid(raw)
    }
}

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
