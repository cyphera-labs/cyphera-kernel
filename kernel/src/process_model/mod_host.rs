pub use cyphera_kapi::Pid;

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
