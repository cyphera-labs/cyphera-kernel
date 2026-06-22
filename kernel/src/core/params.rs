pub use super::scheduling::set_nice;
pub use super::{
    set_cpu_affinity as set_affinity, set_deadline_class as set_deadline,
    set_sched_class as set_class,
};
