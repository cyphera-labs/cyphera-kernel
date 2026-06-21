use super::GLOBAL;
use crate::process::{Pid, SchedClass};

pub fn nice(pid: Pid) -> Option<i8> {
    GLOBAL.lock().processes.get(&pid).map(|p| p.nice)
}

pub fn set_nice(pid: Pid, value: i8) {
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        p.nice = value;
        p.weight = crate::process::nice_to_weight(value);
    }
}

pub fn sched_class(pid: Pid) -> Option<SchedClass> {
    GLOBAL.lock().processes.get(&pid).map(|p| p.sched_class)
}

pub fn class_and_nice(pid: Pid) -> Option<(SchedClass, i8)> {
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| (p.sched_class, p.nice))
}

pub fn home_cpu(pid: Pid) -> Option<u32> {
    GLOBAL.lock().processes.get(&pid).map(|p| p.home_cpu)
}
