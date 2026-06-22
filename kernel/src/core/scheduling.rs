use super::GLOBAL;
use crate::process_model::{Pid, SchedClass};

pub fn nice(pid: Pid) -> Option<i8> {
    GLOBAL.lock().processes.get(&pid).map(|p| p.sched.nice)
}

pub fn set_nice(pid: Pid, value: i8) {
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        p.sched.nice = value;
        p.sched.weight = crate::process_model::nice_to_weight(value);
    }
}

pub fn sched_class(pid: Pid) -> Option<SchedClass> {
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.sched.sched_class)
}

pub fn class_and_nice(pid: Pid) -> Option<(SchedClass, i8)> {
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| (p.sched.sched_class, p.sched.nice))
}

pub fn home_cpu(pid: Pid) -> Option<u32> {
    GLOBAL.lock().processes.get(&pid).map(|p| p.sched.home_cpu)
}
