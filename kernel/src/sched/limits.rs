use super::{GLOBAL, current_pid};

pub fn current_rlimit(resource: u64) -> crate::process::Rlimit {
    let pid = current_pid();
    let g = GLOBAL.lock();
    if let Some(p) = g.processes.get(&pid) {
        if (resource as usize) < 16 {
            if let Some(r) = p.rlimits[resource as usize] {
                return r;
            }
        }
    }
    crate::syscall::default_rlimit(resource)
}

pub fn set_current_rlimit(resource: u64, r: crate::process::Rlimit) {
    if (resource as usize) >= 16 {
        return;
    }
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.rlimits[resource as usize] = Some(r);
    }
}
