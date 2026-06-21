use super::{GLOBAL, current_pid};
use crate::process::Pid;

pub struct CpuAccounting {
    pub utime_ns: u64,
    pub stime_ns: u64,
    pub cutime_ns: u64,
    pub cstime_ns: u64,
}

pub fn cpu_accounting(pid: Pid) -> Option<CpuAccounting> {
    GLOBAL.lock().processes.get(&pid).map(|p| CpuAccounting {
        utime_ns: p.total_utime_ns,
        stime_ns: p.total_stime_ns,
        cutime_ns: p.cutime_ns,
        cstime_ns: p.cstime_ns,
    })
}

pub fn current_cputime_nanos() -> u64 {
    let pid = current_pid();
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| {
            let now = frame::cpu::clock::nanos_since_boot();
            p.total_utime_ns
                .saturating_add(p.total_stime_ns)
                .saturating_add(now.saturating_sub(p.last_run_ns))
        })
        .unwrap_or(0)
}
