use super::{GLOBAL, current_pid};
use crate::process_model::Pid;

pub struct CpuAccounting {
    pub utime_ns: u64,
    pub stime_ns: u64,
    pub cutime_ns: u64,
    pub cstime_ns: u64,
    pub minflt: u64,
    pub majflt: u64,
}

pub fn cpu_accounting(pid: Pid) -> Option<CpuAccounting> {
    GLOBAL.lock().processes.get(&pid).map(|p| CpuAccounting {
        utime_ns: p.cpu_times.total_utime_ns,
        stime_ns: p.cpu_times.total_stime_ns,
        cutime_ns: p.cpu_times.cutime_ns,
        cstime_ns: p.cpu_times.cstime_ns,
        minflt: p.memory.minflt(),
        majflt: p.memory.majflt(),
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
            p.cpu_times
                .total_utime_ns
                .saturating_add(p.cpu_times.total_stime_ns)
                .saturating_add(now.saturating_sub(p.sched.last_run_ns))
        })
        .unwrap_or(0)
}
