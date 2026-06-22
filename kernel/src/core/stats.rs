use super::*;

const DEFAULT_RT_PERIOD_NS: u64 = 1_000_000_000;
const DEFAULT_RT_RUNTIME_NS: u64 = 950_000_000;

static RT_PERIOD_NS: AtomicU64 = AtomicU64::new(DEFAULT_RT_PERIOD_NS);
static RT_RUNTIME_NS: AtomicU64 = AtomicU64::new(DEFAULT_RT_RUNTIME_NS);
static RT_PERIOD_START_NS: AtomicU64 = AtomicU64::new(0);
static RT_RUNTIME_CONSUMED_NS: AtomicU64 = AtomicU64::new(0);
static RT_THROTTLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn rt_throttled() -> bool {
    RT_THROTTLED.load(Ordering::Relaxed)
}

pub(crate) fn charge_rt_runtime(delta_ns: u64) {
    let runtime_cap = RT_RUNTIME_NS.load(Ordering::Relaxed);
    if runtime_cap == u64::MAX {
        return;
    }
    let period = RT_PERIOD_NS.load(Ordering::Relaxed);
    let now = frame::cpu::clock::nanos_since_boot();
    let start = RT_PERIOD_START_NS.load(Ordering::Relaxed);
    if start == 0 || now.saturating_sub(start) >= period {
        RT_PERIOD_START_NS.store(now, Ordering::Relaxed);
        RT_RUNTIME_CONSUMED_NS.store(0, Ordering::Relaxed);
        RT_THROTTLED.store(false, Ordering::Relaxed);
    }
    let consumed = RT_RUNTIME_CONSUMED_NS.fetch_add(delta_ns, Ordering::Relaxed) + delta_ns;
    if consumed >= runtime_cap {
        RT_THROTTLED.store(true, Ordering::Relaxed);
    }
}

pub(crate) fn rt_bandwidth_tick() {
    let period = RT_PERIOD_NS.load(Ordering::Relaxed);
    let now = frame::cpu::clock::nanos_since_boot();
    let start = RT_PERIOD_START_NS.load(Ordering::Relaxed);
    if start != 0 && now.saturating_sub(start) >= period {
        RT_PERIOD_START_NS.store(now, Ordering::Relaxed);
        RT_RUNTIME_CONSUMED_NS.store(0, Ordering::Relaxed);
        RT_THROTTLED.store(false, Ordering::Relaxed);
    }
}

pub fn rt_bandwidth_cfg() -> (u64, u64) {
    (
        RT_PERIOD_NS.load(Ordering::Relaxed),
        RT_RUNTIME_NS.load(Ordering::Relaxed),
    )
}

pub fn set_rt_period_ns(period_ns: u64) -> bool {
    if period_ns == 0 {
        return false;
    }
    RT_PERIOD_NS.store(period_ns, Ordering::Relaxed);
    RT_PERIOD_START_NS.store(0, Ordering::Relaxed);
    RT_RUNTIME_CONSUMED_NS.store(0, Ordering::Relaxed);
    RT_THROTTLED.store(false, Ordering::Relaxed);
    true
}

pub fn set_rt_runtime_ns(runtime_ns: u64) {
    RT_RUNTIME_NS.store(runtime_ns, Ordering::Relaxed);
    RT_PERIOD_START_NS.store(0, Ordering::Relaxed);
    RT_RUNTIME_CONSUMED_NS.store(0, Ordering::Relaxed);
    RT_THROTTLED.store(false, Ordering::Relaxed);
}

#[derive(Default)]
pub struct CpuStat {
    pub user_jiffies: AtomicU64,
    pub nice_jiffies: AtomicU64,
    pub system_jiffies: AtomicU64,
    pub idle_jiffies: AtomicU64,
}

impl CpuStat {
    pub const fn new() -> Self {
        Self {
            user_jiffies: AtomicU64::new(0),
            nice_jiffies: AtomicU64::new(0),
            system_jiffies: AtomicU64::new(0),
            idle_jiffies: AtomicU64::new(0),
        }
    }
}

pub static CPU_STATS: [CpuStat; MAX_CPUS] = [const { CpuStat::new() }; MAX_CPUS];
pub static CTXT_SWITCHES: AtomicU64 = AtomicU64::new(0);

pub static INTR_COUNT: AtomicU64 = AtomicU64::new(0);

pub(crate) fn account_tick_jiffy() {
    let cpu = this_cpu() as usize;
    if cpu >= MAX_CPUS {
        return;
    }
    INTR_COUNT.fetch_add(1, Ordering::Relaxed);
    let cur = CPU_QUEUES[cpu].lock().current;
    let bucket = match cur {
        None => &CPU_STATS[cpu].idle_jiffies,
        Some(pid) => {
            let g = GLOBAL.lock();
            let (in_syscall, nice) = g
                .processes
                .get(&pid)
                .map(|p| (p.lifecycle.in_syscall(), p.sched.nice))
                .unwrap_or((false, 0));
            if in_syscall {
                &CPU_STATS[cpu].system_jiffies
            } else if nice > 0 {
                &CPU_STATS[cpu].nice_jiffies
            } else {
                &CPU_STATS[cpu].user_jiffies
            }
        }
    };
    bucket.fetch_add(1, Ordering::Relaxed);
}

pub fn jiffies_summary() -> (u64, u64, u64, u64) {
    let mut user = 0;
    let mut nice = 0;
    let mut system = 0;
    let mut idle = 0;
    for stats in CPU_STATS.iter() {
        user += stats.user_jiffies.load(Ordering::Relaxed);
        nice += stats.nice_jiffies.load(Ordering::Relaxed);
        system += stats.system_jiffies.load(Ordering::Relaxed);
        idle += stats.idle_jiffies.load(Ordering::Relaxed);
    }
    (user, nice, system, idle)
}

pub fn jiffies_for_cpu(cpu: usize) -> Option<(u64, u64, u64, u64)> {
    if cpu >= MAX_CPUS {
        return None;
    }
    Some((
        CPU_STATS[cpu].user_jiffies.load(Ordering::Relaxed),
        CPU_STATS[cpu].nice_jiffies.load(Ordering::Relaxed),
        CPU_STATS[cpu].system_jiffies.load(Ordering::Relaxed),
        CPU_STATS[cpu].idle_jiffies.load(Ordering::Relaxed),
    ))
}

pub fn ctxt_switches() -> u64 {
    CTXT_SWITCHES.load(Ordering::Relaxed)
}

pub fn intr_count() -> u64 {
    INTR_COUNT.load(Ordering::Relaxed)
}

pub fn add_cgroup_charge(bytes: u64) {
    let cpu = this_cpu() as usize;
    let pid = match CPU_QUEUES[cpu].lock().current {
        Some(p) => p,
        None => return,
    };
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.cgroup_charged_bytes = p.cgroup_charged_bytes.saturating_add(bytes);
    }
}

pub fn charge_process_memory(pid: Pid, bytes: u64) {
    if bytes == 0 {
        return;
    }
    let cg = {
        let g = GLOBAL.lock();
        match g.processes.get(&pid) {
            Some(p) => p.cgroup.clone(),
            None => return,
        }
    };
    if let Some(cg) = &cg {
        if cg.try_charge_memory(bytes).is_err() {
            cg.oom_kill_one();
            return;
        }
    }
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.cgroup_charged_bytes = p.cgroup_charged_bytes.saturating_add(bytes);
    }
}

pub fn sub_cgroup_charge(bytes: u64) {
    let cpu = this_cpu() as usize;
    let pid = match CPU_QUEUES[cpu].lock().current {
        Some(p) => p,
        None => return,
    };
    let (cg, actual) = {
        let mut g = GLOBAL.lock();
        let p = match g.processes.get_mut(&pid) {
            Some(p) => p,
            None => return,
        };
        let actual = bytes.min(p.cgroup_charged_bytes);
        p.cgroup_charged_bytes -= actual;
        (p.cgroup.clone(), actual)
    };
    if let Some(cg) = cg {
        if actual > 0 {
            cg.uncharge_memory(actual);
        }
    }
}

const LOAD_FSHIFT: u32 = 11;
const LOAD_FIXED_1: u64 = 1 << LOAD_FSHIFT;
const LOAD_FREQ_TICKS: u64 = 500;

const EXP_1: u64 = 1884;
const EXP_5: u64 = 2014;
const EXP_15: u64 = 2037;

static LOAD_TICK_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn loadavg_tick_count() -> u64 {
    LOAD_TICK_COUNTER.load(Ordering::Relaxed)
}

pub(crate) static RESCHED_TICK_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn resched_tick_count() -> u64 {
    RESCHED_TICK_COUNTER.load(Ordering::Relaxed)
}

static LOADAVG_1: AtomicU64 = AtomicU64::new(0);
static LOADAVG_5: AtomicU64 = AtomicU64::new(0);
static LOADAVG_15: AtomicU64 = AtomicU64::new(0);

#[inline(never)]
pub(crate) fn sample_loadavg_if_due() {
    let n = LOAD_TICK_COUNTER.fetch_add(1, Ordering::Relaxed);
    if !(n + 1).is_multiple_of(LOAD_FREQ_TICKS) {
        return;
    }
    let active = {
        let g = GLOBAL.lock();
        let mut a = 0u64;
        for p in g.processes.values() {
            match p.state.0 {
                ProcessState::Running | ProcessState::Runnable => a += 1,
                _ => {}
            }
        }
        a
    };
    let active_fp = active << LOAD_FSHIFT;
    update_loadavg(&LOADAVG_1, EXP_1, active_fp);
    update_loadavg(&LOADAVG_5, EXP_5, active_fp);
    update_loadavg(&LOADAVG_15, EXP_15, active_fp);
}

fn update_loadavg(slot: &AtomicU64, decay: u64, active_fp: u64) {
    let prev = slot.load(Ordering::Relaxed);
    let next = (prev.saturating_mul(decay) + active_fp.saturating_mul(LOAD_FIXED_1 - decay))
        >> LOAD_FSHIFT;
    slot.store(next, Ordering::Relaxed);
}

pub fn last_pid() -> u32 {
    NEXT_PID.load(Ordering::Relaxed).saturating_sub(1)
}

pub fn loadavg_fp() -> (u64, u64, u64) {
    (
        LOADAVG_1.load(Ordering::Relaxed),
        LOADAVG_5.load(Ordering::Relaxed),
        LOADAVG_15.load(Ordering::Relaxed),
    )
}

pub fn loadavg_for_sysinfo() -> (u64, u64, u64) {
    let (a, b, c) = loadavg_fp();
    (a << 5, b << 5, c << 5)
}

pub fn record_minor_fault() {
    let pid = match CPU_QUEUES[this_cpu() as usize].lock().current {
        Some(p) => p,
        None => return,
    };
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        p.memory.incr_minflt();
    }
}

pub fn record_major_fault() {
    let pid = match CPU_QUEUES[this_cpu() as usize].lock().current {
        Some(p) => p,
        None => return,
    };
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        p.memory.incr_majflt();
    }
}

#[inline(never)]
pub fn procs_running_blocked() -> (u64, u64) {
    let g = GLOBAL.lock();
    let mut running = 0u64;
    let mut blocked = 0u64;
    for p in g.processes.values() {
        match p.state.0 {
            ProcessState::Running | ProcessState::Runnable => running += 1,
            ProcessState::Parked => blocked += 1,
            _ => {}
        }
    }
    (running, blocked)
}

pub fn syscall_enter_account() {
    let cpu = this_cpu() as usize;
    let pid = match CPU_QUEUES[cpu].lock().current {
        Some(p) => p,
        None => return,
    };
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.lifecycle.set_in_syscall(true);
    }
}

pub fn syscall_exit_account() {
    let cpu = this_cpu() as usize;
    let pid = match CPU_QUEUES[cpu].lock().current {
        Some(p) => p,
        None => return,
    };
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.lifecycle.set_in_syscall(false);
    }
}
