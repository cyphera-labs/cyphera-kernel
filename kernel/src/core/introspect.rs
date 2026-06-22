use super::*;

pub fn signal_pgrp(pgid: Pid, signal: u32) -> usize {
    let targets: alloc::vec::Vec<Pid> = {
        let g = GLOBAL.lock();
        g.processes
            .iter()
            .filter(|(_, p)| p.identity.pgid() == pgid)
            .map(|(pid, _)| *pid)
            .collect()
    };
    let mut count = 0;
    for pid in targets {
        if send_signal(pid, signal).is_ok() {
            count += 1;
        }
    }
    count
}

pub fn current_parent_pid() -> u32 {
    let pid = current_pid();
    let g = GLOBAL.lock();
    g.processes
        .get(&pid)
        .and_then(|p| p.parent)
        .map(|pp| pp.0)
        .unwrap_or(0)
}

pub fn all_pids() -> Vec<Pid> {
    GLOBAL.lock().processes.keys().copied().collect()
}

pub struct ProcessSummary {
    pub pid: Pid,
    pub state_char: char,
    pub parent_pid: u32,
    pub brk_bytes: u64,
    pub pgrp: u32,
    pub session: u32,
    pub utime_clk: u64,
    pub stime_clk: u64,
    pub priority: i32,
    pub nice: i8,
    pub num_threads: u32,
    pub vsize: u64,
    pub rss_pages: u64,
    pub minflt: u64,
    pub majflt: u64,
    pub cutime_clk: u64,
    pub cstime_clk: u64,
    pub policy: u32,
    pub rt_priority: u32,
    pub processor: u32,
}

pub fn process_name(pid: Pid) -> [u8; 16] {
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.name)
        .unwrap_or([0u8; 16])
}

pub fn process_summary(pid: Pid) -> Option<ProcessSummary> {
    let g = GLOBAL.lock();
    let proc = g.processes.get(&pid)?;
    let state_char = match proc.state.0 {
        ProcessState::Running | ProcessState::Runnable => 'R',
        ProcessState::Parked => 'S',
        ProcessState::Zombie(_) => 'Z',
        ProcessState::KilledByFault { .. } => 'X',
        ProcessState::KilledBySignal { .. } => 'X',
        ProcessState::Stopped => 'T',
        ProcessState::Traced => 't',
        ProcessState::DlThrottled => 'D',
        ProcessState::CgroupThrottled => 'D',
    };
    let (priority, rt_priority, policy_num) = match proc.sched.sched_class {
        SchedClass::Cfs => (20 + proc.sched.nice as i32, 0u32, 0u32),
        SchedClass::Rt {
            priority: rt_p,
            round_robin,
        } => (
            -1 - (rt_p as i32),
            rt_p as u32,
            if round_robin { 2 } else { 1 },
        ),
        SchedClass::Deadline { .. } => (-1, 0u32, 6u32),
    };
    let (vsize, brk_cur, brk_start): (u64, u64, u64) = match proc.addr_space.as_ref() {
        Some(a) => {
            let vsize = a.mmap.lock().vmas.iter().map(|v| v.end - v.start).sum();
            let b = *a.brk.lock();
            (vsize, b.current, b.start)
        }
        None => (0, 0, 0),
    };
    let rss_pages = vsize / 4096;
    Some(ProcessSummary {
        pid,
        state_char,
        parent_pid: proc.parent.map(|p| p.0).unwrap_or(0),
        brk_bytes: brk_cur.saturating_sub(brk_start),
        pgrp: proc.identity.pgid().0,
        session: proc.identity.sid().0,
        utime_clk: proc.cpu_times.total_utime_ns / 10_000_000,
        stime_clk: proc.cpu_times.total_stime_ns / 10_000_000,
        minflt: proc.memory.minflt(),
        majflt: proc.memory.majflt(),
        cutime_clk: proc.cpu_times.cutime_ns / 10_000_000,
        cstime_clk: proc.cpu_times.cstime_ns / 10_000_000,
        priority,
        nice: proc.sched.nice,
        num_threads: 1,
        vsize,
        rss_pages,
        policy: policy_num,
        rt_priority,
        processor: proc.sched.home_cpu,
    })
}

pub fn process_cmdline(pid: Pid) -> Option<Vec<u8>> {
    Some(
        GLOBAL
            .lock()
            .processes
            .get(&pid)?
            .identity
            .cmdline()
            .to_vec(),
    )
}

pub fn set_cmdline(pid: Pid, cmdline: Vec<u8>) {
    if let Some(proc) = GLOBAL.lock().processes.get_mut(&pid) {
        proc.identity.set_cmdline(cmdline);
    }
}

pub fn process_exe(pid: Pid) -> Option<Vec<u8>> {
    let v = GLOBAL
        .lock()
        .processes
        .get(&pid)?
        .identity
        .exe_path()
        .to_vec();
    if v.is_empty() { None } else { Some(v) }
}

pub fn set_exe_path(pid: Pid, path: Vec<u8>) {
    if let Some(proc) = GLOBAL.lock().processes.get_mut(&pid) {
        proc.identity.set_exe_path(path);
    }
}

pub extern "C" fn dump_all_processes() {
    frame::println!("=== dump_all_processes ===");
    let g = GLOBAL.lock();
    frame::println!("count: {}", g.processes.len());
    for (pid, proc) in g.processes.iter() {
        let state = match proc.state.0 {
            ProcessState::Runnable => "Runnable",
            ProcessState::Running => "Running",
            ProcessState::Parked => "Parked",
            ProcessState::Stopped => "Stopped",
            ProcessState::Traced => "Traced",
            ProcessState::Zombie(_) => "Zombie",
            ProcessState::KilledByFault { .. } => "KilledByFault",
            ProcessState::KilledBySignal { .. } => "KilledBySignal",
            ProcessState::DlThrottled => "DlThrottled",
            ProcessState::CgroupThrottled => "CgroupThrottled",
        };
        let owner = match proc.sched_owner.0 {
            SchedOwner::None => String::from("None"),
            SchedOwner::Running { cpu } => alloc::format!("Running({cpu})"),
            SchedOwner::Runnable { cpu } => alloc::format!("Runnable({cpu})"),
            SchedOwner::Parked { waitq_addr } => alloc::format!("Parked({waitq_addr:#x})"),
            SchedOwner::Stopped => String::from("Stopped"),
            SchedOwner::Traced => String::from("Traced"),
            SchedOwner::Zombie => String::from("Zombie"),
            SchedOwner::Reaping => String::from("Reaping"),
        };
        let ppid = proc.parent.map(|p| p.0).unwrap_or(0);
        let on_queue = match proc.sched_owner.0 {
            SchedOwner::Runnable { cpu } => {
                Some(CPU_QUEUES[cpu as usize].lock().runnable.contains_pid(*pid))
            }
            _ => None,
        };
        let on_queue_str = match on_queue {
            Some(true) => "on_q=true",
            Some(false) => "on_q=FALSE_LOST",
            None => "",
        };
        frame::println!(
            "pid={} ppid={} state={} owner={} pending={:#x} blocked={:#x} {}",
            pid.0,
            ppid,
            state,
            owner,
            proc.signals.pending(),
            proc.signals.blocked(),
            on_queue_str,
        );
    }
    frame::println!("=== end dump ===");
}
