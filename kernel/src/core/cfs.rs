use super::*;

fn calc_delta_vruntime(delta_ns: u64, weight: u64) -> u64 {
    if weight == 0 {
        return delta_ns;
    }
    delta_ns.saturating_mul(NICE_0_LOAD) / weight
}

pub(crate) fn enqueue_data_from_proc(proc: &Process) -> EnqueueData {
    EnqueueData {
        class: proc.sched.sched_class,
        vruntime: proc.sched.vruntime,
        weight: cgroup_scaled_weight(proc),
        dl_deadline: proc.sched.dl_absolute_deadline,
    }
}

fn cgroup_scaled_weight(proc: &Process) -> u64 {
    let cg_weight = proc
        .cgroup
        .as_ref()
        .map(|cg| cg.cpu.lock().weight)
        .unwrap_or(100);
    proc.sched.weight.saturating_mul(cg_weight) / 100
}

pub(crate) fn bank_cpu_time(proc: &mut Process, delta_ns: u64) {
    proc.cpu_times.total_cpu_ns = proc.cpu_times.total_cpu_ns.saturating_add(delta_ns);
    let (user_ns, sys_ns) = if proc.lifecycle.in_syscall() {
        proc.cpu_times.total_stime_ns = proc.cpu_times.total_stime_ns.saturating_add(delta_ns);
        (0, delta_ns)
    } else {
        proc.cpu_times.total_utime_ns = proc.cpu_times.total_utime_ns.saturating_add(delta_ns);
        (delta_ns, 0)
    };

    let (virt_fired, prof_fired) = proc.signals.charge_cpu_itimers(user_ns, sys_ns);
    if virt_fired {
        const SIGVTALRM: u32 = 26;
        proc.signals.set_siginfo(
            SIGVTALRM as usize,
            crate::core::signal::SigInfo::for_kernel(SIGVTALRM),
        );
        proc.signals.raise(1u64 << SIGVTALRM);
    }
    if prof_fired {
        const SIGPROF: u32 = 27;
        proc.signals.set_siginfo(
            SIGPROF as usize,
            crate::core::signal::SigInfo::for_kernel(SIGPROF),
        );
        proc.signals.raise(1u64 << SIGPROF);
    }
}

pub(crate) fn bank_slice_off_cpu(proc: &mut Process) {
    let now = frame::cpu::clock::nanos_since_boot();
    bank_cpu_time(proc, now.saturating_sub(proc.sched.last_run_ns));
    proc.sched.last_run_ns = now;
}

pub(crate) fn charge_runtime(proc: &mut Process, delta_ns: u64) {
    bank_cpu_time(proc, delta_ns);
    if matches!(
        proc.sched.sched_class,
        SchedClass::Rt { .. } | SchedClass::Deadline { .. }
    ) {
        charge_rt_runtime(delta_ns);
    }
    if !matches!(proc.sched.sched_class, SchedClass::Cfs) {
        return;
    }
    let raw = if proc.sched.weight == 0 {
        nice_to_weight(proc.sched.nice)
    } else {
        proc.sched.weight
    };
    let cg_weight = proc
        .cgroup
        .as_ref()
        .map(|cg| cg.cpu.lock().weight)
        .unwrap_or(100);
    let weight = raw.saturating_mul(cg_weight) / 100;
    let dv = calc_delta_vruntime(delta_ns, weight.max(1));
    proc.sched.vruntime = proc.sched.vruntime.saturating_add(dv);
}
