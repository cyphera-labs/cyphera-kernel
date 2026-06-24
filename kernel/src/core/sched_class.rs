use super::*;

pub fn set_deadline_class(
    target: Pid,
    runtime_ns: u64,
    deadline_ns: u64,
    period_ns: u64,
) -> Result<(), i64> {
    const ESRCH: i64 = -3;
    const EBUSY: i64 = -16;
    let home = {
        let g = GLOBAL.lock();
        match g.processes.get(&target) {
            Some(p) => p.sched.home_cpu,
            None => return Err(ESRCH),
        }
    };
    let mut q = CPU_QUEUES[home as usize].lock();
    let mut g = GLOBAL.lock();
    let proc = match g.processes.get_mut(&target) {
        Some(p) => p,
        None => return Err(ESRCH),
    };
    if let crate::process_model::SchedClass::Deadline {
        runtime_ns: rt,
        period_ns: pe,
        ..
    } = proc.sched.sched_class
    {
        q.runnable.release_dl_bandwidth(rt, pe);
    }
    if !q.runnable.admit_dl_bandwidth(runtime_ns, period_ns) {
        if let crate::process_model::SchedClass::Deadline {
            runtime_ns: rt,
            period_ns: pe,
            ..
        } = proc.sched.sched_class
        {
            let _ = q.runnable.admit_dl_bandwidth(rt, pe);
        }
        return Err(EBUSY);
    }
    let was_runnable = proc.state.0 == ProcessState::Runnable;
    if was_runnable {
        let (rt_r, dl_r, cfs_r) = q.runnable.remove_pid(target);
        if rt_r + dl_r + cfs_r > 0 {
            record_dequeue(target);
        }
    }
    let now_ns = frame::cpu::clock::nanos_since_boot();
    proc.sched.sched_class = crate::process_model::SchedClass::Deadline {
        runtime_ns,
        deadline_ns,
        period_ns,
    };
    proc.sched.dl_runtime_remaining = runtime_ns;
    proc.sched.dl_absolute_deadline = now_ns.saturating_add(deadline_ns);
    proc.sched.dl_next_replenish = proc.sched.dl_absolute_deadline;
    proc.sched.dl_throttled = false;
    if was_runnable {
        let placed = q
            .runnable
            .enqueue(target, enqueue_data_from_proc(proc), CfsPlace::Continuing);
        proc.sched.vruntime = placed;
        record_enqueue(target, "set_deadline_class", proc);
    }
    crate::core::timeout::register_callback(
        proc.sched.dl_next_replenish,
        target.raw() as u64,
        dl_replenish_callback,
    );
    Ok(())
}

pub fn dl_replenish_callback(key: u64) {
    let pid = Pid::from_raw(key as u32);
    let next_deadline = {
        let mut g = GLOBAL.lock();
        let proc = match g.processes.get_mut(&pid) {
            Some(p) => p,
            None => return,
        };
        let (runtime_ns, period_ns) = match proc.sched.sched_class {
            crate::process_model::SchedClass::Deadline {
                runtime_ns,
                period_ns,
                ..
            } => (runtime_ns, period_ns),
            _ => return,
        };
        proc.sched.dl_runtime_remaining = runtime_ns;
        proc.sched.dl_absolute_deadline = proc.sched.dl_absolute_deadline.saturating_add(period_ns);
        proc.sched.dl_next_replenish = proc.sched.dl_absolute_deadline;
        let was_throttled = proc.state.0 == ProcessState::DlThrottled;
        proc.sched.dl_throttled = false;
        if was_throttled {
            set_state(proc, ProcessState::Runnable, "sched_class");
        }
        proc.sched.dl_next_replenish
    };

    let (home, was_throttled) = {
        let g = GLOBAL.lock();
        match g.processes.get(&pid) {
            Some(p) => {
                let throttled = matches!(p.state.0, ProcessState::Runnable)
                    && matches!(
                        p.sched.sched_class,
                        crate::process_model::SchedClass::Deadline { .. }
                    );
                (p.sched.home_cpu, throttled)
            }
            None => return,
        }
    };
    if was_throttled {
        let mut q = CPU_QUEUES[home as usize].lock();
        let mut g = GLOBAL.lock();
        if let Some(proc) = g.processes.get_mut(&pid) {
            if proc.state.0 == ProcessState::Runnable {
                set_sched_owner(
                    proc,
                    SchedOwner::Runnable { cpu: home },
                    "dl_replenish_callback",
                );
                let placed =
                    q.runnable
                        .enqueue(pid, enqueue_data_from_proc(proc), CfsPlace::Continuing);
                proc.sched.vruntime = placed;
                record_enqueue(pid, "dl_replenish_callback", proc);
            }
        }
        drop(g);
        drop(q);
        if home != this_cpu() {
            send_resched_ipi(home);
        }
    }

    crate::core::timeout::register_callback(next_deadline, key, dl_replenish_callback);
}

pub fn set_sched_class(
    target: Pid,
    new_class: crate::process_model::SchedClass,
) -> Result<(), i64> {
    const ESRCH: i64 = -3;
    let home = {
        let g = GLOBAL.lock();
        match g.processes.get(&target) {
            Some(p) => p.sched.home_cpu,
            None => return Err(ESRCH),
        }
    };
    let mut q = CPU_QUEUES[home as usize].lock();
    let mut g = GLOBAL.lock();
    let proc = match g.processes.get_mut(&target) {
        Some(p) => p,
        None => return Err(ESRCH),
    };
    let was_running = proc.state.0 == ProcessState::Running;
    let was_queued = proc.state.0 == ProcessState::Runnable && !was_running;
    if was_queued {
        let (rt_r, dl_r, cfs_r) = q.runnable.remove_pid(target);
        if rt_r + dl_r + cfs_r > 0 {
            record_dequeue(target);
        }
    }
    let leaving_dl = matches!(
        proc.sched.sched_class,
        crate::process_model::SchedClass::Deadline { .. }
    ) && !matches!(new_class, crate::process_model::SchedClass::Deadline { .. });
    if let crate::process_model::SchedClass::Deadline {
        runtime_ns: rt,
        period_ns: pe,
        ..
    } = proc.sched.sched_class
    {
        if !matches!(new_class, crate::process_model::SchedClass::Deadline { .. }) {
            q.runnable.release_dl_bandwidth(rt, pe);
            proc.sched.dl_runtime_remaining = 0;
            proc.sched.dl_absolute_deadline = 0;
            proc.sched.dl_next_replenish = 0;
            proc.sched.dl_throttled = false;
            if proc.state.0 == ProcessState::DlThrottled {
                set_state(proc, ProcessState::Runnable, "sched_class");
            }
        }
    }
    proc.sched.sched_class = new_class;
    if matches!(new_class, crate::process_model::SchedClass::Cfs) {
        let placed_floor = q.runnable.cfs_min_vruntime();
        proc.sched.vruntime = proc.sched.vruntime.max(placed_floor);
    }
    if was_queued {
        let placed = q
            .runnable
            .enqueue(target, enqueue_data_from_proc(proc), CfsPlace::Continuing);
        proc.sched.vruntime = placed;
        record_enqueue(target, "set_sched_class", proc);
    }
    drop(g);
    drop(q);
    if leaving_dl {
        crate::core::timeout::cancel_callback(target.raw() as u64);
    }
    if matches!(new_class, crate::process_model::SchedClass::Rt { .. }) && home != this_cpu() {
        send_resched_ipi(home);
    }
    Ok(())
}

pub fn pi_boost(holder: Pid, target_prio: u8) -> bool {
    use crate::process_model::SchedClass;
    let new_class = {
        let mut g = GLOBAL.lock();
        let p = match g.processes.get_mut(&holder) {
            Some(p) => p,
            None => return false,
        };
        let cur = match p.sched.sched_class {
            SchedClass::Rt { priority, .. } => priority,
            _ => 0,
        };
        if cur >= target_prio {
            return false;
        }
        if p.sched.pi_orig_class.is_none() {
            p.sched.pi_orig_class = Some(p.sched.sched_class);
        }
        SchedClass::Rt {
            priority: target_prio,
            round_robin: false,
        }
    };
    let _ = set_sched_class(holder, new_class);
    true
}

pub fn pi_refresh(holder: Pid, top_waiter_prio: u8) -> bool {
    use crate::process_model::SchedClass;
    let new_class = {
        let mut g = GLOBAL.lock();
        let p = match g.processes.get_mut(&holder) {
            Some(p) => p,
            None => return false,
        };
        let orig_class = p.sched.pi_orig_class;
        let orig_prio = orig_class
            .map(|c| match c {
                SchedClass::Rt { priority, .. } => priority,
                _ => 0,
            })
            .unwrap_or(match p.sched.sched_class {
                SchedClass::Rt { priority, .. } => priority,
                _ => 0,
            });
        let final_prio = top_waiter_prio.max(orig_prio);
        if final_prio == orig_prio {
            match orig_class {
                Some(orig) => {
                    p.sched.pi_orig_class = None;
                    orig
                }
                None => return false,
            }
        } else {
            let nc = SchedClass::Rt {
                priority: final_prio,
                round_robin: false,
            };
            if nc == p.sched.sched_class {
                return false;
            }
            nc
        }
    };
    let _ = set_sched_class(holder, new_class);
    true
}
