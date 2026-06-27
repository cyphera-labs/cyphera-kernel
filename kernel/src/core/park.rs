use super::*;

pub enum ParkDest {
    Sleep { waitq_addr: usize },
    Stopped,
    Traced,
}

pub enum ParkArm {
    Abort,
    Park { dest: ParkDest },
}

impl ParkArm {
    fn sleep(waitq_addr: usize) -> Self {
        ParkArm::Park {
            dest: ParkDest::Sleep { waitq_addr },
        }
    }
}

pub(in crate::core) fn park_current(
    site: &'static str,
    prep: &dyn Fn(&mut Global, Pid) -> ParkArm,
) {
    park_current_then(site, prep, &|_| {});
}

pub(in crate::core) fn park_current_then(
    site: &'static str,
    prep: &dyn Fn(&mut Global, Pid) -> ParkArm,
    on_parked: &dyn Fn(Pid),
) {
    let cpu = this_cpu() as usize;
    let cur_pid;
    let ptrs = {
        let mut q = CPU_QUEUES[cpu].lock();
        let cur = match q.current {
            Some(p) => p,
            None => return,
        };
        cur_pid = cur;
        let mut g = GLOBAL.lock();
        if !g.processes.contains_key(&cur) {
            let idle_ctx_ptr: *mut Context = &mut q.idle_ctx as *mut Context;
            let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
            let _ = q.current.take();
            drop(q);
            drop(g);
            let mut throwaway = Context::bootstrap();
            task::switch_to_ctx(
                &mut throwaway as *mut Context,
                idle_ctx_ptr,
                idle_xsave,
                idle_xsave,
            );
            return;
        }
        let dest = match prep(&mut g, cur) {
            ParkArm::Abort => return,
            ParkArm::Park { dest } => dest,
        };
        let _ = q.current.take();
        let proc = g.processes.get_mut(&cur).unwrap();
        bank_slice_off_cpu(proc);
        match dest {
            ParkDest::Sleep { waitq_addr } => {
                set_state(proc, ProcessState::Parked, "park");
                set_sched_owner(proc, SchedOwner::Parked { waitq_addr }, site);
            }
            ParkDest::Stopped => {
                set_state(proc, ProcessState::Stopped, "park");
                set_sched_owner(proc, SchedOwner::Stopped, site);
            }
            ParkDest::Traced => {
                set_state(proc, ProcessState::Traced, "park");
                set_sched_owner(proc, SchedOwner::Traced, site);
            }
        }
        (
            proc.task.0.context_ptr(),
            proc.task.0.xsave_ptr(),
            proc.task.0.kstack_bounds(),
        )
    };
    on_parked(cur_pid);
    let (cur_ctx, cur_xsave, cur_kstack) = ptrs;
    park_current_off_cpu(site, cur_pid, cur_kstack, cur_ctx, cur_xsave);
}

pub(in crate::core) fn wake_pid(pid: Pid) -> bool {
    let home = {
        let mut g = GLOBAL.lock();
        let proc = match g.processes.get_mut(&pid) {
            Some(p) => p,
            None => return false,
        };
        if proc.state.0 != ProcessState::Parked {
            return false;
        }
        set_state(proc, ProcessState::Runnable, "park");
        let home = effective_home_cpu(proc);
        set_sched_owner(proc, SchedOwner::Runnable { cpu: home }, "wake_pid");
        home
    };
    {
        let mut q = CPU_QUEUES[home as usize].lock();
        let mut g = GLOBAL.lock();
        if let Some(proc) = g.processes.get_mut(&pid) {
            if proc.state.0 == ProcessState::Runnable {
                let placed = q
                    .runnable
                    .enqueue(pid, enqueue_data_from_proc(proc), CfsPlace::Wake);
                proc.sched.vruntime = placed;
                record_enqueue(pid, "wake_pid", proc);
            }
        }
    }
    send_resched_ipi(home);
    true
}

pub(in crate::core) fn reenqueue_runnable(pid: Pid) {
    let home = {
        let mut g = GLOBAL.lock();
        match g.processes.get_mut(&pid) {
            Some(p) if p.state.0 == ProcessState::Runnable => effective_home_cpu(p),
            _ => return,
        }
    };
    {
        let mut q = CPU_QUEUES[home as usize].lock();
        let mut g = GLOBAL.lock();
        if let Some(proc) = g.processes.get_mut(&pid) {
            let placed = q
                .runnable
                .enqueue(pid, enqueue_data_from_proc(proc), CfsPlace::Wake);
            proc.sched.vruntime = placed;
            set_sched_owner(
                proc,
                SchedOwner::Runnable { cpu: home },
                "reenqueue_runnable",
            );
            record_enqueue(pid, "reenqueue_runnable", proc);
        }
    }
    send_resched_ipi(home);
}

pub fn park_on_pre_enqueued(wq: &crate::core::wait::WaitQueue) {
    let addr = wq as *const _ as usize;
    park_current("park_on_pre_enqueued", &|_g, cur| {
        if wq.contains(cur) {
            ParkArm::sleep(addr)
        } else {
            ParkArm::Abort
        }
    });
}

pub(in crate::core) fn park_on(wq: &crate::core::wait::WaitQueue) {
    let addr = wq as *const _ as usize;
    park_current("park_on", &|_g, cur| {
        wq.enqueue(cur);
        if wq.contains(cur) {
            ParkArm::sleep(addr)
        } else {
            ParkArm::Abort
        }
    });
}

pub(crate) fn drain_vfork_done(pid: Pid) {
    let waiters = {
        let mut g = GLOBAL.lock();
        match g.processes.get_mut(&pid) {
            Some(p) => {
                p.lifecycle.set_vfork_done_set(true);
                p.wait_sites.vfork_done.drain()
            }
            None => Vec::new(),
        }
    };
    for w in waiters {
        let _ = wake_pid(w);
    }
}

pub fn park_on_vfork_done(child: Pid) {
    {
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        let mut g = GLOBAL.lock();
        let admit = g
            .processes
            .get(&child)
            .is_some_and(|p| matches!(p.sched_owner.0, SchedOwner::None));
        if admit {
            admit_runnable_locked(&mut q, &mut g, child, cpu as u32, "vfork_child");
        }
    }
    loop {
        let still_blocked = {
            let g = GLOBAL.lock();
            match g.processes.get(&child) {
                None => false,
                Some(p) => {
                    !p.lifecycle.vfork_done_set()
                        && !matches!(
                            p.state.0,
                            ProcessState::Zombie(_)
                                | ProcessState::KilledByFault { .. }
                                | ProcessState::KilledBySignal { .. }
                        )
                }
            }
        };
        if !still_blocked {
            return;
        }
        park_current("park_on_vfork_done", &|g, cur| {
            let already_done = match g.processes.get(&child) {
                None => true,
                Some(p) => {
                    p.lifecycle.vfork_done_set()
                        || matches!(
                            p.state.0,
                            ProcessState::Zombie(_)
                                | ProcessState::KilledByFault { .. }
                                | ProcessState::KilledBySignal { .. }
                        )
                }
            };
            if already_done {
                return ParkArm::Abort;
            }
            let child_proc = g.processes.get_mut(&child).unwrap();
            child_proc.wait_sites.vfork_done.enqueue(cur);
            let addr = &child_proc.wait_sites.vfork_done as *const _ as usize;
            ParkArm::sleep(addr)
        });
    }
}

pub(crate) fn drain_exit_waiters(target: Pid) {
    let waiters = {
        let mut g = GLOBAL.lock();
        match g.processes.get_mut(&target) {
            Some(p) => p.wait_sites.exit_waiters.drain(),
            None => Vec::new(),
        }
    };
    for w in waiters {
        let _ = wake_pid(w);
    }
}

pub fn park_on_signalfd_wait() {
    park_current("park_on_signalfd_wait", &|g, cur| {
        let proc = match g.processes.get_mut(&cur) {
            Some(p) => p,
            None => return ParkArm::Abort,
        };
        if proc.signals.deliverable() != 0 {
            return ParkArm::Abort;
        }
        proc.wait_sites.signalfd_waiters.enqueue(cur);
        let addr = &proc.wait_sites.signalfd_waiters as *const _ as usize;
        ParkArm::sleep(addr)
    });
}

pub fn park_on_child_exit(ready: impl Fn(&Global) -> bool) {
    park_current("park_on_child_exit", &|g, cur| {
        if ready(g) {
            return ParkArm::Abort;
        }
        let proc = match g.processes.get_mut(&cur) {
            Some(p) => p,
            None => return ParkArm::Abort,
        };
        proc.wait_sites.child_exit.enqueue(cur);
        let addr = &proc.wait_sites.child_exit as *const _ as usize;
        ParkArm::sleep(addr)
    });
}

pub fn park_on_pi_wait(key: cyphera_kapi::WaitKey) {
    park_current("park_on_pi_wait", &|g, cur| match g.processes.get(&cur) {
        Some(p) if p.pi_blocked_on == Some(key) => ParkArm::sleep(0),
        _ => ParkArm::Abort,
    });
}

pub fn park_on_pi_requeue(wq: &crate::core::wait::WaitQueue, me: Pid) {
    let addr = wq as *const _ as usize;
    park_current("park_on_pi_requeue", &|_g, _cur| {
        wq.enqueue(me);
        if wq.contains(me) {
            ParkArm::sleep(addr)
        } else {
            ParkArm::Abort
        }
    });
}

pub fn park_on_exit_of(target: Pid) {
    park_current("park_on_exit_of", &|g, cur| {
        let already_dead = match g.processes.get(&target) {
            None => true,
            Some(p) => matches!(
                p.state.0,
                ProcessState::Zombie(_)
                    | ProcessState::KilledByFault { .. }
                    | ProcessState::KilledBySignal { .. }
            ),
        };
        if already_dead {
            return ParkArm::Abort;
        }
        let target_proc = g.processes.get_mut(&target).unwrap();
        target_proc.wait_sites.exit_waiters.enqueue(cur);
        let addr = &target_proc.wait_sites.exit_waiters as *const _ as usize;
        ParkArm::sleep(addr)
    });
}

pub enum StopReason {
    JobControl,
}

pub enum ContinueReason {
    JobControl,
}

pub(in crate::core) fn request_continue(target: Pid, _reason: ContinueReason) -> bool {
    let home = {
        let mut g = GLOBAL.lock();
        let p = match g.processes.get_mut(&target) {
            Some(p) => p,
            None => return false,
        };
        if p.state.0 != ProcessState::Stopped {
            return false;
        }
        let stop_mask = (1u64 << SIGSTOP) | (1u64 << 20) | (1u64 << 21) | (1u64 << 22);
        p.signals.clear_pending(stop_mask);
        set_state(p, ProcessState::Runnable, "park");
        p.sched.home_cpu
    };
    {
        let mut q = CPU_QUEUES[home as usize].lock();
        let mut g = GLOBAL.lock();
        if let Some(p) = g.processes.get_mut(&target) {
            let placed = q
                .runnable
                .enqueue(target, enqueue_data_from_proc(p), CfsPlace::Wake);
            p.sched.vruntime = placed;
            set_sched_owner(p, SchedOwner::Runnable { cpu: home }, "sigcont_wake");
            record_enqueue(target, "sigcont_wake", p);
        }
    }
    if home != this_cpu() {
        send_resched_ipi(home);
    }
    true
}

pub(in crate::core) fn request_stop(_reason: StopReason) {
    let notify_tgid = core::cell::Cell::new(None);
    park_current_then(
        "stop_current",
        &|g, cur| {
            let proc = match g.processes.get_mut(&cur) {
                Some(p) => p,
                None => return ParkArm::Abort,
            };
            let tgid = proc.tgid;
            let last_to_stop = match g.processes.get_mut(&tgid) {
                Some(leader) => leader.signals.group_stop_arrive(),
                None => false,
            };
            notify_tgid.set(if last_to_stop { Some(tgid) } else { None });
            ParkArm::Park {
                dest: ParkDest::Stopped,
            }
        },
        &|_| {
            if let Some(tgid) = notify_tgid.get() {
                crate::core::notify_parent_status_change(
                    tgid,
                    crate::core::CLD_STOPPED,
                    SIGSTOP as i32,
                );
            }
        },
    );
}

pub fn sleep_until(deadline_ns: u64) {
    let cur_opt = {
        let cpu = this_cpu() as usize;
        CPU_QUEUES[cpu].lock().current
    };
    let cur = match cur_opt {
        Some(p) => p,
        None => return,
    };
    crate::core::timeout::register(deadline_ns, cur);
    loop {
        if frame::cpu::clock::nanos_since_boot() >= deadline_ns {
            break;
        }
        if current_signal_pending() {
            break;
        }
        park_current("sleep_until", &|_g, _cur| {
            if frame::cpu::clock::nanos_since_boot() >= deadline_ns {
                ParkArm::Abort
            } else {
                ParkArm::sleep(0)
            }
        });
    }
    let _ = crate::core::timeout::unregister(cur);
}

pub fn sleep_until_signal() {
    let cur_opt = {
        let cpu = this_cpu() as usize;
        CPU_QUEUES[cpu].lock().current
    };
    if cur_opt.is_none() {
        return;
    }
    loop {
        let deliverable = {
            let g = GLOBAL.lock();
            match g.processes.get(&cur_opt.unwrap()) {
                Some(p) => p.signals.deliverable(),
                None => return,
            }
        };
        if deliverable != 0 {
            return;
        }
        park_current(
            "sleep_until_signal",
            &|g, cur| match g.processes.get(&cur) {
                Some(p) if p.signals.deliverable() == 0 => ParkArm::sleep(0),
                _ => ParkArm::Abort,
            },
        );
    }
}

pub fn park_self() {
    park_self_at("park_self");
}

pub fn park_self_at(site: &'static str) {
    park_current(site, &|_g, _cur| ParkArm::sleep(0));
}

pub(in crate::core) fn park_self_at_guarded(site: &'static str, still_queued: &dyn Fn() -> bool) {
    park_current(site, &|_g, _cur| {
        if still_queued() {
            ParkArm::sleep(0)
        } else {
            ParkArm::Abort
        }
    });
}
