use super::*;

pub fn park_on_pre_enqueued(wq: &crate::core::wait::WaitQueue) {
    park_on_inner(wq, true)
}

pub(in crate::core) fn park_on(wq: &crate::core::wait::WaitQueue) {
    park_on_inner(wq, false)
}

fn park_on_inner(wq: &crate::core::wait::WaitQueue, pre_enqueued: bool) {
    let cpu = this_cpu() as usize;
    let cur_pid;
    let cur_ctx_xsave = {
        let mut q = CPU_QUEUES[cpu].lock();
        let cur = q.current.take().expect("park_on: no current");
        cur_pid = cur;
        if !pre_enqueued {
            wq.enqueue(cur);
        }
        let mut g = GLOBAL.lock();
        let proc = match g.processes.get_mut(&cur) {
            Some(p) => p,
            None => {
                wq.dequeue(cur);
                let idle_ctx_ptr: *mut Context = &mut q.idle_ctx as *mut Context;
                let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
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
        };
        bank_slice_off_cpu(proc);
        proc.state.0 = ProcessState::Parked;
        set_sched_owner(
            proc,
            SchedOwner::Parked {
                waitq_addr: wq as *const _ as usize,
            },
            "park_on_inner",
        );
        let ptrs = (
            proc.task.0.context_ptr(),
            proc.task.0.xsave_ptr(),
            proc.task.0.kstack_bounds(),
        );
        if !wq.contains(cur) {
            proc.state.0 = ProcessState::Runnable;
            set_sched_owner(
                proc,
                SchedOwner::Running { cpu: this_cpu() },
                "park_on_inner/recover",
            );
            drop(g);
            q.current = Some(cur);
            return;
        }
        ptrs
    };
    let (cur_ctx, cur_xsave, cur_kstack) = cur_ctx_xsave;
    park_current_off_cpu("park_on_inner", cur_pid, cur_kstack, cur_ctx, cur_xsave);
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
        proc.state.0 = ProcessState::Runnable;
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
    let mut first = true;
    loop {
        let cpu = this_cpu() as usize;
        let cur_pid_vfork;
        let (cur_ctx, cur_xsave, cur_kstack) = {
            let mut q = CPU_QUEUES[cpu].lock();
            let cur = q.current.take().expect("park_on_vfork_done: no current");
            cur_pid_vfork = cur;
            let mut g = GLOBAL.lock();
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
                q.current = Some(cur);
                return;
            }
            let proc = g.processes.get_mut(&cur).unwrap();
            let cur_ctx = proc.task.0.context_ptr();
            let cur_xsave = proc.task.0.xsave_ptr();
            let cur_kstack = proc.task.0.kstack_bounds();
            bank_slice_off_cpu(proc);
            proc.state.0 = ProcessState::Parked;
            let waitq_addr = {
                let child_proc = g.processes.get_mut(&child).unwrap();
                if first {
                    child_proc.wait_sites.vfork_done.enqueue(cur);
                }
                &child_proc.wait_sites.vfork_done as *const _ as usize
            };
            let proc = g.processes.get_mut(&cur).unwrap();
            set_sched_owner(proc, SchedOwner::Parked { waitq_addr }, "vfork_park");
            if first {
                let admit = g.processes.get(&child).is_some_and(|p| {
                    matches!(p.sched_owner.0, crate::process_model::SchedOwner::None)
                });
                if admit {
                    admit_runnable_locked(&mut q, &mut g, child, cpu as u32, "vfork_child");
                }
            }
            (cur_ctx, cur_xsave, cur_kstack)
        };
        first = false;
        park_current_off_cpu(
            "park_on_vfork_done",
            cur_pid_vfork,
            cur_kstack,
            cur_ctx,
            cur_xsave,
        );
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
    let cpu = this_cpu() as usize;
    let cur = {
        let q = CPU_QUEUES[cpu].lock();
        match q.current {
            Some(p) => p,
            None => return,
        }
    };
    let (cur_ctx, cur_xsave, cur_kstack) = {
        let mut q = CPU_QUEUES[cpu].lock();
        let _ = q.current.take();
        let mut g = GLOBAL.lock();
        let proc = g.processes.get_mut(&cur).unwrap();
        let cur_ctx = proc.task.0.context_ptr();
        let cur_xsave = proc.task.0.xsave_ptr();
        let cur_kstack = proc.task.0.kstack_bounds();
        bank_slice_off_cpu(proc);
        proc.state.0 = ProcessState::Parked;
        proc.wait_sites.signalfd_waiters.enqueue(cur);
        set_sched_owner(
            proc,
            SchedOwner::Parked {
                waitq_addr: &proc.wait_sites.signalfd_waiters as *const _ as usize,
            },
            "signalfd_park",
        );
        (cur_ctx, cur_xsave, cur_kstack)
    };
    park_current_off_cpu("park_on_signalfd_wait", cur, cur_kstack, cur_ctx, cur_xsave);
}

pub fn park_on_exit_of(target: Pid) {
    let cpu = this_cpu() as usize;
    let cur_pid_outer;
    let (cur_ctx, cur_xsave, cur_kstack) = {
        let mut q = CPU_QUEUES[cpu].lock();
        let cur = q.current.take().expect("park_on_exit_of: no current");
        cur_pid_outer = cur;
        let mut g = GLOBAL.lock();
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
            q.current = Some(cur);
            return;
        }
        let proc = g.processes.get_mut(&cur).unwrap();
        let cur_ctx = proc.task.0.context_ptr();
        let cur_xsave = proc.task.0.xsave_ptr();
        let cur_kstack = proc.task.0.kstack_bounds();
        bank_slice_off_cpu(proc);
        proc.state.0 = ProcessState::Parked;
        let target_proc = g.processes.get_mut(&target).unwrap();
        target_proc.wait_sites.exit_waiters.enqueue(cur);
        let waitq_addr = &target_proc.wait_sites.exit_waiters as *const _ as usize;
        let proc = g.processes.get_mut(&cur).unwrap();
        set_sched_owner(proc, SchedOwner::Parked { waitq_addr }, "exit_waiters_park");
        (cur_ctx, cur_xsave, cur_kstack)
    };
    park_current_off_cpu(
        "park_on_exit_of",
        cur_pid_outer,
        cur_kstack,
        cur_ctx,
        cur_xsave,
    );
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
        p.state.0 = ProcessState::Runnable;
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
    let (cur_pid_stop, cur_ctx, cur_xsave, cur_kstack, parent_wakers) = {
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        let cur = q.current.take().expect("stop_current: no current");
        let mut g = GLOBAL.lock();
        let proc = g.processes.get_mut(&cur).unwrap();
        bank_slice_off_cpu(proc);
        proc.state.0 = ProcessState::Stopped;
        set_sched_owner(proc, SchedOwner::Stopped, "stop_current");
        let parent = proc.parent;
        let cur_ctx = proc.task.0.context_ptr();
        let cur_xsave = proc.task.0.xsave_ptr();
        let cur_kstack = proc.task.0.kstack_bounds();
        let waiters: Vec<Pid> = if let Some(ppid) = parent {
            if let Some(p) = g.processes.get_mut(&ppid) {
                p.wait_sites.child_exit.drain()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        (cur, cur_ctx, cur_xsave, cur_kstack, waiters)
    };
    for w in parent_wakers {
        let _ = wake_pid(w);
    }
    park_current_off_cpu("stop_current", cur_pid_stop, cur_kstack, cur_ctx, cur_xsave);
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
        park_self_at_guarded("sleep_until_or_signal", &|| {
            frame::cpu::clock::nanos_since_boot() < deadline_ns
        });
    }
    let _ = crate::core::timeout::unregister(cur);
}

pub fn sleep_until_signal() {
    let cur_opt = {
        let cpu = this_cpu() as usize;
        CPU_QUEUES[cpu].lock().current
    };
    let cur = match cur_opt {
        Some(p) => p,
        None => return,
    };
    loop {
        let (cur_ctx, cur_xsave, cur_kstack) = {
            let cpu = this_cpu() as usize;
            let mut q = CPU_QUEUES[cpu].lock();
            let mut g = GLOBAL.lock();
            let p = match g.processes.get_mut(&cur) {
                Some(p) => p,
                None => return,
            };
            if (p.signals.deliverable()) != 0 {
                return;
            }
            let _ = q.current.take();
            bank_slice_off_cpu(p);
            p.state.0 = ProcessState::Parked;
            set_sched_owner(
                p,
                SchedOwner::Parked { waitq_addr: 0 },
                "sleep_until_signal",
            );
            (
                p.task.0.context_ptr(),
                p.task.0.xsave_ptr(),
                p.task.0.kstack_bounds(),
            )
        };
        park_current_off_cpu("sleep_until_signal", cur, cur_kstack, cur_ctx, cur_xsave);
    }
}

pub fn park_self() {
    park_self_at("park_self");
}

pub fn park_self_at(site: &'static str) {
    let (cur_pid, cur_ctx, cur_xsave, cur_kstack) = {
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        let cur = q.current.take().expect("park_self: no current");
        let mut g = GLOBAL.lock();
        let proc = g.processes.get_mut(&cur).unwrap();
        bank_slice_off_cpu(proc);
        proc.state.0 = ProcessState::Parked;
        set_sched_owner(proc, SchedOwner::Parked { waitq_addr: 0 }, site);
        (
            cur,
            proc.task.0.context_ptr(),
            proc.task.0.xsave_ptr(),
            proc.task.0.kstack_bounds(),
        )
    };
    park_current_off_cpu("park_self", cur_pid, cur_kstack, cur_ctx, cur_xsave);
}

pub(in crate::core) fn park_self_at_guarded(site: &'static str, still_queued: &dyn Fn() -> bool) {
    let cpu = this_cpu() as usize;
    let cur_pid;
    let cur_ctx_xsave = {
        let mut q = CPU_QUEUES[cpu].lock();
        let cur = q.current.take().expect("park_self_at_guarded: no current");
        cur_pid = cur;
        let mut g = GLOBAL.lock();
        let proc = match g.processes.get_mut(&cur) {
            Some(p) => p,
            None => {
                let idle_ctx_ptr: *mut Context = &mut q.idle_ctx as *mut Context;
                let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
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
        };
        bank_slice_off_cpu(proc);
        proc.state.0 = ProcessState::Parked;
        set_sched_owner(proc, SchedOwner::Parked { waitq_addr: 0 }, site);
        let ptrs = (
            proc.task.0.context_ptr(),
            proc.task.0.xsave_ptr(),
            proc.task.0.kstack_bounds(),
        );
        if !still_queued() {
            proc.state.0 = ProcessState::Runnable;
            set_sched_owner(
                proc,
                SchedOwner::Running { cpu: this_cpu() },
                "park_self_at_guarded/recover",
            );
            drop(g);
            q.current = Some(cur);
            return;
        }
        ptrs
    };
    let (cur_ctx, cur_xsave, cur_kstack) = cur_ctx_xsave;
    park_current_off_cpu(site, cur_pid, cur_kstack, cur_ctx, cur_xsave);
}
