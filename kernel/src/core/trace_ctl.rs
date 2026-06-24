use super::*;

pub(crate) fn wake_tracer_on_exit(cur: Pid) {
    let (tracer, parent) = {
        let g = GLOBAL.lock();
        match g.processes.get(&cur) {
            Some(p) => (p.trace.tracer_pid(), p.parent),
            None => (None, None),
        }
    };
    let Some(tpid) = tracer else {
        return;
    };
    if Some(tpid) == parent {
        return;
    }
    let waiters = {
        let mut g = GLOBAL.lock();
        match g.processes.get_mut(&tpid) {
            Some(p) => p.wait_sites.child_exit.drain(),
            None => alloc::vec::Vec::new(),
        }
    };
    for w in waiters {
        let _ = wake_pid(w);
    }
    let _ = wake_pid(tpid);
}

pub(crate) fn forward_signal_to_tracer_if_any(tf: &mut TrapFrame) {
    {
        let cur = current_pid();
        let consume = {
            let mut g = GLOBAL.lock();
            match g.processes.get_mut(&cur) {
                Some(p)
                    if p.trace.is_traced()
                        && (p.signals.pending() & (1u64 << SIGKILL)) == 0
                        && p.trace.attach_stop_pending() =>
                {
                    p.trace.take_attach_stop()
                }
                _ => false,
            }
        };
        if consume {
            crate::ptrace::save_user_regs_for_trace(cur, tf);
            park_for_trace_stop(crate::process_model::TraceStop::Attach);
            crate::ptrace::restore_user_regs_after_trace(cur, tf);
        }
    }
    for _ in 0..NSIG {
        let cur = current_pid();
        let (traced, signal) = {
            let g = GLOBAL.lock();
            let p = match g.processes.get(&cur) {
                Some(p) => p,
                None => return,
            };
            if !p.trace.is_traced() {
                return;
            }
            let mask = p.signals.deliverable();
            if mask == 0 {
                return;
            }
            let sig = mask.trailing_zeros();
            if sig == SIGKILL {
                return;
            }
            (true, sig)
        };
        if !traced {
            return;
        }
        {
            let mut g = GLOBAL.lock();
            if let Some(p) = g.processes.get_mut(&cur) {
                p.signals.discard_signal(signal);
                p.trace.set_event_msg(signal as u64);
                p.trace.clear_pending_inject();
            }
        }
        crate::ptrace::save_user_regs_for_trace(cur, tf);
        park_for_trace_stop(crate::process_model::TraceStop::Signal(signal));
        let inject = {
            let g = GLOBAL.lock();
            g.processes
                .get(&cur)
                .map(|p| p.trace.pending_inject())
                .unwrap_or(0)
        };
        crate::ptrace::restore_user_regs_after_trace(cur, tf);
        if inject == 0 {
            continue;
        }
        if inject < NSIG as u32 {
            let mut g = GLOBAL.lock();
            if let Some(p) = g.processes.get_mut(&cur) {
                p.signals.raise(1u64 << inject);
                p.trace.clear_pending_inject();
            }
        }
        break;
    }
}

pub(crate) fn detach_orphaned_tracees(tracer: Pid) {
    let to_resume: alloc::vec::Vec<Pid> = {
        let mut g = GLOBAL.lock();
        let tracees: alloc::vec::Vec<Pid> = match g.processes.get_mut(&tracer) {
            Some(p) => p.trace.take_tracees(),
            None => return,
        };
        let mut resume = alloc::vec::Vec::new();
        for tpid in &tracees {
            if let Some(t) = g.processes.get_mut(tpid) {
                if t.trace.traced_by(tracer) {
                    t.trace.detach();
                    if t.state.0 == ProcessState::Traced {
                        set_state(t, ProcessState::Runnable, "trace_ctl");
                        resume.push(*tpid);
                    }
                }
            }
        }
        resume
    };
    for pid in to_resume {
        reenqueue_runnable(pid);
    }
}

pub fn park_for_trace_stop(reason: crate::process_model::TraceStop) {
    let cur = current_pid();
    let (tracer, cur_ctx, cur_xsave, cur_kstack) = {
        let mut q = CPU_QUEUES[this_cpu() as usize].lock();
        let mut g = GLOBAL.lock();
        let me = match g.processes.get_mut(&cur) {
            Some(p) => p,
            None => return,
        };
        let tracer = me.trace.tracer_pid();
        if tracer.is_none() || (me.signals.pending() & (1u64 << SIGKILL)) != 0 {
            return;
        }
        let _ = q.current.take();
        bank_slice_off_cpu(me);
        set_state(me, ProcessState::Traced, "trace_ctl");
        set_sched_owner(me, SchedOwner::Traced, "park_for_trace_stop");
        me.trace.enter_stop(reason);
        (
            tracer,
            me.task.0.context_ptr(),
            me.task.0.xsave_ptr(),
            me.task.0.kstack_bounds(),
        )
    };
    if let Some(tracer_pid) = tracer {
        let waiters = {
            let mut g = GLOBAL.lock();
            match g.processes.get_mut(&tracer_pid) {
                Some(p) => p.wait_sites.child_exit.drain(),
                None => alloc::vec::Vec::new(),
            }
        };
        for pid in waiters {
            let _ = wake_pid(pid);
        }
    }
    park_current_off_cpu("park_for_trace_stop", cur, cur_kstack, cur_ctx, cur_xsave);
}

pub fn resume_traced(
    target: Pid,
    caller: Pid,
    inject_signal: u32,
    trace_syscall: bool,
    single_step: bool,
) -> bool {
    let needs_enqueue = {
        let mut g = GLOBAL.lock();
        let inject_capped = inject_signal >= crate::process_model::RT_SIG_MIN
            && (inject_signal as usize) < NSIG
            && match g.processes.get(&target) {
                Some(p) => {
                    let ruid = p.creds.lock().ruid;
                    let limit = rt_sigpending_limit(p);
                    uid_rt_pending(&g, ruid) >= limit
                }
                None => return false,
            };
        let p = match g.processes.get_mut(&target) {
            Some(p) => p,
            None => return false,
        };
        if !p.trace.traced_by(caller) || p.state.0 != ProcessState::Traced {
            return false;
        }
        if single_step {
            p.trace.enable_single_step();
        }
        p.trace.resume(trace_syscall);
        if inject_signal != 0 && (inject_signal as usize) < NSIG && !inject_capped {
            let tracer = p.trace.tracer_pid().map(|t| t.raw()).unwrap_or(0);
            let info = crate::core::signal::SigInfo::for_kill(inject_signal, tracer);
            p.signals.enqueue_signal(inject_signal, info, usize::MAX);
            p.trace.set_pending_inject(inject_signal);
        }
        set_state(p, ProcessState::Runnable, "trace_ctl");
        true
    };
    if needs_enqueue {
        reenqueue_runnable(target);
    }
    true
}

pub enum AttachOutcome {
    Gone,
    AlreadyTraced,
    Untraceable,
    Denied,
    Deferred(u32),
    Stopped,
}

pub fn request_ptrace_attach(target: Pid, tracer: Pid) -> AttachOutcome {
    let (outcome, waiters) = {
        let mut g = GLOBAL.lock();
        let (caller_uid, caller_is_root) = match g.processes.get(&tracer) {
            Some(p) => {
                let c = p.creds.lock();
                (c.euid, c.euid == 0)
            }
            None => return AttachOutcome::Gone,
        };
        match g.processes.get(&target) {
            None => return AttachOutcome::Gone,
            Some(p) => {
                if p.trace.is_traced() {
                    return AttachOutcome::AlreadyTraced;
                }
                if matches!(p.kind, crate::process_model::ProcessKind::Kernel) {
                    return AttachOutcome::Untraceable;
                }
                if matches!(
                    p.state.0,
                    ProcessState::Zombie(_)
                        | ProcessState::KilledByFault { .. }
                        | ProcessState::KilledBySignal { .. }
                ) {
                    return AttachOutcome::Gone;
                }
                if !caller_is_root {
                    let target_uid = p.creds.lock().euid;
                    let dumpable = p.security.dumpable();
                    if target_uid != caller_uid || dumpable == 0 {
                        return AttachOutcome::Denied;
                    }
                }
            }
        }
        let p = g.processes.get_mut(&target).unwrap();
        let outcome = match p.state.0 {
            ProcessState::Running | ProcessState::Runnable => {
                p.trace.attach_deferred(tracer);
                AttachOutcome::Deferred(cpu_to_nudge(p))
            }
            _ => {
                set_state(p, ProcessState::Traced, "trace_ctl");
                p.trace.attach(tracer);
                AttachOutcome::Stopped
            }
        };
        let caller = match g.processes.get_mut(&tracer) {
            Some(c) => c,
            None => return AttachOutcome::Gone,
        };
        caller.trace.add_tracee(target);
        (outcome, caller.wait_sites.child_exit.drain())
    };
    for pid in waiters {
        let _ = wake_pid(pid);
    }
    outcome
}

pub enum PtraceResume {
    Detach { signal: u32 },
    Kill,
}

pub fn request_ptrace_continue(target: Pid, caller: Pid, how: PtraceResume) -> bool {
    let reenqueue = {
        let mut g = GLOBAL.lock();
        let p = match g.processes.get_mut(&target) {
            Some(p) => p,
            None => return false,
        };
        if !p.trace.traced_by(caller) {
            return false;
        }
        match how {
            PtraceResume::Detach { signal } => {
                p.trace.detach();
                if signal != 0 && signal < 64 {
                    p.signals.raise(1u64 << signal);
                }
            }
            PtraceResume::Kill => {
                p.signals.raise(1u64 << crate::process_model::SIGKILL);
            }
        }
        if p.state.0 == ProcessState::Traced {
            set_state(p, ProcessState::Runnable, "trace_ctl");
            if matches!(how, PtraceResume::Kill) {
                p.trace.clear_stop();
            }
            true
        } else {
            false
        }
    };
    if reenqueue {
        reenqueue_runnable(target);
    }
    reenqueue
}
