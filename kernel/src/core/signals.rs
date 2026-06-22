use super::*;

pub fn deliver_user_fault(tf: &mut TrapFrame, vector: u8, error: u64, addr: u64) -> ! {
    frame::cpu::enable_interrupts();

    const SIGILL: u32 = 4;
    const SIGBUS: u32 = 7;
    const SIGFPE: u32 = 8;
    use crate::core::signal::{
        BUS_ADRALN, FPE_INTDIV, ILL_ILLOPN, SEGV_ACCERR, SEGV_MAPERR, SI_KERNEL, SigInfo,
    };
    let (signo, info) = match vector {
        14 => {
            let code = if error & 1 != 0 {
                SEGV_ACCERR
            } else {
                SEGV_MAPERR
            };
            (SIGSEGV, SigInfo::for_fault_code(addr, code))
        }
        0 => (SIGFPE, SigInfo::for_fault_code(tf.rip_user, FPE_INTDIV)),
        6 => (SIGILL, SigInfo::for_fault_code(tf.rip_user, ILL_ILLOPN)),
        16 | 19 => (SIGFPE, SigInfo::for_fault_code(tf.rip_user, SI_KERNEL)),
        17 => (SIGBUS, SigInfo::for_fault_code(tf.rip_user, BUS_ADRALN)),
        _ => (SIGSEGV, SigInfo::for_fault_code(addr, SI_KERNEL)),
    };

    force_fault_signal(signo, info);
    deliver_pending_signals(tf);
    frame::user::resume_user_from_tf(tf)
}

fn force_fault_signal(signo: u32, info: crate::core::signal::PendingSigInfo) {
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    let proc = g.processes.get_mut(&pid).unwrap();
    let bit = 1u64 << signo;
    let blocked = proc.signals.blocked();
    if blocked & bit != 0 {
        proc.signals.set_blocked(blocked & !bit);
    }
    {
        let mut sa = proc.sigactions.lock();
        if sa[signo as usize].handler == 1 {
            sa[signo as usize] = crate::process_model::SigAction::default();
        }
    }
    proc.signals.enqueue_signal(signo, info, usize::MAX);
}

const RLIMIT_SIGPENDING: u64 = 11;
const RT_SIGPENDING_HARD_MAX: u64 = 1 << 16;

pub fn send_signal(target: Pid, signal: u32) -> cyphera_kapi::KResult<()> {
    let info = crate::core::signal::SigInfo::for_kill(signal, current_pid().raw());
    send_signal_with_info(target, signal, info)
}

pub(crate) fn rt_sigpending_limit(p: &Process) -> usize {
    p.rlimits
        .get(RLIMIT_SIGPENDING as usize)
        .copied()
        .flatten()
        .unwrap_or_else(|| crate::syscall::default_rlimit(RLIMIT_SIGPENDING))
        .cur
        .min(RT_SIGPENDING_HARD_MAX) as usize
}

pub(crate) fn uid_rt_pending(g: &Global, ruid: u32) -> usize {
    g.processes
        .values()
        .filter(|p| p.creds.lock().ruid == ruid)
        .map(|p| p.signals.rt_pending_count())
        .sum()
}

pub fn send_signal_with_info(
    target: Pid,
    signal: u32,
    info: crate::core::signal::PendingSigInfo,
) -> cyphera_kapi::KResult<()> {
    if signal == 0 || signal as usize >= NSIG {
        return Err(cyphera_kapi::Errno::INVAL);
    }
    let mut g = GLOBAL.lock();
    if signal >= crate::process_model::RT_SIG_MIN {
        let (limit, ruid) = match g.processes.get(&target) {
            Some(p) => (rt_sigpending_limit(p), p.creds.lock().ruid),
            None => return Err(cyphera_kapi::Errno::SRCH),
        };
        if uid_rt_pending(&g, ruid) >= limit {
            return Err(cyphera_kapi::Errno::AGAIN);
        }
    }
    let proc = g
        .processes
        .get_mut(&target)
        .ok_or(cyphera_kapi::Errno::SRCH)?;

    if signal == SIGKILL {
        let mut zombified = false;
        let mut dying_fds: Option<Arc<crate::vfs::fd::FdTable>> = None;
        let killed_as = proc.addr_space.clone();
        let killed_ipc = proc.namespaces.ipc();
        match proc.state.0 {
            ProcessState::Running => {
                proc.signals.raise(1u64 << SIGKILL);
                let home = proc.sched.home_cpu;
                drop(g);
                if home != this_cpu() {
                    send_resched_ipi(home);
                }
                return Ok(());
            }
            ProcessState::Runnable => {
                proc.signals.raise(1u64 << SIGKILL);
                let home = proc.sched.home_cpu;
                drop(g);
                if home != this_cpu() {
                    send_resched_ipi(home);
                }
                return Ok(());
            }
            ProcessState::Stopped => {
                proc.state.0 = ProcessState::KilledBySignal { signal: SIGKILL };
                let home = proc.sched.home_cpu;
                if Arc::strong_count(&proc.fds) == 1 {
                    dying_fds = Some(core::mem::replace(
                        &mut proc.fds,
                        Arc::new(crate::vfs::fd::FdTable::new()),
                    ));
                }
                drop(g);
                let (rt, dl, cfs) = CPU_QUEUES[home as usize].lock().runnable.remove_pid(target);
                if rt + dl + cfs > 0 {
                    record_dequeue(target);
                }
                zombified = true;
            }
            ProcessState::Parked => {
                proc.signals.raise(1u64 << SIGKILL);
                proc.state.0 = ProcessState::Runnable;
                let home = proc.sched.home_cpu;
                drop(g);
                {
                    let mut q = CPU_QUEUES[home as usize].lock();
                    let mut g = GLOBAL.lock();
                    if let Some(p) = g.processes.get_mut(&target) {
                        let placed =
                            q.runnable
                                .enqueue(target, enqueue_data_from_proc(p), CfsPlace::Wake);
                        p.sched.vruntime = placed;
                        set_sched_owner(
                            p,
                            SchedOwner::Runnable { cpu: home },
                            "sigkill_parked_wake",
                        );
                        record_enqueue(target, "sigkill_parked_wake", p);
                    }
                }
                if home != this_cpu() {
                    send_resched_ipi(home);
                }
                return Ok(());
            }
            ProcessState::Traced => {
                proc.signals.raise(1u64 << SIGKILL);
                proc.state.0 = ProcessState::Runnable;
                proc.trace.clear_stop();
                drop(g);
                reenqueue_runnable(target);
                return Ok(());
            }
            ProcessState::CgroupThrottled => {
                proc.state.0 = ProcessState::KilledBySignal { signal: SIGKILL };
                if Arc::strong_count(&proc.fds) == 1 {
                    dying_fds = Some(core::mem::replace(
                        &mut proc.fds,
                        Arc::new(crate::vfs::fd::FdTable::new()),
                    ));
                }
                drop(g);
                zombified = true;
            }
            ProcessState::DlThrottled => {
                let was_dl = matches!(
                    proc.sched.sched_class,
                    crate::process_model::SchedClass::Deadline { .. }
                );
                let (rt_ns, pe_ns) = match proc.sched.sched_class {
                    crate::process_model::SchedClass::Deadline {
                        runtime_ns,
                        period_ns,
                        ..
                    } => (runtime_ns, period_ns),
                    _ => (0, 0),
                };
                proc.state.0 = ProcessState::KilledBySignal { signal: SIGKILL };
                let home = proc.sched.home_cpu;
                if Arc::strong_count(&proc.fds) == 1 {
                    dying_fds = Some(core::mem::replace(
                        &mut proc.fds,
                        Arc::new(crate::vfs::fd::FdTable::new()),
                    ));
                }

                drop(g);
                crate::core::timeout::cancel_callback(target.raw() as u64);
                if was_dl {
                    CPU_QUEUES[home as usize]
                        .lock()
                        .runnable
                        .release_dl_bandwidth(rt_ns, pe_ns);
                }
                zombified = true;
            }
            _ => {}
        }
        if let Some(fds) = dying_fds {
            fds.close_all();
            drop(fds);
        }
        if zombified {
            if let Some(addr_space) = killed_as {
                release_addr_space_user(&addr_space, killed_ipc.as_ref());
            }
        }
        if zombified {
            drain_exit_waiters(target);
        }
        if zombified {
            drain_vfork_done(target);
        }
        if zombified {
            let parent = {
                let g = GLOBAL.lock();
                g.processes.get(&target).and_then(|p| p.parent)
            };
            if let Some(ppid) = parent {
                const CLD_KILLED: i32 = 2;
                let info_chld =
                    crate::core::signal::SigInfo::for_child(target.0, SIGKILL as i32, CLD_KILLED);
                let waiters = {
                    let mut g = GLOBAL.lock();
                    if let Some(pp) = g.processes.get_mut(&ppid) {
                        pp.signals.raise(1u64 << SIGCHLD);
                        pp.signals.set_siginfo(SIGCHLD as usize, info_chld);
                        pp.wait_sites.child_exit.drain()
                    } else {
                        Vec::new()
                    }
                };
                for w in waiters {
                    let _ = wake_pid(w);
                }
                let _ = wake_pid(ppid);
            }
        }
        return Ok(());
    }

    proc.signals.enqueue_signal(signal, info, usize::MAX);

    if signal == SIGCONT && proc.state.0 == ProcessState::Stopped {
        drop(g);
        request_continue(target, ContinueReason::JobControl);
        return Ok(());
    }

    let blocked = proc.signals.blocked();
    let sfd_waiters = proc.wait_sites.signalfd_waiters.drain();

    if proc.state.0 == ProcessState::Parked && (blocked & (1u64 << signal)) == 0 {
        proc.state.0 = ProcessState::Runnable;
        let home = proc.sched.home_cpu;
        drop(g);
        {
            let mut q = CPU_QUEUES[home as usize].lock();
            let mut g = GLOBAL.lock();
            if let Some(p) = g.processes.get_mut(&target) {
                let placed = q
                    .runnable
                    .enqueue(target, enqueue_data_from_proc(p), CfsPlace::Wake);
                p.sched.vruntime = placed;
                set_sched_owner(p, SchedOwner::Runnable { cpu: home }, "signal_wake_parked");
                record_enqueue(target, "signal_wake_parked", p);
            }
        }
        if home != this_cpu() {
            send_resched_ipi(home);
        }
    } else {
        drop(g);
    }
    for w in sfd_waiters {
        let _ = wake_pid(w);
    }
    Ok(())
}

pub fn current_signal_pending() -> bool {
    let pid = current_pid();
    let g = GLOBAL.lock();
    let p = match g.processes.get(&pid) {
        Some(p) => p,
        None => return false,
    };
    let candidate = p.signals.deliverable();
    if candidate == 0 {
        return false;
    }
    let acts = p.sigactions.lock();
    for sig in 1..crate::process_model::NSIG as u32 {
        if candidate & (1u64 << sig) == 0 {
            continue;
        }
        let handler = acts[sig as usize].handler;
        let ignored = handler == 1
            || (handler == 0
                && matches!(
                    crate::core::signal::default_action(sig),
                    crate::core::signal::DefaultAction::Ignore
                ));
        if !ignored {
            return true;
        }
    }
    false
}

pub fn current_pending_in_mask(mask: u64) -> u64 {
    let pid = current_pid();
    let g = GLOBAL.lock();
    g.processes
        .get(&pid)
        .map(|p| p.signals.pending() & mask)
        .unwrap_or(0)
}

pub fn consume_pending_signal(signum: u32) -> (i32, u64) {
    if signum == 0 || (signum as usize) >= NSIG {
        return (0, 0);
    }
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    let proc = match g.processes.get_mut(&pid) {
        Some(p) => p,
        None => return (0, 0),
    };
    let bit = 1u64 << signum;
    if proc.signals.pending() & bit == 0 {
        return (0, 0);
    }
    let pinfo = proc.signals.dequeue_signal(signum);
    (pinfo.si_code, pinfo.aux)
}

pub fn with_current_sigaction(signal: u32) -> Option<crate::process_model::SigAction> {
    if signal == 0 || signal as usize >= NSIG {
        return None;
    }
    let pid = CPU_QUEUES[this_cpu() as usize].lock().current?;
    let sigs = {
        let g = GLOBAL.lock();
        let proc = g.processes.get(&pid)?;
        proc.sigactions.clone()
    };
    let result = sigs.lock()[signal as usize];
    Some(result)
}

pub fn set_sigaction(
    signal: u32,
    action: crate::process_model::SigAction,
) -> cyphera_kapi::KResult<()> {
    if signal == 0 || signal as usize >= NSIG || signal == SIGKILL || signal == SIGSTOP {
        return Err(cyphera_kapi::Errno::INVAL);
    }
    let pid = current_pid();
    let g = GLOBAL.lock();
    let proc = g.processes.get(&pid).unwrap();
    proc.sigactions.lock()[signal as usize] = action;
    Ok(())
}

pub fn current_blocked() -> u64 {
    let pid = current_pid();
    let g = GLOBAL.lock();
    g.processes
        .get(&pid)
        .map(|p| p.signals.blocked())
        .unwrap_or(0)
}

pub fn sigprocmask(how: u32, set: u64) -> cyphera_kapi::KResult<u64> {
    const SIG_BLOCK: u32 = 0;
    const SIG_UNBLOCK: u32 = 1;
    const SIG_SETMASK: u32 = 2;
    let kept = !((1u64 << SIGKILL) | (1u64 << SIGSTOP));
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    let proc = g.processes.get_mut(&pid).ok_or(cyphera_kapi::Errno::SRCH)?;
    let old = proc.signals.blocked();
    let new = match how {
        SIG_BLOCK => old | (set & kept),
        SIG_UNBLOCK => old & !set,
        SIG_SETMASK => set & kept,
        _ => return Err(cyphera_kapi::Errno::INVAL),
    };
    proc.signals.set_blocked(new);
    Ok(old)
}

pub fn irq_notify_resume_checkpoint() {
    enum Act {
        Term(u32),
        Stop,
    }
    let act = {
        let pid = match CPU_QUEUES[this_cpu() as usize].lock().current {
            Some(p) => p,
            None => return,
        };
        let mut g = GLOBAL.lock();
        let proc = match g.processes.get_mut(&pid) {
            Some(p) => p,
            None => return,
        };
        let mask = proc.signals.deliverable();
        if mask == 0 {
            return;
        }
        let signal = mask.trailing_zeros();
        if signal != SIGKILL && proc.trace.is_traced() {
            return;
        }
        let force_default = signal == SIGKILL || signal == SIGSTOP;
        let handler = proc.sigactions.lock()[signal as usize].handler;
        if handler != 0 && !force_default {
            return;
        }
        use crate::core::signal::DefaultAction;
        match crate::core::signal::default_action(signal) {
            DefaultAction::Term | DefaultAction::Core => {
                proc.signals.discard_signal(signal);
                Act::Term(signal)
            }
            DefaultAction::Stop => {
                proc.signals.discard_signal(signal);
                Act::Stop
            }
            DefaultAction::Cont | DefaultAction::Ignore => {
                proc.signals.discard_signal(signal);
                return;
            }
        }
    };
    match act {
        Act::Term(signal) => terminate_current_with_signal(signal),
        Act::Stop => request_stop(StopReason::JobControl),
    }
}

pub fn deliver_pending_signals(tf: &mut TrapFrame) {
    forward_signal_to_tracer_if_any(tf);

    enum Action {
        None,
        TerminateBySignal(u32),
        Stop,
        Cont,
        InvokeHandler {
            signal: u32,
            action: crate::process_model::SigAction,
            pre_blocked: u64,
            info: crate::core::signal::SigInfo,
            altstack: crate::core::signal::AltStack,
        },
    }

    let action = {
        let mut result = Action::None;
        for _ in 0..NSIG {
            let pid = match CPU_QUEUES[this_cpu() as usize].lock().current {
                Some(p) => p,
                None => return,
            };
            let mut g = GLOBAL.lock();
            let proc = g.processes.get_mut(&pid).unwrap();
            let traced = proc.trace.is_traced();
            let mask = proc.signals.deliverable();
            if mask == 0 {
                break;
            }
            let signal = mask.trailing_zeros();
            let act = proc.sigactions.lock()[signal as usize];
            let pinfo = proc.signals.dequeue_signal(signal);
            let info = pinfo.expand(signal);
            let force_default = signal == SIGKILL || signal == SIGSTOP;
            let this = if act.handler == 1 && !force_default {
                Action::None
            } else if act.handler == 0 || force_default {
                use crate::core::signal::DefaultAction;
                match crate::core::signal::default_action(signal) {
                    DefaultAction::Term | DefaultAction::Core => Action::TerminateBySignal(signal),
                    DefaultAction::Stop => Action::Stop,
                    DefaultAction::Cont => Action::Cont,
                    DefaultAction::Ignore => Action::None,
                }
            } else {
                Action::InvokeHandler {
                    signal,
                    action: act,
                    pre_blocked: proc.signals.blocked(),
                    info,
                    altstack: proc.signals.altstack(),
                }
            };
            match this {
                Action::None | Action::Cont if !traced => continue,
                other => {
                    result = other;
                    break;
                }
            }
        }
        result
    };

    match action {
        Action::None => {}
        Action::TerminateBySignal(signal) => terminate_current_with_signal(signal),
        Action::Stop => request_stop(StopReason::JobControl),
        Action::Cont => {}
        Action::InvokeHandler {
            signal,
            action,
            pre_blocked,
            info,
            altstack,
        } => {
            match crate::core::signal::deliver_to_handler(
                tf,
                signal,
                &action,
                pre_blocked,
                &info,
                altstack,
            ) {
                Ok(new_blocked) => {
                    let pid = current_pid();
                    let mut g = GLOBAL.lock();
                    if let Some(p) = g.processes.get_mut(&pid) {
                        p.signals.set_blocked(new_blocked);
                        if action.flags & crate::process_model::sa::SA_RESETHAND != 0 {
                            p.sigactions.lock()[signal as usize] =
                                crate::process_model::SigAction::default();
                        }
                    }
                }
                Err(_) => exit_current(tf, 128 + SIGSEGV as i32),
            }
        }
    }
}

pub fn rt_sigreturn(tf: &mut TrapFrame) {
    match crate::core::signal::restore_from_frame(tf) {
        Ok(saved_blocked) => {
            let pid = current_pid();
            let mut g = GLOBAL.lock();
            if let Some(p) = g.processes.get_mut(&pid) {
                p.signals.set_blocked(saved_blocked);
            }
        }
        Err(_) => exit_current(tf, 128 + SIGSEGV as i32),
    }
}
