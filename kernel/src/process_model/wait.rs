use super::*;
use crate::core::*;

fn root_has_live_user(root_phys: u64) -> bool {
    let g = GLOBAL.lock();
    g.processes.values().any(|p| {
        p.addr_space_root.map(|r| r.as_phys()) == Some(root_phys)
            && !matches!(
                p.state.0,
                ProcessState::Zombie(_)
                    | ProcessState::KilledByFault { .. }
                    | ProcessState::KilledBySignal { .. }
            )
    })
}

const WNOHANG: u64 = 1;
const WUNTRACED: u64 = 2;
#[allow(dead_code)]
const WCONTINUED: u64 = 8;

fn wait_selector_matches(target_pid: i64, cpid: Pid, child_pgid: Pid, caller_pgid: Pid) -> bool {
    match target_pid {
        p if p > 0 => cpid.0 as i64 == p,
        0 => child_pgid == caller_pgid,
        -1 => true,
        neg => child_pgid.0 as i64 == -neg,
    }
}

enum WaitScan {
    NoChildren,
    Reap(Pid, i32),
    Report(Pid, i32, bool),
    NoneReady,
}

fn wait4_scan(g: &Global, cur: Pid, target_pid: i64, options: u64) -> WaitScan {
    let me = match g.processes.get(&cur) {
        Some(p) => p,
        None => return WaitScan::NoChildren,
    };
    if me.children.is_empty() && me.trace.tracees().is_empty() {
        return WaitScan::NoChildren;
    }
    let caller_pgid = me.identity.pgid();
    let mut candidates: alloc::vec::Vec<Pid> = me.children.to_vec();
    for t in me.trace.tracees() {
        if !candidates.contains(t) {
            candidates.push(*t);
        }
    }
    let tracee_set: alloc::vec::Vec<Pid> = me.trace.tracees().to_vec();
    let any_selected = candidates.iter().any(|c| {
        g.processes
            .get(c)
            .map(|ch| wait_selector_matches(target_pid, *c, ch.identity.pgid(), caller_pgid))
            .unwrap_or(false)
    });
    if !any_selected {
        return WaitScan::NoChildren;
    }
    for cpid in &candidates {
        let child = match g.processes.get(cpid) {
            Some(c) => c,
            None => continue,
        };
        if !wait_selector_matches(target_pid, *cpid, child.identity.pgid(), caller_pgid) {
            continue;
        }
        match child.state.0 {
            ProcessState::Zombie(code) => {
                return WaitScan::Reap(*cpid, exit_status_code(code));
            }
            ProcessState::KilledByFault { .. } => {
                return WaitScan::Reap(*cpid, fault_status_code());
            }
            ProcessState::KilledBySignal { signal } => {
                return WaitScan::Reap(*cpid, signal as i32 & 0x7f);
            }
            ProcessState::Stopped if (options & WUNTRACED) != 0 => {
                return WaitScan::Report(*cpid, (SIGSTOP as i32) << 8 | 0x7f, false);
            }
            ProcessState::Traced
                if tracee_set.contains(cpid) && crate::ptrace::is_reportable_stop(child) =>
            {
                let sig = crate::ptrace::stop_status_signal(child).unwrap_or(SIGSTOP);
                return WaitScan::Report(*cpid, (sig as i32) << 8 | 0x7f, true);
            }
            _ => continue,
        }
    }
    WaitScan::NoneReady
}

pub fn wait4_current(
    target_pid: i64,
    options: u64,
) -> cyphera_kapi::KResult<Option<(Pid, u32, i32)>> {
    let cur_pid = current_pid();
    loop {
        let mut g = GLOBAL.lock();
        match wait4_scan(&g, cur_pid, target_pid, options) {
            WaitScan::NoChildren => return Err(cyphera_kapi::Errno::CHILD),
            WaitScan::Reap(rpid, status) => {
                let (child_u, child_s, child_cu, child_cs) = match g.processes.get(&rpid) {
                    Some(c) => (
                        c.cpu_times.total_utime_ns,
                        c.cpu_times.total_stime_ns,
                        c.cpu_times.cutime_ns,
                        c.cpu_times.cstime_ns,
                    ),
                    None => (0, 0, 0, 0),
                };
                let me = g.processes.get_mut(&cur_pid).unwrap();
                me.children.retain(|p| *p != rpid);
                me.trace.remove_tracee(rpid);
                me.cpu_times.cutime_ns = me
                    .cpu_times
                    .cutime_ns
                    .saturating_add(child_u)
                    .saturating_add(child_cu);
                me.cpu_times.cstime_ns = me
                    .cpu_times
                    .cstime_ns
                    .saturating_add(child_s)
                    .saturating_add(child_cs);
                drop(g);
                let mut stale: Option<(&'static str, usize)> = None;
                for (cpu, q_lock) in CPU_QUEUES.iter().enumerate() {
                    let q = q_lock.lock();
                    if q.current == Some(rpid) {
                        stale = Some(("current", cpu));
                        break;
                    }
                    if q.runnable.contains_pid(rpid) {
                        stale = Some(("runqueue", cpu));
                        break;
                    }
                }
                if let Some((slot, cpu)) = stale {
                    print_stale_pid_provenance(rpid, this_cpu(), "wait4_reap_drain");
                    panic!(
                        "[STALE-RQ] wait4 reap: pid {} still in {} on cpu {} at reap time",
                        rpid.0, slot, cpu,
                    );
                }
                let mut g = GLOBAL.lock();
                let removed = g.processes.remove(&rpid);
                drop(g);
                let caller_ns = process_pid_ns(cur_pid).unwrap_or_else(host_pid_ns);
                let local_in_caller = caller_ns.host_to_local_in(rpid);
                if let Some(boxed) = removed {
                    if let Some(pns) = boxed.namespaces.pid() {
                        crate::process_model::PidNamespace::drop_chain(&pns, rpid);
                    }
                    if let Some(root) = boxed.addr_space_root {
                        let root_phys = root.as_phys();
                        if !root_has_live_user(root_phys) {
                            crate::ipc::futex::drop_vmspace(root_phys);
                        }
                    }
                    drop(boxed);
                }
                return Ok(Some((rpid, local_in_caller, status)));
            }
            WaitScan::Report(rpid, status, is_trace_stop) => {
                if is_trace_stop {
                    if let Some(p) = g.processes.get_mut(&rpid) {
                        p.trace.mark_wait_consumed();
                    }
                }
                drop(g);
                let caller_ns = process_pid_ns(cur_pid).unwrap_or_else(host_pid_ns);
                let local_in_caller = caller_ns.host_to_local_in(rpid);
                return Ok(Some((rpid, local_in_caller, status)));
            }
            WaitScan::NoneReady => {
                drop(g);
                if options & WNOHANG != 0 {
                    return Ok(None);
                }
                let park_ctx = {
                    let mut q = CPU_QUEUES[this_cpu() as usize].lock();
                    let mut g = GLOBAL.lock();
                    match wait4_scan(&g, cur_pid, target_pid, options) {
                        WaitScan::NoneReady => {
                            let me = g.processes.get_mut(&cur_pid).unwrap();
                            me.wait_sites.child_exit.enqueue(cur_pid);
                            let _ = q.current.take();
                            bank_slice_off_cpu(me);
                            me.state.0 = ProcessState::Parked;
                            set_sched_owner(
                                me,
                                SchedOwner::Parked {
                                    waitq_addr: &me.wait_sites.child_exit as *const _ as usize,
                                },
                                "wait4_park",
                            );
                            Some((
                                me.task.0.context_ptr(),
                                me.task.0.xsave_ptr(),
                                me.task.0.kstack_bounds(),
                            ))
                        }
                        _ => None,
                    }
                };
                let (cur_ctx, cur_xsave, cur_kstack) = match park_ctx {
                    Some(c) => c,
                    None => continue,
                };
                park_current_off_cpu("wait4_park", cur_pid, cur_kstack, cur_ctx, cur_xsave);
                let other_signal = {
                    let g = GLOBAL.lock();
                    g.processes
                        .get(&cur_pid)
                        .map(|p| {
                            let deliverable = p.signals.deliverable();
                            deliverable & !(1u64 << SIGCHLD) != 0
                        })
                        .unwrap_or(false)
                };
                if other_signal {
                    return Err(cyphera_kapi::Errno::INTR);
                }
            }
        }
    }
}

fn exit_status_code(code: i32) -> i32 {
    (((code as u32) & 0xff) << 8) as i32
}

fn fault_status_code() -> i32 {
    crate::process_model::SIGSEGV as i32
}
