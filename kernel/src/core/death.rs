use super::*;

type TaskExitHook = fn(u64, crate::process_model::Pid, u64, u64);
type AddrSpaceReleaseHook = fn(
    &alloc::sync::Arc<crate::process_model::AddressSpace>,
    Option<&alloc::sync::Arc<crate::process_model::IpcNamespace>>,
);
static TASK_EXIT_HOOK: frame::sync::SpinIrq<Option<TaskExitHook>> = frame::sync::SpinIrq::new(None);
static ADDR_SPACE_RELEASE_HOOK: frame::sync::SpinIrq<Option<AddrSpaceReleaseHook>> =
    frame::sync::SpinIrq::new(None);

pub fn register_task_exit_hook(f: TaskExitHook) {
    *TASK_EXIT_HOOK.lock() = Some(f);
}

pub fn register_addr_space_release_hook(f: AddrSpaceReleaseHook) {
    *ADDR_SPACE_RELEASE_HOOK.lock() = Some(f);
}

fn run_task_exit_hook(
    vmspace_id: u64,
    pid: crate::process_model::Pid,
    clear_child_tid: u64,
    robust_list: u64,
) {
    let h = *TASK_EXIT_HOOK.lock();
    if let Some(f) = h {
        f(vmspace_id, pid, clear_child_tid, robust_list);
    }
}

fn run_addr_space_release_hook(
    a: &alloc::sync::Arc<crate::process_model::AddressSpace>,
    ns: Option<&alloc::sync::Arc<crate::process_model::IpcNamespace>>,
) {
    let h = *ADDR_SPACE_RELEASE_HOOK.lock();
    if let Some(f) = h {
        f(a, ns);
    }
}

pub fn exit_group_current(tf: &mut TrapFrame, code: i32) -> ! {
    let cur_pid = current_pid();
    let tgid = {
        let g = GLOBAL.lock();
        g.processes.get(&cur_pid).map(|p| p.tgid).unwrap_or(cur_pid)
    };

    let live_peers: alloc::vec::Vec<Pid> = {
        let mut g = GLOBAL.lock();
        let peers: alloc::vec::Vec<Pid> = g
            .processes
            .iter()
            .filter(|(pid, p)| {
                **pid != cur_pid
                    && p.tgid == tgid
                    && !matches!(
                        p.state.0,
                        ProcessState::Zombie(_)
                            | ProcessState::KilledByFault { .. }
                            | ProcessState::KilledBySignal { .. }
                    )
            })
            .map(|(pid, _)| *pid)
            .collect();
        if tgid != cur_pid {
            if let Some(leader) = g.processes.get_mut(&tgid) {
                if leader.lifecycle.pending_exit().is_none() {
                    leader
                        .lifecycle
                        .set_pending_exit(ProcessState::Zombie(code));
                }
            }
        }
        peers
    };
    for peer in live_peers {
        let _ = send_signal(peer, SIGKILL);
    }
    exit_current(tf, code)
}

pub(crate) fn publish_corpse(dead: Pid) {
    let (final_state, parent, exit_waiters, is_leader) = {
        let mut g = GLOBAL.lock();
        let Some(p) = g.processes.get_mut(&dead) else {
            return;
        };
        let Some(st) = p.lifecycle.take_pending_exit() else {
            return;
        };
        set_state(p, st.clone(), "death");
        let exit_waiters = p.wait_sites.exit_waiters.drain();
        let is_leader = p.tgid == dead;
        (st, p.parent, exit_waiters, is_leader)
    };
    wake_tracer_on_exit(dead);
    for w in exit_waiters {
        let _ = wake_pid(w);
    }
    if !is_leader {
        reap_thread_corpse(dead);
        return;
    }
    if parent.is_some() {
        let (code, status) = match final_state {
            ProcessState::Zombie(c) => (CLD_EXITED, c),
            ProcessState::KilledBySignal { signal } => (CLD_KILLED, signal as i32),
            ProcessState::KilledByFault { vector, .. } => (CLD_KILLED, 128 + vector as i32),
            _ => return,
        };
        notify_parent_status_change(dead, code, status);
    }
}

fn reap_thread_corpse(dead: Pid) {
    let stale = crate::core::find_stale_scheduled(dead);
    if let Some((slot, cpu)) = stale {
        print_stale_pid_provenance(dead, this_cpu(), "thread_corpse_reap");
        panic!(
            "[STALE-RQ] thread corpse reap: pid {} still in {} on cpu {} at reap time",
            dead.0, slot, cpu,
        );
    }
    let removed = {
        let mut g = GLOBAL.lock();
        g.processes.remove(&dead)
    };
    if let Some(boxed) = removed {
        if let Some(pns) = boxed.namespaces.pid() {
            crate::process_model::PidNamespace::drop_chain(&pns, dead);
        }
        if let Some(root) = boxed.addr_space_root {
            let root_phys = root.as_phys();
            if !root_has_live_user(root_phys) {
                crate::ipc::futex::drop_vmspace(root_phys);
            }
        }
        drop(boxed);
    }
}

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

pub(crate) fn release_addr_space_user(
    addr_space: &alloc::sync::Arc<crate::process_model::AddressSpace>,
    ipc_ns: Option<&alloc::sync::Arc<crate::process_model::IpcNamespace>>,
) {
    if addr_space
        .live_users
        .fetch_sub(1, core::sync::atomic::Ordering::AcqRel)
        == 1
    {
        run_addr_space_release_hook(addr_space, ipc_ns);
    }
}

fn snapshot_addr_space_release_if_live(
    proc: &crate::process_model::Process,
) -> Option<(
    alloc::sync::Arc<crate::process_model::AddressSpace>,
    Option<alloc::sync::Arc<crate::process_model::IpcNamespace>>,
)> {
    let live = !matches!(
        proc.state.0,
        ProcessState::Zombie(_)
            | ProcessState::KilledByFault { .. }
            | ProcessState::KilledBySignal { .. }
    );
    if live {
        proc.addr_space.clone().map(|a| (a, proc.namespaces.ipc()))
    } else {
        None
    }
}

pub fn exit_current(_tf: &mut TrapFrame, code: i32) -> ! {
    let cur = {
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        q.current.take().expect("exit_current: no current")
    };

    let (clear_child_tid_addr, robust_list_head, vmspace_id) = {
        let g = GLOBAL.lock();
        let proc = g.processes.get(&cur).unwrap();
        (
            proc.memory.clear_child_tid(),
            proc.memory.robust_list_head(),
            proc.addr_space_root.map(|f| f.as_phys()).unwrap_or(0),
        )
    };
    if vmspace_id != 0 {
        run_task_exit_hook(vmspace_id, cur, clear_child_tid_addr, robust_list_head);
    }
    {
        let g = GLOBAL.lock();
        if let Some(p) = g.processes.get(&cur) {
            if let crate::process_model::SchedClass::Deadline {
                runtime_ns: rt,
                period_ns: pe,
                ..
            } = p.sched.sched_class
            {
                let home = p.sched.home_cpu as usize;
                drop(g);
                CPU_QUEUES[home]
                    .lock()
                    .runnable
                    .release_dl_bandwidth(rt, pe);
                crate::core::timeout::cancel_callback(cur.raw() as u64);
            }
        }
    }
    crate::core::timeout::drop_pid(cur);
    crate::core::timeout::cancel_callback((cur.raw() as u64) | (1u64 << 63));
    crate::syscall::posix_timer::clear_timers(cur);
    crate::vfs::locks::posix::drop_owner(cur);

    let dying_fds = {
        let mut g = GLOBAL.lock();
        if let Some(proc) = g.processes.get_mut(&cur) {
            if Arc::strong_count(&proc.fds) == 1 {
                Some(core::mem::replace(
                    &mut proc.fds,
                    Arc::new(crate::vfs::fd::FdTable::new()),
                ))
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some(fds) = dying_fds {
        fds.close_all();
        drop(fds);
    }

    let as_release = {
        let mut g = GLOBAL.lock();
        let proc = g.processes.get_mut(&cur).unwrap();
        let as_release = snapshot_addr_space_release_if_live(proc);
        if proc.lifecycle.pending_exit().is_none() {
            proc.lifecycle.set_pending_exit(ProcessState::Zombie(code));
        }
        set_sched_owner(proc, SchedOwner::Zombie, "exit_current");
        as_release
    };
    if let Some((a, ipc)) = as_release {
        release_addr_space_user(&a, ipc.as_ref());
    }
    crate::core::tty::session_leader_exit(cur);
    handle_dying_children(cur);
    crate::core::tty::handle_orphaned_pgrps_on_exit(cur);
    if let Some(cg) = process_cgroup(cur) {
        let charged = process_charged_bytes(cur);
        if charged > 0 {
            cg.uncharge_memory(charged);
        }
        cg.detach_pid(cur);
    }
    drain_vfork_done(cur);
    detach_orphaned_tracees(cur);

    let cpu = this_cpu() as usize;
    let idle_ctx_ptr: *mut Context = {
        let mut q = CPU_QUEUES[cpu].lock();
        q.pending_corpse = Some(cur);
        &mut q.idle_ctx as *mut Context
    };
    let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
    let mut throwaway = Context::bootstrap();
    task::switch_to_ctx(
        &mut throwaway as *mut Context,
        idle_ctx_ptr,
        idle_xsave,
        idle_xsave,
    );
    unreachable!("exit_current resumed dying task");
}

pub fn terminate_current_with_signal(signal: u32) -> ! {
    let cur = {
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        q.current
            .take()
            .expect("terminate_current_with_signal: no current")
    };

    let (clear_child_tid_addr, robust_list_head, vmspace_id) = {
        let g = GLOBAL.lock();
        let proc = g.processes.get(&cur).unwrap();
        (
            proc.memory.clear_child_tid(),
            proc.memory.robust_list_head(),
            proc.addr_space_root.map(|f| f.as_phys()).unwrap_or(0),
        )
    };
    if vmspace_id != 0 {
        run_task_exit_hook(vmspace_id, cur, clear_child_tid_addr, robust_list_head);
    }
    crate::core::timeout::drop_pid(cur);
    crate::syscall::posix_timer::clear_timers(cur);
    crate::vfs::locks::posix::drop_owner(cur);

    let as_release = {
        let mut g = GLOBAL.lock();
        let proc = g.processes.get_mut(&cur).unwrap();
        let as_release = snapshot_addr_space_release_if_live(proc);
        if proc.lifecycle.pending_exit().is_none() {
            proc.lifecycle
                .set_pending_exit(ProcessState::KilledBySignal { signal });
        }
        frame::println!(
            "[sched] pid {} killed by signal {} on cpu {}",
            cur.0,
            signal,
            this_cpu()
        );
        as_release
    };
    if let Some((a, ipc)) = as_release {
        release_addr_space_user(&a, ipc.as_ref());
    }
    crate::core::tty::session_leader_exit(cur);
    crate::core::tty::handle_orphaned_pgrps_on_exit(cur);
    if let Some(cg) = process_cgroup(cur) {
        let charged = process_charged_bytes(cur);
        if charged > 0 {
            cg.uncharge_memory(charged);
        }
        cg.detach_pid(cur);
    }
    drain_vfork_done(cur);
    detach_orphaned_tracees(cur);

    let cpu = this_cpu() as usize;
    let idle_ctx_ptr: *mut Context = {
        let mut q = CPU_QUEUES[cpu].lock();
        q.pending_corpse = Some(cur);
        &mut q.idle_ctx as *mut Context
    };
    let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
    let mut throwaway = Context::bootstrap();
    task::switch_to_ctx(
        &mut throwaway as *mut Context,
        idle_ctx_ptr,
        idle_xsave,
        idle_xsave,
    );
    unreachable!("terminate_current_with_signal resumed dying task");
}

fn handle_dying_children(cur: Pid) {
    use core::sync::atomic::Ordering;
    let children: alloc::vec::Vec<Pid> = {
        let g = GLOBAL.lock();
        g.processes
            .get(&cur)
            .map(|p| p.children.clone())
            .unwrap_or_default()
    };
    if children.is_empty() {
        return;
    }
    let new_parent: Pid = {
        let g = GLOBAL.lock();
        let mut walk = g.processes.get(&cur).and_then(|p| p.parent);
        let mut found: Option<Pid> = None;
        let mut depth = 0;
        while let Some(p) = walk {
            if depth > 1024 {
                break;
            }
            depth += 1;
            match g.processes.get(&p) {
                Some(proc) => {
                    if proc.lifecycle.child_subreaper()
                        && !matches!(proc.state.0, ProcessState::Zombie(_))
                    {
                        found = Some(p);
                        break;
                    }
                    walk = proc.parent;
                }
                None => break,
            }
        }
        found.unwrap_or(Pid(1))
    };

    for child in children {
        let pdeathsig = {
            let g = GLOBAL.lock();
            g.processes
                .get(&child)
                .map(|p| p.pdeathsig.load(Ordering::Relaxed))
                .unwrap_or(0)
        };
        if pdeathsig != 0 && pdeathsig < 64 {
            let info = crate::core::signal::SigInfo::for_kill(pdeathsig, cur.raw());
            let _ = send_signal_with_info(child, pdeathsig, info);
        }
        {
            let mut g = GLOBAL.lock();
            if let Some(c_proc) = g.processes.get_mut(&child) {
                c_proc.parent = Some(new_parent);
            }
            if let Some(np) = g.processes.get_mut(&new_parent) {
                if !np.children.contains(&child) {
                    np.children.push(child);
                }
            }
        }
    }
}
