use super::*;

pub extern "C" fn first_launch_trampoline() -> ! {
    use crate::process_model::FirstLaunch;
    let pid = current_pid();
    let launch = {
        let mut g = GLOBAL.lock();
        let proc = g.processes.get_mut(&pid).unwrap();
        proc.first_launch
            .take()
            .expect("first_launch: no pending launch")
    };
    match launch {
        FirstLaunch::Fresh {
            entry,
            user_stack_top,
        } => start_user_process(entry, user_stack_top),
        FirstLaunch::Fork { tf } => frame::user::resume_user_from_tf(&tf),
    }
}

fn install_kernel_rsp(top: u64) {
    frame::cpu::set_kernel_stack(top);
    frame::user::install_task_kernel_rsp(top);
}

pub fn enter_scheduler_bsp() -> ! {
    scheduler_loop()
}

fn scheduler_loop() -> ! {
    frame::cpu::enable_interrupts();

    loop {
        let corpse = CPU_QUEUES[this_cpu() as usize].lock().pending_corpse.take();
        if let Some(dead) = corpse {
            publish_corpse(dead);
        }
        let (pick, src_min_vr) = {
            let mut q = CPU_QUEUES[this_cpu() as usize].lock();
            let p = q.runnable.pick_next(!rt_throttled());
            if let Some(pid) = p {
                record_dequeue(pid);
            }
            (p, q.runnable.cfs_min_vruntime())
        };
        let pid = match pick {
            Some(p) => {
                frame::intr::lapic::arm_periodic();
                p
            }
            None => {
                if all_processes_done() {
                    qemu_exit_for_state();
                }
                idle_halt();
                continue;
            }
        };

        let (allowed, affinity) = {
            let g = GLOBAL.lock();
            match g.processes.get(&pid) {
                Some(p) => (
                    affinity_allows(p.sched.cpu_affinity, this_cpu()),
                    p.sched.cpu_affinity,
                ),
                None => (true, u64::MAX),
            }
        };
        if !allowed {
            let target = pick_home_cpu_in(affinity);
            if target != this_cpu() {
                migrate_dispatched_to(pid, target, src_min_vr);
                continue;
            }
        }

        switch_to_pid(pid);
    }
}

fn migrate_dispatched_to(pid: Pid, target: u32, src_min_vr: u64) {
    let mut q = CPU_QUEUES[target as usize].lock();
    let dst_min_vr = q.runnable.cfs_min_vruntime();
    let mut g = GLOBAL.lock();
    let proc = match g.processes.get_mut(&pid) {
        Some(p) => p,
        None => return,
    };
    if matches!(
        proc.state.0,
        ProcessState::Zombie(_)
            | ProcessState::KilledByFault { .. }
            | ProcessState::KilledBySignal { .. }
    ) {
        return;
    }
    proc.sched.home_cpu = target;
    set_sched_owner(
        proc,
        SchedOwner::Runnable { cpu: target },
        "affinity_migrate",
    );
    if matches!(proc.sched.sched_class, SchedClass::Cfs) {
        proc.sched.vruntime = proc
            .sched
            .vruntime
            .saturating_sub(src_min_vr)
            .saturating_add(dst_min_vr);
    }
    let placed = q
        .runnable
        .enqueue(pid, enqueue_data_from_proc(proc), CfsPlace::Continuing);
    proc.sched.vruntime = placed;
    record_enqueue(pid, "affinity_migrate", proc);
    drop(g);
    drop(q);
    send_resched_ipi(target);
}

pub(crate) fn park_current_off_cpu(
    site: &'static str,
    cur_pid: Pid,
    cur_kstack: (u64, u64),
    cur_ctx: *mut Context,
    cur_xsave: *mut u8,
) {
    let cpu = this_cpu() as usize;
    let idle_ctx_ptr: *mut Context = {
        let mut q = CPU_QUEUES[cpu].lock();
        &mut q.idle_ctx as *mut Context
    };
    let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
    checked_save_into_task(
        site,
        cur_pid,
        cur_kstack,
        cur_ctx,
        idle_ctx_ptr,
        cur_xsave,
        idle_xsave,
    );
}

fn checked_save_into_task(
    site: &'static str,
    prev_pid: Pid,
    prev_kstack: (u64, u64),
    prev_ctx: *mut Context,
    next_ctx: *mut Context,
    prev_xsave: *mut u8,
    next_xsave: *mut u8,
) {
    let rsp = frame::cpu::task::current_rsp();
    let (lo, hi) = prev_kstack;
    if rsp < lo || rsp >= hi {
        panic!(
            "[BAD_SAVE_TARGET] site={site} cpu={} prev_pid={} running_rsp=0x{:x} expected=[0x{:x}..0x{:x}) prev_ctx=0x{:x} next_ctx=0x{:x}",
            this_cpu(),
            prev_pid.0,
            rsp,
            lo,
            hi,
            prev_ctx as usize,
            next_ctx as usize,
        );
    }
    task::switch_to_ctx(prev_ctx, next_ctx, prev_xsave, next_xsave);
}

fn try_steal_one_to_local() -> Option<Pid> {
    let me = this_cpu() as usize;
    for off in 1..MAX_CPUS {
        let peer = (me + off) % MAX_CPUS;
        let (stolen, peer_min_vr) = {
            let mut peer_q = CPU_QUEUES[peer].lock();
            let mut g = GLOBAL.lock();
            let peer_min = peer_q.runnable.cfs_min_vruntime();
            let cand = peer_q.runnable.pick_next(!rt_throttled());
            let stolen = match cand {
                Some(pid) => {
                    record_dequeue(pid);
                    let skip = g
                        .processes
                        .get(&pid)
                        .map(|p| {
                            p.sched.parking_unsaved
                                || !affinity_allows(p.sched.cpu_affinity, me as u32)
                                || matches!(
                                    p.state.0,
                                    ProcessState::Zombie(_)
                                        | ProcessState::KilledByFault { .. }
                                        | ProcessState::KilledBySignal { .. }
                                )
                        })
                        .unwrap_or(false);
                    if skip {
                        if let Some(proc) = g.processes.get_mut(&pid) {
                            let placed = peer_q.runnable.enqueue(
                                pid,
                                enqueue_data_from_proc(proc),
                                CfsPlace::Continuing,
                            );
                            proc.sched.vruntime = placed;
                            record_enqueue(pid, "try_steal/skip", proc);
                        }
                        None
                    } else {
                        Some(pid)
                    }
                }
                None => None,
            };
            (stolen, peer_min)
        };
        if let Some(pid) = stolen {
            let mut q = CPU_QUEUES[me].lock();
            let me_min_vr = q.runnable.cfs_min_vruntime();
            let mut g = GLOBAL.lock();
            let proc = g.processes.get_mut(&pid)?;
            if matches!(
                proc.state.0,
                ProcessState::Zombie(_)
                    | ProcessState::KilledByFault { .. }
                    | ProcessState::KilledBySignal { .. }
            ) {
                return None;
            }
            proc.sched.home_cpu = me as u32;
            set_sched_owner(
                proc,
                SchedOwner::Runnable { cpu: me as u32 },
                "try_steal_one_to_local",
            );
            if matches!(proc.sched.sched_class, SchedClass::Cfs) {
                let adjusted = proc
                    .sched
                    .vruntime
                    .saturating_sub(peer_min_vr)
                    .saturating_add(me_min_vr);
                proc.sched.vruntime = adjusted;
            }
            let placed =
                q.runnable
                    .enqueue(pid, enqueue_data_from_proc(proc), CfsPlace::Continuing);
            proc.sched.vruntime = placed;
            record_enqueue(pid, "try_steal_one_to_local", proc);
            return Some(pid);
        }
    }
    None
}

fn switch_to_pid(pid: Pid) {
    CTXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
    let _irq = frame::sync::IrqGuard::new();

    let (task_ctx, task_xsave, kstack_top, next_vm, next_root, rseq_addr, rseq_len, rseq_cpu_id) = {
        let mut g = GLOBAL.lock();
        let proc = match g.processes.get_mut(&pid) {
            Some(p) => p,
            None => {
                drop(g);
                print_stale_pid_provenance(pid, this_cpu(), "switch_to_pid");
                panic!(
                    "[STALE-RQ] switch_to_pid: pid {} no longer in g.processes (picker_cpu={})",
                    pid.0,
                    this_cpu(),
                );
            }
        };
        if matches!(
            proc.state.0,
            ProcessState::Zombie(_)
                | ProcessState::KilledByFault { .. }
                | ProcessState::KilledBySignal { .. }
        ) {
            return;
        }
        proc.state.0 = ProcessState::Running;
        let cpu = this_cpu();
        set_sched_owner(proc, SchedOwner::Running { cpu }, "switch_to_pid");
        proc.sched.last_run_ns = frame::cpu::clock::nanos_since_boot();
        frame::cpu::set_user_tls_base(proc.memory.tls_base());
        (
            proc.task.0.context_ptr(),
            proc.task.0.xsave_ptr(),
            proc.task.0.kstack_top(),
            proc.vmspace(),
            proc.addr_space_root,
            proc.memory.rseq_addr(),
            proc.memory.rseq_len(),
            this_cpu(),
        )
    };

    {
        let (saved_rsp, saved_rip) = task::peek_saved_rsp_and_rip(task_ctx);
        if saved_rip < 0x1000 || saved_rip == u64::MAX {
            let (kbot, ktop) = {
                let g = GLOBAL.lock();
                match g.processes.get(&pid) {
                    Some(p) => (p.task.0.kstack_bottom(), p.task.0.kstack_top()),
                    None => (0, 0),
                }
            };
            print_stale_pid_provenance(pid, this_cpu(), "switch_to_pid_BADCTX");
            panic!(
                "[BADCTX] switch_to_pid: pid {} cpu {} saved_rsp=0x{:x} saved_rip=0x{:x} kstack=[0x{:x}..0x{:x}) in_range={}",
                pid.0,
                this_cpu(),
                saved_rsp,
                saved_rip,
                kbot,
                ktop,
                saved_rsp >= kbot && saved_rsp < ktop,
            );
        }
    }

    if rseq_addr != 0 && rseq_len >= 32 {
        let bytes = rseq_cpu_id.to_le_bytes();
        let _ = frame::user::copy_to_user(rseq_addr, &bytes);
        let _ = frame::user::copy_to_user(rseq_addr + 4, &bytes);
    }

    let _old_vmspace = if let (Some(_vm_arc), Some(root)) = (next_vm.as_ref(), next_root) {
        frame::mm::vm::VmSpace::activate_root(root);
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        q.current = Some(pid);
        core::mem::replace(&mut q.active_vmspace, next_vm)
    } else {
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        q.current = Some(pid);
        None
    };

    install_kernel_rsp(kstack_top);
    let cpu = this_cpu() as usize;
    let idle_ctx_ptr: *mut Context = {
        let mut q = CPU_QUEUES[cpu].lock();
        &mut q.idle_ctx as *mut Context
    };
    let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
    task::switch_to_ctx(idle_ctx_ptr, task_ctx, idle_xsave, task_xsave);
}

fn idle_halt() {
    const IDLE_MAX_SLEEP_NS: u64 = 100_000_000;
    const IDLE_MIN_SLEEP_NS: u64 = 1_000_000;
    let now = frame::cpu::clock::nanos_since_boot();
    let next = crate::core::timeout::next_deadline_ns().unwrap_or(u64::MAX);
    let until = next.saturating_sub(now);
    let delta = until.clamp(IDLE_MIN_SLEEP_NS, IDLE_MAX_SLEEP_NS);
    frame::intr::lapic::arm_oneshot_ns(delta);
    frame::cpu::idle_halt();
    let cpu = this_cpu() as usize;
    let has_work = !CPU_QUEUES[cpu].lock().runnable.is_empty();
    if has_work {
        frame::intr::lapic::arm_periodic();
    }
}

#[inline(never)]
fn all_processes_done() -> bool {
    if !EVER_REGISTERED.load(Ordering::Acquire) {
        return false;
    }
    let g = GLOBAL.lock();
    let mut saw_user = false;
    for p in g.processes.values() {
        if p.kind == ProcessKind::Kernel {
            continue;
        }
        saw_user = true;
        if !matches!(
            p.state.0,
            ProcessState::Zombie(_)
                | ProcessState::KilledByFault { .. }
                | ProcessState::KilledBySignal { .. }
        ) {
            return false;
        }
    }
    saw_user
}

fn qemu_exit_for_state() -> ! {
    let any_real_failure = {
        let g = GLOBAL.lock();
        g.processes
            .values()
            .any(|p| matches!(p.state.0, ProcessState::Zombie(c) if c != 0))
    };
    frame::println!("[sched] all processes exited");
    if any_real_failure {
        exit(ExitCode::Failed);
    } else {
        exit(ExitCode::Success);
    }
}

pub fn start_first() -> ! {
    scheduler_loop()
}

pub extern "C" fn ap_main(cpu_id: u64) -> ! {
    frame::println!("ap{cpu_id}: online");
    scheduler_loop()
}

pub fn yield_current(_tf: &mut TrapFrame) {
    let (cur_pid, cur_ctx, cur_xsave, cur_kstack) = {
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        let cur = q.current.take().expect("yield_current: no current");
        let now_ns = frame::cpu::clock::nanos_since_boot();
        let mut g = GLOBAL.lock();
        let proc = g.processes.get_mut(&cur).unwrap();
        proc.state.0 = ProcessState::Runnable;
        set_sched_owner(
            proc,
            SchedOwner::Runnable { cpu: this_cpu() },
            "yield_current",
        );
        proc.sched.parking_unsaved = true;
        let delta = now_ns.saturating_sub(proc.sched.last_run_ns);
        charge_runtime(proc, delta);
        proc.sched.last_run_ns = now_ns;
        let placed = q
            .runnable
            .enqueue(cur, enqueue_data_from_proc(proc), CfsPlace::Continuing);
        proc.sched.vruntime = placed;
        record_enqueue(cur, "yield_current", proc);
        (
            cur,
            proc.task.0.context_ptr(),
            proc.task.0.xsave_ptr(),
            proc.task.0.kstack_bounds(),
        )
    };

    park_current_off_cpu("yield_current", cur_pid, cur_kstack, cur_ctx, cur_xsave);
}

pub fn on_tick(is_timer: bool) {
    if !is_timer {
        RESCHED_TICK_COUNTER.fetch_add(1, Ordering::Relaxed);
    }
    if is_timer {
        account_tick_jiffy();
        sample_loadavg_if_due();
    }
    rt_bandwidth_tick();

    if is_timer {
        crate::net::signal_pump_tick();
    }

    crate::console::poll_rx_from_tick();

    crate::device::input::poll_from_tick();

    let now_ns = frame::cpu::clock::nanos_since_boot();
    crate::core::timeout::wake_expired(now_ns);
    crate::core::timeout::wake_expired_callbacks(now_ns);

    cgroup_replenish_throttled(now_ns);

    {
        let cpu = this_cpu() as usize;
        let (no_current, empty) = {
            let q = CPU_QUEUES[cpu].lock();
            (q.current.is_none(), q.runnable.is_empty())
        };
        if no_current && empty {
            let _ = try_steal_one_to_local();
            return;
        }
    }

    let switch_targets = {
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        let cur = match q.current {
            Some(p) => p,
            None => return,
        };
        let runqueue_empty = q.runnable.is_empty();
        let now_ns = frame::cpu::clock::nanos_since_boot();
        let mut force_throttle = false;
        {
            let mut g = GLOBAL.lock();
            if let Some(cur_proc) = g.processes.get_mut(&cur) {
                let delta = now_ns.saturating_sub(cur_proc.sched.last_run_ns);
                let rt_top = q.runnable.rt_top_priority();
                match cur_proc.sched.sched_class {
                    SchedClass::Cfs => {
                        let cgroup_throttled_now = if let Some(cg) = cur_proc.cgroup.clone() {
                            let mut cpu_ctl = cg.cpu.lock();
                            cpu_ctl.charge_cpu_runtime(delta, now_ns)
                        } else {
                            false
                        };
                        if cgroup_throttled_now {
                            bank_cpu_time(cur_proc, delta);
                            cur_proc.sched.last_run_ns = now_ns;
                            cur_proc.state.0 = ProcessState::CgroupThrottled;
                            force_throttle = true;
                        } else if runqueue_empty {
                            charge_runtime(cur_proc, delta);
                            cur_proc.sched.last_run_ns = now_ns;
                            return;
                        } else if rt_top.is_some() {
                            charge_runtime(cur_proc, delta);
                            cur_proc.sched.last_run_ns = now_ns;
                        } else {
                            charge_runtime(cur_proc, delta);
                            cur_proc.sched.last_run_ns = now_ns;
                            let leftmost_vr = q.runnable.cfs_leftmost_vruntime_pub();
                            let cur_vr = cur_proc.sched.vruntime;
                            let wake_preempt =
                                leftmost_vr.saturating_add(SCHED_WAKEUP_GRANULARITY_NS) < cur_vr;
                            if !wake_preempt {
                                let slice = q.runnable.cfs_slice_for(cur_proc.sched.weight);
                                if delta < slice {
                                    return;
                                }
                            }
                        }
                    }
                    SchedClass::Rt {
                        priority,
                        round_robin,
                    } => {
                        if runqueue_empty {
                            bank_cpu_time(cur_proc, delta);
                            cur_proc.sched.last_run_ns = now_ns;
                            return;
                        }
                        let preempted_by_higher = rt_top.map(|t| t > priority).unwrap_or(false);
                        if preempted_by_higher {
                            bank_cpu_time(cur_proc, delta);
                            cur_proc.sched.last_run_ns = now_ns;
                        } else if round_robin {
                            let peer_at_same = rt_top.map(|t| t == priority).unwrap_or(false);
                            if !peer_at_same || delta < SCHED_RR_TIMESLICE_NS {
                                return;
                            }
                            bank_cpu_time(cur_proc, delta);
                            cur_proc.sched.last_run_ns = now_ns;
                        } else {
                            return;
                        }
                    }
                    SchedClass::Deadline { .. } => {
                        let consumed = delta.min(cur_proc.sched.dl_runtime_remaining);
                        cur_proc.sched.dl_runtime_remaining =
                            cur_proc.sched.dl_runtime_remaining.saturating_sub(consumed);
                        bank_cpu_time(cur_proc, delta);
                        cur_proc.sched.last_run_ns = now_ns;
                        if cur_proc.sched.dl_runtime_remaining == 0 {
                            cur_proc.sched.dl_throttled = true;
                            cur_proc.state.0 = ProcessState::DlThrottled;
                            force_throttle = true;
                        } else if runqueue_empty {
                            return;
                        }
                    }
                }
            }
        }
        let next = match q.runnable.pick_next(!rt_throttled()) {
            Some(n) => {
                record_dequeue(n);
                n
            }
            None => {
                if force_throttle {
                    q.current = None;
                    let cpu_idx = this_cpu() as usize;
                    let idle_ctx_ptr: *mut Context = &mut q.idle_ctx as *mut Context;
                    let idle_xsave = task::bootstrap_xsave_ptr(cpu_idx as u32);
                    let mut g = GLOBAL.lock();
                    let cur_proc = match g.processes.get_mut(&cur) {
                        Some(p) => p,
                        None => return,
                    };
                    set_sched_owner(
                        cur_proc,
                        SchedOwner::Parked { waitq_addr: 0 },
                        "on_tick/throttle_idle",
                    );
                    let cur_ctx = cur_proc.task.0.context_ptr();
                    let cur_xsave = cur_proc.task.0.xsave_ptr();
                    let cur_kstack = cur_proc.task.0.kstack_bounds();
                    drop(g);
                    drop(q);
                    {
                        let mut q = CPU_QUEUES[cpu_idx].lock();
                        q.active_vmspace = None;
                    }
                    checked_save_into_task(
                        "on_tick/throttle_idle",
                        cur,
                        cur_kstack,
                        cur_ctx,
                        idle_ctx_ptr,
                        cur_xsave,
                        idle_xsave,
                    );
                    return;
                }
                return;
            }
        };
        {
            let allowed = {
                let g = GLOBAL.lock();
                g.processes
                    .get(&next)
                    .map(|p| affinity_allows(p.sched.cpu_affinity, this_cpu()))
                    .unwrap_or(true)
            };
            if !allowed {
                let mut g = GLOBAL.lock();
                if let Some(proc) = g.processes.get_mut(&next) {
                    let placed = q.runnable.enqueue(
                        next,
                        enqueue_data_from_proc(proc),
                        CfsPlace::Continuing,
                    );
                    proc.sched.vruntime = placed;
                    record_enqueue(next, "on_tick/affinity_skip", proc);
                }
                return;
            }
        }
        debug_assert!(next != cur, "pick_next returned current task");
        q.current = Some(next);

        let mut g = GLOBAL.lock();
        let cur_proc = g.processes.get_mut(&cur).unwrap();
        if !force_throttle {
            cur_proc.state.0 = ProcessState::Runnable;
            set_sched_owner(
                cur_proc,
                SchedOwner::Runnable { cpu: this_cpu() },
                "on_tick/preempt(cur)",
            );
            cur_proc.sched.parking_unsaved = true;
            let placed =
                q.runnable
                    .enqueue(cur, enqueue_data_from_proc(cur_proc), CfsPlace::Continuing);
            cur_proc.sched.vruntime = placed;
            record_enqueue(cur, "on_tick/preempt(cur)", cur_proc);
        } else {
            set_sched_owner(
                cur_proc,
                SchedOwner::Parked { waitq_addr: 0 },
                "on_tick/throttle_preempt",
            );
        }
        let cur_ctx = cur_proc.task.0.context_ptr();
        let cur_xsave = cur_proc.task.0.xsave_ptr();
        let cur_kstack = cur_proc.task.0.kstack_bounds();
        let next_proc = match g.processes.get_mut(&next) {
            Some(p) => p,
            None => {
                drop(g);
                drop(q);
                print_stale_pid_provenance(next, this_cpu(), "on_tick/preempt(next)");
                panic!(
                    "[STALE-RQ] on_tick/preempt(next): pid {} no longer in g.processes (picker_cpu={})",
                    next.0,
                    this_cpu(),
                );
            }
        };
        if matches!(
            next_proc.state.0,
            ProcessState::Zombie(_)
                | ProcessState::KilledByFault { .. }
                | ProcessState::KilledBySignal { .. }
        ) {
            let k = state_kind(&next_proc.state.0);
            drop(g);
            drop(q);
            print_stale_pid_provenance(next, this_cpu(), "on_tick/preempt(next)_DEAD");
            panic!(
                "[DEAD-RQ] on_tick/preempt(next): pid {} picked to run but state={} on cpu {} (resurrected dead task)",
                next.0,
                fmt_state_kind(k),
                this_cpu(),
            );
        }
        next_proc.state.0 = ProcessState::Running;
        set_sched_owner(
            next_proc,
            SchedOwner::Running { cpu: this_cpu() },
            "on_tick/preempt(next)",
        );
        next_proc.sched.last_run_ns = now_ns;
        let next_ctx = next_proc.task.0.context_ptr();
        let next_xsave = next_proc.task.0.xsave_ptr();
        let next_top = next_proc.task.0.kstack_top();
        let next_vm = next_proc.vmspace();
        let next_root = next_proc.addr_space_root;
        let next_tls_base = next_proc.memory.tls_base();
        Some((
            cur,
            cur_ctx,
            next_ctx,
            cur_xsave,
            next_xsave,
            next_top,
            next_vm,
            next_root,
            cur_kstack,
            next_tls_base,
        ))
    };

    if let Some((
        cur_pid_tick,
        cur_ctx,
        next_ctx,
        cur_xsave,
        next_xsave,
        next_top,
        next_vm,
        next_root,
        cur_kstack,
        next_tls_base,
    )) = switch_targets
    {
        {
            let (saved_rsp, saved_rip) = task::peek_saved_rsp_and_rip(next_ctx);
            if saved_rip < 0x1000 || saved_rip == u64::MAX {
                panic!(
                    "[BADCTX] on_tick/preempt(next): cpu={} saved_rsp=0x{:x} saved_rip=0x{:x}",
                    this_cpu(),
                    saved_rsp,
                    saved_rip,
                );
            }
        }
        let _old_vmspace = if let (Some(_vm_arc), Some(root)) = (next_vm.as_ref(), next_root) {
            frame::mm::vm::VmSpace::activate_root(root);
            let cpu = this_cpu() as usize;
            let mut q = CPU_QUEUES[cpu].lock();
            core::mem::replace(&mut q.active_vmspace, next_vm)
        } else {
            None
        };
        install_kernel_rsp(next_top);
        frame::cpu::set_user_tls_base(next_tls_base);
        checked_save_into_task(
            "on_tick/preempt",
            cur_pid_tick,
            cur_kstack,
            cur_ctx,
            next_ctx,
            cur_xsave,
            next_xsave,
        );
    }
}

fn cgroup_replenish_throttled(now_ns: u64) {
    use alloc::vec::Vec;
    let candidates: Vec<Pid> = {
        let g = GLOBAL.lock();
        g.processes
            .iter()
            .filter_map(|(pid, p)| {
                if p.state.0 == ProcessState::CgroupThrottled {
                    Some(*pid)
                } else {
                    None
                }
            })
            .collect()
    };
    for pid in candidates {
        let cg_opt = {
            let g = GLOBAL.lock();
            g.processes.get(&pid).and_then(|p| p.cgroup.clone())
        };
        let cg = match cg_opt {
            Some(c) => c,
            None => continue,
        };
        let elapsed = {
            let cpu_ctl = cg.cpu.lock();
            cpu_ctl.period_elapsed(now_ns)
        };
        if !elapsed {
            continue;
        }
        {
            let mut cpu_ctl = cg.cpu.lock();
            cpu_ctl.replenish(now_ns);
        }
        let home_opt = {
            let g = GLOBAL.lock();
            g.processes.get(&pid).map(|p| p.sched.home_cpu)
        };
        let home = match home_opt {
            Some(h) => h,
            None => continue,
        };
        let mut q = CPU_QUEUES[home as usize].lock();
        let mut g = GLOBAL.lock();
        if let Some(proc) = g.processes.get_mut(&pid) {
            if proc.state.0 == ProcessState::CgroupThrottled {
                proc.state.0 = ProcessState::Runnable;
                set_sched_owner(
                    proc,
                    SchedOwner::Runnable { cpu: home },
                    "cgroup_throttle_replenish",
                );
                let placed = q
                    .runnable
                    .enqueue(pid, enqueue_data_from_proc(proc), CfsPlace::Wake);
                proc.sched.vruntime = placed;
                record_enqueue(pid, "cgroup_throttle_replenish", proc);
            }
        }
        drop(g);
        drop(q);
        if home != this_cpu() {
            send_resched_ipi(home);
        }
    }
}
