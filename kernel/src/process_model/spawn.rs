use super::*;
use crate::core::*;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use frame::user::TrapFrame;

pub fn spawn_kthread(name: &str, entry: extern "C" fn() -> !) -> Pid {
    let pid = next_pid();
    let home_cpu = pick_home_cpu();
    let mut proc = Process::new_kthread(pid, entry);
    proc.sched.home_cpu = home_cpu;
    proc.identity.set_cmdline(name.as_bytes().to_vec());
    proc.cgroup = Some(crate::cgroup::root());

    GLOBAL.lock().processes.insert(pid, Box::new(proc));
    admit_task(pid, home_cpu, "spawn_kthread");
    EVER_REGISTERED.store(true, Ordering::Release);
    if home_cpu != this_cpu() {
        send_resched_ipi(home_cpu);
    }
    frame::println!(
        "[sched] kthread \"{}\" registered as pid {} on cpu {}",
        name,
        pid.0,
        home_cpu
    );
    pid
}

pub fn register(entry: u64, user_stack_top: u64, brk_start: u64) -> Pid {
    register_with_vmspace(None, entry, user_stack_top, brk_start)
}

pub fn register_with_vmspace(
    vmspace: Option<frame::mm::vm::VmSpace>,
    entry: u64,
    user_stack_top: u64,
    brk_start: u64,
) -> Pid {
    let pid = next_pid();
    let home_cpu = pick_home_cpu();
    let mut proc = Process::new(pid, entry, user_stack_top, brk_start);
    proc.sched.home_cpu = home_cpu;
    proc.addr_space_root = vmspace.as_ref().map(|v| v.root());
    proc.addr_space = vmspace.map(|v| crate::process_model::AddressSpace::new(v, pid, brk_start));

    if let Some(root) = crate::vfs::try_root_inode() {
        proc.files.set_cwd(CwdState {
            inode: root.clone(),
            path: String::from("/"),
        });
        if let Ok(console) =
            crate::vfs::path::resolve(&crate::vfs::path::Context::global(), &root, "/dev/console")
        {
            use crate::vfs::{OpenFile, OpenFlags};
            let stdin = Arc::new(OpenFile::new(console.clone(), OpenFlags::RDONLY));
            let stdout = Arc::new(OpenFile::new(console.clone(), OpenFlags::WRONLY));
            let stderr = Arc::new(OpenFile::new(console, OpenFlags::WRONLY));
            proc.fds.install_at(0, stdin);
            proc.fds.install_at(1, stdout);
            proc.fds.install_at(2, stderr);
        }
    }

    proc.cgroup = Some(crate::cgroup::root());
    proc.namespaces.set_pid(Some(host_pid_ns()));
    GLOBAL.lock().processes.insert(pid, Box::new(proc));
    crate::process_model::PidNamespace::assign_chain(&host_pid_ns(), pid);
    let _ = crate::cgroup::root().attach_pid(pid);
    admit_task(pid, home_cpu, "register_with_vmspace");
    EVER_REGISTERED.store(true, Ordering::Release);
    if home_cpu != this_cpu() {
        send_resched_ipi(home_cpu);
    }
    pid
}

#[allow(clippy::too_many_arguments)]
pub fn register_with_argv(
    vmspace: frame::mm::vm::VmSpace,
    entry: u64,
    user_stack_top: u64,
    brk_start: u64,
    exe_path: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    aux: &crate::loader::stack_init::AuxvInfo,
) -> cyphera_kapi::KResult<Pid> {
    let new_rsp =
        crate::loader::stack_init::build_user_stack(&vmspace, user_stack_top, argv, envp, aux)?;
    let pid = register_with_vmspace(Some(vmspace), entry, new_rsp, brk_start);
    let mut cmdline: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    for s in argv {
        cmdline.extend_from_slice(s);
        cmdline.push(0);
    }
    set_cmdline(pid, cmdline);
    set_exe_path(pid, exe_path.to_vec());
    Ok(pid)
}

pub fn fork_current(parent_tf: &TrapFrame, share_vmspace: bool) -> cyphera_kapi::KResult<Pid> {
    let parent_pid = current_pid();
    let child_pid = next_pid();
    let parent_affinity = GLOBAL
        .lock()
        .processes
        .get(&parent_pid)
        .map(|p| p.sched.cpu_affinity)
        .unwrap_or(u64::MAX);
    let home_cpu = pick_home_cpu_in(parent_affinity);

    enum ShareKind {
        File {
            inode_id: u64,
            offset_base: u64,
        },
        Shm {
            segment: Arc<crate::ipc::shm::ShmSegment>,
        },
    }
    let (child_vm, child_root) = if share_vmspace {
        let g = GLOBAL.lock();
        let parent = g
            .processes
            .get(&parent_pid)
            .ok_or(cyphera_kapi::Errno::INVAL)?;
        let arc = parent.vmspace().ok_or(cyphera_kapi::Errno::INVAL)?;
        let root = parent.addr_space_root.ok_or(cyphera_kapi::Errno::INVAL)?;
        (arc, root)
    } else {
        let child_vm = {
            let shareable: Vec<(u64, u64, ShareKind)> = {
                let g = GLOBAL.lock();
                let parent = g
                    .processes
                    .get(&parent_pid)
                    .ok_or(cyphera_kapi::Errno::INVAL)?;
                let m = parent
                    .addr_space
                    .as_ref()
                    .ok_or(cyphera_kapi::Errno::INVAL)?
                    .mmap
                    .lock();
                m.vmas
                    .iter()
                    .filter(|v| v.flags.contains(crate::process_model::VmaFlags::SHARED))
                    .filter_map(|v| match &v.backing {
                        crate::process_model::VmaBacking::File {
                            inode,
                            file_offset_base,
                        } => Some((
                            v.start,
                            v.end,
                            ShareKind::File {
                                inode_id: inode.inode_id(),
                                offset_base: *file_offset_base,
                            },
                        )),
                        crate::process_model::VmaBacking::Shm { segment, .. } => Some((
                            v.start,
                            v.end,
                            ShareKind::Shm {
                                segment: segment.clone(),
                            },
                        )),
                        crate::process_model::VmaBacking::Anonymous => None,
                    })
                    .collect()
            };
            let parent_vm_arc = {
                let g = GLOBAL.lock();
                let parent = g
                    .processes
                    .get(&parent_pid)
                    .ok_or(cyphera_kapi::Errno::INVAL)?;
                parent.vmspace().ok_or(cyphera_kapi::Errno::INVAL)?
            };
            let shared_ranges: Vec<(u64, u64)> =
                shareable.iter().map(|(lo, hi, _)| (*lo, *hi)).collect();
            let clone = {
                let mut parent_vm = parent_vm_arc.lock();
                let r = parent_vm.clone_user_half_phase1(&shared_ranges);
                drop(parent_vm);
                match r {
                    Ok(c) => c,
                    Err(_) => {
                        frame::cpu::tlb::shootdown_all();
                        return Err(cyphera_kapi::Errno::NOMEM);
                    }
                }
            };
            if clone.needs_shootdown() {
                frame::cpu::tlb::shootdown_all();
            }
            let (new_vm, shared_vaddrs) = {
                let mut parent_vm = parent_vm_arc.lock();
                let r = parent_vm.finish_cow_clone(clone);
                drop(parent_vm);
                match r {
                    Ok(v) => v,
                    Err(_) => {
                        frame::cpu::tlb::shootdown_all();
                        return Err(cyphera_kapi::Errno::NOMEM);
                    }
                }
            };
            for (_, _, kind) in &shareable {
                if let ShareKind::Shm { segment } = kind {
                    segment
                        .attached
                        .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
                }
            }
            for &v in &shared_vaddrs {
                for (lo, hi, kind) in &shareable {
                    if v >= *lo && v < *hi {
                        if let ShareKind::File {
                            inode_id,
                            offset_base,
                        } = kind
                        {
                            crate::fs::pagecache::pin(*inode_id, offset_base + (v - lo));
                        }
                        break;
                    }
                }
            }
            Arc::new(frame::sync::SpinIrq::new(new_vm))
        };
        let child_root = child_vm.lock().root();
        (child_vm, child_root)
    };

    let mut child_tf = parent_tf.clone();
    child_tf.rax = 0;

    let child = {
        let g = GLOBAL.lock();
        let parent = g
            .processes
            .get(&parent_pid)
            .ok_or(cyphera_kapi::Errno::INVAL)?;
        let task = SchedCell::new(frame::cpu::task::Task::spawn(first_launch_trampoline));
        let creds_snapshot = parent.creds.lock().clone();
        let sigactions_snapshot = *parent.sigactions.lock();
        let child_addr_space = if share_vmspace {
            let as_arc = parent
                .addr_space
                .as_ref()
                .ok_or(cyphera_kapi::Errno::INVAL)?
                .clone();
            as_arc
                .live_users
                .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            as_arc
        } else {
            parent
                .addr_space
                .as_ref()
                .ok_or(cyphera_kapi::Errno::INVAL)?
                .deep_copy_with_vmspace(child_vm)
        };
        Process {
            pid: child_pid,
            tgid: child_pid,
            identity: crate::process_model::IdentityContext::inherit(&parent.identity),
            creds: alloc::sync::Arc::new(frame::sync::SpinIrq::new(creds_snapshot)),
            parent: Some(parent_pid),
            state: SchedCell::new(ProcessState::Runnable),
            kind: ProcessKind::User,
            saved: parent.saved,
            memory: crate::process_model::MemoryContext::inherit(&parent.memory),
            fds: Arc::new(parent.fds.clone_for_child()),
            files: crate::process_model::FileContext::inherit(&parent.files),
            namespaces: crate::process_model::NamespaceContext::inherit(&parent.namespaces),
            cgroup: parent.cgroup.clone(),
            cgroup_charged_bytes: 0,
            security: crate::process_model::SecurityContext::inherit(&parent.security),
            signals: crate::process_model::SignalContext::inherit(&parent.signals),
            sigactions: Arc::new(frame::sync::SpinIrq::new(sigactions_snapshot)),
            task,
            first_launch: Some(FirstLaunch::Fork { tf: child_tf }),
            sched: SchedEntity {
                home_cpu,
                cpu_affinity: parent.sched.cpu_affinity,
                parking_unsaved: false,
                nice: parent.sched.nice,
                sched_class: parent.sched.sched_class,
                vruntime: parent.sched.vruntime,
                weight: parent.sched.weight,
                last_run_ns: 0,
                dl_runtime_remaining: 0,
                dl_absolute_deadline: 0,
                dl_next_replenish: 0,
                dl_throttled: false,
                pi_orig_class: None,
            },
            addr_space: Some(child_addr_space),
            addr_space_root: Some(child_root),
            sched_owner: SchedCell::new(crate::process_model::SchedOwner::None),
            children: Vec::new(),
            wait_sites: WaitSites::default(),
            lifecycle: crate::process_model::LifecycleContext::with_vfork_shared(share_vmspace),
            pdeathsig: core::sync::atomic::AtomicU32::new(0),
            name: [0u8; 16],
            rlimits: parent.rlimits,
            pi_blocked_on: None,
            pi_held: Vec::new(),
            cpu_times: CpuTimes::default(),
            trace: crate::process_model::TraceContext::default(),
        }
    };

    let child_pid_ns: Arc<crate::process_model::PidNamespace> = {
        let mut g = GLOBAL.lock();
        let parent_proc = g.processes.get_mut(&parent_pid).unwrap();
        if let Some(staged) = parent_proc.namespaces.take_pending_pid() {
            staged
        } else {
            parent_proc.namespaces.pid().unwrap_or_else(host_pid_ns)
        }
    };

    {
        let mut g = GLOBAL.lock();
        let mut child_box = Box::new(child);
        child_box.namespaces.set_pid(Some(child_pid_ns.clone()));
        if let Some(p) = g.processes.get_mut(&parent_pid) {
            if let Some(staged) = p.namespaces.take_pending_ipc() {
                child_box.namespaces.set_ipc(Some(staged));
            }
            if let Some(staged) = p.namespaces.take_pending_net() {
                child_box.namespaces.set_net(Some(staged));
            }
        }
        let (event_opt_bit, fork_event) = if share_vmspace {
            (
                crate::ptrace::PTRACE_O_TRACEVFORK,
                crate::ptrace::PTRACE_EVENT_VFORK,
            )
        } else {
            (
                crate::ptrace::PTRACE_O_TRACEFORK,
                crate::ptrace::PTRACE_EVENT_FORK,
            )
        };
        let (parent_tracer, trace_fork_set, parent_trace_options) =
            match g.processes.get(&parent_pid) {
                Some(p) => (
                    p.trace.tracer_pid(),
                    (p.trace.options() & event_opt_bit) != 0,
                    p.trace.options(),
                ),
                None => (None, false, 0),
            };
        if let (Some(tracer), true) = (parent_tracer, trace_fork_set) {
            child_box.trace.inherit_trace(tracer, parent_trace_options);
        }
        g.processes.insert(child_pid, child_box);
        if let Some(p) = g.processes.get_mut(&parent_pid) {
            p.children.push(child_pid);
            if trace_fork_set {
                p.trace.post_event_stop(
                    crate::process_model::TraceStop::EventStop(fork_event),
                    child_pid.0 as u64,
                );
            }
        }
        if let (Some(tracer), true) = (parent_tracer, trace_fork_set) {
            if let Some(tr) = g.processes.get_mut(&tracer) {
                tr.trace.add_tracee(child_pid);
            }
        }
    }
    crate::process_model::PidNamespace::assign_chain(&child_pid_ns, child_pid);
    let inherited_cg = process_cgroup(child_pid);
    if let Some(cg) = inherited_cg {
        if cg.attach_pid(child_pid).is_err() {
            let mut g = GLOBAL.lock();
            if share_vmspace {
                if let Some(p) = g.processes.get(&child_pid) {
                    let was_live = !matches!(
                        *p.state.get(),
                        ProcessState::Zombie(_)
                            | ProcessState::KilledByFault { .. }
                            | ProcessState::KilledBySignal { .. }
                    );
                    if was_live {
                        if let Some(a) = p.addr_space.as_ref() {
                            a.live_users
                                .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
                        }
                    }
                }
            }
            g.processes.remove(&child_pid);
            crate::process_model::PidNamespace::drop_chain(&child_pid_ns, child_pid);
            if let Some(p) = g.processes.get_mut(&parent_pid) {
                p.children.retain(|&c| c != child_pid);
            }
            return Err(cyphera_kapi::Errno::NOMEM);
        }
    }
    if !share_vmspace {
        admit_task(child_pid, home_cpu, "fork_current_child");
    }
    EVER_REGISTERED.store(true, Ordering::Release);
    if !share_vmspace && home_cpu != this_cpu() {
        send_resched_ipi(home_cpu);
    }
    Ok(child_pid)
}

pub fn clone_thread_current(parent_tf: &TrapFrame, child_stack: u64) -> cyphera_kapi::KResult<Pid> {
    let parent_pid = current_pid();
    let child_pid = next_pid();
    let parent_affinity = GLOBAL
        .lock()
        .processes
        .get(&parent_pid)
        .map(|p| p.sched.cpu_affinity)
        .unwrap_or(u64::MAX);
    let home_cpu = pick_home_cpu_in(parent_affinity);

    let mut child_tf = parent_tf.clone();
    child_tf.rax = 0;
    if child_stack != 0 {
        child_tf.rsp_user = child_stack;
    }

    let child = {
        let g = GLOBAL.lock();
        let parent = g
            .processes
            .get(&parent_pid)
            .ok_or(cyphera_kapi::Errno::INVAL)?;
        let task = SchedCell::new(frame::cpu::task::Task::spawn(first_launch_trampoline));
        if let Some(a) = parent.addr_space.as_ref() {
            a.live_users
                .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        }
        Process {
            pid: child_pid,
            tgid: parent.tgid,
            identity: crate::process_model::IdentityContext::inherit(&parent.identity),
            creds: parent.creds.clone(),
            parent: parent.parent,
            state: SchedCell::new(ProcessState::Runnable),
            kind: ProcessKind::User,
            saved: parent.saved,
            memory: crate::process_model::MemoryContext::inherit(&parent.memory),
            fds: parent.fds.clone(),
            files: crate::process_model::FileContext::inherit(&parent.files),
            namespaces: crate::process_model::NamespaceContext::inherit(&parent.namespaces),
            cgroup: parent.cgroup.clone(),
            cgroup_charged_bytes: 0,
            security: crate::process_model::SecurityContext::inherit(&parent.security),
            signals: crate::process_model::SignalContext::inherit(&parent.signals),
            sigactions: parent.sigactions.clone(),
            task,
            first_launch: Some(FirstLaunch::Fork { tf: child_tf }),
            sched: SchedEntity {
                home_cpu,
                cpu_affinity: parent.sched.cpu_affinity,
                parking_unsaved: false,
                nice: parent.sched.nice,
                sched_class: parent.sched.sched_class,
                vruntime: parent.sched.vruntime,
                weight: parent.sched.weight,
                last_run_ns: 0,
                dl_runtime_remaining: 0,
                dl_absolute_deadline: 0,
                dl_next_replenish: 0,
                dl_throttled: false,
                pi_orig_class: None,
            },
            addr_space: parent.addr_space.clone(),
            addr_space_root: parent.addr_space_root,
            sched_owner: SchedCell::new(crate::process_model::SchedOwner::None),
            children: Vec::new(),
            wait_sites: WaitSites::default(),
            lifecycle: crate::process_model::LifecycleContext::default(),
            pdeathsig: core::sync::atomic::AtomicU32::new(0),
            name: [0u8; 16],
            rlimits: parent.rlimits,
            pi_blocked_on: None,
            pi_held: Vec::new(),
            cpu_times: CpuTimes::default(),
            trace: crate::process_model::TraceContext::default(),
        }
    };

    {
        let mut g = GLOBAL.lock();
        let (parent_tracer, trace_clone_set, parent_trace_options) =
            match g.processes.get(&parent_pid) {
                Some(p) => (
                    p.trace.tracer_pid(),
                    (p.trace.options() & crate::ptrace::PTRACE_O_TRACECLONE) != 0,
                    p.trace.options(),
                ),
                None => (None, false, 0),
            };
        let mut child_box = Box::new(child);
        if let (Some(tracer), true) = (parent_tracer, trace_clone_set) {
            child_box.trace.inherit_trace(tracer, parent_trace_options);
        }
        g.processes.insert(child_pid, child_box);
        if trace_clone_set {
            if let Some(p) = g.processes.get_mut(&parent_pid) {
                p.trace.post_event_stop(
                    crate::process_model::TraceStop::EventStop(crate::ptrace::PTRACE_EVENT_CLONE),
                    child_pid.0 as u64,
                );
            }
            if let (Some(tracer), true) = (parent_tracer, trace_clone_set) {
                if let Some(tr) = g.processes.get_mut(&tracer) {
                    tr.trace.add_tracee(child_pid);
                }
            }
        }
    }
    let thread_ns = process_pid_ns(child_pid).unwrap_or_else(host_pid_ns);
    crate::process_model::PidNamespace::assign_chain(&thread_ns, child_pid);
    let inherited_cg = process_cgroup(child_pid);
    if let Some(cg) = inherited_cg {
        if cg.attach_pid(child_pid).is_err() {
            let mut g = GLOBAL.lock();
            if let Some(p) = g.processes.get(&child_pid) {
                let was_live = !matches!(
                    *p.state.get(),
                    ProcessState::Zombie(_)
                        | ProcessState::KilledByFault { .. }
                        | ProcessState::KilledBySignal { .. }
                );
                if was_live {
                    if let Some(a) = p.addr_space.as_ref() {
                        a.live_users
                            .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
                    }
                }
            }
            g.processes.remove(&child_pid);
            crate::process_model::PidNamespace::drop_chain(&thread_ns, child_pid);
            return Err(cyphera_kapi::Errno::NOMEM);
        }
    }
    admit_task(child_pid, home_cpu, "clone_thread_child");
    EVER_REGISTERED.store(true, Ordering::Release);
    if home_cpu != this_cpu() {
        send_resched_ipi(home_cpu);
    }
    Ok(child_pid)
}
