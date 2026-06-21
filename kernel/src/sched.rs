extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use frame::cpu::per_cpu::{MAX_CPUS, current_cpu_id};
use frame::cpu::task::{self, Context};
use frame::io::qemu_exit::{ExitCode, exit};
use frame::sync::SpinIrq;
use frame::user::{TrapFrame, start_user_process};

use crate::process::{
    BrkState, CwdState, FirstLaunch, MmapState, NICE_0_LOAD, NSIG, Pid, Process, ProcessKind,
    ProcessState, SIGCHLD, SIGCONT, SIGKILL, SIGSEGV, SIGSTOP, SchedClass, SchedOwner,
    nice_to_weight,
};
pub use crate::sched_runqueue::{
    CfsPlace, DL_BW_MAX, DL_BW_SCALE, EnqueueData, RT_PRIO_COUNT, RT_PRIO_MAX, RT_PRIO_MIN,
    RunQueues, SCHED_LATENCY_NS, SCHED_MIN_GRANULARITY_NS, SCHED_WAKEUP_VRUNTIME_THRESH_NS,
};
mod accounting;
mod credentials;
mod file;
mod identity;
mod lifecycle;
mod limits;
mod memory;
mod namespace;
pub mod scheduling;
mod signal_context;
mod trace;
pub use accounting::*;
pub use credentials::*;
pub use file::*;
pub use identity::*;
pub use lifecycle::*;
pub use limits::*;
pub use memory::*;
pub use namespace::*;
pub use signal_context::*;
pub use trace::*;

pub const SCHED_WAKEUP_GRANULARITY_NS: u64 = 1_000_000;

pub const SCHED_RR_TIMESLICE_NS: u64 = 100_000_000;

fn calc_delta_vruntime(delta_ns: u64, weight: u64) -> u64 {
    if weight == 0 {
        return delta_ns;
    }
    delta_ns.saturating_mul(NICE_0_LOAD) / weight
}

fn enqueue_data_from_proc(proc: &Process) -> EnqueueData {
    EnqueueData {
        class: proc.sched_class,
        vruntime: proc.vruntime,
        weight: cgroup_scaled_weight(proc),
        dl_deadline: proc.dl_absolute_deadline,
    }
}

fn cgroup_scaled_weight(proc: &Process) -> u64 {
    let cg_weight = proc
        .cgroup
        .as_ref()
        .map(|cg| cg.cpu.lock().weight)
        .unwrap_or(100);
    proc.weight.saturating_mul(cg_weight) / 100
}

fn bank_cpu_time(proc: &mut Process, delta_ns: u64) {
    proc.total_cpu_ns = proc.total_cpu_ns.saturating_add(delta_ns);
    if proc.lifecycle.in_syscall() {
        proc.total_stime_ns = proc.total_stime_ns.saturating_add(delta_ns);
    } else {
        proc.total_utime_ns = proc.total_utime_ns.saturating_add(delta_ns);
    }
}

fn bank_slice_off_cpu(proc: &mut Process) {
    let now = frame::cpu::clock::nanos_since_boot();
    bank_cpu_time(proc, now.saturating_sub(proc.last_run_ns));
    proc.last_run_ns = now;
}

fn charge_runtime(proc: &mut Process, delta_ns: u64) {
    bank_cpu_time(proc, delta_ns);
    if matches!(
        proc.sched_class,
        SchedClass::Rt { .. } | SchedClass::Deadline { .. }
    ) {
        charge_rt_runtime(delta_ns);
    }
    if !matches!(proc.sched_class, SchedClass::Cfs) {
        return;
    }
    let raw = if proc.weight == 0 {
        nice_to_weight(proc.nice)
    } else {
        proc.weight
    };
    let cg_weight = proc
        .cgroup
        .as_ref()
        .map(|cg| cg.cpu.lock().weight)
        .unwrap_or(100);
    let weight = raw.saturating_mul(cg_weight) / 100;
    let dv = calc_delta_vruntime(delta_ns, weight.max(1));
    proc.vruntime = proc.vruntime.saturating_add(dv);
}

struct CpuQueue {
    runnable: RunQueues,
    current: Option<Pid>,
    idle_ctx: Context,
    active_vmspace: Option<alloc::sync::Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>>,
    pending_corpse: Option<Pid>,
}

impl CpuQueue {
    const fn new() -> Self {
        Self {
            runnable: RunQueues::new(),
            current: None,
            idle_ctx: Context::bootstrap(),
            active_vmspace: None,
            pending_corpse: None,
        }
    }
}

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY_QUEUE: SpinIrq<CpuQueue> = SpinIrq::new(CpuQueue::new());
static CPU_QUEUES: [SpinIrq<CpuQueue>; MAX_CPUS] = [EMPTY_QUEUE; MAX_CPUS];

pub struct Global {
    pub processes: BTreeMap<Pid, Box<Process>>,
}

pub(crate) static GLOBAL: SpinIrq<Global> = SpinIrq::new(Global {
    processes: BTreeMap::new(),
});

static NEXT_PID: AtomicU32 = AtomicU32::new(1);
static NEXT_HOME_CPU: AtomicU32 = AtomicU32::new(0);
static EVER_REGISTERED: AtomicBool = AtomicBool::new(false);

fn next_pid() -> Pid {
    Pid(NEXT_PID.fetch_add(1, Ordering::SeqCst))
}

fn affinity_allows(affinity: u64, cpu: u32) -> bool {
    cpu < 64 && (affinity & (1u64 << cpu)) != 0
}

fn pick_home_cpu_in(affinity: u64) -> u32 {
    let online = frame::arch::x86_64::smp::online_mask();
    let mut eff = online & affinity;
    if eff == 0 {
        eff = online;
    }
    let count = eff.count_ones();
    let idx = NEXT_HOME_CPU.fetch_add(1, Ordering::Relaxed) % count;
    let mut m = eff;
    for _ in 0..idx {
        m &= m.wrapping_sub(1);
    }
    m.trailing_zeros()
}

fn pick_home_cpu() -> u32 {
    pick_home_cpu_in(u64::MAX)
}

fn effective_home_cpu(proc: &mut Process) -> u32 {
    if affinity_allows(proc.cpu_affinity, proc.home_cpu) {
        proc.home_cpu
    } else {
        let h = pick_home_cpu_in(proc.cpu_affinity);
        proc.home_cpu = h;
        h
    }
}

fn this_cpu() -> u32 {
    current_cpu_id()
}

pub fn spawn_kthread(name: &str, entry: extern "C" fn() -> !) -> Pid {
    let pid = next_pid();
    let home_cpu = pick_home_cpu();
    let mut proc = Process::new_kthread(pid, entry);
    proc.home_cpu = home_cpu;
    proc.identity.set_cmdline(name.as_bytes().to_vec());
    proc.cgroup = Some(crate::cgroup::root());

    let home_q = &CPU_QUEUES[home_cpu as usize];
    {
        let mut q = home_q.lock();
        let mut g = GLOBAL.lock();
        g.processes.insert(pid, Box::new(proc));
        let proc_ref = g.processes.get_mut(&pid).unwrap();
        let placed = q
            .runnable
            .enqueue(pid, enqueue_data_from_proc(proc_ref), CfsPlace::New);
        proc_ref.vruntime = placed;
        set_sched_owner(
            proc_ref,
            SchedOwner::Runnable { cpu: home_cpu },
            "spawn_kthread",
        );
        record_enqueue(pid, "spawn_kthread", proc_ref);
    }
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
    proc.home_cpu = home_cpu;
    proc.pml4_root = vmspace.as_ref().map(|v| v.root_frame());
    proc.addr_space = vmspace.map(|v| crate::process::AddressSpace::new(v, pid, brk_start));

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
    crate::process::PidNamespace::assign_chain(&host_pid_ns(), pid);
    let _ = crate::cgroup::root().attach_pid(pid);
    {
        let mut q = CPU_QUEUES[home_cpu as usize].lock();
        let mut g = GLOBAL.lock();
        if let Some(p) = g.processes.get_mut(&pid) {
            let placed = q
                .runnable
                .enqueue(pid, enqueue_data_from_proc(p), CfsPlace::New);
            p.vruntime = placed;
            set_sched_owner(
                p,
                SchedOwner::Runnable { cpu: home_cpu },
                "register_with_vmspace",
            );
            record_enqueue(pid, "register_with_vmspace", p);
        }
    }
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
    aux: &crate::stack_init::AuxvInfo,
) -> Result<Pid, crate::stack_init::StackInitError> {
    let new_rsp = crate::stack_init::build_user_stack(&vmspace, user_stack_top, argv, envp, aux)?;
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

pub fn fork_current(parent_tf: &TrapFrame, share_vmspace: bool) -> Result<Pid, ForkError> {
    let parent_pid = current_pid();
    let child_pid = next_pid();
    let parent_affinity = GLOBAL
        .lock()
        .processes
        .get(&parent_pid)
        .map(|p| p.cpu_affinity)
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
    let (child_vm, child_pml4_root) = if share_vmspace {
        let g = GLOBAL.lock();
        let parent = g.processes.get(&parent_pid).ok_or(ForkError::NoCurrent)?;
        let arc = parent.vmspace().ok_or(ForkError::NoVmSpace)?;
        let root = parent.pml4_root.ok_or(ForkError::NoVmSpace)?;
        (arc, root)
    } else {
        let child_vm = {
            let shareable: Vec<(u64, u64, ShareKind)> = {
                let g = GLOBAL.lock();
                let parent = g.processes.get(&parent_pid).ok_or(ForkError::NoCurrent)?;
                let m = parent
                    .addr_space
                    .as_ref()
                    .ok_or(ForkError::NoVmSpace)?
                    .mmap
                    .lock();
                m.vmas
                    .iter()
                    .filter(|v| v.flags.contains(crate::process::VmaFlags::SHARED))
                    .filter_map(|v| match &v.backing {
                        crate::process::VmaBacking::File {
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
                        crate::process::VmaBacking::Shm { segment } => Some((
                            v.start,
                            v.end,
                            ShareKind::Shm {
                                segment: segment.clone(),
                            },
                        )),
                        crate::process::VmaBacking::Anonymous => None,
                    })
                    .collect()
            };
            let parent_vm_arc = {
                let g = GLOBAL.lock();
                let parent = g.processes.get(&parent_pid).ok_or(ForkError::NoCurrent)?;
                parent.vmspace().ok_or(ForkError::NoVmSpace)?
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
                        return Err(ForkError::OutOfMemory);
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
                        return Err(ForkError::OutOfMemory);
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
        let child_pml4_root = child_vm.lock().root_frame();
        (child_vm, child_pml4_root)
    };

    let mut child_tf = parent_tf.clone();
    child_tf.rax = 0;

    let child = {
        let g = GLOBAL.lock();
        let parent = g.processes.get(&parent_pid).ok_or(ForkError::NoCurrent)?;
        let task = SchedCell::new(frame::cpu::task::Task::spawn(first_launch_trampoline));
        let creds_snapshot = parent.creds.lock().clone();
        let sigactions_snapshot = *parent.sigactions.lock();
        let child_addr_space = if share_vmspace {
            let as_arc = parent
                .addr_space
                .as_ref()
                .ok_or(ForkError::NoVmSpace)?
                .clone();
            as_arc
                .live_users
                .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            as_arc
        } else {
            parent
                .addr_space
                .as_ref()
                .ok_or(ForkError::NoVmSpace)?
                .deep_copy_with_vmspace(child_vm)
        };
        Process {
            pid: child_pid,
            tgid: child_pid,
            identity: crate::process::IdentityContext::inherit(&parent.identity),
            creds: alloc::sync::Arc::new(frame::sync::SpinIrq::new(creds_snapshot)),
            parent: Some(parent_pid),
            state: SchedCell::new(ProcessState::Runnable),
            kind: ProcessKind::User,
            saved: parent.saved,
            memory: crate::process::MemoryContext::inherit(&parent.memory),
            fds: Arc::new(parent.fds.clone_for_child()),
            files: crate::process::FileContext::inherit(&parent.files),
            namespaces: crate::process::NamespaceContext::inherit(&parent.namespaces),
            cgroup: parent.cgroup.clone(),
            cgroup_charged_bytes: 0,
            security: crate::process::SecurityContext::inherit(&parent.security),
            signals: crate::process::SignalContext::inherit(&parent.signals),
            sigactions: Arc::new(frame::sync::SpinIrq::new(sigactions_snapshot)),
            task,
            first_launch: Some(FirstLaunch::Fork { tf: child_tf }),
            home_cpu,
            cpu_affinity: parent.cpu_affinity,
            addr_space: Some(child_addr_space),
            pml4_root: Some(child_pml4_root),
            sched_owner: SchedCell::new(crate::process::SchedOwner::None),
            parking_unsaved: false,
            children: Vec::new(),
            child_exit: crate::wait::WaitQueue::new(),
            exit_waiters: crate::wait::WaitQueue::new(),
            signalfd_waiters: crate::wait::WaitQueue::new(),
            vfork_done: crate::wait::WaitQueue::new(),
            lifecycle: crate::process::LifecycleContext::with_vfork_shared(share_vmspace),
            pdeathsig: core::sync::atomic::AtomicU32::new(0),
            name: [0u8; 16],
            rlimits: [None; 16],
            nice: parent.nice,
            sched_class: parent.sched_class,
            vruntime: parent.vruntime,
            weight: parent.weight,
            last_run_ns: 0,
            pi_blocked_on: None,
            pi_held: Vec::new(),
            pi_orig_class: None,
            dl_runtime_remaining: 0,
            dl_absolute_deadline: 0,
            dl_next_replenish: 0,
            dl_throttled: false,
            total_cpu_ns: 0,
            total_stime_ns: 0,
            total_utime_ns: 0,
            cutime_ns: 0,
            cstime_ns: 0,
            trace: crate::process::TraceContext::default(),
        }
    };

    let child_pid_ns: Arc<crate::process::PidNamespace> = {
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
                    crate::process::TraceStop::EventStop(fork_event),
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
    crate::process::PidNamespace::assign_chain(&child_pid_ns, child_pid);
    let inherited_cg = process_cgroup(child_pid);
    if let Some(cg) = inherited_cg {
        if cg.attach_pid(child_pid).is_err() {
            let mut g = GLOBAL.lock();
            if share_vmspace {
                if let Some(p) = g.processes.get(&child_pid) {
                    let was_live = !matches!(
                        p.state.0,
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
            crate::process::PidNamespace::drop_chain(&child_pid_ns, child_pid);
            if let Some(p) = g.processes.get_mut(&parent_pid) {
                p.children.retain(|&c| c != child_pid);
            }
            return Err(ForkError::OutOfMemory);
        }
    }
    if !share_vmspace {
        let mut q = CPU_QUEUES[home_cpu as usize].lock();
        let mut g = GLOBAL.lock();
        if let Some(p) = g.processes.get_mut(&child_pid) {
            let placed = q
                .runnable
                .enqueue(child_pid, enqueue_data_from_proc(p), CfsPlace::New);
            p.vruntime = placed;
            set_sched_owner(
                p,
                SchedOwner::Runnable { cpu: home_cpu },
                "fork/clone_child",
            );
            record_enqueue(child_pid, "fork_current_child", p);
        }
    }
    EVER_REGISTERED.store(true, Ordering::Release);
    if !share_vmspace && home_cpu != this_cpu() {
        send_resched_ipi(home_cpu);
    }
    Ok(child_pid)
}

#[derive(Debug)]
pub enum ForkError {
    NoCurrent,
    NoVmSpace,
    OutOfMemory,
}

impl ForkError {
    pub fn errno(&self) -> i64 {
        match self {
            ForkError::OutOfMemory => -12,
            ForkError::NoCurrent | ForkError::NoVmSpace => -22,
        }
    }
}

pub fn clone_thread_current(parent_tf: &TrapFrame, child_stack: u64) -> Result<Pid, ForkError> {
    let parent_pid = current_pid();
    let child_pid = next_pid();
    let parent_affinity = GLOBAL
        .lock()
        .processes
        .get(&parent_pid)
        .map(|p| p.cpu_affinity)
        .unwrap_or(u64::MAX);
    let home_cpu = pick_home_cpu_in(parent_affinity);

    let mut child_tf = parent_tf.clone();
    child_tf.rax = 0;
    if child_stack != 0 {
        child_tf.rsp_user = child_stack;
    }

    let child = {
        let g = GLOBAL.lock();
        let parent = g.processes.get(&parent_pid).ok_or(ForkError::NoCurrent)?;
        let task = SchedCell::new(frame::cpu::task::Task::spawn(first_launch_trampoline));
        if let Some(a) = parent.addr_space.as_ref() {
            a.live_users
                .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        }
        Process {
            pid: child_pid,
            tgid: parent.tgid,
            identity: crate::process::IdentityContext::inherit(&parent.identity),
            creds: parent.creds.clone(),
            parent: parent.parent,
            state: SchedCell::new(ProcessState::Runnable),
            kind: ProcessKind::User,
            saved: parent.saved,
            memory: crate::process::MemoryContext::inherit(&parent.memory),
            fds: parent.fds.clone(),
            files: crate::process::FileContext::inherit(&parent.files),
            namespaces: crate::process::NamespaceContext::inherit(&parent.namespaces),
            cgroup: parent.cgroup.clone(),
            cgroup_charged_bytes: 0,
            security: crate::process::SecurityContext::inherit(&parent.security),
            signals: crate::process::SignalContext::inherit(&parent.signals),
            sigactions: parent.sigactions.clone(),
            task,
            first_launch: Some(FirstLaunch::Fork { tf: child_tf }),
            home_cpu,
            cpu_affinity: parent.cpu_affinity,
            addr_space: parent.addr_space.clone(),
            pml4_root: parent.pml4_root,
            sched_owner: SchedCell::new(crate::process::SchedOwner::None),
            parking_unsaved: false,
            children: Vec::new(),
            child_exit: crate::wait::WaitQueue::new(),
            exit_waiters: crate::wait::WaitQueue::new(),
            signalfd_waiters: crate::wait::WaitQueue::new(),
            vfork_done: crate::wait::WaitQueue::new(),
            lifecycle: crate::process::LifecycleContext::default(),
            pdeathsig: core::sync::atomic::AtomicU32::new(0),
            name: [0u8; 16],
            rlimits: [None; 16],
            nice: parent.nice,
            sched_class: parent.sched_class,
            vruntime: parent.vruntime,
            weight: parent.weight,
            last_run_ns: 0,
            pi_blocked_on: None,
            pi_held: Vec::new(),
            pi_orig_class: None,
            dl_runtime_remaining: 0,
            dl_absolute_deadline: 0,
            dl_next_replenish: 0,
            dl_throttled: false,
            total_cpu_ns: 0,
            total_stime_ns: 0,
            total_utime_ns: 0,
            cutime_ns: 0,
            cstime_ns: 0,
            trace: crate::process::TraceContext::default(),
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
                    crate::process::TraceStop::EventStop(crate::ptrace::PTRACE_EVENT_CLONE),
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
    crate::process::PidNamespace::assign_chain(&thread_ns, child_pid);
    let inherited_cg = process_cgroup(child_pid);
    if let Some(cg) = inherited_cg {
        if cg.attach_pid(child_pid).is_err() {
            let mut g = GLOBAL.lock();
            if let Some(p) = g.processes.get(&child_pid) {
                let was_live = !matches!(
                    p.state.0,
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
            crate::process::PidNamespace::drop_chain(&thread_ns, child_pid);
            return Err(ForkError::OutOfMemory);
        }
    }
    {
        let mut q = CPU_QUEUES[home_cpu as usize].lock();
        let mut g = GLOBAL.lock();
        if let Some(p) = g.processes.get_mut(&child_pid) {
            let placed = q
                .runnable
                .enqueue(child_pid, enqueue_data_from_proc(p), CfsPlace::New);
            p.vruntime = placed;
            set_sched_owner(
                p,
                SchedOwner::Runnable { cpu: home_cpu },
                "fork/clone_child",
            );
            record_enqueue(child_pid, "clone_thread_child", p);
        }
    }
    EVER_REGISTERED.store(true, Ordering::Release);
    if home_cpu != this_cpu() {
        send_resched_ipi(home_cpu);
    }
    Ok(child_pid)
}

pub fn exit_group_current(tf: &mut TrapFrame, code: i32) -> ! {
    let cur_pid = current_pid();
    let tgid = {
        let g = GLOBAL.lock();
        g.processes.get(&cur_pid).map(|p| p.tgid).unwrap_or(cur_pid)
    };

    let siblings: alloc::vec::Vec<Pid> = {
        let g = GLOBAL.lock();
        g.processes
            .iter()
            .filter(|(pid, p)| **pid != cur_pid && p.tgid == tgid)
            .map(|(pid, _)| *pid)
            .collect()
    };
    let mut dying_sibling_fds: alloc::vec::Vec<Arc<crate::vfs::fd::FdTable>> =
        alloc::vec::Vec::new();
    for sib in siblings {
        let mut info = None;
        loop {
            let home = {
                let g = GLOBAL.lock();
                match g.processes.get(&sib) {
                    Some(p) => p.home_cpu,
                    None => break,
                }
            };
            let mut q = CPU_QUEUES[home as usize].lock();
            let mut g = GLOBAL.lock();
            let Some(p) = g.processes.get_mut(&sib) else {
                break;
            };
            if p.home_cpu != home {
                continue;
            }
            let was_live = !matches!(
                p.state.0,
                ProcessState::Zombie(_)
                    | ProcessState::KilledByFault { .. }
                    | ProcessState::KilledBySignal { .. }
            );
            let sib_as = if was_live { p.addr_space.clone() } else { None };
            let sib_ipc = if was_live { p.namespaces.ipc() } else { None };
            if matches!(p.state.0, ProcessState::Running) {
                if p.lifecycle.pending_exit().is_none() {
                    p.lifecycle.set_pending_exit(ProcessState::Zombie(code));
                }
            } else {
                p.state.0 = ProcessState::Zombie(code);
                dying_sibling_fds.push(core::mem::replace(
                    &mut p.fds,
                    Arc::new(crate::vfs::fd::FdTable::new()),
                ));
            }
            let (rt, dl, cfs) = q.runnable.remove_pid(sib);
            if rt + dl + cfs > 0 {
                record_dequeue(sib);
            }
            info = Some((was_live, sib_as, sib_ipc));
            break;
        }
        if let Some((was_live, sib_as, sib_ipc)) = info {
            if let Some(sib_as) = sib_as {
                release_addr_space_user(&sib_as, sib_ipc.as_ref());
            }
            if was_live {
                wake_tracer_on_exit(sib);
            }
            drain_vfork_done(sib);
        }
    }
    drop(dying_sibling_fds);
    exit_current(tf, code)
}

#[derive(Debug)]
pub enum ExecError {
    NoCurrent,
    NoVmSpace,
    Load(crate::elf::LoadError),
    OutOfMemory,
    InterpNotFound,
}

impl ExecError {
    pub fn errno(&self) -> i64 {
        match self {
            ExecError::OutOfMemory => -12,
            ExecError::Load(_) => -8,
            ExecError::NoCurrent | ExecError::NoVmSpace => -22,
            ExecError::InterpNotFound => -2,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn exec_current(
    elf_bytes: &[u8],
    exe_path: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    post_euid: u32,
    post_egid: u32,
    secure: bool,
    tf: &mut TrapFrame,
) -> Result<(), ExecError> {
    use frame::mm::VirtAddr;
    use frame::mm::vm::Perms;

    const STACK_VADDR: u64 = 0x7000_0000_0000;
    const STACK_PAGES: usize = 16;
    const BRK_PAD: u64 = 0x1_0000;
    const RFLAGS_USER: u64 = 0x202;

    let pid = current_pid();

    let vfork_shared = with_current_lifecycle(|l| l.vfork_shared_vm()).unwrap_or(false);

    let live_peers: Vec<Pid> = if vfork_shared {
        Vec::new()
    } else {
        let g = GLOBAL.lock();
        let my_tgid = g.processes.get(&pid).map(|p| p.tgid).unwrap_or(pid);
        g.processes
            .iter()
            .filter(|(p, pr)| {
                **p != pid
                    && pr.tgid == my_tgid
                    && !matches!(
                        pr.state.0,
                        ProcessState::Zombie(_)
                            | ProcessState::KilledByFault { .. }
                            | ProcessState::KilledBySignal { .. }
                    )
            })
            .map(|(p, _)| *p)
            .collect()
    };

    let building_fresh = vfork_shared || !live_peers.is_empty();

    crate::ipc::shm::detach_all_current();
    crate::mmap_fault::detach_shared_file_current();

    let (vm_arc, fresh_root) = if building_fresh {
        let fresh = frame::mm::vm::VmSpace::new_user().map_err(|_| ExecError::OutOfMemory)?;
        let root = fresh.root_frame();
        (Arc::new(frame::sync::SpinIrq::new(fresh)), Some(root))
    } else {
        let g = GLOBAL.lock();
        let proc = g.processes.get(&pid).ok_or(ExecError::NoCurrent)?;
        (proc.vmspace().ok_or(ExecError::NoVmSpace)?, None)
    };

    if let Some(interp) = crate::elf::interp_path(elf_bytes) {
        let ctx = crate::vfs::path::Context::global();
        if crate::vfs::path::resolve(&ctx, &ctx.root, &interp).is_err() {
            return Err(ExecError::InterpNotFound);
        }
    }

    let mut leaving_as: Option<(
        alloc::sync::Arc<crate::process::AddressSpace>,
        Option<alloc::sync::Arc<crate::process::IpcNamespace>>,
    )> = None;
    if let Some(root) = fresh_root {
        let _irq = frame::sync::IrqGuard::new();
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        {
            let mut g = GLOBAL.lock();
            if let Some(proc) = g.processes.get_mut(&pid) {
                if let Some(old) = proc.addr_space.clone() {
                    leaving_as = Some((old, proc.namespaces.ipc()));
                }
                proc.addr_space = Some(alloc::sync::Arc::new(crate::process::AddressSpace {
                    vmspace: vm_arc.clone(),
                    mmap: frame::sync::SpinIrq::new(MmapState::for_pid(pid)),
                    brk: frame::sync::SpinIrq::new(BrkState::new(0)),
                    live_users: core::sync::atomic::AtomicUsize::new(1),
                }));
                proc.pml4_root = Some(root);
                proc.lifecycle.set_vfork_shared_vm(false);
            }
        }
        frame::mm::vm::VmSpace::activate_root(root);
        q.active_vmspace = Some(vm_arc.clone());
    }
    if let Some((old_as, old_ipc)) = leaving_as {
        release_addr_space_user(&old_as, old_ipc.as_ref());
    }

    for peer in &live_peers {
        let _ = send_signal(*peer, SIGKILL);
    }

    let (loaded, new_rsp, brk_start) = {
        let mut vm = vm_arc.lock();
        let vm = &mut *vm;

        vm.clear_user();

        let loaded = crate::elf::load_static(elf_bytes, vm).map_err(ExecError::Load)?;

        let stack = vm
            .map_anon(
                VirtAddr::new(STACK_VADDR),
                STACK_PAGES,
                Perms::READ | Perms::WRITE | Perms::USER,
            )
            .map_err(|_| ExecError::OutOfMemory)?;
        core::mem::forget(stack);

        let stack_top = STACK_VADDR + (STACK_PAGES * 4096) as u64;
        let brk_start = (loaded.image_end + BRK_PAD + 0xfff) & !0xfff;

        let (ruid, rgid) = with_current_creds(|c| (c.ruid, c.rgid));
        let aux = crate::stack_init::AuxvInfo::for_exec(
            &loaded, ruid, post_euid, rgid, post_egid, secure,
        );
        let new_rsp = crate::stack_init::build_user_stack(vm, stack_top, argv, envp, &aux)
            .map_err(|_| ExecError::OutOfMemory)?;

        (loaded, new_rsp, brk_start)
    };

    let proc_pid = pid;
    {
        let mut g = GLOBAL.lock();
        let proc = g.processes.get_mut(&proc_pid).ok_or(ExecError::NoCurrent)?;

        let mut cmdline: Vec<u8> = Vec::new();
        for s in argv {
            cmdline.extend_from_slice(s);
            cmdline.push(0);
        }

        if let Some(addr_space) = proc.addr_space.as_ref() {
            *addr_space.mmap.lock() = MmapState::for_pid(proc.pid);
            *addr_space.brk.lock() = BrkState::new(brk_start);
        }
        {
            use crate::process::{MapSegLabel, MapSegment, MapsLayout};
            let mut layout = MapsLayout::default();
            for (lo, hi, prot) in &loaded.segments {
                layout.segments.push(MapSegment {
                    start: *lo,
                    end: *hi,
                    prot: *prot,
                    label: MapSegLabel::Image,
                });
            }
            for (lo, hi, prot) in &loaded.interp_segments {
                layout.segments.push(MapSegment {
                    start: *lo,
                    end: *hi,
                    prot: *prot,
                    label: MapSegLabel::Interp,
                });
            }
            layout.segments.push(MapSegment {
                start: STACK_VADDR,
                end: STACK_VADDR + (STACK_PAGES * 4096) as u64,
                prot: Perms::READ | Perms::WRITE | Perms::USER,
                label: MapSegLabel::Stack,
            });
            proc.memory.set_maps_layout(layout);
        }
        proc.sigactions = Arc::new(frame::sync::SpinIrq::new(
            [crate::process::SigAction::default(); NSIG],
        ));
        proc.signals.set_pending(0);
        if proc.trace.is_traced() {
            if proc.trace.options() & crate::ptrace::PTRACE_O_TRACEEXEC != 0 {
                let msg = proc.pid.raw() as u64;
                proc.trace.post_event_stop(
                    crate::process::TraceStop::EventStop(crate::ptrace::PTRACE_EVENT_EXEC),
                    msg,
                );
            } else {
                proc.trace.arm_post_exec_trap();
            }
        } else {
            proc.trace.clear_pending_event_stop();
        }
        proc.signals.reset_siginfo();
        proc.signals
            .set_altstack(crate::signal::AltStack::disabled());
        proc.memory.set_fs_base(0);
        proc.sched_class = crate::process::SchedClass::default_cfs();
        proc.signals.set_itimer_interval(0);
        proc.signals.set_itimer_deadline(0);
        let key = (proc.pid.raw() as u64) | (1u64 << 63);
        crate::timeout::cancel_callback(key);
        proc.identity.set_cmdline(cmdline);
        proc.identity.set_exe_path(exe_path.to_vec());
        proc.fds.close_cloexec();

        *tf = TrapFrame {
            rax: 0,
            rdi: 0,
            rsi: 0,
            rdx: 0,
            r10: 0,
            r8: 0,
            r9: 0,
            rip_user: loaded.interp_entry.unwrap_or(loaded.entry),
            rflags_user: RFLAGS_USER,
            rsp_user: new_rsp,
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            orig_rax: 0,
        };
    }

    drain_vfork_done(pid);

    Ok(())
}

pub fn send_resched_ipi_pub(target_cpu: u32) {
    send_resched_ipi(target_cpu);
}

fn send_resched_ipi(target_cpu: u32) {
    if target_cpu < MAX_CPUS as u32 {
        frame::intr::lapic::send_ipi(
            target_cpu as u8,
            frame::intr::lapic::RESCHED_IPI_VECTOR,
            frame::intr::lapic::IpiKind::Fixed,
        );
    }
}

pub fn current_pid() -> Pid {
    CPU_QUEUES[this_cpu() as usize]
        .lock()
        .current
        .expect("current_pid: no current")
}

pub fn current_pid_opt() -> Option<Pid> {
    CPU_QUEUES[this_cpu() as usize].lock().current
}

pub fn current_is_vfork_borrower() -> bool {
    with_current_lifecycle(|l| l.vfork_shared_vm()).unwrap_or(false)
}

fn root_has_live_user(root_phys: u64) -> bool {
    let g = GLOBAL.lock();
    g.processes.values().any(|p| {
        p.pml4_root.map(|r| r.start_address().as_u64()) == Some(root_phys)
            && !matches!(
                p.state.0,
                ProcessState::Zombie(_)
                    | ProcessState::KilledByFault { .. }
                    | ProcessState::KilledBySignal { .. }
            )
    })
}

pub fn signal_pgrp(pgid: Pid, signal: u32) -> usize {
    let targets: alloc::vec::Vec<Pid> = {
        let g = GLOBAL.lock();
        g.processes
            .iter()
            .filter(|(_, p)| p.identity.pgid() == pgid)
            .map(|(pid, _)| *pid)
            .collect()
    };
    let mut count = 0;
    for pid in targets {
        if send_signal(pid, signal).is_ok() {
            count += 1;
        }
    }
    count
}

pub fn current_parent_pid() -> u32 {
    let pid = current_pid();
    let g = GLOBAL.lock();
    g.processes
        .get(&pid)
        .and_then(|p| p.parent)
        .map(|pp| pp.0)
        .unwrap_or(0)
}

pub fn all_pids() -> Vec<Pid> {
    GLOBAL.lock().processes.keys().copied().collect()
}

pub struct ProcessSummary {
    pub pid: Pid,
    pub state_char: char,
    pub parent_pid: u32,
    pub brk_bytes: u64,
    pub pgrp: u32,
    pub session: u32,
    pub utime_clk: u64,
    pub stime_clk: u64,
    pub priority: i32,
    pub nice: i8,
    pub num_threads: u32,
    pub vsize: u64,
    pub rss_pages: u64,
    pub minflt: u64,
    pub majflt: u64,
    pub cutime_clk: u64,
    pub cstime_clk: u64,
    pub policy: u32,
    pub rt_priority: u32,
    pub processor: u32,
}

pub fn process_name(pid: Pid) -> [u8; 16] {
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.name)
        .unwrap_or([0u8; 16])
}

pub fn process_summary(pid: Pid) -> Option<ProcessSummary> {
    let g = GLOBAL.lock();
    let proc = g.processes.get(&pid)?;
    let state_char = match proc.state.0 {
        ProcessState::Running | ProcessState::Runnable => 'R',
        ProcessState::Parked => 'S',
        ProcessState::Zombie(_) => 'Z',
        ProcessState::KilledByFault { .. } => 'X',
        ProcessState::KilledBySignal { .. } => 'X',
        ProcessState::Stopped => 'T',
        ProcessState::Traced => 't',
        ProcessState::DlThrottled => 'D',
        ProcessState::CgroupThrottled => 'D',
    };
    let (priority, rt_priority, policy_num) = match proc.sched_class {
        SchedClass::Cfs => (20 + proc.nice as i32, 0u32, 0u32),
        SchedClass::Rt {
            priority: rt_p,
            round_robin,
        } => (
            -1 - (rt_p as i32),
            rt_p as u32,
            if round_robin { 2 } else { 1 },
        ),
        SchedClass::Deadline { .. } => (-1, 0u32, 6u32),
    };
    let (vsize, brk_cur, brk_start): (u64, u64, u64) = match proc.addr_space.as_ref() {
        Some(a) => {
            let vsize = a.mmap.lock().vmas.iter().map(|v| v.end - v.start).sum();
            let b = *a.brk.lock();
            (vsize, b.current, b.start)
        }
        None => (0, 0, 0),
    };
    let rss_pages = vsize / 4096;
    Some(ProcessSummary {
        pid,
        state_char,
        parent_pid: proc.parent.map(|p| p.0).unwrap_or(0),
        brk_bytes: brk_cur.saturating_sub(brk_start),
        pgrp: proc.identity.pgid().0,
        session: proc.identity.sid().0,
        utime_clk: proc.total_utime_ns / 10_000_000,
        stime_clk: proc.total_stime_ns / 10_000_000,
        minflt: proc.memory.minflt(),
        majflt: proc.memory.majflt(),
        cutime_clk: proc.cutime_ns / 10_000_000,
        cstime_clk: proc.cstime_ns / 10_000_000,
        priority,
        nice: proc.nice,
        num_threads: 1,
        vsize,
        rss_pages,
        policy: policy_num,
        rt_priority,
        processor: proc.home_cpu,
    })
}

pub fn process_cmdline(pid: Pid) -> Option<Vec<u8>> {
    Some(
        GLOBAL
            .lock()
            .processes
            .get(&pid)?
            .identity
            .cmdline()
            .to_vec(),
    )
}

pub fn set_cmdline(pid: Pid, cmdline: Vec<u8>) {
    if let Some(proc) = GLOBAL.lock().processes.get_mut(&pid) {
        proc.identity.set_cmdline(cmdline);
    }
}

pub fn process_exe(pid: Pid) -> Option<Vec<u8>> {
    let v = GLOBAL
        .lock()
        .processes
        .get(&pid)?
        .identity
        .exe_path()
        .to_vec();
    if v.is_empty() { None } else { Some(v) }
}

pub fn set_exe_path(pid: Pid, path: Vec<u8>) {
    if let Some(proc) = GLOBAL.lock().processes.get_mut(&pid) {
        proc.identity.set_exe_path(path);
    }
}

pub extern "C" fn first_launch_trampoline() -> ! {
    use crate::process::FirstLaunch;
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
    frame::arch::x86_64::tss::set_rsp0(top);
    frame::user::install_task_kernel_rsp(top);
}

pub extern "C" fn dump_all_processes() {
    frame::println!("=== dump_all_processes ===");
    let g = GLOBAL.lock();
    frame::println!("count: {}", g.processes.len());
    for (pid, proc) in g.processes.iter() {
        let state = match proc.state.0 {
            ProcessState::Runnable => "Runnable",
            ProcessState::Running => "Running",
            ProcessState::Parked => "Parked",
            ProcessState::Stopped => "Stopped",
            ProcessState::Traced => "Traced",
            ProcessState::Zombie(_) => "Zombie",
            ProcessState::KilledByFault { .. } => "KilledByFault",
            ProcessState::KilledBySignal { .. } => "KilledBySignal",
            ProcessState::DlThrottled => "DlThrottled",
            ProcessState::CgroupThrottled => "CgroupThrottled",
        };
        let owner = match proc.sched_owner.0 {
            SchedOwner::None => String::from("None"),
            SchedOwner::Running { cpu } => alloc::format!("Running({cpu})"),
            SchedOwner::Runnable { cpu } => alloc::format!("Runnable({cpu})"),
            SchedOwner::Parked { waitq_addr } => alloc::format!("Parked({waitq_addr:#x})"),
            SchedOwner::Stopped => String::from("Stopped"),
            SchedOwner::Traced => String::from("Traced"),
            SchedOwner::Zombie => String::from("Zombie"),
            SchedOwner::Reaping => String::from("Reaping"),
        };
        let ppid = proc.parent.map(|p| p.0).unwrap_or(0);
        let on_queue = match proc.sched_owner.0 {
            SchedOwner::Runnable { cpu } => {
                Some(CPU_QUEUES[cpu as usize].lock().runnable.contains_pid(*pid))
            }
            _ => None,
        };
        let on_queue_str = match on_queue {
            Some(true) => "on_q=true",
            Some(false) => "on_q=FALSE_LOST",
            None => "",
        };
        frame::println!(
            "pid={} ppid={} state={} owner={} pending={:#x} blocked={:#x} {}",
            pid.0,
            ppid,
            state,
            owner,
            proc.signals.pending(),
            proc.signals.blocked(),
            on_queue_str,
        );
    }
    frame::println!("=== end dump ===");
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
                Some(p) => (affinity_allows(p.cpu_affinity, this_cpu()), p.cpu_affinity),
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
    proc.home_cpu = target;
    set_sched_owner(
        proc,
        SchedOwner::Runnable { cpu: target },
        "affinity_migrate",
    );
    if matches!(proc.sched_class, SchedClass::Cfs) {
        proc.vruntime = proc
            .vruntime
            .saturating_sub(src_min_vr)
            .saturating_add(dst_min_vr);
    }
    let placed = q
        .runnable
        .enqueue(pid, enqueue_data_from_proc(proc), CfsPlace::Continuing);
    proc.vruntime = placed;
    record_enqueue(pid, "affinity_migrate", proc);
    drop(g);
    drop(q);
    send_resched_ipi(target);
}

fn publish_corpse(dead: Pid) {
    let (final_state, parent, exit_waiters) = {
        let mut g = GLOBAL.lock();
        let Some(p) = g.processes.get_mut(&dead) else {
            return;
        };
        let Some(st) = p.lifecycle.take_pending_exit() else {
            return;
        };
        p.state.0 = st.clone();
        let exit_waiters = p.exit_waiters.drain();
        (st, p.parent, exit_waiters)
    };
    if let Some(ppid) = parent {
        const CLD_EXITED: i32 = 1;
        const CLD_KILLED: i32 = 2;
        let info = match final_state {
            ProcessState::Zombie(code) => {
                crate::signal::SigInfo::for_child(dead.0, code, CLD_EXITED)
            }
            ProcessState::KilledBySignal { signal } => {
                crate::signal::SigInfo::for_child(dead.0, signal as i32, CLD_KILLED)
            }
            ProcessState::KilledByFault { vector, .. } => {
                crate::signal::SigInfo::for_child(dead.0, 128 + vector as i32, CLD_KILLED)
            }
            _ => return,
        };
        let waiters = {
            let mut g = GLOBAL.lock();
            if let Some(p) = g.processes.get_mut(&ppid) {
                p.signals.raise(1u64 << SIGCHLD);
                p.signals.set_siginfo(SIGCHLD as usize, info);
                p.child_exit.drain()
            } else {
                Vec::new()
            }
        };
        for w in waiters {
            let _ = wake_pid(w);
        }
        let _ = wake_pid(ppid);
    }
    wake_tracer_on_exit(dead);
    for w in exit_waiters {
        let _ = wake_pid(w);
    }
}

fn fmt_owner(o: SchedOwner) -> &'static str {
    match o {
        SchedOwner::None => "None",
        SchedOwner::Running { .. } => "Running",
        SchedOwner::Runnable { .. } => "Runnable",
        SchedOwner::Parked { .. } => "Parked",
        SchedOwner::Stopped => "Stopped",
        SchedOwner::Traced => "Traced",
        SchedOwner::Zombie => "Zombie",
        SchedOwner::Reaping => "Reaping",
    }
}

pub struct SchedCell<T>(T);

impl<T> SchedCell<T> {
    pub const fn new(v: T) -> Self {
        SchedCell(v)
    }

    pub fn get(&self) -> &T {
        &self.0
    }
}

fn set_sched_owner(proc: &mut Process, new: SchedOwner, site: &'static str) {
    let cur = proc.sched_owner.0;
    let pid = proc.pid;
    let ok = match (cur, new) {
        (SchedOwner::None, SchedOwner::Runnable { .. }) => true,
        (SchedOwner::None, SchedOwner::Running { .. }) => true,

        (SchedOwner::Runnable { cpu: a }, SchedOwner::Running { cpu: b }) => a == b,
        (SchedOwner::Running { cpu: a }, SchedOwner::Runnable { cpu: b }) => a == b,

        (SchedOwner::Running { .. }, SchedOwner::Parked { .. }) => true,
        (SchedOwner::Parked { .. }, SchedOwner::Runnable { .. }) => true,

        (SchedOwner::Parked { .. }, SchedOwner::Running { cpu: _ }) => true,

        (SchedOwner::Runnable { .. }, SchedOwner::Runnable { .. }) => true,

        (SchedOwner::Running { .. }, SchedOwner::Stopped) => true,
        (SchedOwner::Running { .. }, SchedOwner::Traced) => true,
        (SchedOwner::Stopped, SchedOwner::Runnable { .. }) => true,
        (SchedOwner::Traced, SchedOwner::Runnable { .. }) => true,

        (SchedOwner::Running { .. }, SchedOwner::Zombie) => true,
        (SchedOwner::Runnable { .. }, SchedOwner::Zombie) => true,
        (SchedOwner::Parked { .. }, SchedOwner::Zombie) => true,
        (SchedOwner::Stopped, SchedOwner::Zombie) => true,
        (SchedOwner::Traced, SchedOwner::Zombie) => true,

        (SchedOwner::Zombie, SchedOwner::Reaping) => true,
        (SchedOwner::Reaping, SchedOwner::None) => true,

        (a, b) if a == b => true,

        _ => false,
    };
    if !ok {
        panic!(
            "[sched-invariant] BAD TRANSITION at {site}: pid {} {} -> {} (full: {:?} -> {:?})",
            pid.0,
            fmt_owner(cur),
            fmt_owner(new),
            cur,
            new,
        );
    }
    match new {
        SchedOwner::Stopped | SchedOwner::Traced | SchedOwner::Parked { .. } => {
            proc.parking_unsaved = true;
        }
        SchedOwner::Running { .. } => {
            proc.parking_unsaved = false;
        }
        _ => {}
    }
    proc.sched_owner.0 = new;
}

#[derive(Clone, Copy)]
struct EnqProv {
    seq: u64,
    site: &'static str,
    enq_cpu: u32,
    owner_at_enq: SchedOwner,
    state_kind: u8,
}

fn state_kind(s: &ProcessState) -> u8 {
    match s {
        ProcessState::Runnable => 0,
        ProcessState::Running => 1,
        ProcessState::Parked => 2,
        ProcessState::Zombie(_) => 3,
        ProcessState::KilledByFault { .. } => 4,
        ProcessState::Stopped => 5,
        ProcessState::DlThrottled => 6,
        ProcessState::CgroupThrottled => 7,
        ProcessState::Traced => 8,
        ProcessState::KilledBySignal { .. } => 9,
    }
}

fn fmt_state_kind(k: u8) -> &'static str {
    match k {
        0 => "Runnable",
        1 => "Running",
        2 => "Parked",
        3 => "Zombie",
        4 => "KilledByFault",
        5 => "Stopped",
        6 => "DlThrottled",
        7 => "CgroupThrottled",
        8 => "Traced",
        9 => "KilledBySignal",
        _ => "?",
    }
}

static ENQ_SEQ: AtomicU64 = AtomicU64::new(0);
static ENQ_LOG: SpinIrq<BTreeMap<Pid, EnqProv>> = SpinIrq::new(BTreeMap::new());

fn record_enqueue(pid: Pid, site: &'static str, proc: &Process) {
    let prov = EnqProv {
        seq: ENQ_SEQ.fetch_add(1, Ordering::SeqCst),
        site,
        enq_cpu: this_cpu(),
        owner_at_enq: proc.sched_owner.0,
        state_kind: state_kind(&proc.state.0),
    };
    ENQ_LOG.lock().insert(pid, prov);
}

fn record_dequeue(pid: Pid) {
    ENQ_LOG.lock().remove(&pid);
}

fn dump_enq_log(pid: Pid) -> Option<EnqProv> {
    ENQ_LOG.lock().get(&pid).copied()
}

fn print_stale_pid_provenance(pid: Pid, picker_cpu: u32, picker_site: &'static str) {
    let cur_seq = ENQ_SEQ.load(Ordering::Relaxed);
    match dump_enq_log(pid) {
        Some(p) => frame::println!(
            "[STALE-RQ] pid={} picker_cpu={} picker={} | last_enq: site={} seq={} enq_cpu={} owner={:?} state={} | cur_seq={}",
            pid.0,
            picker_cpu,
            picker_site,
            p.site,
            p.seq,
            p.enq_cpu,
            p.owner_at_enq,
            fmt_state_kind(p.state_kind),
            cur_seq,
        ),
        None => frame::println!(
            "[STALE-RQ] pid={} picker_cpu={} picker={} | NO last_enq record (already dequeued, but pid was on the runqueue?!) | cur_seq={}",
            pid.0,
            picker_cpu,
            picker_site,
            cur_seq,
        ),
    }
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
                            p.parking_unsaved
                                || !affinity_allows(p.cpu_affinity, me as u32)
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
                            proc.vruntime = placed;
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
            proc.home_cpu = me as u32;
            set_sched_owner(
                proc,
                SchedOwner::Runnable { cpu: me as u32 },
                "try_steal_one_to_local",
            );
            if matches!(proc.sched_class, SchedClass::Cfs) {
                let adjusted = proc
                    .vruntime
                    .saturating_sub(peer_min_vr)
                    .saturating_add(me_min_vr);
                proc.vruntime = adjusted;
            }
            let placed =
                q.runnable
                    .enqueue(pid, enqueue_data_from_proc(proc), CfsPlace::Continuing);
            proc.vruntime = placed;
            record_enqueue(pid, "try_steal_one_to_local", proc);
            return Some(pid);
        }
    }
    None
}

fn switch_to_pid(pid: Pid) {
    CTXT_SWITCHES.fetch_add(1, Ordering::Relaxed);
    let _irq = frame::sync::IrqGuard::new();

    let (task_ctx, task_xsave, kstack_top, next_vm, next_pml4, rseq_addr, rseq_len, rseq_cpu_id) = {
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
        proc.last_run_ns = frame::cpu::clock::nanos_since_boot();
        frame::cpu::set_user_fs_base(proc.memory.fs_base());
        (
            proc.task.0.context_ptr(),
            proc.task.0.xsave_ptr(),
            proc.task.0.kstack_top(),
            proc.vmspace(),
            proc.pml4_root,
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

    let _old_vmspace = if let (Some(_vm_arc), Some(root)) = (next_vm.as_ref(), next_pml4) {
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
    let next = crate::timeout::next_deadline_ns().unwrap_or(u64::MAX);
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
        proc.parking_unsaved = true;
        let delta = now_ns.saturating_sub(proc.last_run_ns);
        charge_runtime(proc, delta);
        proc.last_run_ns = now_ns;
        let placed = q
            .runnable
            .enqueue(cur, enqueue_data_from_proc(proc), CfsPlace::Continuing);
        proc.vruntime = placed;
        record_enqueue(cur, "yield_current", proc);
        (
            cur,
            proc.task.0.context_ptr(),
            proc.task.0.xsave_ptr(),
            proc.task.0.kstack_bounds(),
        )
    };

    let cpu = this_cpu() as usize;
    let idle_ctx_ptr: *mut Context = {
        let mut q = CPU_QUEUES[cpu].lock();
        &mut q.idle_ctx as *mut Context
    };
    let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
    checked_save_into_task(
        "yield_current",
        cur_pid,
        cur_kstack,
        cur_ctx,
        idle_ctx_ptr,
        cur_xsave,
        idle_xsave,
    );
}

fn release_addr_space_user(
    addr_space: &alloc::sync::Arc<crate::process::AddressSpace>,
    ipc_ns: Option<&alloc::sync::Arc<crate::process::IpcNamespace>>,
) {
    if addr_space
        .live_users
        .fetch_sub(1, core::sync::atomic::Ordering::AcqRel)
        == 1
    {
        crate::ipc::shm::detach_all_for(addr_space, ipc_ns);
        crate::mmap_fault::detach_shared_file_for(addr_space);
    }
}

fn snapshot_addr_space_release_if_live(
    proc: &crate::process::Process,
) -> Option<(
    alloc::sync::Arc<crate::process::AddressSpace>,
    Option<alloc::sync::Arc<crate::process::IpcNamespace>>,
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

fn wake_tracer_on_exit(cur: Pid) {
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
            Some(p) => p.child_exit.drain(),
            None => alloc::vec::Vec::new(),
        }
    };
    for w in waiters {
        let _ = wake_pid(w);
    }
    let _ = wake_pid(tpid);
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
            proc.pml4_root
                .map(|f| f.start_address().as_u64())
                .unwrap_or(0),
        )
    };
    if vmspace_id != 0 {
        crate::futex::clear_child_tid(vmspace_id, clear_child_tid_addr);
        crate::futex::exit_robust_list(vmspace_id, robust_list_head);
        crate::futex::pi_owner_died(vmspace_id, cur);
    }
    {
        let g = GLOBAL.lock();
        if let Some(p) = g.processes.get(&cur) {
            if let crate::process::SchedClass::Deadline {
                runtime_ns: rt,
                period_ns: pe,
                ..
            } = p.sched_class
            {
                let home = p.home_cpu as usize;
                drop(g);
                CPU_QUEUES[home]
                    .lock()
                    .runnable
                    .release_dl_bandwidth(rt, pe);
                crate::timeout::cancel_callback(cur.raw() as u64);
            }
        }
    }
    crate::timeout::drop_pid(cur);
    crate::timeout::cancel_callback((cur.raw() as u64) | (1u64 << 63));
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
    handle_dying_children(cur);
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
            proc.pml4_root
                .map(|f| f.start_address().as_u64())
                .unwrap_or(0),
        )
    };
    if vmspace_id != 0 {
        crate::futex::clear_child_tid(vmspace_id, clear_child_tid_addr);
        crate::futex::exit_robust_list(vmspace_id, robust_list_head);
        crate::futex::pi_owner_died(vmspace_id, cur);
    }
    crate::timeout::drop_pid(cur);
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

pub fn kill_user_fault(addr: u64, vector: u8, error: u64) -> ! {
    let cur = {
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        q.current.take().expect("kill_user_fault: no current")
    };

    let (clear_child_tid_addr, robust_list_head, vmspace_id) = {
        let g = GLOBAL.lock();
        let proc = g.processes.get(&cur).unwrap();
        (
            proc.memory.clear_child_tid(),
            proc.memory.robust_list_head(),
            proc.pml4_root
                .map(|f| f.start_address().as_u64())
                .unwrap_or(0),
        )
    };
    if vmspace_id != 0 {
        crate::futex::clear_child_tid(vmspace_id, clear_child_tid_addr);
        crate::futex::exit_robust_list(vmspace_id, robust_list_head);
        crate::futex::pi_owner_died(vmspace_id, cur);
    }

    let as_release = {
        let mut g = GLOBAL.lock();
        let proc = g.processes.get_mut(&cur).unwrap();
        let as_release = snapshot_addr_space_release_if_live(proc);
        if proc.lifecycle.pending_exit().is_none() {
            proc.lifecycle
                .set_pending_exit(ProcessState::KilledByFault {
                    vector,
                    addr,
                    error,
                });
        }
        frame::println!(
            "[sched] pid {} killed by fault on cpu {}: vector={} addr={:#x} err={:#x}",
            cur.0,
            this_cpu(),
            vector,
            addr,
            error
        );
        as_release
    };
    if let Some((a, ipc)) = as_release {
        release_addr_space_user(&a, ipc.as_ref());
    }
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
    unreachable!("kill_user_fault resumed dying task");
}

pub fn park_on_pre_enqueued(wq: &crate::wait::WaitQueue) {
    park_on_inner(wq, true)
}

pub fn park_on(wq: &crate::wait::WaitQueue) {
    park_on_inner(wq, false)
}

fn park_on_inner(wq: &crate::wait::WaitQueue, pre_enqueued: bool) {
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
    let idle_ctx_ptr: *mut Context = {
        let mut q = CPU_QUEUES[cpu].lock();
        &mut q.idle_ctx as *mut Context
    };
    let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
    checked_save_into_task(
        "park_on_inner",
        cur_pid,
        cur_kstack,
        cur_ctx,
        idle_ctx_ptr,
        cur_xsave,
        idle_xsave,
    );
}

const WNOHANG: u64 = 1;
const WUNTRACED: u64 = 2;
#[allow(dead_code)]
const WCONTINUED: u64 = 8;

#[derive(Debug)]
pub enum WaitError {
    NoChildren,
    Interrupted,
}

impl WaitError {
    pub fn errno(&self) -> i64 {
        match self {
            WaitError::NoChildren => -10,
            WaitError::Interrupted => -4,
        }
    }
}

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

pub fn wait4_current(target_pid: i64, options: u64) -> Result<Option<(Pid, u32, i32)>, WaitError> {
    let cur_pid = current_pid();
    loop {
        let mut g = GLOBAL.lock();
        match wait4_scan(&g, cur_pid, target_pid, options) {
            WaitScan::NoChildren => return Err(WaitError::NoChildren),
            WaitScan::Reap(rpid, status) => {
                let (child_u, child_s, child_cu, child_cs) = match g.processes.get(&rpid) {
                    Some(c) => (c.total_utime_ns, c.total_stime_ns, c.cutime_ns, c.cstime_ns),
                    None => (0, 0, 0, 0),
                };
                let me = g.processes.get_mut(&cur_pid).unwrap();
                me.children.retain(|p| *p != rpid);
                me.trace.remove_tracee(rpid);
                me.cutime_ns = me
                    .cutime_ns
                    .saturating_add(child_u)
                    .saturating_add(child_cu);
                me.cstime_ns = me
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
                        crate::process::PidNamespace::drop_chain(&pns, rpid);
                    }
                    if let Some(root) = boxed.pml4_root {
                        let root_phys = root.start_address().as_u64();
                        if !root_has_live_user(root_phys) {
                            crate::futex::drop_vmspace(root_phys);
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
                            me.child_exit.enqueue(cur_pid);
                            let _ = q.current.take();
                            bank_slice_off_cpu(me);
                            me.state.0 = ProcessState::Parked;
                            set_sched_owner(
                                me,
                                SchedOwner::Parked {
                                    waitq_addr: &me.child_exit as *const _ as usize,
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
                let cpu = this_cpu() as usize;
                let idle_ctx_ptr: *mut Context = {
                    let mut q = CPU_QUEUES[cpu].lock();
                    &mut q.idle_ctx as *mut Context
                };
                let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
                checked_save_into_task(
                    "wait4_park",
                    cur_pid,
                    cur_kstack,
                    cur_ctx,
                    idle_ctx_ptr,
                    cur_xsave,
                    idle_xsave,
                );
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
                    return Err(WaitError::Interrupted);
                }
            }
        }
    }
}

fn exit_status_code(code: i32) -> i32 {
    (((code as u32) & 0xff) << 8) as i32
}

fn fault_status_code() -> i32 {
    crate::process::SIGSEGV as i32
}

pub fn wake_pid(pid: Pid) -> bool {
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
                proc.vruntime = placed;
                record_enqueue(pid, "wake_pid", proc);
            }
        }
    }
    send_resched_ipi(home);
    true
}

fn forward_signal_to_tracer_if_any(tf: &mut TrapFrame) {
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
            park_for_trace_stop(crate::process::TraceStop::Attach);
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
                p.signals.clear_pending(1u64 << signal);
                p.trace.set_event_msg(signal as u64);
                p.trace.clear_pending_inject();
            }
        }
        crate::ptrace::save_user_regs_for_trace(cur, tf);
        park_for_trace_stop(crate::process::TraceStop::Signal(signal));
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
                        t.state.0 = ProcessState::Runnable;
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

pub(crate) fn reenqueue_runnable(pid: Pid) {
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
            proc.vruntime = placed;
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
                p.vfork_done.drain()
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
                    child_proc.vfork_done.enqueue(cur);
                }
                &child_proc.vfork_done as *const _ as usize
            };
            let proc = g.processes.get_mut(&cur).unwrap();
            set_sched_owner(proc, SchedOwner::Parked { waitq_addr }, "vfork_park");
            if first {
                if let Some(child_p) = g.processes.get_mut(&child) {
                    if matches!(child_p.sched_owner.0, crate::process::SchedOwner::None) {
                        let placed = q.runnable.enqueue(
                            child,
                            enqueue_data_from_proc(child_p),
                            CfsPlace::New,
                        );
                        child_p.vruntime = placed;
                        set_sched_owner(
                            child_p,
                            SchedOwner::Runnable { cpu: cpu as u32 },
                            "vfork_child_enqueue",
                        );
                        record_enqueue(child, "vfork_child", child_p);
                    }
                }
            }
            (cur_ctx, cur_xsave, cur_kstack)
        };
        first = false;
        let cpu = this_cpu() as usize;
        let idle_ctx_ptr: *mut frame::cpu::task::Context = {
            let mut q = CPU_QUEUES[cpu].lock();
            &mut q.idle_ctx as *mut _
        };
        let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
        checked_save_into_task(
            "park_on_vfork_done",
            cur_pid_vfork,
            cur_kstack,
            cur_ctx,
            idle_ctx_ptr,
            cur_xsave,
            idle_xsave,
        );
    }
}

fn drain_exit_waiters(target: Pid) {
    let waiters = {
        let mut g = GLOBAL.lock();
        match g.processes.get_mut(&target) {
            Some(p) => p.exit_waiters.drain(),
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
        proc.signalfd_waiters.enqueue(cur);
        set_sched_owner(
            proc,
            SchedOwner::Parked {
                waitq_addr: &proc.signalfd_waiters as *const _ as usize,
            },
            "signalfd_park",
        );
        (cur_ctx, cur_xsave, cur_kstack)
    };
    let cpu = this_cpu() as usize;
    let idle_ctx_ptr: *mut frame::cpu::task::Context = {
        let mut q = CPU_QUEUES[cpu].lock();
        &mut q.idle_ctx as *mut _
    };
    let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
    checked_save_into_task(
        "park_on_signalfd_wait",
        cur,
        cur_kstack,
        cur_ctx,
        idle_ctx_ptr,
        cur_xsave,
        idle_xsave,
    );
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
        target_proc.exit_waiters.enqueue(cur);
        let waitq_addr = &target_proc.exit_waiters as *const _ as usize;
        let proc = g.processes.get_mut(&cur).unwrap();
        set_sched_owner(proc, SchedOwner::Parked { waitq_addr }, "exit_waiters_park");
        (cur_ctx, cur_xsave, cur_kstack)
    };
    let cpu = this_cpu() as usize;
    let idle_ctx_ptr: *mut frame::cpu::task::Context = {
        let mut q = CPU_QUEUES[cpu].lock();
        &mut q.idle_ctx as *mut _
    };
    let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
    checked_save_into_task(
        "park_on_exit_of",
        cur_pid_outer,
        cur_kstack,
        cur_ctx,
        idle_ctx_ptr,
        cur_xsave,
        idle_xsave,
    );
}

pub fn stop_current() {
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
                p.child_exit.drain()
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
    let cpu = this_cpu() as usize;
    let idle_ctx_ptr: *mut frame::cpu::task::Context = {
        let mut q = CPU_QUEUES[cpu].lock();
        &mut q.idle_ctx as *mut _
    };
    let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
    checked_save_into_task(
        "stop_current",
        cur_pid_stop,
        cur_kstack,
        cur_ctx,
        idle_ctx_ptr,
        cur_xsave,
        idle_xsave,
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
    crate::timeout::register(deadline_ns, cur);
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
    let _ = crate::timeout::unregister(cur);
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
        let cpu = this_cpu() as usize;
        let idle_ctx_ptr: *mut Context = {
            let mut q = CPU_QUEUES[cpu].lock();
            &mut q.idle_ctx as *mut Context
        };
        let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
        checked_save_into_task(
            "sleep_until_signal",
            cur,
            cur_kstack,
            cur_ctx,
            idle_ctx_ptr,
            cur_xsave,
            idle_xsave,
        );
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
    let cpu = this_cpu() as usize;
    let idle_ctx_ptr: *mut Context = {
        let mut q = CPU_QUEUES[cpu].lock();
        &mut q.idle_ctx as *mut Context
    };
    let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
    checked_save_into_task(
        "park_self",
        cur_pid,
        cur_kstack,
        cur_ctx,
        idle_ctx_ptr,
        cur_xsave,
        idle_xsave,
    );
}

pub fn park_self_at_guarded(site: &'static str, still_queued: &dyn Fn() -> bool) {
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

const DEFAULT_RT_PERIOD_NS: u64 = 1_000_000_000;
const DEFAULT_RT_RUNTIME_NS: u64 = 950_000_000;

static RT_PERIOD_NS: AtomicU64 = AtomicU64::new(DEFAULT_RT_PERIOD_NS);
static RT_RUNTIME_NS: AtomicU64 = AtomicU64::new(DEFAULT_RT_RUNTIME_NS);
static RT_PERIOD_START_NS: AtomicU64 = AtomicU64::new(0);
static RT_RUNTIME_CONSUMED_NS: AtomicU64 = AtomicU64::new(0);
static RT_THROTTLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn rt_throttled() -> bool {
    RT_THROTTLED.load(Ordering::Relaxed)
}

fn charge_rt_runtime(delta_ns: u64) {
    let runtime_cap = RT_RUNTIME_NS.load(Ordering::Relaxed);
    if runtime_cap == u64::MAX {
        return;
    }
    let period = RT_PERIOD_NS.load(Ordering::Relaxed);
    let now = frame::cpu::clock::nanos_since_boot();
    let start = RT_PERIOD_START_NS.load(Ordering::Relaxed);
    if start == 0 || now.saturating_sub(start) >= period {
        RT_PERIOD_START_NS.store(now, Ordering::Relaxed);
        RT_RUNTIME_CONSUMED_NS.store(0, Ordering::Relaxed);
        RT_THROTTLED.store(false, Ordering::Relaxed);
    }
    let consumed = RT_RUNTIME_CONSUMED_NS.fetch_add(delta_ns, Ordering::Relaxed) + delta_ns;
    if consumed >= runtime_cap {
        RT_THROTTLED.store(true, Ordering::Relaxed);
    }
}

fn rt_bandwidth_tick() {
    let period = RT_PERIOD_NS.load(Ordering::Relaxed);
    let now = frame::cpu::clock::nanos_since_boot();
    let start = RT_PERIOD_START_NS.load(Ordering::Relaxed);
    if start != 0 && now.saturating_sub(start) >= period {
        RT_PERIOD_START_NS.store(now, Ordering::Relaxed);
        RT_RUNTIME_CONSUMED_NS.store(0, Ordering::Relaxed);
        RT_THROTTLED.store(false, Ordering::Relaxed);
    }
}

pub fn rt_bandwidth_cfg() -> (u64, u64) {
    (
        RT_PERIOD_NS.load(Ordering::Relaxed),
        RT_RUNTIME_NS.load(Ordering::Relaxed),
    )
}

pub fn set_rt_period_ns(period_ns: u64) -> bool {
    if period_ns == 0 {
        return false;
    }
    RT_PERIOD_NS.store(period_ns, Ordering::Relaxed);
    RT_PERIOD_START_NS.store(0, Ordering::Relaxed);
    RT_RUNTIME_CONSUMED_NS.store(0, Ordering::Relaxed);
    RT_THROTTLED.store(false, Ordering::Relaxed);
    true
}

pub fn set_rt_runtime_ns(runtime_ns: u64) {
    RT_RUNTIME_NS.store(runtime_ns, Ordering::Relaxed);
    RT_PERIOD_START_NS.store(0, Ordering::Relaxed);
    RT_RUNTIME_CONSUMED_NS.store(0, Ordering::Relaxed);
    RT_THROTTLED.store(false, Ordering::Relaxed);
}

#[derive(Default)]
pub struct CpuStat {
    pub user_jiffies: AtomicU64,
    pub nice_jiffies: AtomicU64,
    pub system_jiffies: AtomicU64,
    pub idle_jiffies: AtomicU64,
}

impl CpuStat {
    pub const fn new() -> Self {
        Self {
            user_jiffies: AtomicU64::new(0),
            nice_jiffies: AtomicU64::new(0),
            system_jiffies: AtomicU64::new(0),
            idle_jiffies: AtomicU64::new(0),
        }
    }
}

pub static CPU_STATS: [CpuStat; MAX_CPUS] = [const { CpuStat::new() }; MAX_CPUS];
pub static CTXT_SWITCHES: AtomicU64 = AtomicU64::new(0);

pub static INTR_COUNT: AtomicU64 = AtomicU64::new(0);

fn account_tick_jiffy() {
    let cpu = this_cpu() as usize;
    if cpu >= MAX_CPUS {
        return;
    }
    INTR_COUNT.fetch_add(1, Ordering::Relaxed);
    let cur = CPU_QUEUES[cpu].lock().current;
    let bucket = match cur {
        None => &CPU_STATS[cpu].idle_jiffies,
        Some(pid) => {
            let g = GLOBAL.lock();
            let (in_syscall, nice) = g
                .processes
                .get(&pid)
                .map(|p| (p.lifecycle.in_syscall(), p.nice))
                .unwrap_or((false, 0));
            if in_syscall {
                &CPU_STATS[cpu].system_jiffies
            } else if nice > 0 {
                &CPU_STATS[cpu].nice_jiffies
            } else {
                &CPU_STATS[cpu].user_jiffies
            }
        }
    };
    bucket.fetch_add(1, Ordering::Relaxed);
}

pub fn jiffies_summary() -> (u64, u64, u64, u64) {
    let mut user = 0;
    let mut nice = 0;
    let mut system = 0;
    let mut idle = 0;
    for stats in CPU_STATS.iter() {
        user += stats.user_jiffies.load(Ordering::Relaxed);
        nice += stats.nice_jiffies.load(Ordering::Relaxed);
        system += stats.system_jiffies.load(Ordering::Relaxed);
        idle += stats.idle_jiffies.load(Ordering::Relaxed);
    }
    (user, nice, system, idle)
}

pub fn jiffies_for_cpu(cpu: usize) -> Option<(u64, u64, u64, u64)> {
    if cpu >= MAX_CPUS {
        return None;
    }
    Some((
        CPU_STATS[cpu].user_jiffies.load(Ordering::Relaxed),
        CPU_STATS[cpu].nice_jiffies.load(Ordering::Relaxed),
        CPU_STATS[cpu].system_jiffies.load(Ordering::Relaxed),
        CPU_STATS[cpu].idle_jiffies.load(Ordering::Relaxed),
    ))
}

pub fn ctxt_switches() -> u64 {
    CTXT_SWITCHES.load(Ordering::Relaxed)
}

pub fn intr_count() -> u64 {
    INTR_COUNT.load(Ordering::Relaxed)
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

    crate::net::signal_pump_tick();

    crate::console::poll_rx_from_tick();

    crate::input::poll_from_tick();

    let now_ns = frame::cpu::clock::nanos_since_boot();
    crate::timeout::wake_expired(now_ns);
    crate::timeout::wake_expired_callbacks(now_ns);

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
                let delta = now_ns.saturating_sub(cur_proc.last_run_ns);
                let rt_top = q.runnable.rt_top_priority();
                match cur_proc.sched_class {
                    SchedClass::Cfs => {
                        let cgroup_throttled_now = if let Some(cg) = cur_proc.cgroup.clone() {
                            let mut cpu_ctl = cg.cpu.lock();
                            cpu_ctl.charge_cpu_runtime(delta, now_ns)
                        } else {
                            false
                        };
                        if cgroup_throttled_now {
                            bank_cpu_time(cur_proc, delta);
                            cur_proc.last_run_ns = now_ns;
                            cur_proc.state.0 = ProcessState::CgroupThrottled;
                            force_throttle = true;
                        } else if runqueue_empty {
                            return;
                        } else if rt_top.is_some() {
                            charge_runtime(cur_proc, delta);
                            cur_proc.last_run_ns = now_ns;
                        } else {
                            charge_runtime(cur_proc, delta);
                            cur_proc.last_run_ns = now_ns;
                            let leftmost_vr = q.runnable.cfs_leftmost_vruntime_pub();
                            let cur_vr = cur_proc.vruntime;
                            let wake_preempt =
                                leftmost_vr.saturating_add(SCHED_WAKEUP_GRANULARITY_NS) < cur_vr;
                            if !wake_preempt {
                                let slice = q.runnable.cfs_slice_for(cur_proc.weight);
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
                            return;
                        }
                        let preempted_by_higher = rt_top.map(|t| t > priority).unwrap_or(false);
                        if preempted_by_higher {
                            bank_cpu_time(cur_proc, delta);
                            cur_proc.last_run_ns = now_ns;
                        } else if round_robin {
                            let peer_at_same = rt_top.map(|t| t == priority).unwrap_or(false);
                            if !peer_at_same || delta < SCHED_RR_TIMESLICE_NS {
                                return;
                            }
                            bank_cpu_time(cur_proc, delta);
                            cur_proc.last_run_ns = now_ns;
                        } else {
                            return;
                        }
                    }
                    SchedClass::Deadline { .. } => {
                        let consumed = delta.min(cur_proc.dl_runtime_remaining);
                        cur_proc.dl_runtime_remaining =
                            cur_proc.dl_runtime_remaining.saturating_sub(consumed);
                        bank_cpu_time(cur_proc, delta);
                        cur_proc.last_run_ns = now_ns;
                        if cur_proc.dl_runtime_remaining == 0 {
                            cur_proc.dl_throttled = true;
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
                    .map(|p| affinity_allows(p.cpu_affinity, this_cpu()))
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
                    proc.vruntime = placed;
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
            cur_proc.parking_unsaved = true;
            let placed =
                q.runnable
                    .enqueue(cur, enqueue_data_from_proc(cur_proc), CfsPlace::Continuing);
            cur_proc.vruntime = placed;
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
        next_proc.last_run_ns = now_ns;
        let next_ctx = next_proc.task.0.context_ptr();
        let next_xsave = next_proc.task.0.xsave_ptr();
        let next_top = next_proc.task.0.kstack_top();
        let next_vm = next_proc.vmspace();
        let next_pml4 = next_proc.pml4_root;
        let next_fs_base = next_proc.memory.fs_base();
        Some((
            cur,
            cur_ctx,
            next_ctx,
            cur_xsave,
            next_xsave,
            next_top,
            next_vm,
            next_pml4,
            cur_kstack,
            next_fs_base,
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
        next_pml4,
        cur_kstack,
        next_fs_base,
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
        let _old_vmspace = if let (Some(_vm_arc), Some(root)) = (next_vm.as_ref(), next_pml4) {
            frame::mm::vm::VmSpace::activate_root(root);
            let cpu = this_cpu() as usize;
            let mut q = CPU_QUEUES[cpu].lock();
            core::mem::replace(&mut q.active_vmspace, next_vm)
        } else {
            None
        };
        install_kernel_rsp(next_top);
        frame::cpu::set_user_fs_base(next_fs_base);
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

#[derive(Debug)]
pub enum SignalError {
    Invalid,
    NoSuchProcess,
}

pub fn send_signal(target: Pid, signal: u32) -> Result<(), SignalError> {
    let info = crate::signal::SigInfo::for_kill(signal, current_pid().raw());
    send_signal_with_info(target, signal, info)
}

pub fn send_signal_with_info(
    target: Pid,
    signal: u32,
    info: crate::signal::PendingSigInfo,
) -> Result<(), SignalError> {
    if signal == 0 || signal as usize >= NSIG {
        return Err(SignalError::Invalid);
    }
    let mut g = GLOBAL.lock();
    let proc = g
        .processes
        .get_mut(&target)
        .ok_or(SignalError::NoSuchProcess)?;

    if signal == SIGKILL {
        let mut zombified = false;
        let mut dying_fds: Option<Arc<crate::vfs::fd::FdTable>> = None;
        let killed_as = proc.addr_space.clone();
        let killed_ipc = proc.namespaces.ipc();
        match proc.state.0 {
            ProcessState::Running => {
                proc.signals.raise(1u64 << SIGKILL);
                let home = proc.home_cpu;
                drop(g);
                if home != this_cpu() {
                    send_resched_ipi(home);
                }
                return Ok(());
            }
            ProcessState::Runnable => {
                proc.signals.raise(1u64 << SIGKILL);
                let home = proc.home_cpu;
                drop(g);
                if home != this_cpu() {
                    send_resched_ipi(home);
                }
                return Ok(());
            }
            ProcessState::Stopped => {
                proc.state.0 = ProcessState::KilledBySignal { signal: SIGKILL };
                let home = proc.home_cpu;
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
                let home = proc.home_cpu;
                drop(g);
                {
                    let mut q = CPU_QUEUES[home as usize].lock();
                    let mut g = GLOBAL.lock();
                    if let Some(p) = g.processes.get_mut(&target) {
                        let placed =
                            q.runnable
                                .enqueue(target, enqueue_data_from_proc(p), CfsPlace::Wake);
                        p.vruntime = placed;
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
                    proc.sched_class,
                    crate::process::SchedClass::Deadline { .. }
                );
                let (rt_ns, pe_ns) = match proc.sched_class {
                    crate::process::SchedClass::Deadline {
                        runtime_ns,
                        period_ns,
                        ..
                    } => (runtime_ns, period_ns),
                    _ => (0, 0),
                };
                proc.state.0 = ProcessState::KilledBySignal { signal: SIGKILL };
                let home = proc.home_cpu;
                if Arc::strong_count(&proc.fds) == 1 {
                    dying_fds = Some(core::mem::replace(
                        &mut proc.fds,
                        Arc::new(crate::vfs::fd::FdTable::new()),
                    ));
                }

                drop(g);
                crate::timeout::cancel_callback(target.raw() as u64);
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
                    crate::signal::SigInfo::for_child(target.0, SIGKILL as i32, CLD_KILLED);
                let waiters = {
                    let mut g = GLOBAL.lock();
                    if let Some(pp) = g.processes.get_mut(&ppid) {
                        pp.signals.raise(1u64 << SIGCHLD);
                        pp.signals.set_siginfo(SIGCHLD as usize, info_chld);
                        pp.child_exit.drain()
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

    proc.signals.raise(1u64 << signal);
    proc.signals.set_siginfo(signal as usize, info);

    if signal == SIGCONT && proc.state.0 == ProcessState::Stopped {
        let stop_mask = (1u64 << SIGSTOP) | (1u64 << 20) | (1u64 << 21) | (1u64 << 22);
        proc.signals.clear_pending(stop_mask);
        proc.state.0 = ProcessState::Runnable;
        let home = proc.home_cpu;
        drop(g);
        {
            let mut q = CPU_QUEUES[home as usize].lock();
            let mut g = GLOBAL.lock();
            if let Some(p) = g.processes.get_mut(&target) {
                let placed = q
                    .runnable
                    .enqueue(target, enqueue_data_from_proc(p), CfsPlace::Wake);
                p.vruntime = placed;
                set_sched_owner(p, SchedOwner::Runnable { cpu: home }, "sigcont_wake");
                record_enqueue(target, "sigcont_wake", p);
            }
        }
        if home != this_cpu() {
            send_resched_ipi(home);
        }
        return Ok(());
    }

    let blocked = proc.signals.blocked();
    let sfd_waiters = proc.signalfd_waiters.drain();

    if proc.state.0 == ProcessState::Parked && (blocked & (1u64 << signal)) == 0 {
        proc.state.0 = ProcessState::Runnable;
        let home = proc.home_cpu;
        drop(g);
        {
            let mut q = CPU_QUEUES[home as usize].lock();
            let mut g = GLOBAL.lock();
            if let Some(p) = g.processes.get_mut(&target) {
                let placed = q
                    .runnable
                    .enqueue(target, enqueue_data_from_proc(p), CfsPlace::Wake);
                p.vruntime = placed;
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
    for sig in 1..crate::process::NSIG as u32 {
        if candidate & (1u64 << sig) == 0 {
            continue;
        }
        let handler = acts[sig as usize].handler;
        let ignored = handler == 1
            || (handler == 0
                && matches!(
                    crate::signal::default_action(sig),
                    crate::signal::DefaultAction::Ignore
                ));
        if !ignored {
            return true;
        }
    }
    false
}

pub fn add_cgroup_charge(bytes: u64) {
    let cpu = this_cpu() as usize;
    let pid = match CPU_QUEUES[cpu].lock().current {
        Some(p) => p,
        None => return,
    };
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.cgroup_charged_bytes = p.cgroup_charged_bytes.saturating_add(bytes);
    }
}

pub fn charge_process_memory(pid: Pid, bytes: u64) {
    if bytes == 0 {
        return;
    }
    let cg = {
        let g = GLOBAL.lock();
        match g.processes.get(&pid) {
            Some(p) => p.cgroup.clone(),
            None => return,
        }
    };
    if let Some(cg) = &cg {
        if cg.try_charge_memory(bytes).is_err() {
            cg.oom_kill_one();
            return;
        }
    }
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.cgroup_charged_bytes = p.cgroup_charged_bytes.saturating_add(bytes);
    }
}

pub fn sub_cgroup_charge(bytes: u64) {
    let cpu = this_cpu() as usize;
    let pid = match CPU_QUEUES[cpu].lock().current {
        Some(p) => p,
        None => return,
    };
    let (cg, actual) = {
        let mut g = GLOBAL.lock();
        let p = match g.processes.get_mut(&pid) {
            Some(p) => p,
            None => return,
        };
        let actual = bytes.min(p.cgroup_charged_bytes);
        p.cgroup_charged_bytes -= actual;
        (p.cgroup.clone(), actual)
    };
    if let Some(cg) = cg {
        if actual > 0 {
            cg.uncharge_memory(actual);
        }
    }
}

const LOAD_FSHIFT: u32 = 11;
const LOAD_FIXED_1: u64 = 1 << LOAD_FSHIFT;
const LOAD_FREQ_TICKS: u64 = 500;

const EXP_1: u64 = 1884;
const EXP_5: u64 = 2014;
const EXP_15: u64 = 2037;

static LOAD_TICK_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn loadavg_tick_count() -> u64 {
    LOAD_TICK_COUNTER.load(Ordering::Relaxed)
}

static RESCHED_TICK_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn resched_tick_count() -> u64 {
    RESCHED_TICK_COUNTER.load(Ordering::Relaxed)
}

static LOADAVG_1: AtomicU64 = AtomicU64::new(0);
static LOADAVG_5: AtomicU64 = AtomicU64::new(0);
static LOADAVG_15: AtomicU64 = AtomicU64::new(0);

#[inline(never)]
fn sample_loadavg_if_due() {
    let n = LOAD_TICK_COUNTER.fetch_add(1, Ordering::Relaxed);
    if !(n + 1).is_multiple_of(LOAD_FREQ_TICKS) {
        return;
    }
    let active = {
        let g = GLOBAL.lock();
        let mut a = 0u64;
        for p in g.processes.values() {
            match p.state.0 {
                ProcessState::Running | ProcessState::Runnable => a += 1,
                ProcessState::Parked => a += 1,
                _ => {}
            }
        }
        a
    };
    let active_fp = active << LOAD_FSHIFT;
    update_loadavg(&LOADAVG_1, EXP_1, active_fp);
    update_loadavg(&LOADAVG_5, EXP_5, active_fp);
    update_loadavg(&LOADAVG_15, EXP_15, active_fp);
}

fn update_loadavg(slot: &AtomicU64, decay: u64, active_fp: u64) {
    let prev = slot.load(Ordering::Relaxed);
    let next = (prev.saturating_mul(decay) + active_fp.saturating_mul(LOAD_FIXED_1 - decay))
        >> LOAD_FSHIFT;
    slot.store(next, Ordering::Relaxed);
}

pub fn last_pid() -> u32 {
    NEXT_PID.load(Ordering::Relaxed).saturating_sub(1)
}

pub fn loadavg_fp() -> (u64, u64, u64) {
    (
        LOADAVG_1.load(Ordering::Relaxed),
        LOADAVG_5.load(Ordering::Relaxed),
        LOADAVG_15.load(Ordering::Relaxed),
    )
}

pub fn loadavg_for_sysinfo() -> (u64, u64, u64) {
    let (a, b, c) = loadavg_fp();
    (a << 5, b << 5, c << 5)
}

pub fn record_minor_fault() {
    let pid = match CPU_QUEUES[this_cpu() as usize].lock().current {
        Some(p) => p,
        None => return,
    };
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        p.memory.incr_minflt();
    }
}

pub fn record_major_fault() {
    let pid = match CPU_QUEUES[this_cpu() as usize].lock().current {
        Some(p) => p,
        None => return,
    };
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        p.memory.incr_majflt();
    }
}

#[inline(never)]
pub fn procs_running_blocked() -> (u64, u64) {
    let g = GLOBAL.lock();
    let mut running = 0u64;
    let mut blocked = 0u64;
    for p in g.processes.values() {
        match p.state.0 {
            ProcessState::Running | ProcessState::Runnable => running += 1,
            ProcessState::Parked => blocked += 1,
            _ => {}
        }
    }
    (running, blocked)
}

pub fn syscall_enter_account() {
    let cpu = this_cpu() as usize;
    let pid = match CPU_QUEUES[cpu].lock().current {
        Some(p) => p,
        None => return,
    };
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.lifecycle.set_in_syscall(true);
    }
}

pub fn syscall_exit_account() {
    let cpu = this_cpu() as usize;
    let pid = match CPU_QUEUES[cpu].lock().current {
        Some(p) => p,
        None => return,
    };
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.lifecycle.set_in_syscall(false);
    }
}

pub fn global_lock() -> frame::sync::SpinIrqGuard<'static, Global> {
    GLOBAL.lock()
}

pub fn park_for_trace_stop(reason: crate::process::TraceStop) {
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
        me.state.0 = ProcessState::Traced;
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
                Some(p) => p.child_exit.drain(),
                None => alloc::vec::Vec::new(),
            }
        };
        for pid in waiters {
            let _ = wake_pid(pid);
        }
    }
    let cpu = this_cpu() as usize;
    let idle_ctx_ptr: *mut Context = {
        let mut q = CPU_QUEUES[cpu].lock();
        &mut q.idle_ctx as *mut Context
    };
    let idle_xsave = task::bootstrap_xsave_ptr(cpu as u32);
    checked_save_into_task(
        "park_for_trace_stop",
        cur,
        cur_kstack,
        cur_ctx,
        idle_ctx_ptr,
        cur_xsave,
        idle_xsave,
    );
}

pub fn resume_traced(target: Pid, inject_signal: u32, trace_syscall: bool) -> bool {
    let needs_enqueue = {
        let mut g = GLOBAL.lock();
        let p = match g.processes.get_mut(&target) {
            Some(p) => p,
            None => return false,
        };
        if p.state.0 != ProcessState::Traced {
            return false;
        }
        p.trace.resume(trace_syscall);
        if inject_signal != 0 && inject_signal < NSIG as u32 {
            p.signals.raise(1u64 << inject_signal);
            p.trace.set_pending_inject(inject_signal);
        }
        p.state.0 = ProcessState::Runnable;
        true
    };
    if needs_enqueue {
        reenqueue_runnable(target);
    }
    true
}

pub fn set_traced(p: &mut Process) {
    p.state.0 = ProcessState::Traced;
}

pub fn resume_from_traced(p: &mut Process) -> bool {
    if p.state.0 == ProcessState::Traced {
        p.state.0 = ProcessState::Runnable;
        true
    } else {
        false
    }
}

pub fn cpu_to_nudge(p: &Process) -> u32 {
    match p.sched_owner.0 {
        SchedOwner::Running { cpu } | SchedOwner::Runnable { cpu } => cpu,
        _ => p.home_cpu,
    }
}

pub fn with_target_vmspace(
    target: Pid,
) -> Option<Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>> {
    let g = GLOBAL.lock();
    g.processes.get(&target).and_then(|p| p.vmspace())
}

pub fn snapshot_user_regs(target: Pid) -> Option<crate::ptrace::UserRegs> {
    GLOBAL
        .lock()
        .processes
        .get(&target)
        .and_then(|p| p.trace.saved_regs())
}

pub fn write_user_regs(target: Pid, regs: &crate::ptrace::UserRegs) -> bool {
    let mut g = GLOBAL.lock();
    match g.processes.get_mut(&target) {
        Some(p) => {
            p.trace.set_saved_regs(*regs);
            true
        }
        None => false,
    }
}

pub fn sched_class_of_pid(pid: Pid) -> Option<crate::process::SchedClass> {
    GLOBAL.lock().processes.get(&pid).map(|p| p.sched_class)
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
            let info = crate::signal::SigInfo::for_kill(pdeathsig, cur.raw());
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
            g.processes.get(&pid).map(|p| p.home_cpu)
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
                proc.vruntime = placed;
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
            Some(p) => p.home_cpu,
            None => return Err(ESRCH),
        }
    };
    let mut q = CPU_QUEUES[home as usize].lock();
    let mut g = GLOBAL.lock();
    let proc = match g.processes.get_mut(&target) {
        Some(p) => p,
        None => return Err(ESRCH),
    };
    if let crate::process::SchedClass::Deadline {
        runtime_ns: rt,
        period_ns: pe,
        ..
    } = proc.sched_class
    {
        q.runnable.release_dl_bandwidth(rt, pe);
    }
    if !q.runnable.admit_dl_bandwidth(runtime_ns, period_ns) {
        if let crate::process::SchedClass::Deadline {
            runtime_ns: rt,
            period_ns: pe,
            ..
        } = proc.sched_class
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
    proc.sched_class = crate::process::SchedClass::Deadline {
        runtime_ns,
        deadline_ns,
        period_ns,
    };
    proc.dl_runtime_remaining = runtime_ns;
    proc.dl_absolute_deadline = now_ns.saturating_add(deadline_ns);
    proc.dl_next_replenish = proc.dl_absolute_deadline;
    proc.dl_throttled = false;
    if was_runnable {
        let placed = q
            .runnable
            .enqueue(target, enqueue_data_from_proc(proc), CfsPlace::Continuing);
        proc.vruntime = placed;
        record_enqueue(target, "set_deadline_class", proc);
    }
    crate::timeout::register_callback(
        proc.dl_next_replenish,
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
        let (runtime_ns, period_ns) = match proc.sched_class {
            crate::process::SchedClass::Deadline {
                runtime_ns,
                period_ns,
                ..
            } => (runtime_ns, period_ns),
            _ => return,
        };
        proc.dl_runtime_remaining = runtime_ns;
        proc.dl_absolute_deadline = proc.dl_absolute_deadline.saturating_add(period_ns);
        proc.dl_next_replenish = proc.dl_absolute_deadline;
        let was_throttled = proc.state.0 == ProcessState::DlThrottled;
        proc.dl_throttled = false;
        if was_throttled {
            proc.state.0 = ProcessState::Runnable;
        }
        proc.dl_next_replenish
    };

    let (home, was_throttled) = {
        let g = GLOBAL.lock();
        match g.processes.get(&pid) {
            Some(p) => {
                let throttled = matches!(p.state.0, ProcessState::Runnable)
                    && matches!(p.sched_class, crate::process::SchedClass::Deadline { .. });
                (p.home_cpu, throttled)
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
                proc.vruntime = placed;
                record_enqueue(pid, "dl_replenish_callback", proc);
            }
        }
        drop(g);
        drop(q);
        if home != this_cpu() {
            send_resched_ipi(home);
        }
    }

    crate::timeout::register_callback(next_deadline, key, dl_replenish_callback);
}

pub fn set_sched_class(target: Pid, new_class: crate::process::SchedClass) -> Result<(), i64> {
    const ESRCH: i64 = -3;
    let home = {
        let g = GLOBAL.lock();
        match g.processes.get(&target) {
            Some(p) => p.home_cpu,
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
        proc.sched_class,
        crate::process::SchedClass::Deadline { .. }
    ) && !matches!(new_class, crate::process::SchedClass::Deadline { .. });
    if let crate::process::SchedClass::Deadline {
        runtime_ns: rt,
        period_ns: pe,
        ..
    } = proc.sched_class
    {
        if !matches!(new_class, crate::process::SchedClass::Deadline { .. }) {
            q.runnable.release_dl_bandwidth(rt, pe);
            proc.dl_runtime_remaining = 0;
            proc.dl_absolute_deadline = 0;
            proc.dl_next_replenish = 0;
            proc.dl_throttled = false;
            if proc.state.0 == ProcessState::DlThrottled {
                proc.state.0 = ProcessState::Runnable;
            }
        }
    }
    proc.sched_class = new_class;
    if matches!(new_class, crate::process::SchedClass::Cfs) {
        let placed_floor = q.runnable.cfs_min_vruntime();
        proc.vruntime = proc.vruntime.max(placed_floor);
    }
    if was_queued {
        let placed = q
            .runnable
            .enqueue(target, enqueue_data_from_proc(proc), CfsPlace::Continuing);
        proc.vruntime = placed;
        record_enqueue(target, "set_sched_class", proc);
    }
    drop(g);
    drop(q);
    if leaving_dl {
        crate::timeout::cancel_callback(target.raw() as u64);
    }
    if matches!(new_class, crate::process::SchedClass::Rt { .. }) && home != this_cpu() {
        send_resched_ipi(home);
    }
    Ok(())
}

pub fn process_pid_ns(pid: Pid) -> Option<Arc<crate::process::PidNamespace>> {
    let g = GLOBAL.lock();
    g.processes.get(&pid).and_then(|p| p.namespaces.pid())
}

pub fn set_current_pending_pid_ns(ns: Option<Arc<crate::process::PidNamespace>>) {
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.namespaces.set_pending_pid(ns);
    }
}

pub fn set_current_pending_ipc_ns(ns: Option<Arc<crate::process::IpcNamespace>>) {
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.namespaces.set_pending_ipc(ns);
    }
}

pub fn current_local_pid() -> u32 {
    let host = current_pid();
    let ns = match process_pid_ns(host) {
        Some(n) => n,
        None => return host.0,
    };
    ns.host_to_local_in(host)
}

pub fn host_to_caller_local(host: Pid) -> u32 {
    let cur = current_pid();
    let ns = match process_pid_ns(cur) {
        Some(n) => n,
        None => return host.0,
    };
    ns.host_to_local_in(host)
}

pub fn caller_local_to_host(local: u32) -> Option<Pid> {
    let cur = current_pid();
    let ns = match process_pid_ns(cur) {
        Some(n) => n,
        None => return Some(Pid(local)),
    };
    ns.local_to_host_in(local)
}

pub fn caller_visible_pids() -> Vec<(Pid, u32)> {
    let cur = current_pid();
    match process_pid_ns(cur) {
        None => all_pids().into_iter().map(|p| (p, p.0)).collect(),
        Some(ns) => ns
            .host_to_local
            .lock()
            .iter()
            .map(|(host, local)| (*host, *local))
            .collect(),
    }
}

pub fn caller_host_to_local(host: Pid) -> u32 {
    let cur = current_pid();
    match process_pid_ns(cur) {
        Some(ns) => ns.host_to_local_in(host),
        None => host.0,
    }
}

pub fn process_umask(pid: Pid) -> u16 {
    let g = GLOBAL.lock();
    g.processes.get(&pid).map(|p| p.files.umask()).unwrap_or(0)
}

pub fn process_charged_bytes(pid: Pid) -> u64 {
    let g = GLOBAL.lock();
    g.processes
        .get(&pid)
        .map(|p| p.cgroup_charged_bytes)
        .unwrap_or(0)
}

pub fn process_count_alive() -> u64 {
    let g = GLOBAL.lock();
    g.processes
        .values()
        .filter(|p| !matches!(p.state.0, ProcessState::Zombie(_)))
        .count() as u64
}

pub fn current_cgroup() -> Option<Arc<crate::cgroup::Cgroup>> {
    let cpu = this_cpu() as usize;
    let pid = CPU_QUEUES[cpu].lock().current?;
    process_cgroup(pid)
}

pub fn process_cgroup(pid: Pid) -> Option<Arc<crate::cgroup::Cgroup>> {
    let g = GLOBAL.lock();
    g.processes.get(&pid).and_then(|p| p.cgroup.clone())
}

pub fn cpu_affinity(pid: Pid) -> Option<u64> {
    GLOBAL.lock().processes.get(&pid).map(|p| p.cpu_affinity)
}

pub fn process_euid(pid: Pid) -> Option<u32> {
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.creds.lock().euid)
}

pub fn set_cpu_affinity(pid: Pid, mask: u64) -> bool {
    let owner = {
        let mut g = GLOBAL.lock();
        let p = match g.processes.get_mut(&pid) {
            Some(p) => p,
            None => return false,
        };
        p.cpu_affinity = mask;
        cpu_to_nudge(p)
    };
    send_resched_ipi_pub(owner);
    true
}

pub fn set_process_cgroup(pid: Pid, cg: Arc<crate::cgroup::Cgroup>) {
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.cgroup = Some(cg);
    }
}

pub fn process_state(pid: Pid) -> Option<crate::process::ProcessState> {
    let g = GLOBAL.lock();
    g.processes.get(&pid).map(|p| p.state.0.clone())
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
    proc.signals.clear_pending(bit);
    let pinfo = proc.signals.siginfo(signum as usize);
    proc.signals
        .set_siginfo(signum as usize, crate::signal::PendingSigInfo::default());
    (pinfo.si_code, pinfo.aux)
}

pub fn with_current_sigaction(signal: u32) -> Option<crate::process::SigAction> {
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

pub fn set_sigaction(signal: u32, action: crate::process::SigAction) -> Result<(), SignalError> {
    if signal == 0 || signal as usize >= NSIG || signal == SIGKILL || signal == SIGSTOP {
        return Err(SignalError::Invalid);
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

pub fn sigprocmask(how: u32, set: u64) -> Result<u64, SignalError> {
    const SIG_BLOCK: u32 = 0;
    const SIG_UNBLOCK: u32 = 1;
    const SIG_SETMASK: u32 = 2;
    let kept = !((1u64 << SIGKILL) | (1u64 << SIGSTOP));
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    let proc = g
        .processes
        .get_mut(&pid)
        .ok_or(SignalError::NoSuchProcess)?;
    let old = proc.signals.blocked();
    let new = match how {
        SIG_BLOCK => old | (set & kept),
        SIG_UNBLOCK => old & !set,
        SIG_SETMASK => set & kept,
        _ => return Err(SignalError::Invalid),
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
        use crate::signal::DefaultAction;
        match crate::signal::default_action(signal) {
            DefaultAction::Term | DefaultAction::Core => {
                proc.signals.clear_pending(1u64 << signal);
                Act::Term(signal)
            }
            DefaultAction::Stop => {
                proc.signals.clear_pending(1u64 << signal);
                Act::Stop
            }
            DefaultAction::Cont | DefaultAction::Ignore => {
                proc.signals.clear_pending(1u64 << signal);
                return;
            }
        }
    };
    match act {
        Act::Term(signal) => terminate_current_with_signal(signal),
        Act::Stop => stop_current(),
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
            action: crate::process::SigAction,
            pre_blocked: u64,
            info: crate::signal::SigInfo,
            altstack: crate::signal::AltStack,
        },
    }

    let action = {
        let pid = match CPU_QUEUES[this_cpu() as usize].lock().current {
            Some(p) => p,
            None => return,
        };
        let mut g = GLOBAL.lock();
        let proc = g.processes.get_mut(&pid).unwrap();
        let mask = proc.signals.deliverable();
        if mask == 0 {
            Action::None
        } else {
            let signal = mask.trailing_zeros();
            proc.signals.clear_pending(1u64 << signal);
            let act = proc.sigactions.lock()[signal as usize];
            let pinfo = proc.signals.siginfo(signal as usize);
            proc.signals
                .set_siginfo(signal as usize, crate::signal::PendingSigInfo::default());
            let info = pinfo.expand(signal);
            let force_default = signal == SIGKILL || signal == SIGSTOP;
            if act.handler == 1 && !force_default {
                Action::None
            } else if act.handler == 0 || force_default {
                use crate::signal::DefaultAction;
                match crate::signal::default_action(signal) {
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
            }
        }
    };

    match action {
        Action::None => {}
        Action::TerminateBySignal(signal) => terminate_current_with_signal(signal),
        Action::Stop => stop_current(),
        Action::Cont => {}
        Action::InvokeHandler {
            signal,
            action,
            pre_blocked,
            info,
            altstack,
        } => {
            match crate::signal::deliver_to_handler(
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
                        if action.flags & crate::process::sa::SA_RESETHAND != 0 {
                            p.sigactions.lock()[signal as usize] =
                                crate::process::SigAction::default();
                        }
                    }
                }
                Err(_) => exit_current(tf, 128 + SIGSEGV as i32),
            }
        }
    }
}

pub fn rt_sigreturn(tf: &mut TrapFrame) {
    match crate::signal::restore_from_frame(tf) {
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
