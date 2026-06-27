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

use crate::process_model::{
    NICE_0_LOAD, NSIG, Pid, Process, ProcessKind, ProcessState, SIGCHLD, SIGCONT, SIGKILL, SIGSEGV,
    SIGSTOP, STOP_SIGNAL_MASK, SchedClass, SchedOwner, nice_to_weight,
};
pub use runqueue::{
    CfsPlace, DL_BW_MAX, DL_BW_SCALE, EnqueueData, RT_PRIO_COUNT, RT_PRIO_MAX, RT_PRIO_MIN,
    RunQueues, SCHED_LATENCY_NS, SCHED_MIN_GRANULARITY_NS, SCHED_WAKEUP_VRUNTIME_THRESH_NS,
};

pub mod runqueue;
pub mod signal;
pub mod timeout;
pub mod tty;
pub mod wait;

mod accounting;
mod cfs;
mod credentials;
mod death;
mod dispatch;
mod file;
mod identity;
mod introspect;
mod lifecycle;
mod limits;
mod memory;
mod namespace;
pub mod params;
mod park;
mod provenance;
mod query;
mod sched_class;
pub mod scheduling;
mod signal_context;
mod signals;
mod stats;
mod trace;
mod trace_ctl;
pub use accounting::*;
pub(crate) use cfs::*;
pub use credentials::*;
pub use death::*;
pub use dispatch::*;
pub use file::*;
pub use identity::*;
pub use introspect::*;
pub use lifecycle::*;
pub use limits::*;
pub use memory::*;
pub use namespace::*;
pub use park::*;
pub(crate) use provenance::*;
pub use query::*;
pub use sched_class::*;
pub use signal_context::*;
pub use signals::*;
pub use stats::*;
pub use trace::*;
pub use trace_ctl::*;

pub const SCHED_WAKEUP_GRANULARITY_NS: u64 = 1_000_000;

pub const SCHED_RR_TIMESLICE_NS: u64 = 100_000_000;

pub(crate) struct CpuQueue {
    pub(crate) runnable: RunQueues,
    pub(crate) current: Option<Pid>,
    idle_ctx: Context,
    pub(crate) active_vmspace:
        Option<alloc::sync::Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>>,
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
pub(crate) static CPU_QUEUES: [SpinIrq<CpuQueue>; MAX_CPUS] = [EMPTY_QUEUE; MAX_CPUS];

pub struct Global {
    pub processes: BTreeMap<Pid, Box<Process>>,
}

pub(crate) static GLOBAL: SpinIrq<Global> = SpinIrq::new(Global {
    processes: BTreeMap::new(),
});

static NEXT_PID: AtomicU32 = AtomicU32::new(1);
static NEXT_HOME_CPU: AtomicU32 = AtomicU32::new(0);
pub(crate) static EVER_REGISTERED: AtomicBool = AtomicBool::new(false);

pub(crate) fn next_pid() -> Pid {
    Pid(NEXT_PID.fetch_add(1, Ordering::SeqCst))
}

fn affinity_allows(affinity: u64, cpu: u32) -> bool {
    cpu < 64 && (affinity & (1u64 << cpu)) != 0
}

pub(crate) fn pick_home_cpu_in(affinity: u64) -> u32 {
    let online = frame::cpu::online_mask();
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

pub(crate) fn pick_home_cpu() -> u32 {
    pick_home_cpu_in(u64::MAX)
}

fn effective_home_cpu(proc: &mut Process) -> u32 {
    if affinity_allows(proc.sched.cpu_affinity, proc.sched.home_cpu) {
        proc.sched.home_cpu
    } else {
        let h = pick_home_cpu_in(proc.sched.cpu_affinity);
        proc.sched.home_cpu = h;
        h
    }
}

pub(crate) fn this_cpu() -> u32 {
    current_cpu_id()
}

pub(crate) fn admit_runnable_locked(
    q: &mut CpuQueue,
    g: &mut Global,
    pid: Pid,
    home_cpu: u32,
    site: &'static str,
) {
    if let Some(p) = g.processes.get_mut(&pid) {
        let placed = q
            .runnable
            .enqueue(pid, enqueue_data_from_proc(p), CfsPlace::New);
        p.sched.vruntime = placed;
        set_sched_owner(p, SchedOwner::Runnable { cpu: home_cpu }, site);
        record_enqueue(pid, site, p);
    }
}

pub fn admit_task(pid: Pid, home_cpu: u32, site: &'static str) {
    let mut q = CPU_QUEUES[home_cpu as usize].lock();
    let mut g = GLOBAL.lock();
    admit_runnable_locked(&mut q, &mut g, pid, home_cpu, site);
}

pub fn send_resched_ipi_pub(target_cpu: u32) {
    send_resched_ipi(target_cpu);
}

pub(crate) fn send_resched_ipi(target_cpu: u32) {
    if target_cpu < MAX_CPUS as u32 {
        if let Some(apic) = frame::cpu::cpu_registry::apic_for_index(target_cpu) {
            frame::intr::lapic::send_ipi(
                apic,
                frame::intr::lapic::RESCHED_IPI_VECTOR,
                frame::intr::lapic::IpiKind::Fixed,
            );
        }
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

pub struct SchedCell<T>(pub(in crate::core) T);

impl<T> SchedCell<T> {
    pub const fn new(v: T) -> Self {
        SchedCell(v)
    }

    pub fn get(&self) -> &T {
        &self.0
    }
}

pub(in crate::core) fn set_sched_owner(proc: &mut Process, new: SchedOwner, site: &'static str) {
    let cur = proc.sched_owner.0;
    let pid = proc.pid;
    let ok = crate::sched_state::sched_owner_transition_ok(cur, new);
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
    let state = &proc.state.0;
    if !crate::sched_state::state_owner_consistent(state, new) {
        panic!(
            "[sched-invariant] state/owner divergence at {site}: pid {} state {:?} vs owner {} -> {}",
            pid.0,
            state,
            fmt_owner(cur),
            fmt_owner(new),
        );
    }
    match new {
        SchedOwner::Stopped | SchedOwner::Traced | SchedOwner::Parked { .. } => {
            proc.sched.parking_unsaved = true;
            proc.park_site = Some(site);
        }
        SchedOwner::Running { .. } => {
            proc.sched.parking_unsaved = false;
            proc.park_site = None;
        }
        _ => {}
    }
    proc.sched_owner.0 = new;
}

pub(in crate::core) fn set_state(
    proc: &mut Process,
    new: crate::process_model::ProcessState,
    site: &'static str,
) {
    if !crate::sched_state::state_transition_ok(&proc.state.0, &new) {
        panic!(
            "[sched-invariant] BAD STATE TRANSITION at {site}: pid {} {:?} -> {:?}",
            proc.pid.0, proc.state.0, new
        );
    }
    if !crate::sched_state::state_owner_consistent(&new, proc.sched_owner.0) {
        panic!(
            "[sched-invariant] state/owner divergence at {site}: pid {} state {:?} -> {:?} vs owner {}",
            proc.pid.0,
            proc.state.0,
            new,
            fmt_owner(proc.sched_owner.0),
        );
    }
    proc.state.0 = new;
}

#[allow(clippy::type_complexity)]
pub(crate) fn swap_current_address_space(
    pid: Pid,
    new_as: alloc::sync::Arc<crate::process_model::AddressSpace>,
    root: frame::mm::vm::AddrSpaceRoot,
    vm_arc: alloc::sync::Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>,
) -> Option<(
    alloc::sync::Arc<crate::process_model::AddressSpace>,
    Option<alloc::sync::Arc<crate::process_model::IpcNamespace>>,
)> {
    let _irq = frame::sync::IrqGuard::new();
    let cpu = this_cpu() as usize;
    let mut q = CPU_QUEUES[cpu].lock();
    let leaving = {
        let mut g = GLOBAL.lock();
        match g.processes.get_mut(&pid) {
            Some(proc) => {
                let old = proc.addr_space.clone().map(|o| (o, proc.namespaces.ipc()));
                proc.addr_space = Some(new_as);
                proc.addr_space_root = Some(root);
                proc.lifecycle.set_vfork_shared_vm(false);
                old
            }
            None => None,
        }
    };
    frame::mm::vm::VmSpace::activate_root(root);
    q.active_vmspace = Some(vm_arc);
    leaving
}

pub fn global_lock() -> frame::sync::SpinIrqGuard<'static, Global> {
    GLOBAL.lock()
}
