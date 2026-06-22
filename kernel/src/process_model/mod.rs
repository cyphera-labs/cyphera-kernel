extern crate alloc;

use alloc::sync::Arc;

use frame::cpu::task::Task;
use frame::mm::AddrSpaceRoot;

pub use cyphera_kapi::Pid;

mod context;
mod creds;
mod memory_map;
mod namespaces;
mod sched_params;

pub mod exec;
pub mod spawn;
pub mod wait;

pub use context::*;
pub use creds::*;
pub use exec::*;
pub use memory_map::*;
pub use namespaces::*;
pub use sched_params::*;
pub use spawn::*;
pub use wait::*;

pub use crate::vfs::fd::FdTable;

pub enum FirstLaunch {
    Fresh { entry: u64, user_stack_top: u64 },
    Fork { tf: frame::user::TrapFrame },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessKind {
    User,
    Kernel,
}

#[derive(Copy, Clone)]
pub struct SchedEntity {
    pub home_cpu: u32,
    pub cpu_affinity: u64,
    pub parking_unsaved: bool,
    pub nice: i8,
    pub sched_class: SchedClass,
    pub vruntime: u64,
    pub weight: u64,
    pub last_run_ns: u64,
    pub dl_runtime_remaining: u64,
    pub dl_absolute_deadline: u64,
    pub dl_next_replenish: u64,
    pub dl_throttled: bool,
    pub pi_orig_class: Option<SchedClass>,
}

#[derive(Copy, Clone, Default)]
pub struct CpuTimes {
    pub total_cpu_ns: u64,
    pub total_stime_ns: u64,
    pub total_utime_ns: u64,
    pub cutime_ns: u64,
    pub cstime_ns: u64,
}

#[derive(Default)]
pub struct WaitSites {
    pub child_exit: crate::core::wait::WaitQueue,
    pub exit_waiters: crate::core::wait::WaitQueue,
    pub signalfd_waiters: crate::core::wait::WaitQueue,
    pub vfork_done: crate::core::wait::WaitQueue,
}

pub struct Process {
    pub pid: Pid,
    pub tgid: Pid,
    pub identity: IdentityContext,
    pub creds: alloc::sync::Arc<frame::sync::SpinIrq<Credentials>>,
    pub parent: Option<Pid>,
    pub state: crate::core::SchedCell<ProcessState>,
    pub kind: ProcessKind,
    pub saved: SavedRegs,
    pub addr_space: Option<Arc<AddressSpace>>,
    pub memory: MemoryContext,
    pub fds: Arc<FdTable>,
    pub files: FileContext,
    pub namespaces: NamespaceContext,
    pub cgroup: Option<alloc::sync::Arc<crate::cgroup::Cgroup>>,
    pub cgroup_charged_bytes: u64,
    pub security: SecurityContext,
    pub signals: SignalContext,
    pub sigactions: Arc<frame::sync::SpinIrq<[SigAction; NSIG]>>,
    pub task: crate::core::SchedCell<Task>,
    pub first_launch: Option<FirstLaunch>,
    pub sched_owner: crate::core::SchedCell<SchedOwner>,
    pub addr_space_root: Option<AddrSpaceRoot>,
    pub children: alloc::vec::Vec<Pid>,
    pub wait_sites: WaitSites,
    pub lifecycle: LifecycleContext,
    pub pdeathsig: core::sync::atomic::AtomicU32,
    pub name: [u8; 16],
    pub rlimits: [Option<Rlimit>; 16],
    pub sched: SchedEntity,
    pub pi_blocked_on: Option<cyphera_kapi::WaitKey>,
    pub pi_held: alloc::vec::Vec<cyphera_kapi::WaitKey>,
    pub cpu_times: CpuTimes,
    pub(crate) trace: TraceContext,
}

#[derive(Copy, Clone, Debug)]
pub struct Rlimit {
    pub cur: u64,
    pub max: u64,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

pub mod sa {
    pub const SA_NOCLDSTOP: u64 = 0x0000_0001;
    pub const SA_NOCLDWAIT: u64 = 0x0000_0002;
    pub const SA_SIGINFO: u64 = 0x0000_0004;
    pub const SA_RESTORER: u64 = 0x0400_0000;
    pub const SA_ONSTACK: u64 = 0x0800_0000;
    pub const SA_RESTART: u64 = 0x1000_0000;
    pub const SA_NODEFER: u64 = 0x4000_0000;
    pub const SA_RESETHAND: u64 = 0x8000_0000;
}

impl Process {
    pub fn vmspace(
        &self,
    ) -> Option<alloc::sync::Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>> {
        self.addr_space.as_ref().map(|a| a.vmspace.clone())
    }

    pub fn new(pid: Pid, entry: u64, user_stack_top: u64, _brk_start: u64) -> Self {
        let task = crate::core::SchedCell::new(Task::spawn(crate::core::first_launch_trampoline));
        Self {
            pid,
            tgid: pid,
            identity: IdentityContext::new(pid),
            parent: None,
            state: crate::core::SchedCell::new(ProcessState::Runnable),
            kind: ProcessKind::User,
            saved: SavedRegs::fresh(entry, user_stack_top),
            addr_space: None,
            memory: MemoryContext::default(),
            fds: Arc::new(FdTable::new()),
            files: FileContext::new(),
            namespaces: NamespaceContext::new(),
            cgroup: None,
            cgroup_charged_bytes: 0,
            security: SecurityContext::new(),
            signals: SignalContext::new(),
            sigactions: Arc::new(frame::sync::SpinIrq::new(
                [SigAction {
                    handler: 0,
                    flags: 0,
                    restorer: 0,
                    mask: 0,
                }; NSIG],
            )),
            creds: alloc::sync::Arc::new(frame::sync::SpinIrq::new(Credentials::root())),
            task,
            first_launch: Some(FirstLaunch::Fresh {
                entry,
                user_stack_top,
            }),
            addr_space_root: None,
            sched_owner: crate::core::SchedCell::new(SchedOwner::None),
            sched: SchedEntity {
                home_cpu: 0,
                cpu_affinity: u64::MAX,
                parking_unsaved: false,
                nice: 0,
                sched_class: SchedClass::default_cfs(),
                vruntime: 0,
                weight: NICE_0_LOAD,
                last_run_ns: 0,
                dl_runtime_remaining: 0,
                dl_absolute_deadline: 0,
                dl_next_replenish: 0,
                dl_throttled: false,
                pi_orig_class: None,
            },
            children: alloc::vec::Vec::new(),
            wait_sites: WaitSites::default(),
            lifecycle: LifecycleContext::default(),
            pdeathsig: core::sync::atomic::AtomicU32::new(0),
            name: [0u8; 16],
            rlimits: [None; 16],
            pi_blocked_on: None,
            pi_held: alloc::vec::Vec::new(),
            cpu_times: CpuTimes::default(),
            trace: TraceContext::default(),
        }
    }

    pub fn new_kthread(pid: Pid, entry: extern "C" fn() -> !) -> Self {
        let task = crate::core::SchedCell::new(Task::spawn(entry));
        Self {
            pid,
            tgid: pid,
            identity: IdentityContext::new(pid),
            parent: None,
            state: crate::core::SchedCell::new(ProcessState::Runnable),
            kind: ProcessKind::Kernel,
            saved: SavedRegs::fresh(0, 0),
            addr_space: None,
            memory: MemoryContext::default(),
            fds: Arc::new(FdTable::new()),
            files: FileContext::new(),
            namespaces: NamespaceContext::new(),
            cgroup: None,
            cgroup_charged_bytes: 0,
            security: SecurityContext::new(),
            signals: SignalContext::new(),
            sigactions: Arc::new(frame::sync::SpinIrq::new(
                [SigAction {
                    handler: 0,
                    flags: 0,
                    restorer: 0,
                    mask: 0,
                }; NSIG],
            )),
            creds: alloc::sync::Arc::new(frame::sync::SpinIrq::new(Credentials::root())),
            task,
            first_launch: None,
            addr_space_root: None,
            sched_owner: crate::core::SchedCell::new(SchedOwner::None),
            sched: SchedEntity {
                home_cpu: 0,
                cpu_affinity: u64::MAX,
                parking_unsaved: false,
                nice: 0,
                sched_class: SchedClass::default_cfs(),
                vruntime: 0,
                weight: NICE_0_LOAD,
                last_run_ns: 0,
                dl_runtime_remaining: 0,
                dl_absolute_deadline: 0,
                dl_next_replenish: 0,
                dl_throttled: false,
                pi_orig_class: None,
            },
            children: alloc::vec::Vec::new(),
            wait_sites: WaitSites::default(),
            lifecycle: LifecycleContext::default(),
            pdeathsig: core::sync::atomic::AtomicU32::new(0),
            name: [0u8; 16],
            rlimits: [None; 16],
            pi_blocked_on: None,
            pi_held: alloc::vec::Vec::new(),
            cpu_times: CpuTimes::default(),
            trace: TraceContext::default(),
        }
    }
}
