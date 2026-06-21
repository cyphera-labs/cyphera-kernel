extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;

use frame::cpu::task::Task;
use frame::mm::{PhysFrame, Size4KiB};
use frame::user::TrapFrame;

pub use cyphera_kapi::Pid;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedClass {
    Cfs,
    Rt {
        priority: u8,
        round_robin: bool,
    },
    Deadline {
        runtime_ns: u64,
        deadline_ns: u64,
        period_ns: u64,
    },
}

impl SchedClass {
    pub const fn default_cfs() -> Self {
        SchedClass::Cfs
    }

    pub fn band(self) -> u16 {
        match self {
            SchedClass::Deadline { .. } => 300,
            SchedClass::Rt { priority, .. } => 200 + priority as u16,
            SchedClass::Cfs => 0,
        }
    }
}

pub const NICE_0_LOAD: u64 = 1024;

pub const PRIO_TO_WEIGHT: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

pub fn nice_to_weight(nice: i8) -> u64 {
    let idx = (nice as i32 + 20) as usize;
    if idx < PRIO_TO_WEIGHT.len() {
        PRIO_TO_WEIGHT[idx]
    } else {
        NICE_0_LOAD
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedOwner {
    None,
    Running { cpu: u32 },
    Runnable { cpu: u32 },
    Parked { waitq_addr: usize },
    Stopped,
    Traced,
    Zombie,
    Reaping,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Runnable,
    Running,
    Parked,
    Zombie(i32),
    KilledByFault { vector: u8, addr: u64, error: u64 },
    Stopped,
    DlThrottled,
    CgroupThrottled,
    Traced,
    KilledBySignal { signal: u32 },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TraceStop {
    Attach,
    SyscallEntry,
    SyscallExit,
    Signal(u32),
    EventStop(u32),
}

#[derive(Debug, Default)]
pub struct TraceContext {
    tracer_pid: Option<Pid>,
    tracees: alloc::vec::Vec<Pid>,
    stop: Option<TraceStop>,
    options: u64,
    in_syscall_stop_mode: bool,
    pending_event_stop: Option<TraceStop>,
    pending_inject: u32,
    wait_consumed: bool,
    event_msg: u64,
    saved_regs: Option<crate::ptrace::UserRegs>,
    pending_attach_stop: bool,
}

impl TraceContext {
    pub fn tracer_pid(&self) -> Option<Pid> {
        self.tracer_pid
    }

    pub fn is_traced(&self) -> bool {
        self.tracer_pid.is_some()
    }

    pub fn traced_by(&self, tracer: Pid) -> bool {
        self.tracer_pid == Some(tracer)
    }

    pub fn stop(&self) -> Option<TraceStop> {
        self.stop
    }

    pub fn options(&self) -> u64 {
        self.options
    }

    pub fn in_syscall_stop_mode(&self) -> bool {
        self.in_syscall_stop_mode
    }

    pub fn pending_inject(&self) -> u32 {
        self.pending_inject
    }

    pub fn wait_consumed(&self) -> bool {
        self.wait_consumed
    }

    pub fn event_msg(&self) -> u64 {
        self.event_msg
    }

    pub fn saved_regs(&self) -> Option<crate::ptrace::UserRegs> {
        self.saved_regs
    }

    pub fn tracees(&self) -> &[Pid] {
        &self.tracees
    }

    pub fn set_tracer(&mut self, tracer: Pid) {
        self.tracer_pid = Some(tracer);
    }

    pub fn add_tracee(&mut self, tracee: Pid) {
        if !self.tracees.contains(&tracee) {
            self.tracees.push(tracee);
        }
    }

    pub fn remove_tracee(&mut self, tracee: Pid) {
        self.tracees.retain(|p| *p != tracee);
    }

    pub fn take_tracees(&mut self) -> alloc::vec::Vec<Pid> {
        core::mem::take(&mut self.tracees)
    }

    pub fn attach(&mut self, tracer: Pid) {
        self.tracer_pid = Some(tracer);
        self.stop = Some(TraceStop::Attach);
        self.wait_consumed = false;
    }

    pub fn attach_deferred(&mut self, tracer: Pid) {
        self.tracer_pid = Some(tracer);
        self.pending_attach_stop = true;
    }

    pub fn attach_stop_pending(&self) -> bool {
        self.pending_attach_stop
    }

    pub fn take_attach_stop(&mut self) -> bool {
        let armed = self.pending_attach_stop;
        self.pending_attach_stop = false;
        armed
    }

    pub fn inherit_trace(&mut self, tracer: Pid, options: u64) {
        self.tracer_pid = Some(tracer);
        self.in_syscall_stop_mode = true;
        self.options = options;
    }

    pub fn detach(&mut self) {
        self.tracer_pid = None;
        self.stop = None;
        self.options = 0;
        self.in_syscall_stop_mode = false;
        self.wait_consumed = false;
        self.pending_inject = 0;
        self.pending_attach_stop = false;
    }

    pub fn set_options(&mut self, options: u64) {
        self.options = options;
    }

    pub fn enter_stop(&mut self, reason: TraceStop) {
        self.stop = Some(reason);
        self.wait_consumed = false;
    }

    pub fn clear_stop(&mut self) {
        self.stop = None;
        self.wait_consumed = false;
    }

    pub fn resume(&mut self, trace_syscall: bool) {
        self.stop = None;
        self.in_syscall_stop_mode = trace_syscall;
        self.wait_consumed = false;
        self.pending_attach_stop = false;
    }

    pub fn mark_wait_consumed(&mut self) {
        self.wait_consumed = true;
    }

    pub fn post_event_stop(&mut self, stop: TraceStop, msg: u64) {
        self.event_msg = msg;
        self.pending_event_stop = Some(stop);
    }

    pub fn arm_post_exec_trap(&mut self) {
        self.pending_event_stop = Some(TraceStop::Signal(SIGTRAP));
    }

    pub fn clear_pending_event_stop(&mut self) {
        self.pending_event_stop = None;
    }

    pub fn take_pending_event_stop(&mut self) -> Option<TraceStop> {
        self.pending_event_stop.take()
    }

    pub fn set_event_msg(&mut self, msg: u64) {
        self.event_msg = msg;
    }

    pub fn set_pending_inject(&mut self, signal: u32) {
        self.pending_inject = signal;
    }

    pub fn clear_pending_inject(&mut self) {
        self.pending_inject = 0;
    }

    pub fn set_saved_regs(&mut self, regs: crate::ptrace::UserRegs) {
        self.saved_regs = Some(regs);
    }

    pub fn enable_single_step(&mut self) {
        if let Some(regs) = self.saved_regs.as_mut() {
            regs.rflags |= 0x100;
        }
    }

    pub fn record_trap_regs(&mut self, rip: u64, rflags: u64) {
        let mut r = self.saved_regs.unwrap_or_default();
        r.rip = rip;
        r.rflags = rflags & !0x100;
        self.saved_regs = Some(r);
    }
}

pub struct SecurityContext {
    no_new_privs: bool,
    dumpable: core::sync::atomic::AtomicU32,
    keep_caps: core::sync::atomic::AtomicBool,
    seccomp_filters: alloc::vec::Vec<alloc::sync::Arc<crate::bpf::BpfProgram>>,
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityContext {
    pub fn new() -> Self {
        Self {
            no_new_privs: false,
            dumpable: core::sync::atomic::AtomicU32::new(1),
            keep_caps: core::sync::atomic::AtomicBool::new(false),
            seccomp_filters: alloc::vec::Vec::new(),
        }
    }

    pub fn inherit(parent: &SecurityContext) -> Self {
        Self {
            no_new_privs: parent.no_new_privs,
            dumpable: core::sync::atomic::AtomicU32::new(1),
            keep_caps: core::sync::atomic::AtomicBool::new(false),
            seccomp_filters: parent.seccomp_filters.clone(),
        }
    }

    pub fn no_new_privs(&self) -> bool {
        self.no_new_privs
    }

    pub fn set_no_new_privs(&mut self) {
        self.no_new_privs = true;
    }

    pub fn dumpable(&self) -> u32 {
        self.dumpable.load(core::sync::atomic::Ordering::Acquire)
    }

    pub fn set_dumpable(&self, value: u32) {
        self.dumpable
            .store(value, core::sync::atomic::Ordering::Release);
    }

    pub fn keep_caps(&self) -> bool {
        self.keep_caps.load(core::sync::atomic::Ordering::Acquire)
    }

    pub fn set_keep_caps(&self, value: bool) {
        self.keep_caps
            .store(value, core::sync::atomic::Ordering::Release);
    }

    pub fn add_seccomp_filter(&mut self, prog: alloc::sync::Arc<crate::bpf::BpfProgram>) {
        self.seccomp_filters.push(prog);
    }

    pub fn seccomp_filters(&self) -> &[alloc::sync::Arc<crate::bpf::BpfProgram>] {
        &self.seccomp_filters
    }

    pub fn has_seccomp(&self) -> bool {
        !self.seccomp_filters.is_empty()
    }
}

#[derive(Default)]
pub struct NamespaceContext {
    uts: Option<Arc<UtsNamespace>>,
    ipc: Option<Arc<IpcNamespace>>,
    pid: Option<Arc<PidNamespace>>,
    cgroup: Option<Arc<CgroupNamespace>>,
    time: Option<Arc<TimeNamespace>>,
    net: Option<Arc<crate::net::NetNamespace>>,
    pending_pid: Option<Arc<PidNamespace>>,
    pending_ipc: Option<Arc<IpcNamespace>>,
    pending_net: Option<Arc<crate::net::NetNamespace>>,
}

impl NamespaceContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inherit(parent: &NamespaceContext) -> Self {
        Self {
            uts: parent.uts.clone(),
            ipc: parent.ipc.clone(),
            pid: parent.pid.clone(),
            cgroup: parent.cgroup.clone(),
            time: parent.time.clone(),
            net: parent.net.clone(),
            pending_pid: None,
            pending_ipc: None,
            pending_net: None,
        }
    }

    pub fn uts(&self) -> Option<Arc<UtsNamespace>> {
        self.uts.clone()
    }

    pub fn set_uts(&mut self, ns: Option<Arc<UtsNamespace>>) {
        self.uts = ns;
    }

    pub fn ipc(&self) -> Option<Arc<IpcNamespace>> {
        self.ipc.clone()
    }

    pub fn set_ipc(&mut self, ns: Option<Arc<IpcNamespace>>) {
        self.ipc = ns;
    }

    pub fn pid(&self) -> Option<Arc<PidNamespace>> {
        self.pid.clone()
    }

    pub fn set_pid(&mut self, ns: Option<Arc<PidNamespace>>) {
        self.pid = ns;
    }

    pub fn cgroup(&self) -> Option<Arc<CgroupNamespace>> {
        self.cgroup.clone()
    }

    pub fn set_cgroup(&mut self, ns: Option<Arc<CgroupNamespace>>) {
        self.cgroup = ns;
    }

    pub fn time(&self) -> Option<Arc<TimeNamespace>> {
        self.time.clone()
    }

    pub fn set_time(&mut self, ns: Option<Arc<TimeNamespace>>) {
        self.time = ns;
    }

    pub fn take_pending_pid(&mut self) -> Option<Arc<PidNamespace>> {
        self.pending_pid.take()
    }

    pub fn set_pending_pid(&mut self, ns: Option<Arc<PidNamespace>>) {
        self.pending_pid = ns;
    }

    pub fn take_pending_ipc(&mut self) -> Option<Arc<IpcNamespace>> {
        self.pending_ipc.take()
    }

    pub fn set_pending_ipc(&mut self, ns: Option<Arc<IpcNamespace>>) {
        self.pending_ipc = ns;
    }

    pub fn net(&self) -> Option<Arc<crate::net::NetNamespace>> {
        self.net.clone()
    }

    pub fn set_net(&mut self, ns: Option<Arc<crate::net::NetNamespace>>) {
        self.net = ns;
    }

    pub fn take_pending_net(&mut self) -> Option<Arc<crate::net::NetNamespace>> {
        self.pending_net.take()
    }

    pub fn set_pending_net(&mut self, ns: Option<Arc<crate::net::NetNamespace>>) {
        self.pending_net = ns;
    }
}

#[derive(Default)]
pub struct LifecycleContext {
    pending_exit: Option<ProcessState>,
    in_syscall: bool,
    vfork_done_set: core::sync::atomic::AtomicBool,
    vfork_shared_vm: core::sync::atomic::AtomicBool,
    did_memfd_exec: core::sync::atomic::AtomicBool,
    child_subreaper: core::sync::atomic::AtomicBool,
}

impl LifecycleContext {
    pub fn with_vfork_shared(share: bool) -> Self {
        Self {
            vfork_shared_vm: core::sync::atomic::AtomicBool::new(share),
            ..Self::default()
        }
    }

    pub fn pending_exit(&self) -> Option<&ProcessState> {
        self.pending_exit.as_ref()
    }

    pub fn set_pending_exit(&mut self, st: ProcessState) {
        self.pending_exit = Some(st);
    }

    pub fn take_pending_exit(&mut self) -> Option<ProcessState> {
        self.pending_exit.take()
    }

    pub fn in_syscall(&self) -> bool {
        self.in_syscall
    }

    pub fn set_in_syscall(&mut self, v: bool) {
        self.in_syscall = v;
    }

    pub fn vfork_done_set(&self) -> bool {
        self.vfork_done_set
            .load(core::sync::atomic::Ordering::Acquire)
    }

    pub fn set_vfork_done_set(&self, v: bool) {
        self.vfork_done_set
            .store(v, core::sync::atomic::Ordering::Release);
    }

    pub fn vfork_shared_vm(&self) -> bool {
        self.vfork_shared_vm
            .load(core::sync::atomic::Ordering::Acquire)
    }

    pub fn set_vfork_shared_vm(&self, v: bool) {
        self.vfork_shared_vm
            .store(v, core::sync::atomic::Ordering::Release);
    }

    pub fn did_memfd_exec(&self) -> bool {
        self.did_memfd_exec
            .load(core::sync::atomic::Ordering::Acquire)
    }

    pub fn set_did_memfd_exec(&self, v: bool) {
        self.did_memfd_exec
            .store(v, core::sync::atomic::Ordering::Release);
    }

    pub fn child_subreaper(&self) -> bool {
        self.child_subreaper
            .load(core::sync::atomic::Ordering::Acquire)
    }

    pub fn set_child_subreaper(&self, v: bool) {
        self.child_subreaper
            .store(v, core::sync::atomic::Ordering::Release);
    }
}

pub struct SignalContext {
    pending: u64,
    blocked: u64,
    siginfo: [crate::signal::PendingSigInfo; NSIG],
    altstack: crate::signal::AltStack,
    itimer_real_interval_ns: u64,
    itimer_real_deadline_ns: u64,
}

impl SignalContext {
    pub fn new() -> Self {
        Self {
            pending: 0,
            blocked: 0,
            siginfo: [crate::signal::PendingSigInfo::default(); NSIG],
            altstack: crate::signal::AltStack::disabled(),
            itimer_real_interval_ns: 0,
            itimer_real_deadline_ns: 0,
        }
    }

    pub fn inherit(parent: &SignalContext) -> Self {
        Self {
            pending: 0,
            blocked: parent.blocked,
            siginfo: [crate::signal::PendingSigInfo::default(); NSIG],
            altstack: parent.altstack,
            itimer_real_interval_ns: parent.itimer_real_interval_ns,
            itimer_real_deadline_ns: parent.itimer_real_deadline_ns,
        }
    }

    pub fn pending(&self) -> u64 {
        self.pending
    }

    pub fn blocked(&self) -> u64 {
        self.blocked
    }

    pub fn deliverable(&self) -> u64 {
        self.pending & !self.blocked
    }

    pub fn set_pending(&mut self, mask: u64) {
        self.pending = mask;
    }

    pub fn set_blocked(&mut self, mask: u64) {
        self.blocked = mask;
    }

    pub fn raise(&mut self, mask: u64) {
        self.pending |= mask;
    }

    pub fn clear_pending(&mut self, mask: u64) {
        self.pending &= !mask;
    }

    pub fn siginfo(&self, signal: usize) -> crate::signal::PendingSigInfo {
        self.siginfo[signal]
    }

    pub fn set_siginfo(&mut self, signal: usize, info: crate::signal::PendingSigInfo) {
        self.siginfo[signal] = info;
    }

    pub fn reset_siginfo(&mut self) {
        self.siginfo = [crate::signal::PendingSigInfo::default(); NSIG];
    }

    pub fn altstack(&self) -> crate::signal::AltStack {
        self.altstack
    }

    pub fn set_altstack(&mut self, alt: crate::signal::AltStack) {
        self.altstack = alt;
    }

    pub fn replace_altstack(&mut self, alt: crate::signal::AltStack) -> crate::signal::AltStack {
        core::mem::replace(&mut self.altstack, alt)
    }

    pub fn itimer_interval(&self) -> u64 {
        self.itimer_real_interval_ns
    }

    pub fn itimer_deadline(&self) -> u64 {
        self.itimer_real_deadline_ns
    }

    pub fn set_itimer_interval(&mut self, ns: u64) {
        self.itimer_real_interval_ns = ns;
    }

    pub fn set_itimer_deadline(&mut self, ns: u64) {
        self.itimer_real_deadline_ns = ns;
    }
}

impl Default for SignalContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct MemoryContext {
    maps_layout: MapsLayout,
    fs_base: u64,
    clear_child_tid: u64,
    robust_list_head: u64,
    rseq_addr: u64,
    rseq_len: u32,
    rseq_sig: u32,
    minflt: u64,
    majflt: u64,
}

impl MemoryContext {
    pub fn inherit(parent: &MemoryContext) -> Self {
        Self {
            maps_layout: parent.maps_layout.clone(),
            fs_base: parent.fs_base,
            ..Self::default()
        }
    }

    pub fn maps_layout(&self) -> &MapsLayout {
        &self.maps_layout
    }

    pub fn set_maps_layout(&mut self, layout: MapsLayout) {
        self.maps_layout = layout;
    }

    pub fn fs_base(&self) -> u64 {
        self.fs_base
    }

    pub fn set_fs_base(&mut self, v: u64) {
        self.fs_base = v;
    }

    pub fn clear_child_tid(&self) -> u64 {
        self.clear_child_tid
    }

    pub fn set_clear_child_tid(&mut self, v: u64) {
        self.clear_child_tid = v;
    }

    pub fn robust_list_head(&self) -> u64 {
        self.robust_list_head
    }

    pub fn set_robust_list_head(&mut self, v: u64) {
        self.robust_list_head = v;
    }

    pub fn rseq_addr(&self) -> u64 {
        self.rseq_addr
    }

    pub fn set_rseq_addr(&mut self, v: u64) {
        self.rseq_addr = v;
    }

    pub fn rseq_len(&self) -> u32 {
        self.rseq_len
    }

    pub fn set_rseq_len(&mut self, v: u32) {
        self.rseq_len = v;
    }

    pub fn rseq_sig(&self) -> u32 {
        self.rseq_sig
    }

    pub fn set_rseq_sig(&mut self, v: u32) {
        self.rseq_sig = v;
    }

    pub fn minflt(&self) -> u64 {
        self.minflt
    }

    pub fn incr_minflt(&mut self) {
        self.minflt = self.minflt.saturating_add(1);
    }

    pub fn majflt(&self) -> u64 {
        self.majflt
    }

    pub fn incr_majflt(&mut self) {
        self.majflt = self.majflt.saturating_add(1);
    }
}

pub struct FileContext {
    cwd: Option<CwdState>,
    fs_root: Option<Arc<dyn Inode>>,
    mount_table: Option<Arc<crate::vfs::MountTable>>,
    umask: u16,
}

impl FileContext {
    pub fn new() -> Self {
        Self {
            cwd: None,
            fs_root: None,
            mount_table: None,
            umask: 0o022,
        }
    }

    pub fn inherit(parent: &FileContext) -> Self {
        Self {
            cwd: parent.cwd.clone(),
            fs_root: parent.fs_root.clone(),
            mount_table: parent.mount_table.clone(),
            umask: parent.umask,
        }
    }

    pub fn cwd(&self) -> Option<&CwdState> {
        self.cwd.as_ref()
    }

    pub fn set_cwd(&mut self, cwd: CwdState) {
        self.cwd = Some(cwd);
    }

    pub fn fs_root(&self) -> Option<&Arc<dyn Inode>> {
        self.fs_root.as_ref()
    }

    pub fn set_fs_root(&mut self, inode: Arc<dyn Inode>) {
        self.fs_root = Some(inode);
    }

    pub fn mount_table(&self) -> &Option<Arc<crate::vfs::MountTable>> {
        &self.mount_table
    }

    pub fn set_mount_table(&mut self, table: Option<Arc<crate::vfs::MountTable>>) {
        self.mount_table = table;
    }

    pub fn umask(&self) -> u16 {
        self.umask
    }

    pub fn set_umask(&mut self, v: u16) {
        self.umask = v;
    }
}

impl Default for FileContext {
    fn default() -> Self {
        Self::new()
    }
}

pub struct IdentityContext {
    pgid: Pid,
    sid: Pid,
    cmdline: alloc::vec::Vec<u8>,
    exe_path: alloc::vec::Vec<u8>,
}

impl IdentityContext {
    pub fn new(pid: Pid) -> Self {
        Self {
            pgid: pid,
            sid: pid,
            cmdline: alloc::vec::Vec::new(),
            exe_path: alloc::vec::Vec::new(),
        }
    }

    pub fn inherit(parent: &IdentityContext) -> Self {
        Self {
            pgid: parent.pgid,
            sid: parent.sid,
            cmdline: parent.cmdline.clone(),
            exe_path: parent.exe_path.clone(),
        }
    }

    pub fn pgid(&self) -> Pid {
        self.pgid
    }

    pub fn set_pgid(&mut self, pgid: Pid) {
        self.pgid = pgid;
    }

    pub fn sid(&self) -> Pid {
        self.sid
    }

    pub fn set_sid(&mut self, sid: Pid) {
        self.sid = sid;
    }

    pub fn cmdline(&self) -> &[u8] {
        &self.cmdline
    }

    pub fn set_cmdline(&mut self, cmdline: alloc::vec::Vec<u8>) {
        self.cmdline = cmdline;
    }

    pub fn exe_path(&self) -> &[u8] {
        &self.exe_path
    }

    pub fn set_exe_path(&mut self, exe_path: alloc::vec::Vec<u8>) {
        self.exe_path = exe_path;
    }
}

#[derive(Copy, Clone, Debug)]
pub struct SavedRegs {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
}

impl SavedRegs {
    pub fn fresh(entry: u64, user_stack_top: u64) -> Self {
        Self {
            rax: 0,
            rdi: 0,
            rsi: 0,
            rdx: 0,
            r10: 0,
            r8: 0,
            r9: 0,
            rip: entry,
            rflags: 0x202,
            rsp: user_stack_top,
        }
    }

    pub fn from_trap_frame(tf: &TrapFrame) -> Self {
        Self {
            rax: tf.rax,
            rdi: tf.rdi,
            rsi: tf.rsi,
            rdx: tf.rdx,
            r10: tf.r10,
            r8: tf.r8,
            r9: tf.r9,
            rip: tf.rip_user,
            rflags: tf.rflags_user,
            rsp: tf.rsp_user,
        }
    }

    pub fn write_to_trap_frame(&self, tf: &mut TrapFrame) {
        tf.rax = self.rax;
        tf.rdi = self.rdi;
        tf.rsi = self.rsi;
        tf.rdx = self.rdx;
        tf.r10 = self.r10;
        tf.r8 = self.r8;
        tf.r9 = self.r9;
        tf.rip_user = self.rip;
        tf.rflags_user = self.rflags;
        tf.rsp_user = self.rsp;
    }
}

#[derive(Copy, Clone, Debug)]
pub struct BrkState {
    pub start: u64,
    pub current: u64,
    pub max: u64,
}

impl BrkState {
    pub fn new(start: u64) -> Self {
        Self {
            start,
            current: start,
            max: start + 256 * 1024 * 1024,
        }
    }
}

pub struct AddressSpace {
    pub vmspace: alloc::sync::Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>,
    pub mmap: frame::sync::SpinIrq<MmapState>,
    pub brk: frame::sync::SpinIrq<BrkState>,
    pub live_users: core::sync::atomic::AtomicUsize,
}

impl AddressSpace {
    pub fn new(
        vmspace: frame::mm::vm::VmSpace,
        pid: Pid,
        brk_start: u64,
    ) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            vmspace: alloc::sync::Arc::new(frame::sync::SpinIrq::new(vmspace)),
            mmap: frame::sync::SpinIrq::new(MmapState::for_pid(pid)),
            brk: frame::sync::SpinIrq::new(BrkState::new(brk_start)),
            live_users: core::sync::atomic::AtomicUsize::new(1),
        })
    }

    pub fn deep_copy_with_vmspace(
        &self,
        child_vmspace: alloc::sync::Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>,
    ) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            vmspace: child_vmspace,
            mmap: frame::sync::SpinIrq::new(self.mmap.lock().clone_for_fork()),
            brk: frame::sync::SpinIrq::new(*self.brk.lock()),
            live_users: core::sync::atomic::AtomicUsize::new(1),
        })
    }
}

pub struct MmapState {
    pub vmas: alloc::vec::Vec<Vma>,
    pub last_end: u64,
    pub arena_lo: u64,
    pub arena_hi: u64,
    pub generation: u64,
}

#[derive(Clone)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: frame::mm::vm::Perms,
    pub flags: VmaFlags,
    pub backing: VmaBacking,
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct VmaFlags: u32 {
        const SHARED = 0x1;
        const ANON = 0x2;
        const GROWSDOWN = 0x4;
    }
}

#[derive(Clone)]
pub enum VmaBacking {
    Anonymous,
    File {
        inode: alloc::sync::Arc<dyn Inode>,
        file_offset_base: u64,
    },
    Shm {
        segment: alloc::sync::Arc<crate::ipc::shm::ShmSegment>,
    },
}

#[derive(Clone)]
pub struct MapSegment {
    pub start: u64,
    pub end: u64,
    pub prot: frame::mm::vm::Perms,
    pub label: MapSegLabel,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum MapSegLabel {
    Image,
    Interp,
    Stack,
}

#[derive(Clone, Default)]
pub struct MapsLayout {
    pub segments: alloc::vec::Vec<MapSegment>,
}

const MMAP_HINT_BASE: u64 = 0x0000_0080_0000_0000;
const MMAP_PER_PID_STRIDE: u64 = 4 * 1024 * 1024 * 1024;

impl MmapState {
    pub fn for_pid(pid: Pid) -> Self {
        let base = MMAP_HINT_BASE + (pid.0 as u64 - 1) * MMAP_PER_PID_STRIDE;
        Self {
            vmas: alloc::vec::Vec::new(),
            last_end: base,
            arena_lo: base,
            arena_hi: base + MMAP_PER_PID_STRIDE,
            generation: 0,
        }
    }

    pub fn clone_for_fork(&self) -> Self {
        Self {
            vmas: self.vmas.clone(),
            last_end: self.last_end,
            arena_lo: self.arena_lo,
            arena_hi: self.arena_hi,
            generation: 0,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn find_gap(&self, length: u64) -> Option<u64> {
        let lo = self.arena_lo;
        let hi = self.arena_hi;
        let try_find = |start: u64, vmas: &[Vma]| -> Option<u64> {
            let mut prev_end = start;
            for v in vmas {
                if v.end <= prev_end {
                    continue;
                }
                if v.start >= prev_end.saturating_add(length) {
                    return Some(prev_end);
                }
                prev_end = prev_end.max(v.end);
            }
            if prev_end.saturating_add(length) <= hi {
                Some(prev_end)
            } else {
                None
            }
        };
        if let Some(a) = try_find(self.last_end.max(lo), &self.vmas) {
            return Some(a);
        }
        try_find(lo, &self.vmas)
    }

    pub fn insert(&mut self, vma: Vma) {
        let pos = self
            .vmas
            .binary_search_by_key(&vma.start, |v| v.start)
            .unwrap_or_else(|p| p);
        self.last_end = vma.end;
        self.vmas.insert(pos, vma);
        self.bump_generation();
    }

    pub fn find_containing(&self, addr: u64) -> Option<&Vma> {
        self.vmas
            .iter()
            .find(|&v| addr >= v.start && addr < v.end)
            .map(|v| v as _)
    }

    pub fn overlaps(&self, lo: u64, hi: u64) -> bool {
        self.vmas.iter().any(|v| v.start < hi && v.end > lo)
    }

    pub fn unmap_range(&mut self, lo: u64, hi: u64) -> alloc::vec::Vec<Vma> {
        let mut removed = alloc::vec::Vec::new();
        let mut new_vmas = alloc::vec::Vec::with_capacity(self.vmas.len());
        for v in self.vmas.drain(..) {
            if v.end <= lo || v.start >= hi {
                new_vmas.push(v);
                continue;
            }
            if v.start >= lo && v.end <= hi {
                removed.push(v);
                continue;
            }
            if v.start < lo && v.end > hi {
                let off_left = lo - v.start;
                let off_mid = hi - v.start;
                let backing_left = v.backing.clone();
                let shift_backing = |delta: u64| match &v.backing {
                    VmaBacking::Anonymous => VmaBacking::Anonymous,
                    VmaBacking::Shm { segment } => VmaBacking::Shm {
                        segment: segment.clone(),
                    },
                    VmaBacking::File {
                        inode,
                        file_offset_base,
                    } => VmaBacking::File {
                        inode: inode.clone(),
                        file_offset_base: file_offset_base + delta,
                    },
                };
                let backing_mid = shift_backing(off_left);
                let backing_right = shift_backing(off_mid);
                new_vmas.push(Vma {
                    start: v.start,
                    end: lo,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_left,
                });
                removed.push(Vma {
                    start: lo,
                    end: hi,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_mid,
                });
                new_vmas.push(Vma {
                    start: hi,
                    end: v.end,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_right,
                });
                continue;
            }
            if v.start < lo {
                let backing_kept = v.backing.clone();
                let off_drop = lo - v.start;
                let backing_drop = match &v.backing {
                    VmaBacking::Anonymous => VmaBacking::Anonymous,
                    VmaBacking::Shm { segment } => VmaBacking::Shm {
                        segment: segment.clone(),
                    },
                    VmaBacking::File {
                        inode,
                        file_offset_base,
                    } => VmaBacking::File {
                        inode: inode.clone(),
                        file_offset_base: file_offset_base + off_drop,
                    },
                };
                new_vmas.push(Vma {
                    start: v.start,
                    end: lo,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_kept,
                });
                removed.push(Vma {
                    start: lo,
                    end: v.end,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_drop,
                });
            } else {
                let off_kept = hi - v.start;
                let backing_kept = match &v.backing {
                    VmaBacking::Anonymous => VmaBacking::Anonymous,
                    VmaBacking::Shm { segment } => VmaBacking::Shm {
                        segment: segment.clone(),
                    },
                    VmaBacking::File {
                        inode,
                        file_offset_base,
                    } => VmaBacking::File {
                        inode: inode.clone(),
                        file_offset_base: file_offset_base + off_kept,
                    },
                };
                let backing_drop = v.backing.clone();
                removed.push(Vma {
                    start: v.start,
                    end: hi,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_drop,
                });
                new_vmas.push(Vma {
                    start: hi,
                    end: v.end,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_kept,
                });
            }
        }
        new_vmas.sort_by_key(|v| v.start);
        self.vmas = new_vmas;
        self.bump_generation();
        removed
    }

    pub fn protect_range(
        &mut self,
        lo: u64,
        hi: u64,
        new_prot: frame::mm::vm::Perms,
    ) -> alloc::vec::Vec<(u64, u64)> {
        fn shift_backing(b: &VmaBacking, delta: u64) -> VmaBacking {
            match b {
                VmaBacking::Anonymous => VmaBacking::Anonymous,
                VmaBacking::Shm { segment } => VmaBacking::Shm {
                    segment: segment.clone(),
                },
                VmaBacking::File {
                    inode,
                    file_offset_base,
                } => VmaBacking::File {
                    inode: inode.clone(),
                    file_offset_base: file_offset_base + delta,
                },
            }
        }

        let mut new_vmas = alloc::vec::Vec::with_capacity(self.vmas.len() + 2);
        let mut gaps = alloc::vec::Vec::new();
        let mut covered_to = lo;
        for v in self.vmas.drain(..) {
            if v.end <= lo || v.start >= hi {
                new_vmas.push(v);
                continue;
            }
            if v.start > covered_to {
                gaps.push((covered_to, v.start));
            }
            let mid_lo = v.start.max(lo);
            let mid_hi = v.end.min(hi);
            if v.start < mid_lo {
                new_vmas.push(Vma {
                    start: v.start,
                    end: mid_lo,
                    prot: v.prot,
                    flags: v.flags,
                    backing: v.backing.clone(),
                });
            }
            new_vmas.push(Vma {
                start: mid_lo,
                end: mid_hi,
                prot: new_prot,
                flags: v.flags,
                backing: shift_backing(&v.backing, mid_lo - v.start),
            });
            if mid_hi < v.end {
                new_vmas.push(Vma {
                    start: mid_hi,
                    end: v.end,
                    prot: v.prot,
                    flags: v.flags,
                    backing: shift_backing(&v.backing, mid_hi - v.start),
                });
            }
            covered_to = covered_to.max(mid_hi);
        }
        if covered_to < hi {
            gaps.push((covered_to, hi));
        }
        new_vmas.sort_by_key(|v| v.start);
        self.vmas = new_vmas;
        self.bump_generation();
        gaps
    }
}

#[derive(Clone)]
pub struct Credentials {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    pub groups: alloc::vec::Vec<u32>,
    pub caps_eff: u64,
    pub caps_perm: u64,
    pub caps_inh: u64,
    pub caps_bnd: u64,
    pub user_ns: Option<alloc::sync::Arc<UserNamespace>>,
}

pub struct UtsNamespace {
    pub hostname: frame::sync::SpinIrq<alloc::string::String>,
    pub domainname: frame::sync::SpinIrq<alloc::string::String>,
}

impl UtsNamespace {
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            hostname: frame::sync::SpinIrq::new(String::from("cyphera")),
            domainname: frame::sync::SpinIrq::new(String::from("(none)")),
        })
    }
    pub fn snapshot(&self) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            hostname: frame::sync::SpinIrq::new(self.hostname.lock().clone()),
            domainname: frame::sync::SpinIrq::new(self.domainname.lock().clone()),
        })
    }
}

pub struct IpcNamespace {
    pub shm_table: frame::sync::SpinIrq<
        alloc::collections::BTreeMap<i32, alloc::sync::Arc<crate::ipc::shm::ShmSegment>>,
    >,
    pub key_to_id: frame::sync::SpinIrq<alloc::collections::BTreeMap<i32, i32>>,
    pub shm_next_id: core::sync::atomic::AtomicI32,
}
impl IpcNamespace {
    fn empty() -> Self {
        Self {
            shm_table: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            key_to_id: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            shm_next_id: core::sync::atomic::AtomicI32::new(1),
        }
    }
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self::empty())
    }
    pub fn fresh() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self::empty())
    }
}

pub struct PidNamespace {
    pub level: u32,
    pub parent: Option<alloc::sync::Arc<PidNamespace>>,
    pub local_to_host: frame::sync::SpinIrq<alloc::collections::BTreeMap<u32, Pid>>,
    pub host_to_local: frame::sync::SpinIrq<alloc::collections::BTreeMap<Pid, u32>>,
    pub next_local: core::sync::atomic::AtomicU32,
}
impl PidNamespace {
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            level: 0,
            parent: None,
            local_to_host: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            host_to_local: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            next_local: core::sync::atomic::AtomicU32::new(1),
        })
    }
    pub fn child(parent: alloc::sync::Arc<Self>) -> alloc::sync::Arc<Self> {
        let level = parent.level.saturating_add(1);
        alloc::sync::Arc::new(Self {
            level,
            parent: Some(parent),
            local_to_host: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            host_to_local: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            next_local: core::sync::atomic::AtomicU32::new(1),
        })
    }
    pub fn assign(&self, host_pid: Pid) -> u32 {
        if let Some(&existing) = self.host_to_local.lock().get(&host_pid) {
            return existing;
        }
        let local = self
            .next_local
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.local_to_host.lock().insert(local, host_pid);
        self.host_to_local.lock().insert(host_pid, local);
        local
    }
    pub fn assign_chain(self_arc: &alloc::sync::Arc<Self>, host_pid: Pid) {
        let mut cur: Option<alloc::sync::Arc<PidNamespace>> = Some(self_arc.clone());
        while let Some(ns) = cur {
            ns.assign(host_pid);
            cur = ns.parent.clone();
        }
    }
    pub fn drop_chain(self_arc: &alloc::sync::Arc<Self>, host_pid: Pid) {
        let mut cur: Option<alloc::sync::Arc<PidNamespace>> = Some(self_arc.clone());
        while let Some(ns) = cur {
            let local = ns.host_to_local.lock().remove(&host_pid);
            if let Some(l) = local {
                ns.local_to_host.lock().remove(&l);
            }
            cur = ns.parent.clone();
        }
    }
    pub fn host_to_local_in(&self, host_pid: Pid) -> u32 {
        self.host_to_local
            .lock()
            .get(&host_pid)
            .copied()
            .unwrap_or(0)
    }
    pub fn local_to_host_in(&self, local: u32) -> Option<Pid> {
        self.local_to_host.lock().get(&local).copied()
    }
}

pub struct CgroupNamespace {
    pub root: alloc::sync::Arc<crate::cgroup::Cgroup>,
}
impl CgroupNamespace {
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            root: crate::cgroup::root(),
        })
    }
    pub fn new(root: alloc::sync::Arc<crate::cgroup::Cgroup>) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self { root })
    }
}

pub struct TimeNamespace {
    pub monotonic_offset_ns: i64,
    pub boottime_offset_ns: i64,
}
impl TimeNamespace {
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            monotonic_offset_ns: 0,
            boottime_offset_ns: 0,
        })
    }
    pub fn fresh() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            monotonic_offset_ns: 0,
            boottime_offset_ns: 0,
        })
    }
}

impl core::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credentials")
            .field("ruid", &self.ruid)
            .field("euid", &self.euid)
            .field("suid", &self.suid)
            .field("fsuid", &self.fsuid)
            .field("rgid", &self.rgid)
            .field("egid", &self.egid)
            .field("caps_eff", &self.caps_eff)
            .field("user_ns_present", &self.user_ns.is_some())
            .finish()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UserNsDepthExceeded;

pub struct UserNamespace {
    pub parent: Option<alloc::sync::Arc<UserNamespace>>,
    pub creator_uid: u32,
    pub uid_map: frame::sync::SpinIrq<alloc::vec::Vec<IdMapping>>,
    pub gid_map: frame::sync::SpinIrq<alloc::vec::Vec<IdMapping>>,
    pub level: u32,
    pub setgroups_allowed: core::sync::atomic::AtomicBool,
}

pub const OVERFLOW_UID: u32 = 65534;
pub const OVERFLOW_GID: u32 = 65534;

fn id_map_down(map: &[IdMapping], id: u32) -> Option<u32> {
    map.iter().find_map(|m| {
        let off = id.checked_sub(m.inside_start)?;
        if off < m.length {
            m.outside_start.checked_add(off)
        } else {
            None
        }
    })
}

fn id_map_up(map: &[IdMapping], id: u32) -> Option<u32> {
    map.iter().find_map(|m| {
        let off = id.checked_sub(m.outside_start)?;
        if off < m.length {
            m.inside_start.checked_add(off)
        } else {
            None
        }
    })
}

#[derive(Copy, Clone, Debug)]
pub struct IdMapping {
    pub inside_start: u32,
    pub outside_start: u32,
    pub length: u32,
}

impl UserNamespace {
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            parent: None,
            creator_uid: 0,
            uid_map: frame::sync::SpinIrq::new(alloc::vec::Vec::new()),
            gid_map: frame::sync::SpinIrq::new(alloc::vec::Vec::new()),
            level: 0,
            setgroups_allowed: core::sync::atomic::AtomicBool::new(true),
        })
    }
    pub fn new_child(
        parent: alloc::sync::Arc<Self>,
        creator_uid: u32,
    ) -> Result<alloc::sync::Arc<Self>, UserNsDepthExceeded> {
        let level = parent.level.saturating_add(1);
        if level > 32 {
            return Err(UserNsDepthExceeded);
        }
        Ok(alloc::sync::Arc::new(Self {
            parent: Some(parent),
            creator_uid,
            uid_map: frame::sync::SpinIrq::new(alloc::vec::Vec::new()),
            gid_map: frame::sync::SpinIrq::new(alloc::vec::Vec::new()),
            level,
            setgroups_allowed: core::sync::atomic::AtomicBool::new(true),
        }))
    }

    pub fn uid_to_kernel(&self, ns_uid: u32) -> Option<u32> {
        if self.level == 0 {
            return Some(ns_uid);
        }
        let parent = self.parent.as_ref()?;
        let parent_uid = id_map_down(&self.uid_map.lock(), ns_uid)?;
        parent.uid_to_kernel(parent_uid)
    }
    pub fn uid_from_kernel(&self, kuid: u32) -> Option<u32> {
        if self.level == 0 {
            return Some(kuid);
        }
        let parent = self.parent.as_ref()?;
        let parent_uid = parent.uid_from_kernel(kuid)?;
        id_map_up(&self.uid_map.lock(), parent_uid)
    }
    pub fn gid_to_kernel(&self, ns_gid: u32) -> Option<u32> {
        if self.level == 0 {
            return Some(ns_gid);
        }
        let parent = self.parent.as_ref()?;
        let parent_gid = id_map_down(&self.gid_map.lock(), ns_gid)?;
        parent.gid_to_kernel(parent_gid)
    }
    pub fn gid_from_kernel(&self, kgid: u32) -> Option<u32> {
        if self.level == 0 {
            return Some(kgid);
        }
        let parent = self.parent.as_ref()?;
        let parent_gid = parent.gid_from_kernel(kgid)?;
        id_map_up(&self.gid_map.lock(), parent_gid)
    }
}

pub const MAX_SUPP_GROUPS: usize = 256;

impl Credentials {
    pub fn root() -> Self {
        Self {
            ruid: 0,
            euid: 0,
            suid: 0,
            fsuid: 0,
            rgid: 0,
            egid: 0,
            sgid: 0,
            fsgid: 0,
            groups: alloc::vec::Vec::new(),
            caps_eff: ALL_CAPS_MASK,
            caps_perm: ALL_CAPS_MASK,
            caps_inh: 0,
            caps_bnd: ALL_CAPS_MASK,
            user_ns: None,
        }
    }
    pub fn has_cap(&self, cap: u32) -> bool {
        if cap > CAP_LAST {
            return false;
        }
        self.caps_eff & (1u64 << cap) != 0
    }
    pub fn in_host_user_ns(&self) -> bool {
        match &self.user_ns {
            None => true,
            Some(ns) => ns.level == 0,
        }
    }
    pub fn capable_host(&self, cap: u32) -> bool {
        self.has_cap(cap) && self.in_host_user_ns()
    }
    pub fn uid_into_kernel(&self, ns_uid: u32) -> Option<u32> {
        match &self.user_ns {
            None => Some(ns_uid),
            Some(ns) => ns.uid_to_kernel(ns_uid),
        }
    }
    pub fn uid_from_kernel(&self, kuid: u32) -> u32 {
        match &self.user_ns {
            None => kuid,
            Some(ns) => ns.uid_from_kernel(kuid).unwrap_or(OVERFLOW_UID),
        }
    }
    pub fn gid_into_kernel(&self, ns_gid: u32) -> Option<u32> {
        match &self.user_ns {
            None => Some(ns_gid),
            Some(ns) => ns.gid_to_kernel(ns_gid),
        }
    }
    pub fn gid_from_kernel(&self, kgid: u32) -> u32 {
        match &self.user_ns {
            None => kgid,
            Some(ns) => ns.gid_from_kernel(kgid).unwrap_or(OVERFLOW_GID),
        }
    }
    pub fn is_privileged(&self) -> bool {
        self.capable_host(CAP_DAC_OVERRIDE)
    }
    pub fn apply_uid_change_caps(
        &mut self,
        old_ruid: u32,
        old_euid: u32,
        old_suid: u32,
        old_fsuid: u32,
    ) {
        let was_any_root = old_ruid == 0 || old_euid == 0 || old_suid == 0 || old_fsuid == 0;
        let now_any_root = self.ruid == 0 || self.euid == 0 || self.suid == 0 || self.fsuid == 0;
        if was_any_root && !now_any_root {
            self.caps_eff = 0;
            self.caps_perm = 0;
            return;
        }
        if old_euid != 0 && self.euid == 0 {
            self.caps_eff = self.caps_perm;
        } else if old_euid == 0 && self.euid != 0 {
            self.caps_eff = 0;
        }
    }
    pub fn is_in_group(&self, gid: u32) -> bool {
        if self.egid == gid {
            return true;
        }
        self.groups.contains(&gid)
    }

    pub fn can_access(&self, file_uid: u32, file_gid: u32, file_mode: u16, mode_req: u8) -> bool {
        if self.is_privileged() {
            return true;
        }
        let class_bits: u16 = if self.euid == file_uid {
            (file_mode >> 6) & 0o7
        } else if self.is_in_group(file_gid) {
            (file_mode >> 3) & 0o7
        } else {
            file_mode & 0o7
        };
        (class_bits as u8) & mode_req == mode_req
    }

    pub fn can_signal(&self, target: &Credentials) -> bool {
        if self.capable_host(CAP_KILL) {
            return true;
        }
        self.ruid == target.ruid
            || self.ruid == target.suid
            || self.euid == target.ruid
            || self.euid == target.suid
    }
}

pub const SETID_KEEP: u32 = u32::MAX;

pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_DAC_READ_SEARCH: u32 = 2;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_FSETID: u32 = 4;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_LINUX_IMMUTABLE: u32 = 9;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_BROADCAST: u32 = 11;
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_IPC_LOCK: u32 = 14;
pub const CAP_IPC_OWNER: u32 = 15;
pub const CAP_SYS_MODULE: u32 = 16;
pub const CAP_SYS_RAWIO: u32 = 17;
pub const CAP_SYS_CHROOT: u32 = 18;
pub const CAP_SYS_PTRACE: u32 = 19;
pub const CAP_SYS_PACCT: u32 = 20;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_BOOT: u32 = 22;
pub const CAP_SYS_NICE: u32 = 23;
pub const CAP_SYS_RESOURCE: u32 = 24;
pub const CAP_SYS_TIME: u32 = 25;
pub const CAP_SYS_TTY_CONFIG: u32 = 26;
pub const CAP_MKNOD: u32 = 27;
pub const CAP_LEASE: u32 = 28;
pub const CAP_AUDIT_WRITE: u32 = 29;
pub const CAP_AUDIT_CONTROL: u32 = 30;
pub const CAP_SETFCAP: u32 = 31;
pub const CAP_MAC_OVERRIDE: u32 = 32;
pub const CAP_MAC_ADMIN: u32 = 33;
pub const CAP_SYSLOG: u32 = 34;
pub const CAP_WAKE_ALARM: u32 = 35;
pub const CAP_BLOCK_SUSPEND: u32 = 36;
pub const CAP_AUDIT_READ: u32 = 37;
pub const CAP_PERFMON: u32 = 38;
pub const CAP_BPF: u32 = 39;
pub const CAP_CHECKPOINT_RESTORE: u32 = 40;

pub const CAP_LAST: u32 = CAP_CHECKPOINT_RESTORE;
pub const ALL_CAPS_MASK: u64 = (1u64 << (CAP_LAST + 1)) - 1;

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGKILL: u32 = 9;
pub const SIGTRAP: u32 = 5;
pub const SIGSEGV: u32 = 11;
pub const SIGSTOP: u32 = 19;
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;

pub const NSIG: usize = 64;

use crate::vfs::Inode;
pub use crate::vfs::fd::FdTable;

#[derive(Clone)]
pub struct CwdState {
    pub inode: Arc<dyn Inode>,
    pub path: String,
}

pub enum FirstLaunch {
    Fresh { entry: u64, user_stack_top: u64 },
    Fork { tf: frame::user::TrapFrame },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessKind {
    User,
    Kernel,
}

pub struct Process {
    pub pid: Pid,
    pub tgid: Pid,
    pub identity: IdentityContext,
    pub creds: alloc::sync::Arc<frame::sync::SpinIrq<Credentials>>,
    pub parent: Option<Pid>,
    pub state: crate::sched::SchedCell<ProcessState>,
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
    pub task: crate::sched::SchedCell<Task>,
    pub first_launch: Option<FirstLaunch>,
    pub home_cpu: u32,
    pub cpu_affinity: u64,
    pub sched_owner: crate::sched::SchedCell<SchedOwner>,
    pub parking_unsaved: bool,
    pub pml4_root: Option<PhysFrame<Size4KiB>>,
    pub children: alloc::vec::Vec<Pid>,
    pub child_exit: crate::wait::WaitQueue,
    pub exit_waiters: crate::wait::WaitQueue,
    pub signalfd_waiters: crate::wait::WaitQueue,
    pub vfork_done: crate::wait::WaitQueue,
    pub lifecycle: LifecycleContext,
    pub pdeathsig: core::sync::atomic::AtomicU32,
    pub name: [u8; 16],
    pub rlimits: [Option<Rlimit>; 16],
    pub nice: i8,
    pub sched_class: SchedClass,
    pub vruntime: u64,
    pub weight: u64,
    pub last_run_ns: u64,
    pub pi_blocked_on: Option<crate::futex::Key>,
    pub pi_held: alloc::vec::Vec<crate::futex::Key>,
    pub dl_runtime_remaining: u64,
    pub dl_absolute_deadline: u64,
    pub dl_next_replenish: u64,
    pub dl_throttled: bool,
    pub total_cpu_ns: u64,
    pub total_stime_ns: u64,
    pub total_utime_ns: u64,
    pub cutime_ns: u64,
    pub cstime_ns: u64,
    pub pi_orig_class: Option<SchedClass>,
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
        let task = crate::sched::SchedCell::new(Task::spawn(crate::sched::first_launch_trampoline));
        Self {
            pid,
            tgid: pid,
            identity: IdentityContext::new(pid),
            parent: None,
            state: crate::sched::SchedCell::new(ProcessState::Runnable),
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
            home_cpu: 0,
            cpu_affinity: u64::MAX,
            pml4_root: None,
            sched_owner: crate::sched::SchedCell::new(SchedOwner::None),
            parking_unsaved: false,
            children: alloc::vec::Vec::new(),
            child_exit: crate::wait::WaitQueue::new(),
            exit_waiters: crate::wait::WaitQueue::new(),
            signalfd_waiters: crate::wait::WaitQueue::new(),
            vfork_done: crate::wait::WaitQueue::new(),
            lifecycle: LifecycleContext::default(),
            pdeathsig: core::sync::atomic::AtomicU32::new(0),
            name: [0u8; 16],
            rlimits: [None; 16],
            nice: 0,
            sched_class: SchedClass::default_cfs(),
            vruntime: 0,
            weight: NICE_0_LOAD,
            last_run_ns: 0,
            pi_blocked_on: None,
            pi_held: alloc::vec::Vec::new(),
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
            trace: TraceContext::default(),
        }
    }

    pub fn new_kthread(pid: Pid, entry: extern "C" fn() -> !) -> Self {
        let task = crate::sched::SchedCell::new(Task::spawn(entry));
        Self {
            pid,
            tgid: pid,
            identity: IdentityContext::new(pid),
            parent: None,
            state: crate::sched::SchedCell::new(ProcessState::Runnable),
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
            home_cpu: 0,
            cpu_affinity: u64::MAX,
            pml4_root: None,
            sched_owner: crate::sched::SchedCell::new(SchedOwner::None),
            parking_unsaved: false,
            children: alloc::vec::Vec::new(),
            child_exit: crate::wait::WaitQueue::new(),
            exit_waiters: crate::wait::WaitQueue::new(),
            signalfd_waiters: crate::wait::WaitQueue::new(),
            vfork_done: crate::wait::WaitQueue::new(),
            lifecycle: LifecycleContext::default(),
            pdeathsig: core::sync::atomic::AtomicU32::new(0),
            name: [0u8; 16],
            rlimits: [None; 16],
            nice: 0,
            sched_class: SchedClass::default_cfs(),
            vruntime: 0,
            weight: NICE_0_LOAD,
            last_run_ns: 0,
            pi_blocked_on: None,
            pi_held: alloc::vec::Vec::new(),
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
            trace: TraceContext::default(),
        }
    }
}
