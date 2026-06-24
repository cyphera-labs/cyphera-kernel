use alloc::string::String;
use alloc::sync::Arc;

use super::*;
use crate::vfs::Inode;

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
    seccomp_filters: alloc::vec::Vec<alloc::sync::Arc<crate::security::bpf::BpfProgram>>,
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

    pub fn add_seccomp_filter(&mut self, prog: alloc::sync::Arc<crate::security::bpf::BpfProgram>) {
        self.seccomp_filters.push(prog);
    }

    pub fn seccomp_filters(&self) -> &[alloc::sync::Arc<crate::security::bpf::BpfProgram>] {
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

    pub fn child_subreaper(&self) -> bool {
        self.child_subreaper
            .load(core::sync::atomic::Ordering::Acquire)
    }

    pub fn set_child_subreaper(&self, v: bool) {
        self.child_subreaper
            .store(v, core::sync::atomic::Ordering::Release);
    }
}

pub const RT_SIG_MIN: u32 = 32;
const RT_SIG_MASK: u64 = !((1u64 << RT_SIG_MIN) - 1);

fn is_rt_signal(signo: u32) -> bool {
    signo >= RT_SIG_MIN && (signo as usize) < NSIG
}

pub struct SignalContext {
    pending: u64,
    blocked: u64,
    siginfo: [crate::core::signal::PendingSigInfo; NSIG],
    rt_queue: alloc::collections::VecDeque<(u32, crate::core::signal::PendingSigInfo)>,
    altstack: crate::core::signal::AltStack,
    itimer_real_interval_ns: u64,
    itimer_real_deadline_ns: u64,
    itimer_virtual_interval_ns: u64,
    itimer_virtual_value_ns: u64,
    itimer_prof_interval_ns: u64,
    itimer_prof_value_ns: u64,
}

impl SignalContext {
    pub fn new() -> Self {
        Self {
            pending: 0,
            blocked: 0,
            siginfo: [crate::core::signal::PendingSigInfo::default(); NSIG],
            rt_queue: alloc::collections::VecDeque::new(),
            altstack: crate::core::signal::AltStack::disabled(),
            itimer_real_interval_ns: 0,
            itimer_real_deadline_ns: 0,
            itimer_virtual_interval_ns: 0,
            itimer_virtual_value_ns: 0,
            itimer_prof_interval_ns: 0,
            itimer_prof_value_ns: 0,
        }
    }

    pub fn inherit(parent: &SignalContext) -> Self {
        Self {
            pending: 0,
            blocked: parent.blocked,
            siginfo: [crate::core::signal::PendingSigInfo::default(); NSIG],
            rt_queue: alloc::collections::VecDeque::new(),
            altstack: parent.altstack,
            itimer_real_interval_ns: parent.itimer_real_interval_ns,
            itimer_real_deadline_ns: parent.itimer_real_deadline_ns,
            itimer_virtual_interval_ns: 0,
            itimer_virtual_value_ns: 0,
            itimer_prof_interval_ns: 0,
            itimer_prof_value_ns: 0,
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
        self.rt_queue.retain(|(s, _)| mask & (1u64 << s) != 0);
    }

    pub fn set_blocked(&mut self, mask: u64) {
        self.blocked = mask & !((1u64 << SIGKILL) | (1u64 << SIGSTOP));
    }

    pub fn raise(&mut self, mask: u64) {
        self.pending |= mask;
    }

    pub fn clear_pending(&mut self, mask: u64) {
        self.pending &= !mask;
    }

    pub fn siginfo(&self, signal: usize) -> crate::core::signal::PendingSigInfo {
        self.siginfo[signal]
    }

    pub fn set_siginfo(&mut self, signal: usize, info: crate::core::signal::PendingSigInfo) {
        self.siginfo[signal] = info;
    }

    pub fn reset_siginfo(&mut self) {
        self.siginfo = [crate::core::signal::PendingSigInfo::default(); NSIG];
        self.rt_queue.clear();
    }

    pub fn rt_pending_count(&self) -> usize {
        (self.pending & RT_SIG_MASK).count_ones() as usize + self.rt_queue.len()
    }

    pub fn enqueue_signal(
        &mut self,
        signo: u32,
        info: crate::core::signal::PendingSigInfo,
        rt_cap: usize,
    ) -> bool {
        let bit = 1u64 << signo;
        if is_rt_signal(signo) {
            if self.rt_pending_count() >= rt_cap {
                return false;
            }
            if self.pending & bit == 0 {
                self.pending |= bit;
                self.siginfo[signo as usize] = info;
            } else {
                self.rt_queue.push_back((signo, info));
            }
        } else {
            self.pending |= bit;
            self.siginfo[signo as usize] = info;
        }
        true
    }

    pub fn dequeue_signal(&mut self, signo: u32) -> crate::core::signal::PendingSigInfo {
        let bit = 1u64 << signo;
        if self.pending & bit == 0 {
            return crate::core::signal::PendingSigInfo::default();
        }
        let head = self.siginfo[signo as usize];
        if is_rt_signal(signo) {
            if let Some(pos) = self.rt_queue.iter().position(|(s, _)| *s == signo) {
                let (_, next) = self.rt_queue.remove(pos).unwrap();
                self.siginfo[signo as usize] = next;
                return head;
            }
        }
        self.pending &= !bit;
        self.siginfo[signo as usize] = crate::core::signal::PendingSigInfo::default();
        head
    }

    pub fn discard_signal(&mut self, signo: u32) {
        let bit = 1u64 << signo;
        self.pending &= !bit;
        self.siginfo[signo as usize] = crate::core::signal::PendingSigInfo::default();
        if is_rt_signal(signo) {
            self.rt_queue.retain(|(s, _)| *s != signo);
        }
    }

    pub fn altstack(&self) -> crate::core::signal::AltStack {
        self.altstack
    }

    pub fn set_altstack(&mut self, alt: crate::core::signal::AltStack) {
        self.altstack = alt;
    }

    pub fn replace_altstack(
        &mut self,
        alt: crate::core::signal::AltStack,
    ) -> crate::core::signal::AltStack {
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

    pub fn itimer_virtual_interval(&self) -> u64 {
        self.itimer_virtual_interval_ns
    }

    pub fn itimer_virtual_value(&self) -> u64 {
        self.itimer_virtual_value_ns
    }

    pub fn set_itimer_virtual(&mut self, interval_ns: u64, value_ns: u64) {
        self.itimer_virtual_interval_ns = interval_ns;
        self.itimer_virtual_value_ns = value_ns;
    }

    pub fn itimer_prof_interval(&self) -> u64 {
        self.itimer_prof_interval_ns
    }

    pub fn itimer_prof_value(&self) -> u64 {
        self.itimer_prof_value_ns
    }

    pub fn set_itimer_prof(&mut self, interval_ns: u64, value_ns: u64) {
        self.itimer_prof_interval_ns = interval_ns;
        self.itimer_prof_value_ns = value_ns;
    }

    pub fn charge_cpu_itimers(&mut self, user_ns: u64, sys_ns: u64) -> (bool, bool) {
        let virt = Self::advance_itimer(
            &mut self.itimer_virtual_value_ns,
            self.itimer_virtual_interval_ns,
            user_ns,
        );
        let prof = Self::advance_itimer(
            &mut self.itimer_prof_value_ns,
            self.itimer_prof_interval_ns,
            user_ns.saturating_add(sys_ns),
        );
        (virt, prof)
    }

    fn advance_itimer(value: &mut u64, interval: u64, delta: u64) -> bool {
        if *value == 0 || delta == 0 {
            return false;
        }
        if delta < *value {
            *value -= delta;
            false
        } else {
            *value = interval;
            true
        }
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
    tls_base: u64,
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
            tls_base: parent.tls_base,
            ..Self::default()
        }
    }

    pub fn maps_layout(&self) -> &MapsLayout {
        &self.maps_layout
    }

    pub fn set_maps_layout(&mut self, layout: MapsLayout) {
        self.maps_layout = layout;
    }

    pub fn tls_base(&self) -> u64 {
        self.tls_base
    }

    pub fn set_tls_base(&mut self, v: u64) {
        self.tls_base = v;
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
    exe_inode: Option<Arc<dyn Inode>>,
    exe_mnt_flags: u64,
}

impl IdentityContext {
    pub fn new(pid: Pid) -> Self {
        Self {
            pgid: pid,
            sid: pid,
            cmdline: alloc::vec::Vec::new(),
            exe_path: alloc::vec::Vec::new(),
            exe_inode: None,
            exe_mnt_flags: 0,
        }
    }

    pub fn inherit(parent: &IdentityContext) -> Self {
        Self {
            pgid: parent.pgid,
            sid: parent.sid,
            cmdline: parent.cmdline.clone(),
            exe_path: parent.exe_path.clone(),
            exe_inode: parent.exe_inode.clone(),
            exe_mnt_flags: parent.exe_mnt_flags,
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

    pub fn exe_inode(&self) -> Option<Arc<dyn Inode>> {
        self.exe_inode.clone()
    }

    pub fn set_exe_inode(&mut self, inode: Option<Arc<dyn Inode>>) {
        self.exe_inode = inode;
    }

    pub fn exe_mnt_flags(&self) -> u64 {
        self.exe_mnt_flags
    }

    pub fn set_exe_mnt_flags(&mut self, flags: u64) {
        self.exe_mnt_flags = flags;
    }
}

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

#[derive(Clone)]
pub struct CwdState {
    pub inode: Arc<dyn Inode>,
    pub path: String,
}
