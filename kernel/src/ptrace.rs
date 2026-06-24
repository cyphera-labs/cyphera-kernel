use crate::core as sched;
use crate::process_model::{Pid, Process, ProcessState, TraceStop};
use frame::sync::SpinIrq;

use crate::errno::{EIO, EPERM, ESRCH};

pub const PTRACE_TRACEME: u64 = 0;
pub const PTRACE_PEEKTEXT: u64 = 1;
pub const PTRACE_PEEKDATA: u64 = 2;
pub const PTRACE_POKETEXT: u64 = 4;
pub const PTRACE_POKEDATA: u64 = 5;
pub const PTRACE_CONT: u64 = 7;
pub const PTRACE_KILL: u64 = 8;
pub const PTRACE_SINGLESTEP: u64 = 9;
pub const PTRACE_GETREGS: u64 = 12;
pub const PTRACE_SETREGS: u64 = 13;
pub const PTRACE_ATTACH: u64 = 16;
pub const PTRACE_DETACH: u64 = 17;
pub const PTRACE_SYSCALL: u64 = 24;
pub const PTRACE_SETOPTIONS: u64 = 0x4200;
pub const PTRACE_GETEVENTMSG: u64 = 0x4201;
pub const PTRACE_GETSIGINFO: u64 = 0x4202;
pub const PTRACE_SETSIGINFO: u64 = 0x4203;
pub const PTRACE_GET_SYSCALL_INFO: u64 = 0x420e;

const PTRACE_SYSCALL_INFO_NONE: u8 = 0;
const PTRACE_SYSCALL_INFO_ENTRY: u8 = 1;
const PTRACE_SYSCALL_INFO_EXIT: u8 = 2;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

pub const PTRACE_O_TRACESYSGOOD: u64 = 0x0000_0001;
pub const PTRACE_O_TRACEFORK: u64 = 0x0000_0002;
pub const PTRACE_O_TRACEVFORK: u64 = 0x0000_0004;
pub const PTRACE_O_TRACECLONE: u64 = 0x0000_0008;
pub const PTRACE_O_TRACEEXEC: u64 = 0x0000_0010;

pub const PTRACE_EVENT_FORK: u32 = 1;
pub const PTRACE_EVENT_VFORK: u32 = 2;
pub const PTRACE_EVENT_CLONE: u32 = 3;
pub const PTRACE_EVENT_EXEC: u32 = 4;
pub const PTRACE_O_TRACEEXIT: u64 = 0x0000_0040;

pub fn do_ptrace(request: u64, local_pid: u64, addr: u64, data: u64) -> i64 {
    if request == PTRACE_TRACEME {
        return traceme();
    }

    let target = match sched::caller_local_to_host(local_pid as u32) {
        Some(p) => p,
        None => return ESRCH,
    };

    match request {
        PTRACE_ATTACH => attach(target),
        PTRACE_DETACH => detach(target, data as u32),
        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => peek(target, addr, data),
        PTRACE_POKETEXT | PTRACE_POKEDATA => poke(target, addr, data),
        PTRACE_GETREGS => getregs(target, data),
        PTRACE_SETREGS => setregs(target, data),
        PTRACE_CONT => cont(target, data as u32, false, false),
        PTRACE_SYSCALL => cont(target, data as u32, true, false),
        PTRACE_SINGLESTEP => cont(target, data as u32, false, true),
        PTRACE_SETOPTIONS => setoptions(target, data),
        PTRACE_KILL => kill(target),
        PTRACE_GETEVENTMSG => geteventmsg(target, data),
        PTRACE_GET_SYSCALL_INFO => get_syscall_info(target, addr, data),
        _ => EIO,
    }
}

fn traceme() -> i64 {
    let me = sched::current_pid();
    if crate::core::register_traceme(me) {
        0
    } else {
        EPERM
    }
}

fn attach(target: Pid) -> i64 {
    let caller = sched::current_pid();
    if target == caller {
        return EPERM;
    }
    match sched::request_ptrace_attach(target, caller) {
        sched::AttachOutcome::Gone => ESRCH,
        sched::AttachOutcome::AlreadyTraced
        | sched::AttachOutcome::Untraceable
        | sched::AttachOutcome::Denied => EPERM,
        sched::AttachOutcome::Deferred(cpu) => {
            sched::send_resched_ipi_pub(cpu);
            0
        }
        sched::AttachOutcome::Stopped => 0,
    }
}

fn detach(target: Pid, signal: u32) -> i64 {
    let caller = sched::current_pid();
    match crate::core::with_trace(target, |t| t.traced_by(caller)) {
        Some(true) => {}
        Some(false) => return EPERM,
        None => return ESRCH,
    }
    crate::core::with_trace_mut(caller, |t| t.remove_tracee(target));
    sched::request_ptrace_continue(target, caller, sched::PtraceResume::Detach { signal });
    0
}

fn peek(target: Pid, addr: u64, data: u64) -> i64 {
    let caller = sched::current_pid();
    let vmspace = match crate::core::traced_target_vmspace(target, caller) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut buf = [0u8; 8];
    {
        let mut vm = vmspace.lock();
        if frame::user::peek_other_vmspace(&mut vm, addr, &mut buf).is_err() {
            return EIO;
        }
    }
    if frame::user::copy_to_user(data, &buf).is_err() {
        return EFAULT;
    }
    0
}

fn poke(target: Pid, addr: u64, data: u64) -> i64 {
    let caller = sched::current_pid();
    let vmspace = match crate::core::traced_target_vmspace(target, caller) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let bytes = data.to_ne_bytes();
    let (breaks, status) = {
        let mut vm = vmspace.lock();
        frame::user::poke_other_vmspace(&mut vm, addr, &bytes)
    };
    if !breaks.0.is_empty() {
        frame::cpu::tlb::shootdown_all();
        let n = breaks.0.len();
        for f in breaks.0 {
            frame::mm::frame_alloc::free_frame(f);
        }
        crate::core::charge_process_memory(target, (n as u64) * 4096);
    }
    if status.is_err() {
        return EIO;
    }
    0
}

fn getregs(target: Pid, data: u64) -> i64 {
    let caller = sched::current_pid();
    let regs = match crate::core::with_traced_target_trace(target, caller, |t| t.saved_regs()) {
        Ok(Some(r)) => r,
        Ok(None) => return ESRCH,
        Err(e) => return e,
    };
    let mut buf = [0u8; 216];
    let words: [u64; 27] = [
        regs.r15,
        regs.r14,
        regs.r13,
        regs.r12,
        regs.rbp,
        regs.rbx,
        regs.r11,
        regs.r10,
        regs.r9,
        regs.r8,
        regs.rax,
        regs.rcx,
        regs.rdx,
        regs.rsi,
        regs.rdi,
        regs.orig_rax,
        regs.rip,
        regs.cs as u64,
        regs.rflags,
        regs.rsp,
        regs.ss as u64,
        regs.fs_base,
        regs.gs_base,
        0,
        0,
        0,
        0,
    ];
    for (i, w) in words.iter().enumerate() {
        buf[i * 8..i * 8 + 8].copy_from_slice(&w.to_ne_bytes());
    }
    if frame::user::copy_to_user(data, &buf).is_err() {
        return EFAULT;
    }
    0
}

fn get_syscall_info(target: Pid, user_size: u64, data: u64) -> i64 {
    let caller = sched::current_pid();
    let (regs, stop) =
        match crate::core::with_traced_target_trace(target, caller, |t| (t.saved_regs(), t.stop()))
        {
            Ok((Some(r), stop)) => (r, stop),
            Ok((None, _)) => return ESRCH,
            Err(e) => return e,
        };

    let mut buf = [0u8; 88];
    let op = match stop {
        Some(TraceStop::SyscallEntry) => PTRACE_SYSCALL_INFO_ENTRY,
        Some(TraceStop::SyscallExit) => PTRACE_SYSCALL_INFO_EXIT,
        _ => PTRACE_SYSCALL_INFO_NONE,
    };
    buf[0] = op;
    buf[4..8].copy_from_slice(&AUDIT_ARCH_X86_64.to_ne_bytes());
    buf[8..16].copy_from_slice(&regs.rip.to_ne_bytes());
    buf[16..24].copy_from_slice(&regs.rsp.to_ne_bytes());

    let actual_size: u64 = match op {
        PTRACE_SYSCALL_INFO_ENTRY => {
            buf[24..32].copy_from_slice(&regs.orig_rax.to_ne_bytes());
            let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
            for (i, a) in args.iter().enumerate() {
                buf[32 + i * 8..40 + i * 8].copy_from_slice(&a.to_ne_bytes());
            }
            80
        }
        PTRACE_SYSCALL_INFO_EXIT => {
            let rval = regs.rax as i64;
            buf[24..32].copy_from_slice(&rval.to_ne_bytes());
            buf[32] = if (-4095..0).contains(&rval) { 1 } else { 0 };
            33
        }
        _ => 24,
    };

    let copy_len = core::cmp::min(user_size as usize, actual_size as usize).min(buf.len());
    if frame::user::copy_to_user(data, &buf[..copy_len]).is_err() {
        return EFAULT;
    }
    actual_size as i64
}

fn setregs(target: Pid, data: u64) -> i64 {
    let caller = sched::current_pid();
    let mut buf = [0u8; 216];
    if frame::user::copy_from_user(data, &mut buf).is_err() {
        return EFAULT;
    }
    let mut words = [0u64; 27];
    for i in 0..27 {
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(&buf[i * 8..i * 8 + 8]);
        words[i] = u64::from_ne_bytes(tmp);
    }
    let regs = UserRegs {
        r15: words[0],
        r14: words[1],
        r13: words[2],
        r12: words[3],
        rbp: words[4],
        rbx: words[5],
        r11: words[6],
        r10: words[7],
        r9: words[8],
        r8: words[9],
        rax: words[10],
        rcx: words[11],
        rdx: words[12],
        rsi: words[13],
        rdi: words[14],
        orig_rax: words[15],
        rip: words[16],
        cs: words[17] as u16,
        rflags: words[18],
        rsp: words[19],
        ss: words[20] as u16,
        fs_base: words[21],
        gs_base: words[22],
    };
    match crate::core::with_traced_target_trace(target, caller, |t| t.set_saved_regs(regs)) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct UserRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u16,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u16,
    pub fs_base: u64,
    pub gs_base: u64,
}

fn geteventmsg(target: Pid, data: u64) -> i64 {
    let caller = sched::current_pid();
    let (raw_msg, is_pid_event) = match crate::core::with_traced_target_trace(target, caller, |t| {
        let is_pid = matches!(t.stop(), Some(TraceStop::EventStop(_)));
        (t.event_msg(), is_pid)
    }) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let msg: u64 = if is_pid_event && raw_msg != 0 {
        sched::caller_host_to_local(Pid(raw_msg as u32)) as u64
    } else {
        raw_msg
    };
    if frame::user::copy_to_user(data, &msg.to_ne_bytes()).is_err() {
        return EFAULT;
    }
    0
}

fn kill(target: Pid) -> i64 {
    let caller = sched::current_pid();
    match sched::with_trace(target, |t| t.traced_by(caller)) {
        Some(true) => {}
        _ => return ESRCH,
    }
    let was_traced = sched::request_ptrace_continue(target, caller, sched::PtraceResume::Kill);
    if !was_traced {
        if let Some(home) = sched::scheduling::home_cpu(target) {
            sched::send_resched_ipi_pub(home);
        }
    }
    0
}

fn cont(target: Pid, signal: u32, trace_syscall: bool, single_step: bool) -> i64 {
    let caller = sched::current_pid();
    if !crate::core::resume_traced(target, caller, signal, trace_syscall, single_step) {
        return ESRCH;
    }
    0
}

fn setoptions(target: Pid, data: u64) -> i64 {
    let caller = sched::current_pid();
    match crate::core::with_traced_target_trace(target, caller, |t| t.set_options(data)) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub fn trace_trap_hook(rip: &mut u64, rflags: &mut u64, _vector: u8) -> bool {
    let cur = sched::current_pid();
    let traced = sched::with_trace(cur, |t| t.is_traced()).unwrap_or(false);
    if !traced {
        return false;
    }
    sched::with_trace_mut(cur, |t| t.record_trap_regs(*rip, *rflags));
    sched::park_for_trace_stop(crate::process_model::TraceStop::Signal(
        crate::process_model::SIGTRAP,
    ));
    let regs = sched::with_trace(cur, |t| t.saved_regs()).flatten();
    if let Some(r) = regs {
        *rip = r.rip;
        *rflags = r.rflags;
    }
    true
}

pub fn install_trap_hook() {
    frame::user::register_trace_trap_hook(trace_trap_hook);
}

pub fn syscall_entry_hook(tf: &mut frame::user::TrapFrame) {
    let cur = sched::current_pid();
    let should_stop =
        sched::with_trace(cur, |t| t.is_traced() && t.in_syscall_stop_mode()).unwrap_or(false);
    if !should_stop {
        return;
    }
    tf.rax = crate::errno::ENOSYS as u64;
    save_tf_to_proc(cur, tf);
    sched::park_for_trace_stop(crate::process_model::TraceStop::SyscallEntry);
    restore_tf_from_proc(cur, tf);
    tf.rax = tf.orig_rax;
}

pub fn syscall_exit_hook(tf: &mut frame::user::TrapFrame) {
    let cur = sched::current_pid();
    let (exec_stop, syscall_stop_armed) = sched::with_trace_mut(cur, |t| {
        if t.is_traced() {
            (t.take_pending_event_stop(), t.in_syscall_stop_mode())
        } else {
            (None, false)
        }
    })
    .unwrap_or((None, false));
    if let Some(ev) = exec_stop {
        save_tf_to_proc(cur, tf);
        sched::park_for_trace_stop(ev);
        restore_tf_from_proc(cur, tf);
        let still_syscall_stop =
            sched::with_trace(cur, |t| t.is_traced() && t.in_syscall_stop_mode()).unwrap_or(false);
        if still_syscall_stop {
            save_tf_to_proc(cur, tf);
            sched::park_for_trace_stop(crate::process_model::TraceStop::SyscallExit);
            restore_tf_from_proc(cur, tf);
        }
        return;
    }
    if !syscall_stop_armed {
        return;
    }
    save_tf_to_proc(cur, tf);
    sched::park_for_trace_stop(crate::process_model::TraceStop::SyscallExit);
    restore_tf_from_proc(cur, tf);
}

pub fn save_user_regs_for_trace(pid: Pid, tf: &frame::user::TrapFrame) {
    save_tf_to_proc(pid, tf);
}

pub fn restore_user_regs_after_trace(pid: Pid, tf: &mut frame::user::TrapFrame) {
    restore_tf_from_proc(pid, tf);
}

fn save_tf_to_proc(pid: Pid, tf: &frame::user::TrapFrame) {
    let regs = UserRegs {
        r15: tf.r15,
        r14: tf.r14,
        r13: tf.r13,
        r12: tf.r12,
        rbp: tf.rbp,
        rbx: tf.rbx,
        r11: 0,
        r10: tf.r10,
        r9: tf.r9,
        r8: tf.r8,
        rax: tf.rax,
        rcx: 0,
        rdx: tf.rdx,
        rsi: tf.rsi,
        rdi: tf.rdi,
        orig_rax: tf.orig_rax,
        rip: tf.rip_user,
        cs: 0x33,
        rflags: tf.rflags_user,
        rsp: tf.rsp_user,
        ss: 0x2b,
        fs_base: 0,
        gs_base: 0,
    };
    sched::with_trace_mut(pid, |t| t.set_saved_regs(regs));
}

fn restore_tf_from_proc(pid: Pid, tf: &mut frame::user::TrapFrame) {
    let regs = match sched::with_trace(pid, |t| t.saved_regs()).flatten() {
        Some(r) => r,
        None => return,
    };
    tf.r15 = regs.r15;
    tf.r14 = regs.r14;
    tf.r13 = regs.r13;
    tf.r12 = regs.r12;
    tf.rbp = regs.rbp;
    tf.rbx = regs.rbx;
    tf.r10 = regs.r10;
    tf.r9 = regs.r9;
    tf.r8 = regs.r8;
    tf.rax = regs.rax;
    tf.rdx = regs.rdx;
    tf.rsi = regs.rsi;
    tf.rdi = regs.rdi;
    tf.orig_rax = regs.orig_rax;
    tf.rip_user = regs.rip;
    tf.rflags_user = regs.rflags;
    tf.rsp_user = regs.rsp;
}

use crate::errno::EFAULT;

pub fn stop_status_signal(p: &Process) -> Option<u32> {
    let stop = p.trace.stop()?;
    let trace_sysgood = (p.trace.options() & PTRACE_O_TRACESYSGOOD) != 0;
    let sig = match stop {
        TraceStop::Attach => crate::process_model::SIGSTOP,
        TraceStop::Signal(s) => s,
        TraceStop::SyscallEntry | TraceStop::SyscallExit => {
            if trace_sysgood {
                crate::process_model::SIGTRAP | 0x80
            } else {
                crate::process_model::SIGTRAP
            }
        }
        TraceStop::EventStop(event) => crate::process_model::SIGTRAP | (event << 8),
    };
    Some(sig)
}

pub fn is_reportable_stop(p: &Process) -> bool {
    *p.state.get() == ProcessState::Traced && !p.trace.wait_consumed() && p.trace.stop().is_some()
}

#[doc(hidden)]
pub static DEFAULT_OPTIONS: SpinIrq<u64> = SpinIrq::new(0);
