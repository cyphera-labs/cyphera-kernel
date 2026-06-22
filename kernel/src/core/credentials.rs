use alloc::sync::Arc;

use super::{CPU_QUEUES, GLOBAL, current_pid, this_cpu};
use crate::process_model::Pid;

fn with_security<R>(
    pid: Pid,
    f: impl FnOnce(&crate::process_model::SecurityContext) -> R,
) -> Option<R> {
    GLOBAL.lock().processes.get(&pid).map(|p| f(&p.security))
}

fn with_security_mut(pid: Pid, f: impl FnOnce(&mut crate::process_model::SecurityContext)) {
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        f(&mut p.security);
    }
}

pub fn seccomp_append_filter(prog: Arc<crate::security::bpf::BpfProgram>) {
    with_security_mut(current_pid(), |s| s.add_seccomp_filter(prog));
}

pub fn seccomp_append_filter_tgid(prog: Arc<crate::security::bpf::BpfProgram>) {
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    let tgid = g.processes.get(&pid).map(|p| p.tgid).unwrap_or(pid);
    for p in g.processes.values_mut() {
        if p.tgid == tgid {
            p.security.add_seccomp_filter(prog.clone());
        }
    }
}

pub fn current_seccomp_chain() -> Option<alloc::vec::Vec<Arc<crate::security::bpf::BpfProgram>>> {
    let pid = CPU_QUEUES[this_cpu() as usize].lock().current?;
    with_security(pid, |s| s.seccomp_filters().to_vec())
}

pub fn current_no_new_privs() -> bool {
    let pid = match CPU_QUEUES[this_cpu() as usize].lock().current {
        Some(p) => p,
        None => return false,
    };
    with_security(pid, |s| s.no_new_privs()).unwrap_or(false)
}

pub fn set_current_no_new_privs() {
    with_security_mut(current_pid(), |s| s.set_no_new_privs());
}

pub fn current_dumpable() -> u32 {
    with_security(current_pid(), |s| s.dumpable()).unwrap_or(1)
}

pub fn set_current_dumpable(v: u32) {
    with_security_mut(current_pid(), |s| s.set_dumpable(v));
}

pub fn current_keep_caps() -> bool {
    with_security(current_pid(), |s| s.keep_caps()).unwrap_or(false)
}

pub fn set_current_keep_caps(v: bool) {
    with_security_mut(current_pid(), |s| s.set_keep_caps(v));
}

pub fn process_dumpable(pid: Pid) -> Option<u32> {
    with_security(pid, |s| s.dumpable())
}

pub fn with_current_creds<R>(f: impl FnOnce(&crate::process_model::Credentials) -> R) -> R {
    let pid = current_pid();
    let g = GLOBAL.lock();
    let proc = g
        .processes
        .get(&pid)
        .expect("with_current_creds: no current");
    let creds = proc.creds.lock();
    f(&creds)
}

pub fn with_current_creds_mut<R>(f: impl FnOnce(&mut crate::process_model::Credentials) -> R) -> R {
    let pid = current_pid();
    let g = GLOBAL.lock();
    let proc = g
        .processes
        .get(&pid)
        .expect("with_current_creds_mut: no current");
    let mut creds = proc.creds.lock();
    f(&mut creds)
}

pub fn with_target_creds<R>(
    target: Pid,
    f: impl FnOnce(&crate::process_model::Credentials) -> R,
) -> Option<R> {
    let g = GLOBAL.lock();
    let proc = g.processes.get(&target)?;
    let creds = proc.creds.lock();
    Some(f(&creds))
}

pub fn process_no_new_privs(pid: Pid) -> bool {
    with_security(pid, |s| s.no_new_privs()).unwrap_or(false)
}

pub fn process_seccomp_active(pid: Pid) -> bool {
    with_security(pid, |s| s.has_seccomp()).unwrap_or(false)
}
