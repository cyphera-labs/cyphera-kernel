use super::{GLOBAL, current_pid};
use crate::process_model::{IdentityContext, Pid};

fn with_identity<R>(pid: Pid, f: impl FnOnce(&IdentityContext) -> R) -> Option<R> {
    GLOBAL.lock().processes.get(&pid).map(|p| f(&p.identity))
}

fn with_identity_mut<R>(pid: Pid, f: impl FnOnce(&mut IdentityContext) -> R) -> Option<R> {
    GLOBAL
        .lock()
        .processes
        .get_mut(&pid)
        .map(|p| f(&mut p.identity))
}

pub fn current_tgid() -> Pid {
    let pid = current_pid();
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.tgid)
        .unwrap_or(pid)
}

pub fn process_tgid(pid: Pid) -> Option<Pid> {
    GLOBAL.lock().processes.get(&pid).map(|p| p.tgid)
}

pub fn current_pgid() -> Pid {
    let pid = current_pid();
    with_identity(pid, |id| id.pgid()).unwrap_or(pid)
}

pub fn current_sid() -> Pid {
    let pid = current_pid();
    with_identity(pid, |id| id.sid()).unwrap_or(pid)
}

fn pgid_exists_in_session(pgid: Pid, sid: Pid) -> bool {
    let g = GLOBAL.lock();
    g.processes
        .values()
        .any(|p| p.identity.pgid() == pgid && p.identity.sid() == sid)
}

pub fn setpgid(target_pid: Pid, new_pgid: Pid) -> Result<(), i64> {
    let caller = current_pid();
    let actual_target = if target_pid.0 == 0 {
        caller
    } else {
        target_pid
    };
    let actual_pgid = if new_pgid.0 == 0 {
        actual_target
    } else {
        new_pgid
    };
    let caller_sid = current_sid();

    let (target_parent, target_sid, target_pgid, target_did_exec) = {
        let g = GLOBAL.lock();
        match g.processes.get(&actual_target) {
            Some(p) => (
                p.parent,
                p.identity.sid(),
                p.identity.pgid(),
                p.lifecycle.has_execd(),
            ),
            None => return Err(crate::errno::ESRCH),
        }
    };

    if actual_target != caller && target_parent != Some(caller) {
        return Err(crate::errno::ESRCH);
    }
    if actual_target != caller && target_did_exec {
        return Err(crate::errno::EACCES);
    }
    if target_sid != caller_sid {
        return Err(crate::errno::EPERM);
    }
    if target_sid == actual_target {
        return Err(crate::errno::EPERM);
    }
    if actual_pgid != actual_target
        && actual_pgid != target_pgid
        && !pgid_exists_in_session(actual_pgid, caller_sid)
    {
        return Err(crate::errno::EPERM);
    }

    with_identity_mut(actual_target, |id| id.set_pgid(actual_pgid)).ok_or(crate::errno::ESRCH)
}

pub fn getpgid(target_pid: Pid) -> Result<Pid, i64> {
    let actual = if target_pid.0 == 0 {
        current_pid()
    } else {
        target_pid
    };
    with_identity(actual, |id| id.pgid()).ok_or(crate::errno::ESRCH)
}

pub fn getsid(target_pid: Pid) -> Result<Pid, i64> {
    let actual = if target_pid.0 == 0 {
        current_pid()
    } else {
        target_pid
    };
    with_identity(actual, |id| id.sid()).ok_or(crate::errno::ESRCH)
}

pub fn setsid() -> Result<Pid, i64> {
    let pid = current_pid();
    with_identity_mut(pid, |id| {
        if id.pgid() == pid {
            return Err(crate::errno::EPERM);
        }
        id.set_pgid(pid);
        id.set_sid(pid);
        id.set_ctty(None);
        Ok(pid)
    })
    .unwrap_or(Err(crate::errno::ESRCH))
}

pub fn set_current_name(name: [u8; 16]) {
    set_name(current_pid(), name);
}

pub fn set_name(pid: Pid, name: [u8; 16]) {
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.name = name;
    }
}

pub fn current_name() -> [u8; 16] {
    let pid = current_pid();
    let g = GLOBAL.lock();
    g.processes.get(&pid).map(|p| p.name).unwrap_or([0u8; 16])
}
