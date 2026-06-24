use super::GLOBAL;
use crate::process_model::Pid;

pub fn with_trace<R>(
    pid: Pid,
    f: impl FnOnce(&crate::process_model::TraceContext) -> R,
) -> Option<R> {
    GLOBAL.lock().processes.get(&pid).map(|p| f(&p.trace))
}

pub fn with_trace_mut<R>(
    pid: Pid,
    f: impl FnOnce(&mut crate::process_model::TraceContext) -> R,
) -> Option<R> {
    GLOBAL
        .lock()
        .processes
        .get_mut(&pid)
        .map(|p| f(&mut p.trace))
}

pub fn register_traceme(child: Pid) -> bool {
    let mut g = GLOBAL.lock();
    let parent = match g.processes.get(&child).and_then(|p| p.parent) {
        Some(par) if g.processes.contains_key(&par) => par,
        _ => return false,
    };
    let newly = match g.processes.get_mut(&child) {
        Some(p) if !p.trace.is_traced() => {
            p.trace.set_tracer(parent);
            true
        }
        _ => false,
    };
    if !newly {
        return false;
    }
    if let Some(par) = g.processes.get_mut(&parent) {
        par.trace.add_tracee(child);
    }
    true
}

pub fn with_traced_target_trace<R>(
    target: Pid,
    caller: Pid,
    op: impl FnOnce(&mut crate::process_model::TraceContext) -> R,
) -> Result<R, i64> {
    let mut g = GLOBAL.lock();
    let ok = match g.processes.get(&target) {
        Some(p) => {
            p.trace.traced_by(caller)
                && *p.state.get() == crate::process_model::ProcessState::Traced
        }
        None => false,
    };
    if !ok {
        return Err(crate::errno::ESRCH);
    }
    let p = g.processes.get_mut(&target).unwrap();
    Ok(op(&mut p.trace))
}

pub fn traced_target_vmspace(
    target: Pid,
    caller: Pid,
) -> Result<alloc::sync::Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>, i64> {
    let g = GLOBAL.lock();
    match g.processes.get(&target) {
        Some(p)
            if p.trace.traced_by(caller)
                && *p.state.get() == crate::process_model::ProcessState::Traced =>
        {
            p.vmspace().ok_or(crate::errno::ESRCH)
        }
        _ => Err(crate::errno::ESRCH),
    }
}
