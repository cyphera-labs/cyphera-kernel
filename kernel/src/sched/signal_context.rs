use super::{GLOBAL, current_pid};
use crate::process::Pid;

pub fn with_signal<R>(pid: Pid, f: impl FnOnce(&crate::process::SignalContext) -> R) -> Option<R> {
    GLOBAL.lock().processes.get(&pid).map(|p| f(&p.signals))
}

pub fn with_signal_mut<R>(
    pid: Pid,
    f: impl FnOnce(&mut crate::process::SignalContext) -> R,
) -> Option<R> {
    GLOBAL
        .lock()
        .processes
        .get_mut(&pid)
        .map(|p| f(&mut p.signals))
}

pub fn current_altstack() -> crate::signal::AltStack {
    let pid = current_pid();
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.signals.altstack())
        .unwrap_or_else(crate::signal::AltStack::disabled)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NoCurrentProcess;

pub fn set_current_altstack(
    new: crate::signal::AltStack,
) -> Result<crate::signal::AltStack, NoCurrentProcess> {
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    let proc = g.processes.get_mut(&pid).ok_or(NoCurrentProcess)?;
    Ok(proc.signals.replace_altstack(new))
}

pub fn current_on_altstack(rsp: u64) -> bool {
    let pid = current_pid();
    let g = GLOBAL.lock();
    g.processes
        .get(&pid)
        .map(|p| {
            let alt = p.signals.altstack();
            alt.is_enabled() && rsp >= alt.sp && rsp < alt.sp + alt.size
        })
        .unwrap_or(false)
}
