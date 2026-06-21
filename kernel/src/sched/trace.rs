use super::GLOBAL;
use crate::process::Pid;

pub fn with_trace<R>(pid: Pid, f: impl FnOnce(&crate::process::TraceContext) -> R) -> Option<R> {
    GLOBAL.lock().processes.get(&pid).map(|p| f(&p.trace))
}
