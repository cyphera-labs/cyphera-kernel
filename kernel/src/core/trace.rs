use super::GLOBAL;
use crate::process_model::Pid;

pub fn with_trace<R>(
    pid: Pid,
    f: impl FnOnce(&crate::process_model::TraceContext) -> R,
) -> Option<R> {
    GLOBAL.lock().processes.get(&pid).map(|p| f(&p.trace))
}
