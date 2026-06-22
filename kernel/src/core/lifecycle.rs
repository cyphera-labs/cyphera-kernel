use super::{GLOBAL, current_pid};

pub fn with_current_lifecycle<R>(
    f: impl FnOnce(&crate::process_model::LifecycleContext) -> R,
) -> Option<R> {
    let pid = current_pid();
    GLOBAL.lock().processes.get(&pid).map(|p| f(&p.lifecycle))
}

pub fn current_pdeathsig() -> u32 {
    let pid = current_pid();
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.pdeathsig.load(core::sync::atomic::Ordering::Acquire))
        .unwrap_or(0)
}

pub fn set_current_pdeathsig(sig: u32) {
    let pid = current_pid();
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        p.pdeathsig
            .store(sig, core::sync::atomic::Ordering::Release);
    }
}
