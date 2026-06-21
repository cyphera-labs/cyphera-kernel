use crate::vfs::FsError;
use crate::wait::{WaitOutcome, WaitQueue, wait_guarded};

pub enum IoAttempt<T> {
    Ready(T),
    WouldBlock,
    Err(FsError),
}

pub fn block_io<T>(
    site: &'static str,
    wq: &WaitQueue,
    nonblock: bool,
    deadline_nanos: Option<u64>,
    mut attempt: impl FnMut() -> IoAttempt<T>,
) -> Result<T, FsError> {
    let cur = crate::sched::current_pid();
    let finish = |r: Result<T, FsError>| {
        wq.dequeue(cur);
        if deadline_nanos.is_some() {
            let _ = crate::timeout::unregister(cur);
        }
        r
    };
    loop {
        wq.enqueue(cur);
        match attempt() {
            IoAttempt::Ready(v) => return finish(Ok(v)),
            IoAttempt::Err(e) => return finish(Err(e)),
            IoAttempt::WouldBlock => {
                if nonblock {
                    return finish(Err(FsError::WouldBlock));
                }
                if let Some(d) = deadline_nanos {
                    if frame::cpu::clock::nanos_since_boot() >= d {
                        return finish(Err(FsError::WouldBlock));
                    }
                    crate::timeout::register(d, cur);
                }
            }
        }
        let outcome = wait_guarded(site, deadline_nanos, &|| wq.contains(cur));
        match outcome {
            WaitOutcome::Interrupted => return finish(Err(FsError::Interrupted)),
            WaitOutcome::TimedOut => return finish(Err(FsError::WouldBlock)),
            WaitOutcome::Woken => wq.dequeue(cur),
        }
    }
}
