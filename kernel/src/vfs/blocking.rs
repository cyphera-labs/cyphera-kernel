use crate::core::wait::{WaitOutcome, WaitQueue, wait_guarded};
use cyphera_kapi::{Errno, KResult};

pub enum IoAttempt<T> {
    Ready(T),
    WouldBlock,
    Err(Errno),
}

pub fn block_io<T>(
    site: &'static str,
    wq: &WaitQueue,
    nonblock: bool,
    deadline_nanos: Option<u64>,
    mut attempt: impl FnMut() -> IoAttempt<T>,
) -> KResult<T> {
    let cur = crate::core::current_pid();
    let finish = |r: KResult<T>| {
        wq.dequeue(cur);
        if deadline_nanos.is_some() {
            let _ = crate::core::timeout::unregister(cur);
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
                    return finish(Err(Errno::AGAIN));
                }
                if let Some(d) = deadline_nanos {
                    if frame::cpu::clock::nanos_since_boot() >= d {
                        return finish(Err(Errno::AGAIN));
                    }
                    crate::core::timeout::register(d, cur);
                }
            }
        }
        let outcome = wait_guarded(site, deadline_nanos, &|| wq.contains(cur));
        match outcome {
            WaitOutcome::Interrupted => return finish(Err(Errno::INTR)),
            WaitOutcome::TimedOut => return finish(Err(Errno::AGAIN)),
            WaitOutcome::Woken => wq.dequeue(cur),
        }
    }
}
