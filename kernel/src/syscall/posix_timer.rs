use crate::core as sched;
use crate::errno::{EFAULT, EINVAL};
use crate::process_model::{PosixTimer, SIGEV_NONE, SIGEV_SIGNAL, SIGEV_THREAD, SIGEV_THREAD_ID};

use super::time::{CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_REALTIME};

const TIMER_ABSTIME: u64 = 1;
const POSIX_TIMER_TAG: u64 = 1u64 << 62;

fn timer_key(pid: crate::process_model::Pid, timer_id: i32) -> u64 {
    POSIX_TIMER_TAG | ((timer_id as u32 as u64) << 32) | (pid.raw() as u64)
}

fn key_pid(key: u64) -> crate::process_model::Pid {
    crate::process_model::Pid::from_raw((key & 0xffff_ffff) as u32)
}

fn key_timer_id(key: u64) -> i32 {
    ((key >> 32) & 0x3fff_ffff) as i32
}

fn clock_now(clockid: u64) -> u64 {
    let monotonic_ns = frame::cpu::clock::nanos_since_boot();
    match clockid {
        CLOCK_REALTIME => {
            let wall = frame::cpu::wall_clock_nanos();
            if wall != 0 { wall } else { monotonic_ns }
        }
        _ => monotonic_ns,
    }
}

fn supported_clock(clockid: u64) -> bool {
    matches!(
        clockid,
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_BOOTTIME
    )
}

fn read_itimerspec(addr: u64) -> Result<(u64, u64), i64> {
    let mut buf = [0u8; 32];
    if frame::user::copy_from_user(addr, &mut buf).is_err() {
        return Err(EFAULT);
    }
    let intv_sec = i64::from_ne_bytes(buf[0..8].try_into().unwrap());
    let intv_nsec = i64::from_ne_bytes(buf[8..16].try_into().unwrap());
    let val_sec = i64::from_ne_bytes(buf[16..24].try_into().unwrap());
    let val_nsec = i64::from_ne_bytes(buf[24..32].try_into().unwrap());
    if !(0..1_000_000_000).contains(&intv_nsec) || !(0..1_000_000_000).contains(&val_nsec) {
        return Err(EINVAL);
    }
    if intv_sec < 0 || val_sec < 0 {
        return Err(EINVAL);
    }
    let interval = (intv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(intv_nsec as u64);
    let value = (val_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(val_nsec as u64);
    Ok((interval, value))
}

fn write_itimerspec(addr: u64, interval_ns: u64, remaining_ns: u64) -> i64 {
    let mut buf = [0u8; 32];
    buf[0..8].copy_from_slice(&((interval_ns / 1_000_000_000) as i64).to_ne_bytes());
    buf[8..16].copy_from_slice(&((interval_ns % 1_000_000_000) as i64).to_ne_bytes());
    buf[16..24].copy_from_slice(&((remaining_ns / 1_000_000_000) as i64).to_ne_bytes());
    buf[24..32].copy_from_slice(&((remaining_ns % 1_000_000_000) as i64).to_ne_bytes());
    if frame::user::copy_to_user(addr, &buf).is_err() {
        return EFAULT;
    }
    0
}

fn timer_fire(key: u64) {
    let owner = key_pid(key);
    let timer_id = key_timer_id(key);

    let owner_tgid = sched::process_tgid(owner).unwrap_or(owner);

    let fire = sched::with_timers_mut(owner, |t| {
        let timer = t.get_mut(timer_id)?;
        if !timer.is_armed() {
            return None;
        }
        let now = frame::cpu::clock::nanos_since_boot();
        let mut missed: u64 = 1;
        if timer.interval_ns != 0 {
            let mut next = timer.deadline_ns.saturating_add(timer.interval_ns);
            while next <= now {
                next = next.saturating_add(timer.interval_ns);
                missed += 1;
            }
            timer.deadline_ns = next;
        } else {
            timer.deadline_ns = 0;
        }
        timer.overrun_last = missed.saturating_sub(1).min(i32::MAX as u64) as i32;
        Some((
            timer.sigev_notify,
            timer.sigev_signo,
            timer.sigev_value,
            timer.sigev_thread_id,
            timer.overrun_last,
            timer.deadline_ns,
        ))
    });

    let (notify, signo, sival, thread_id, overrun, next_deadline) = match fire {
        Some(Some(v)) => v,
        _ => return,
    };

    if notify == SIGEV_SIGNAL || notify == SIGEV_THREAD_ID {
        let target = if notify == SIGEV_THREAD_ID {
            crate::process_model::Pid::from_raw(thread_id)
        } else {
            owner_tgid
        };
        let info = crate::core::signal::SigInfo::for_timer(timer_id, overrun, sival);
        let _ = sched::send_signal_with_info(target, signo, info);
    }

    if next_deadline != 0 {
        crate::core::timeout::register_callback(next_deadline, key, timer_fire);
    }
}

pub(super) fn sys_timer_create(clockid: u64, sevp: u64, timer_id_ptr: u64) -> i64 {
    if !supported_clock(clockid) {
        return EINVAL;
    }
    if timer_id_ptr == 0 {
        return EFAULT;
    }

    let mut sigev_notify = SIGEV_SIGNAL;
    let mut sigev_signo: u32 = crate::process_model::SIGALRM;
    let mut sigev_value: u64 = 0;
    let mut sigev_thread_id: u32 = 0;

    if sevp != 0 {
        let mut buf = [0u8; 64];
        if frame::user::copy_from_user(sevp, &mut buf).is_err() {
            return EFAULT;
        }
        sigev_value = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
        sigev_signo = i32::from_ne_bytes(buf[8..12].try_into().unwrap()) as u32;
        sigev_notify = i32::from_ne_bytes(buf[12..16].try_into().unwrap());
        sigev_thread_id = i32::from_ne_bytes(buf[16..20].try_into().unwrap()) as u32;

        match sigev_notify {
            SIGEV_NONE => {}
            SIGEV_SIGNAL | SIGEV_THREAD => {
                if sigev_signo == 0 || sigev_signo as usize >= crate::process_model::NSIG {
                    return EINVAL;
                }
                sigev_notify = SIGEV_SIGNAL;
            }
            SIGEV_THREAD_ID => {
                if sigev_signo == 0 || sigev_signo as usize >= crate::process_model::NSIG {
                    return EINVAL;
                }
                let target = crate::process_model::Pid::from_raw(sigev_thread_id);
                if sched::process_tgid(target).is_none() {
                    return EINVAL;
                }
            }
            _ => return EINVAL,
        }
    }

    let timer = PosixTimer {
        clockid,
        sigev_notify,
        sigev_signo,
        sigev_value,
        sigev_thread_id,
        deadline_ns: 0,
        interval_ns: 0,
        overrun_last: 0,
    };

    let pid = sched::current_pid();
    let id = match sched::with_timers_mut(pid, |t| t.alloc(timer)) {
        Some(id) => id,
        None => return EINVAL,
    };

    let bytes = id.to_ne_bytes();
    if frame::user::copy_to_user(timer_id_ptr, &bytes).is_err() {
        sched::with_timers_mut(pid, |t| t.remove(id));
        return EFAULT;
    }
    0
}

pub(super) fn sys_timer_settime(timer_id: u64, flags: u64, new_value: u64, old_value: u64) -> i64 {
    let timer_id = timer_id as i32;
    if flags != 0 && flags != TIMER_ABSTIME {
        return EINVAL;
    }
    if new_value == 0 {
        return EFAULT;
    }
    let (interval_ns, value_ns) = match read_itimerspec(new_value) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let pid = sched::current_pid();

    let clockid = match sched::with_timers_mut(pid, |t| t.get(timer_id).map(|x| x.clockid)) {
        Some(Some(c)) => c,
        _ => return EINVAL,
    };

    let now = clock_now(clockid);
    let now_mono = frame::cpu::clock::nanos_since_boot();

    let prev = sched::with_timers_mut(pid, |t| {
        t.get(timer_id).map(|x| {
            let remaining = if x.is_armed() {
                x.deadline_ns.saturating_sub(now_mono)
            } else {
                0
            };
            (x.interval_ns, remaining)
        })
    });
    let (prev_interval, prev_remaining) = match prev {
        Some(Some(v)) => v,
        _ => return EINVAL,
    };

    if old_value != 0 {
        let r = write_itimerspec(old_value, prev_interval, prev_remaining);
        if r != 0 {
            return r;
        }
    }

    let key = timer_key(pid, timer_id);
    crate::core::timeout::cancel_callback(key);

    let deadline_mono = if value_ns == 0 {
        0
    } else if flags == TIMER_ABSTIME {
        let delta = value_ns.saturating_sub(now);
        now_mono.saturating_add(delta)
    } else {
        now_mono.saturating_add(value_ns)
    };

    sched::with_timers_mut(pid, |t| {
        if let Some(x) = t.get_mut(timer_id) {
            x.interval_ns = if value_ns == 0 { 0 } else { interval_ns };
            x.deadline_ns = deadline_mono;
            x.overrun_last = 0;
        }
    });

    if deadline_mono != 0 {
        crate::core::timeout::register_callback(deadline_mono, key, timer_fire);
    }
    0
}

pub(super) fn sys_timer_gettime(timer_id: u64, curr_value: u64) -> i64 {
    let timer_id = timer_id as i32;
    if curr_value == 0 {
        return EFAULT;
    }
    let pid = sched::current_pid();
    let now_mono = frame::cpu::clock::nanos_since_boot();
    let snap = sched::with_timers_mut(pid, |t| {
        t.get(timer_id).map(|x| {
            let remaining = if x.is_armed() {
                x.deadline_ns.saturating_sub(now_mono)
            } else {
                0
            };
            (x.interval_ns, remaining)
        })
    });
    match snap {
        Some(Some((interval, remaining))) => write_itimerspec(curr_value, interval, remaining),
        _ => EINVAL,
    }
}

pub(super) fn sys_timer_getoverrun(timer_id: u64) -> i64 {
    let timer_id = timer_id as i32;
    let pid = sched::current_pid();
    match sched::with_timers_mut(pid, |t| t.get(timer_id).map(|x| x.overrun_last)) {
        Some(Some(o)) => o as i64,
        _ => EINVAL,
    }
}

pub(super) fn sys_timer_delete(timer_id: u64) -> i64 {
    let timer_id = timer_id as i32;
    let pid = sched::current_pid();
    let key = timer_key(pid, timer_id);
    crate::core::timeout::cancel_callback(key);
    match sched::with_timers_mut(pid, |t| t.remove(timer_id)) {
        Some(Some(_)) => 0,
        _ => EINVAL,
    }
}

pub fn clear_timers(pid: crate::process_model::Pid) {
    let ids = sched::with_timers_mut(pid, |t| t.ids()).unwrap_or_default();
    cancel_callbacks(pid, &ids);
    sched::with_timers_mut(pid, |t| t.clear());
}

pub fn cancel_callbacks(pid: crate::process_model::Pid, ids: &[i32]) {
    for id in ids {
        crate::core::timeout::cancel_callback(timer_key(pid, *id));
    }
}
