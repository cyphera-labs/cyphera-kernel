use crate::core as sched;
use crate::errno::{EFAULT, EINTR, EINVAL, EPERM};

use super::util::{caller_can_set_time, split_secs_nsecs, write_timespec};

pub(super) const CLOCK_REALTIME: u64 = 0;
pub(super) const CLOCK_MONOTONIC: u64 = 1;
pub(super) const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
pub(super) const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
pub(super) const CLOCK_MONOTONIC_RAW: u64 = 4;
pub(super) const CLOCK_REALTIME_COARSE: u64 = 5;
pub(super) const CLOCK_MONOTONIC_COARSE: u64 = 6;
pub(super) const CLOCK_BOOTTIME: u64 = 7;

const FINE_RES_NSEC: i64 = 1;
const COARSE_RES_NSEC: i64 = 10_000_000;

const ITIMER_REAL: u64 = 0;
const ITIMER_VIRTUAL: u64 = 1;
const ITIMER_PROF: u64 = 2;

fn process_cputime_nanos() -> u64 {
    sched::current_cputime_nanos()
}

fn apply_offset(base_ns: u64, offset_ns: i64) -> u64 {
    if offset_ns >= 0 {
        base_ns.saturating_add(offset_ns as u64)
    } else {
        base_ns.saturating_sub((-offset_ns) as u64)
    }
}

fn timespec_for_clock(clock: u64) -> Option<(i64, i64)> {
    let monotonic_ns = frame::cpu::nanos_since_boot();
    let wall_ns = frame::cpu::wall_clock_nanos();
    let (mono_off, boot_off) = sched::current_time_ns_offsets();
    let ns = match clock {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => {
            if wall_ns != 0 {
                wall_ns
            } else {
                monotonic_ns
            }
        }
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE => {
            apply_offset(monotonic_ns, mono_off)
        }
        CLOCK_BOOTTIME => apply_offset(monotonic_ns, boot_off),
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => process_cputime_nanos(),
        _ => return None,
    };
    Some(split_secs_nsecs(ns))
}

fn decode_itimerval(buf: &[u8; 32]) -> (u64, u64) {
    let isec = i64::from_ne_bytes(buf[0..8].try_into().unwrap()) as u64;
    let iusec = i64::from_ne_bytes(buf[8..16].try_into().unwrap()) as u64;
    let vsec = i64::from_ne_bytes(buf[16..24].try_into().unwrap()) as u64;
    let vusec = i64::from_ne_bytes(buf[24..32].try_into().unwrap()) as u64;
    let interval_ns = isec
        .saturating_mul(1_000_000_000)
        .saturating_add(iusec.saturating_mul(1000));
    let value_ns = vsec
        .saturating_mul(1_000_000_000)
        .saturating_add(vusec.saturating_mul(1000));
    (interval_ns, value_ns)
}

fn encode_itimerval(interval_ns: u64, value_ns: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    let isec = (interval_ns / 1_000_000_000) as i64;
    let iusec = ((interval_ns % 1_000_000_000) / 1_000) as i64;
    let vsec = (value_ns / 1_000_000_000) as i64;
    let vusec = ((value_ns % 1_000_000_000) / 1_000) as i64;
    buf[0..8].copy_from_slice(&isec.to_ne_bytes());
    buf[8..16].copy_from_slice(&iusec.to_ne_bytes());
    buf[16..24].copy_from_slice(&vsec.to_ne_bytes());
    buf[24..32].copy_from_slice(&vusec.to_ne_bytes());
    buf
}

fn itimer_real_key(pid: crate::process_model::Pid) -> u64 {
    (pid.raw() as u64) | (1u64 << 63)
}

fn itimer_real_fire(key: u64) {
    let pid_raw = (key & !(1u64 << 63)) as u32;
    let target = crate::process_model::Pid::from_raw(pid_raw);
    const SIGALRM: u32 = 14;
    let info = crate::core::signal::SigInfo::for_kernel(SIGALRM);
    let _ = sched::send_signal_with_info(target, SIGALRM, info);
    sched::with_signal_mut(target, |s| {
        if s.itimer_interval() != 0 {
            let now = frame::cpu::clock::nanos_since_boot();
            s.set_itimer_deadline(now.saturating_add(s.itimer_interval()));
            crate::core::timeout::register_callback(s.itimer_deadline(), key, itimer_real_fire);
        } else {
            s.set_itimer_deadline(0);
        }
    });
}

pub(super) fn sys_clock_gettime(clock: u64, ts_ptr: u64) -> i64 {
    if ts_ptr == 0 {
        return EFAULT;
    }
    let (sec, nsec) = match timespec_for_clock(clock) {
        Some(v) => v,
        None => return EINVAL,
    };
    match write_timespec(ts_ptr, sec, nsec) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub(super) fn sys_clock_getres(clock: u64, res_ptr: u64) -> i64 {
    let res_nsec = match clock {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_BOOTTIME => FINE_RES_NSEC,
        CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE => COARSE_RES_NSEC,
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => FINE_RES_NSEC,
        _ => return EINVAL,
    };
    if res_ptr == 0 {
        return 0;
    }
    match write_timespec(res_ptr, 0, res_nsec) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub(super) fn sys_gettimeofday(tv_ptr: u64, _tz_ptr: u64) -> i64 {
    if tv_ptr == 0 {
        return 0;
    }
    let wall_ns = frame::cpu::wall_clock_nanos();
    let ns = if wall_ns != 0 {
        wall_ns
    } else {
        frame::cpu::nanos_since_boot()
    };
    let sec = (ns / 1_000_000_000) as i64;
    let usec = ((ns % 1_000_000_000) / 1_000) as i64;
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&sec.to_le_bytes());
    buf[8..16].copy_from_slice(&usec.to_le_bytes());
    if frame::user::copy_to_user(tv_ptr, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_time(t_ptr: u64) -> i64 {
    let wall_ns = frame::cpu::wall_clock_nanos();
    let ns = if wall_ns != 0 {
        wall_ns
    } else {
        frame::cpu::nanos_since_boot()
    };
    let secs = (ns / 1_000_000_000) as i64;
    if t_ptr != 0 {
        let bytes = secs.to_le_bytes();
        if frame::user::copy_to_user(t_ptr, &bytes).is_err() {
            return EFAULT;
        }
    }
    secs
}

pub(super) fn sys_settimeofday(tv_ptr: u64, _tz_ptr: u64) -> i64 {
    if !caller_can_set_time() {
        return EPERM;
    }
    if tv_ptr == 0 {
        return 0;
    }
    let mut buf = [0u8; 16];
    if frame::user::copy_from_user(tv_ptr, &mut buf).is_err() {
        return EFAULT;
    }
    let sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let usec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    if !(0..1_000_000).contains(&usec) || sec < 0 {
        return EINVAL;
    }
    let target_ns = (sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add((usec as u64) * 1_000);
    frame::cpu::clock::set_wall_clock_target(target_ns);
    0
}

pub(super) fn sys_clock_settime(clk_id: u64, tp_ptr: u64) -> i64 {
    if !caller_can_set_time() {
        return EPERM;
    }
    if !matches!(clk_id, CLOCK_REALTIME | CLOCK_REALTIME_COARSE) {
        return EINVAL;
    }
    if tp_ptr == 0 {
        return EFAULT;
    }
    let mut buf = [0u8; 16];
    if frame::user::copy_from_user(tp_ptr, &mut buf).is_err() {
        return EFAULT;
    }
    let sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    if !(0..1_000_000_000).contains(&nsec) || sec < 0 {
        return EINVAL;
    }
    let target_ns = (sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u64);
    frame::cpu::clock::set_wall_clock_target(target_ns);
    0
}

pub(super) fn sys_adjtimex(buf_ptr: u64) -> i64 {
    if buf_ptr == 0 {
        return EFAULT;
    }
    let mut buf = [0u8; 184];
    if frame::user::copy_from_user(buf_ptr, &mut buf).is_err() {
        return EFAULT;
    }
    let modes = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if modes != 0 {
        if !caller_can_set_time() {
            return EPERM;
        }
        const ADJ_SETOFFSET: u32 = 0x0100;
        const ADJ_NANO: u32 = 0x2000;
        if modes & ADJ_SETOFFSET != 0 {
            let sec = i64::from_le_bytes(buf[96..104].try_into().unwrap());
            let frac = i64::from_le_bytes(buf[104..112].try_into().unwrap());
            let frac_ns = if modes & ADJ_NANO != 0 {
                frac
            } else {
                frac.saturating_mul(1_000)
            };
            if frac_ns.abs() >= 1_000_000_000 {
                return EINVAL;
            }
            let delta_ns = sec.saturating_mul(1_000_000_000).saturating_add(frac_ns);
            frame::cpu::clock::shift_wall_clock_offset(delta_ns);
        }
    }

    let precision: i64 = 1;
    let tick: i64 = 10_000;
    buf[88..96].copy_from_slice(&precision.to_le_bytes());
    buf[64..72].copy_from_slice(&tick.to_le_bytes());
    let wall_ns = frame::cpu::clock::wall_clock_nanos();
    let wall_sec = (wall_ns / 1_000_000_000) as i64;
    let wall_usec = ((wall_ns % 1_000_000_000) / 1_000) as i64;
    buf[96..104].copy_from_slice(&wall_sec.to_le_bytes());
    buf[104..112].copy_from_slice(&wall_usec.to_le_bytes());
    if frame::user::copy_to_user(buf_ptr, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_clock_adjtime(clk_id: u64, buf_ptr: u64) -> i64 {
    if !matches!(clk_id, CLOCK_REALTIME | CLOCK_REALTIME_COARSE) {
        return EINVAL;
    }
    sys_adjtimex(buf_ptr)
}

pub(super) fn sys_nanosleep(req: u64, rem: u64) -> i64 {
    if req == 0 {
        return EINVAL;
    }
    let mut buf = [0u8; 16];
    if frame::user::copy_from_user(req, &mut buf).is_err() {
        return EFAULT;
    }
    let tv_sec = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let tv_nsec = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    if tv_nsec >= 1_000_000_000 {
        return EINVAL;
    }
    let total_ns = tv_sec.saturating_mul(1_000_000_000).saturating_add(tv_nsec);
    if total_ns == 0 {
        return 0;
    }
    let now = frame::cpu::clock::nanos_since_boot();
    let deadline = now.saturating_add(total_ns);
    let pid = sched::current_pid();
    crate::core::timeout::register(deadline, pid);
    let signaled = loop {
        if frame::cpu::clock::nanos_since_boot() >= deadline {
            break false;
        }
        if sched::current_signal_pending() {
            break true;
        }
        let _ = crate::core::wait::wait_guarded("nanosleep", Some(deadline), &|| {
            frame::cpu::clock::nanos_since_boot() < deadline
        });
    };
    let _ = crate::core::timeout::unregister(pid);
    if signaled {
        let now2 = frame::cpu::clock::nanos_since_boot();
        let remaining = deadline.saturating_sub(now2);
        if rem != 0 {
            let mut rb = [0u8; 16];
            rb[0..8].copy_from_slice(&(remaining / 1_000_000_000).to_le_bytes());
            rb[8..16].copy_from_slice(&(remaining % 1_000_000_000).to_le_bytes());
            let _ = frame::user::copy_to_user(rem, &rb);
        }
        return EINTR;
    }
    0
}

pub(super) fn sys_clock_nanosleep(clockid: u64, flags: u64, request: u64, remain: u64) -> i64 {
    const TIMER_ABSTIME: u64 = 1;
    if !matches!(clockid, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME) {
        return EINVAL;
    }
    if flags != 0 && flags != TIMER_ABSTIME {
        return EINVAL;
    }
    if request == 0 {
        return EFAULT;
    }
    let mut tsbuf = [0u8; 16];
    if frame::user::copy_from_user(request, &mut tsbuf).is_err() {
        return EFAULT;
    }
    let mut s = [0u8; 8];
    s.copy_from_slice(&tsbuf[0..8]);
    let mut n = [0u8; 8];
    n.copy_from_slice(&tsbuf[8..16]);
    let secs = i64::from_ne_bytes(s);
    let nsec = i64::from_ne_bytes(n);
    if secs < 0 || !(0..1_000_000_000).contains(&nsec) {
        return EINVAL;
    }
    let target_ns: u64 = (secs as u64).saturating_mul(1_000_000_000) + (nsec as u64);
    let now_ns = frame::cpu::clock::nanos_since_boot();
    let deadline_ns = if flags == TIMER_ABSTIME {
        target_ns
    } else {
        now_ns.saturating_add(target_ns)
    };
    if deadline_ns <= now_ns {
        return 0;
    }
    sched::sleep_until(deadline_ns);
    let after = frame::cpu::clock::nanos_since_boot();
    if after < deadline_ns {
        let remaining = deadline_ns - after;
        if flags == 0 && remain != 0 {
            let mut out = [0u8; 16];
            let rs = (remaining / 1_000_000_000) as i64;
            let rn = (remaining % 1_000_000_000) as i64;
            out[0..8].copy_from_slice(&rs.to_ne_bytes());
            out[8..16].copy_from_slice(&rn.to_ne_bytes());
            let _ = frame::user::copy_to_user(remain, &out);
        }
        return EINTR;
    }
    0
}

pub(super) fn sys_getitimer(which: u64, curr_ptr: u64) -> i64 {
    if which != ITIMER_REAL && which != ITIMER_VIRTUAL && which != ITIMER_PROF {
        return EINVAL;
    }
    if curr_ptr == 0 {
        return EFAULT;
    }
    let pid = sched::current_pid();
    let (interval, value) = match which {
        ITIMER_VIRTUAL => sched::with_signal(pid, |s| {
            (s.itimer_virtual_interval(), s.itimer_virtual_value())
        })
        .unwrap_or((0, 0)),
        ITIMER_PROF => {
            sched::with_signal(pid, |s| (s.itimer_prof_interval(), s.itimer_prof_value()))
                .unwrap_or((0, 0))
        }
        _ => sched::with_signal(pid, |s| {
            let now = frame::cpu::clock::nanos_since_boot();
            (s.itimer_interval(), s.itimer_deadline().saturating_sub(now))
        })
        .unwrap_or((0, 0)),
    };
    let buf = encode_itimerval(interval, value);
    if frame::user::copy_to_user(curr_ptr, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_setitimer(which: u64, new_ptr: u64, old_ptr: u64) -> i64 {
    if which != ITIMER_REAL && which != ITIMER_VIRTUAL && which != ITIMER_PROF {
        return EINVAL;
    }
    if new_ptr == 0 {
        return EFAULT;
    }
    let mut new_buf = [0u8; 32];
    if frame::user::copy_from_user(new_ptr, &mut new_buf).is_err() {
        return EFAULT;
    }
    let (interval_ns, value_ns) = decode_itimerval(&new_buf);

    let target = sched::current_pid();
    let old = match which {
        ITIMER_VIRTUAL => sched::with_signal_mut(target, |s| {
            let old = (s.itimer_virtual_interval(), s.itimer_virtual_value());
            s.set_itimer_virtual(interval_ns, value_ns);
            old
        })
        .unwrap_or((0, 0)),
        ITIMER_PROF => sched::with_signal_mut(target, |s| {
            let old = (s.itimer_prof_interval(), s.itimer_prof_value());
            s.set_itimer_prof(interval_ns, value_ns);
            old
        })
        .unwrap_or((0, 0)),
        _ => {
            let old = sched::with_signal(target, |s| {
                let now = frame::cpu::clock::nanos_since_boot();
                let remaining = s.itimer_deadline().saturating_sub(now);
                (s.itimer_interval(), remaining)
            })
            .unwrap_or((0, 0));
            crate::core::timeout::cancel_callback(itimer_real_key(target));
            sched::with_signal_mut(target, |s| {
                if value_ns == 0 {
                    s.set_itimer_interval(0);
                    s.set_itimer_deadline(0);
                } else {
                    let now = frame::cpu::clock::nanos_since_boot();
                    s.set_itimer_interval(interval_ns);
                    s.set_itimer_deadline(now.saturating_add(value_ns));
                    crate::core::timeout::register_callback(
                        s.itimer_deadline(),
                        itimer_real_key(target),
                        itimer_real_fire,
                    );
                }
            });
            old
        }
    };

    if old_ptr != 0 {
        let old_buf = encode_itimerval(old.0, old.1);
        if frame::user::copy_to_user(old_ptr, &old_buf).is_err() {
            return EFAULT;
        }
    }
    0
}

pub(super) fn sys_alarm(seconds: u64) -> i64 {
    let cur = sched::current_pid();
    let key = itimer_real_key(cur);
    let prev_remaining_sec: u64 = sched::with_signal(cur, |s| {
        let now = frame::cpu::clock::nanos_since_boot();
        if s.itimer_deadline() > now {
            (s.itimer_deadline() - now) / 1_000_000_000
        } else {
            0
        }
    })
    .unwrap_or(0);

    if seconds == 0 {
        sched::with_signal_mut(cur, |s| {
            s.set_itimer_interval(0);
            s.set_itimer_deadline(0);
        });
        crate::core::timeout::cancel_callback(key);
        return prev_remaining_sec as i64;
    }

    let now = frame::cpu::clock::nanos_since_boot();
    let deadline = now.saturating_add(seconds.saturating_mul(1_000_000_000));
    sched::with_signal_mut(cur, |s| {
        s.set_itimer_interval(0);
        s.set_itimer_deadline(deadline);
    });
    crate::core::timeout::cancel_callback(key);
    crate::core::timeout::register_callback(deadline, key, itimer_real_fire);
    prev_remaining_sec as i64
}
