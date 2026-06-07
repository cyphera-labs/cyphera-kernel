use crate::errno::{EFAULT, EINVAL, EPERM, ESRCH};
use crate::sched;

pub(super) fn sys_rseq(rseq_ptr: u64, rseq_len: u64, flags: u64, sig: u64) -> i64 {
    const RSEQ_FLAG_UNREGISTER: u64 = 1;
    const RSEQ_LEN_V0: u64 = 32;
    const RSEQ_LEN_V1: u64 = 32 + 4;
    const RSEQ_LEN_V2: u64 = 32 + 4 + 8;

    if (flags & !RSEQ_FLAG_UNREGISTER) != 0 {
        return EINVAL;
    }
    if rseq_len != RSEQ_LEN_V0 && rseq_len != RSEQ_LEN_V1 && rseq_len != RSEQ_LEN_V2 {
        return EINVAL;
    }
    if rseq_ptr == 0 {
        return EINVAL;
    }
    if rseq_ptr & 0x1f != 0 {
        return EINVAL;
    }

    if (flags & RSEQ_FLAG_UNREGISTER) != 0 {
        return sched::with_current_rseq(|p| {
            if p.rseq_addr == 0 {
                return EINVAL;
            }
            if p.rseq_addr != rseq_ptr || p.rseq_sig != sig as u32 {
                return -1i64;
            }
            p.rseq_addr = 0;
            p.rseq_len = 0;
            p.rseq_sig = 0;
            0
        });
    }

    let early = sched::with_current_rseq(|p| {
        if p.rseq_addr != 0 {
            if p.rseq_addr == rseq_ptr && p.rseq_len == rseq_len as u32 && p.rseq_sig == sig as u32
            {
                return Some(0i64);
            }
            return Some(-16i64);
        }
        p.rseq_addr = rseq_ptr;
        p.rseq_len = rseq_len as u32;
        p.rseq_sig = sig as u32;
        None
    });
    if let Some(r) = early {
        return r;
    }

    let cpu_id = frame::cpu::per_cpu::current_cpu_id();
    let cpu_id_le = cpu_id.to_le_bytes();
    let _ = frame::user::copy_to_user(rseq_ptr, &cpu_id_le);
    let _ = frame::user::copy_to_user(rseq_ptr + 4, &cpu_id_le);
    if rseq_len >= RSEQ_LEN_V1 {
        let node_id_le = 0u32.to_le_bytes();
        let _ = frame::user::copy_to_user(rseq_ptr + 24, &node_id_le);
    }
    if rseq_len >= RSEQ_LEN_V2 {
        let mm_cid_le = 0u64.to_le_bytes();
        let _ = frame::user::copy_to_user(rseq_ptr + 28, &mm_cid_le);
    }
    0
}

pub(super) fn sys_getpriority(which: u64, who: u64) -> i64 {
    const PRIO_PROCESS: u64 = 0;
    if which != PRIO_PROCESS {
        return EINVAL;
    }
    let target_host = if who == 0 {
        sched::current_pid()
    } else {
        match sched::caller_local_to_host(who as u32) {
            Some(p) => p,
            None => return ESRCH,
        }
    };
    let nice = sched::with_target_process(target_host, |p| p.nice).unwrap_or(0);
    20 - nice as i64
}

pub(super) fn sys_setpriority(which: u64, who: u64, niceval: u64) -> i64 {
    const PRIO_PROCESS: u64 = 0;
    if which != PRIO_PROCESS {
        return EINVAL;
    }
    let nice_signed = niceval as i32 as i8;
    let clamped = nice_signed.clamp(-20, 19);
    let target_host = if who == 0 {
        sched::current_pid()
    } else {
        match sched::caller_local_to_host(who as u32) {
            Some(p) => p,
            None => return ESRCH,
        }
    };
    let cur_nice = sched::with_target_process(target_host, |p| p.nice).unwrap_or(0);
    if clamped < cur_nice
        && !sched::with_current_creds(|c| c.capable_host(crate::process::CAP_SYS_NICE))
    {
        return EPERM;
    }
    sched::with_target_process_mut(target_host, |p| {
        p.nice = clamped;
        p.weight = crate::process::nice_to_weight(clamped);
    });
    0
}

const SCHED_OTHER: u64 = 0;
const SCHED_FIFO: u64 = 1;
const SCHED_RR: u64 = 2;
const SCHED_BATCH: u64 = 3;
const SCHED_IDLE: u64 = 5;
const SCHED_DEADLINE: u64 = 6;

pub(super) fn sys_sched_setscheduler(pid: u64, policy: u64, param: u64) -> i64 {
    if param == 0 {
        return EFAULT;
    }
    let mut buf = [0u8; 4];
    if frame::user::copy_from_user(param, &mut buf).is_err() {
        return EFAULT;
    }
    let priority = i32::from_ne_bytes(buf);
    let target = if pid == 0 {
        sched::current_pid()
    } else {
        match sched::caller_local_to_host(pid as u32) {
            Some(p) => p,
            None => return ESRCH,
        }
    };

    let new_class = match policy {
        SCHED_FIFO => {
            if !(1..=99).contains(&priority) {
                return EINVAL;
            }
            crate::process::SchedClass::Rt {
                priority: priority as u8,
                round_robin: false,
            }
        }
        SCHED_RR => {
            if !(1..=99).contains(&priority) {
                return EINVAL;
            }
            crate::process::SchedClass::Rt {
                priority: priority as u8,
                round_robin: true,
            }
        }
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => {
            if priority != 0 {
                return EINVAL;
            }
            crate::process::SchedClass::Cfs
        }
        _ => return EINVAL,
    };

    if matches!(new_class, crate::process::SchedClass::Rt { .. }) {
        let allowed = sched::with_target_process(sched::current_pid(), |p| {
            p.creds.lock().capable_host(crate::process::CAP_SYS_NICE)
        })
        .unwrap_or(false);
        if !allowed {
            return EPERM;
        }
    }

    match sched::set_sched_class(target, new_class) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub(super) fn sys_sched_getscheduler(pid: u64) -> i64 {
    let target = if pid == 0 {
        sched::current_pid()
    } else {
        match sched::caller_local_to_host(pid as u32) {
            Some(p) => p,
            None => return ESRCH,
        }
    };
    sched::with_target_process(target, |p| match p.sched_class {
        crate::process::SchedClass::Cfs => SCHED_OTHER as i64,
        crate::process::SchedClass::Rt { round_robin, .. } => {
            if round_robin {
                SCHED_RR as i64
            } else {
                SCHED_FIFO as i64
            }
        }
        crate::process::SchedClass::Deadline { .. } => SCHED_DEADLINE as i64,
    })
    .unwrap_or(ESRCH)
}

pub(super) fn sys_sched_setparam(pid: u64, param: u64) -> i64 {
    if param == 0 {
        return EFAULT;
    }
    let mut buf = [0u8; 4];
    if frame::user::copy_from_user(param, &mut buf).is_err() {
        return EFAULT;
    }
    let priority = i32::from_ne_bytes(buf);
    let target = if pid == 0 {
        sched::current_pid()
    } else {
        match sched::caller_local_to_host(pid as u32) {
            Some(p) => p,
            None => return ESRCH,
        }
    };
    let cur_class = match sched::with_target_process(target, |p| p.sched_class) {
        Some(c) => c,
        None => return ESRCH,
    };
    let new_class = match cur_class {
        crate::process::SchedClass::Rt { round_robin, .. } => {
            if !(1..=99).contains(&priority) {
                return EINVAL;
            }
            crate::process::SchedClass::Rt {
                priority: priority as u8,
                round_robin,
            }
        }
        crate::process::SchedClass::Cfs => {
            if priority != 0 {
                return EINVAL;
            }
            return 0;
        }
        crate::process::SchedClass::Deadline { .. } => return EINVAL,
    };
    let allowed = sched::with_target_process(sched::current_pid(), |p| {
        p.creds.lock().capable_host(crate::process::CAP_SYS_NICE)
    })
    .unwrap_or(false);
    if !allowed {
        return EPERM;
    }
    match sched::set_sched_class(target, new_class) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub(super) fn sys_sched_getparam(pid: u64, param: u64) -> i64 {
    if param == 0 {
        return EFAULT;
    }
    let target = if pid == 0 {
        sched::current_pid()
    } else {
        match sched::caller_local_to_host(pid as u32) {
            Some(p) => p,
            None => return ESRCH,
        }
    };
    let priority = match sched::with_target_process(target, |p| p.sched_class) {
        Some(crate::process::SchedClass::Rt { priority, .. }) => priority as i32,
        Some(_) => 0,
        None => return ESRCH,
    };
    let buf = priority.to_ne_bytes();
    if frame::user::copy_to_user(param, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_sched_get_priority_max(policy: u64) -> i64 {
    match policy {
        SCHED_FIFO | SCHED_RR => 99,
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => 0,
        _ => EINVAL,
    }
}

pub(super) fn sys_sched_get_priority_min(policy: u64) -> i64 {
    match policy {
        SCHED_FIFO | SCHED_RR => 1,
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => 0,
        _ => EINVAL,
    }
}

pub(super) fn sys_sched_setattr(pid: u64, attr_ptr: u64, _flags: u64) -> i64 {
    if attr_ptr == 0 {
        return EFAULT;
    }
    let mut hdr = [0u8; 4];
    if frame::user::copy_from_user(attr_ptr, &mut hdr).is_err() {
        return EFAULT;
    }
    let size = u32::from_ne_bytes(hdr) as usize;
    if size < 48 {
        return EINVAL;
    }
    let mut buf = [0u8; 48];
    if frame::user::copy_from_user(attr_ptr, &mut buf).is_err() {
        return EFAULT;
    }
    let policy = u32::from_ne_bytes(buf[4..8].try_into().unwrap()) as u64;
    let nice = i32::from_ne_bytes(buf[16..20].try_into().unwrap());
    let priority = u32::from_ne_bytes(buf[20..24].try_into().unwrap()) as i32;
    let runtime = u64::from_ne_bytes(buf[24..32].try_into().unwrap());
    let deadline = u64::from_ne_bytes(buf[32..40].try_into().unwrap());
    let period_raw = u64::from_ne_bytes(buf[40..48].try_into().unwrap());

    let target = if pid == 0 {
        sched::current_pid()
    } else {
        match sched::caller_local_to_host(pid as u32) {
            Some(p) => p,
            None => return ESRCH,
        }
    };

    if policy == SCHED_DEADLINE {
        let period = if period_raw == 0 {
            deadline
        } else {
            period_raw
        };
        if runtime == 0 || deadline == 0 || period == 0 {
            return EINVAL;
        }
        if runtime > deadline || deadline > period {
            return EINVAL;
        }
        let allowed = sched::with_target_process(sched::current_pid(), |p| {
            p.creds.lock().capable_host(crate::process::CAP_SYS_NICE)
        })
        .unwrap_or(false);
        if !allowed {
            return EPERM;
        }
        return sched::set_deadline_class(target, runtime, deadline, period)
            .map(|_| 0)
            .unwrap_or_else(|e| e);
    }

    let new_class = match policy {
        0 | 3 | 5 => {
            if priority != 0 {
                return EINVAL;
            }
            if policy == 0 {
                let clamped = (nice as i8).clamp(-20, 19);
                let cur_nice = sched::with_target_process(target, |p| p.nice).unwrap_or(0);
                if clamped < cur_nice
                    && !sched::with_current_creds(|c| c.capable_host(crate::process::CAP_SYS_NICE))
                {
                    return EPERM;
                }
                sched::with_target_process_mut(target, |p| {
                    p.nice = clamped;
                    p.weight = crate::process::nice_to_weight(clamped);
                });
            }
            crate::process::SchedClass::Cfs
        }
        1 => {
            if !(1..=99).contains(&priority) {
                return EINVAL;
            }
            crate::process::SchedClass::Rt {
                priority: priority as u8,
                round_robin: false,
            }
        }
        2 => {
            if !(1..=99).contains(&priority) {
                return EINVAL;
            }
            crate::process::SchedClass::Rt {
                priority: priority as u8,
                round_robin: true,
            }
        }
        _ => return EINVAL,
    };

    if matches!(new_class, crate::process::SchedClass::Rt { .. }) {
        let allowed = sched::with_target_process(sched::current_pid(), |p| {
            p.creds.lock().capable_host(crate::process::CAP_SYS_NICE)
        })
        .unwrap_or(false);
        if !allowed {
            return EPERM;
        }
    }

    match sched::set_sched_class(target, new_class) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

pub(super) fn sys_sched_getattr(pid: u64, attr_ptr: u64, size: u64, _flags: u64) -> i64 {
    if attr_ptr == 0 {
        return EFAULT;
    }
    if size < 48 {
        return EINVAL;
    }
    let target = if pid == 0 {
        sched::current_pid()
    } else {
        match sched::caller_local_to_host(pid as u32) {
            Some(p) => p,
            None => return ESRCH,
        }
    };
    let snapshot = sched::with_target_process(target, |p| (p.sched_class, p.nice));
    let (class, nice) = match snapshot {
        Some(s) => s,
        None => return ESRCH,
    };
    let mut buf = [0u8; 48];
    buf[0..4].copy_from_slice(&48u32.to_ne_bytes());
    let (policy, prio, runtime, deadline, period): (u32, u32, u64, u64, u64) = match class {
        crate::process::SchedClass::Cfs => (0, 0, 0, 0, 0),
        crate::process::SchedClass::Rt {
            priority,
            round_robin,
        } => {
            let pol = if round_robin { 2 } else { 1 };
            (pol, priority as u32, 0, 0, 0)
        }
        crate::process::SchedClass::Deadline {
            runtime_ns,
            deadline_ns,
            period_ns,
        } => (6, 0, runtime_ns, deadline_ns, period_ns),
    };
    buf[4..8].copy_from_slice(&policy.to_ne_bytes());
    buf[16..20].copy_from_slice(&(nice as i32).to_ne_bytes());
    buf[20..24].copy_from_slice(&prio.to_ne_bytes());
    buf[24..32].copy_from_slice(&runtime.to_ne_bytes());
    buf[32..40].copy_from_slice(&deadline.to_ne_bytes());
    buf[40..48].copy_from_slice(&period.to_ne_bytes());
    if frame::user::copy_to_user(attr_ptr, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_sched_rr_get_interval(pid: u64, ts_ptr: u64) -> i64 {
    if ts_ptr == 0 {
        return EFAULT;
    }
    let target = if pid == 0 {
        sched::current_pid()
    } else {
        match sched::caller_local_to_host(pid as u32) {
            Some(p) => p,
            None => return ESRCH,
        }
    };
    let is_rr = matches!(
        sched::with_target_process(target, |p| p.sched_class),
        Some(crate::process::SchedClass::Rt {
            round_robin: true,
            ..
        })
    );
    let slice_ns = if is_rr {
        sched::SCHED_RR_TIMESLICE_NS
    } else {
        0
    };
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&((slice_ns / 1_000_000_000) as i64).to_ne_bytes());
    buf[8..16].copy_from_slice(&((slice_ns % 1_000_000_000) as i64).to_ne_bytes());
    if frame::user::copy_to_user(ts_ptr, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_sched_getaffinity(_pid: u64, cpusetsize: u64, mask: u64) -> i64 {
    if mask == 0 {
        return EFAULT;
    }
    if cpusetsize == 0 || !cpusetsize.is_multiple_of(core::mem::size_of::<u64>() as u64) {
        return EINVAL;
    }
    let nproc = frame::cpu::per_cpu::MAX_CPUS;
    let needed_bytes = nproc.div_ceil(8);
    if (cpusetsize as usize) < needed_bytes {
        return EINVAL;
    }
    let mut buf = alloc::vec![0u8; cpusetsize as usize];
    for i in 0..nproc {
        buf[i / 8] |= 1u8 << (i % 8);
    }
    if frame::user::copy_to_user(mask, &buf).is_err() {
        return EFAULT;
    }
    cpusetsize as i64
}

pub(super) fn sys_getcpu(cpu_ptr: u64, node_ptr: u64, _tcache: u64) -> i64 {
    let cpu_id: u32 = frame::cpu::per_cpu::current_cpu_id();
    if cpu_ptr != 0 && frame::user::copy_to_user(cpu_ptr, &cpu_id.to_ne_bytes()).is_err() {
        return EFAULT;
    }
    if node_ptr != 0 {
        let node: u32 = 0;
        if frame::user::copy_to_user(node_ptr, &node.to_ne_bytes()).is_err() {
            return EFAULT;
        }
    }
    0
}
