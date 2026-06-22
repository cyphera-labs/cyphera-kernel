use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use frame::user::TrapFrame;

use crate::core as sched;
use crate::errno::{EAGAIN, EBADF, EFAULT, EINTR, EINVAL, EPERM, ESRCH};
use crate::vfs::{self, Inode, OpenFile, OpenFlags};

pub(super) fn sys_sigaltstack(new_ptr: u64, old_ptr: u64, current_rsp: u64) -> i64 {
    if old_ptr != 0 {
        let cur = sched::current_altstack();
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&cur.sp.to_le_bytes());
        buf[8..12].copy_from_slice(&cur.flags.to_le_bytes());
        buf[16..24].copy_from_slice(&cur.size.to_le_bytes());
        if frame::user::copy_to_user(old_ptr, &buf).is_err() {
            return EFAULT;
        }
    }

    if new_ptr != 0 {
        if sched::current_on_altstack(current_rsp) {
            return -1;
        }
        let mut buf = [0u8; 24];
        if frame::user::copy_from_user(new_ptr, &mut buf).is_err() {
            return EFAULT;
        }
        let sp = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let flags = i32::from_le_bytes(buf[8..12].try_into().unwrap());
        let size = u64::from_le_bytes(buf[16..24].try_into().unwrap());

        let mut new = crate::core::signal::AltStack { sp, flags, size };
        if flags & crate::core::signal::AltStack::SS_DISABLE != 0 {
            new = crate::core::signal::AltStack::disabled();
        } else if size < crate::core::signal::AltStack::MIN_SIZE {
            return EINVAL;
        }

        if sched::set_current_altstack(new).is_err() {
            return -3;
        }
    }
    0
}

pub(super) fn sys_kill(pid: u64, signal: u64) -> i64 {
    if signal as u32 >= 64 {
        return EINVAL;
    }
    let signed = pid as i64;
    if signed < 0 {
        let local_pgid = (-signed) as u32;
        let pgid_host = match sched::caller_local_to_host(local_pgid) {
            Some(p) => p,
            None => return ESRCH,
        };
        sched::signal_pgrp(pgid_host, signal as u32);
        return 0;
    }
    if signed == 0 {
        let pgid = sched::current_pgid();
        sched::signal_pgrp(pgid, signal as u32);
        return 0;
    }
    let target = match sched::caller_local_to_host(pid as u32) {
        Some(p) => p,
        None => return ESRCH,
    };
    let caller_snap = sched::with_current_creds(|c| c.clone());
    let permitted =
        sched::with_target_creds(target, |tgt| caller_snap.can_signal(tgt)).unwrap_or(false);
    if !permitted {
        return -1;
    }
    match sched::send_signal(target, signal as u32) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(super) fn sys_tkill(tid: u64, sig: u64) -> i64 {
    if sig as u32 >= 64 {
        return EINVAL;
    }
    let target_host = match sched::caller_local_to_host(tid as u32) {
        Some(p) => p,
        None => return ESRCH,
    };
    if sig == 0 {
        return 0;
    }
    let sender_host = sched::current_pid();
    let sender_local = sched::process_pid_ns(target_host)
        .map(|ns| ns.host_to_local_in(sender_host))
        .unwrap_or(0);
    let info = crate::core::signal::SigInfo::for_tkill(sig as u32, sender_local);
    match sched::send_signal_with_info(target_host, sig as u32, info) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(super) fn sys_tgkill(tgid: u64, tid: u64, sig: u64) -> i64 {
    if (tgid as i64) <= 0 || (tid as i64) <= 0 {
        return EINVAL;
    }
    if sig as u32 >= 64 {
        return EINVAL;
    }
    let target_host = match sched::caller_local_to_host(tid as u32) {
        Some(p) => p,
        None => return ESRCH,
    };
    if sig == 0 {
        return 0;
    }
    let sender_host = sched::current_pid();
    let sender_local = target_host_pid_in_ns_of(sender_host, target_host).unwrap_or(0);
    let info = crate::core::signal::SigInfo::for_tkill(sig as u32, sender_local);
    match sched::send_signal_with_info(target_host, sig as u32, info) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

fn target_host_pid_in_ns_of(
    host_pid: crate::process_model::Pid,
    target_pid: crate::process_model::Pid,
) -> Option<u32> {
    let ns = sched::process_pid_ns(target_pid)?;
    Some(ns.host_to_local_in(host_pid))
}

pub(super) fn sys_rt_sigaction(signum: u64, new_act: u64, old_act: u64, sigsetsize: u64) -> i64 {
    use crate::process_model::SigAction;
    if signum == 0 || signum >= 64 {
        return EINVAL;
    }
    if new_act != 0 && (signum == 9 || signum == 19) {
        return EINVAL;
    }
    if sigsetsize != 8 {
        return EINVAL;
    }

    if old_act != 0 {
        let cur = sched::with_current_sigaction(signum as u32).unwrap_or_default();
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&cur.handler.to_le_bytes());
        buf[8..16].copy_from_slice(&cur.flags.to_le_bytes());
        buf[16..24].copy_from_slice(&cur.restorer.to_le_bytes());
        buf[24..32].copy_from_slice(&cur.mask.to_le_bytes());
        if frame::user::copy_to_user(old_act, &buf).is_err() {
            return EFAULT;
        }
    }

    if new_act != 0 {
        let mut buf = [0u8; 32];
        if frame::user::copy_from_user(new_act, &mut buf).is_err() {
            return EFAULT;
        }
        let action = SigAction {
            handler: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            flags: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            restorer: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            mask: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
        };
        if sched::set_sigaction(signum as u32, action).is_err() {
            return EINVAL;
        }
    }
    0
}

pub(super) fn sys_rt_sigprocmask(how: u64, set: u64, oldset: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    let new = if set != 0 {
        let mut buf = [0u8; 8];
        if frame::user::copy_from_user(set, &mut buf).is_err() {
            return EFAULT;
        }
        Some(u64::from_le_bytes(buf))
    } else {
        None
    };
    let old = match new {
        Some(set_val) => match sched::sigprocmask(how as u32, set_val) {
            Ok(o) => o,
            Err(_) => return EINVAL,
        },
        None => sched::current_blocked(),
    };
    if oldset != 0 && frame::user::copy_to_user(oldset, &old.to_le_bytes()).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_rt_sigreturn(tf: &mut TrapFrame) {
    sched::rt_sigreturn(tf);
}

static PIDFD_INDEX: frame::sync::SpinIrq<BTreeMap<usize, crate::process_model::Pid>> =
    frame::sync::SpinIrq::new(BTreeMap::new());

const PIDFD_NONBLOCK: u64 = 0o4000;

pub(crate) fn install_pidfd(target: crate::process_model::Pid, nonblock: bool) -> Result<i32, i64> {
    let typed = crate::ipc::fdtypes::PidFdInode::new(target);
    let inode_dyn: Arc<dyn Inode> = typed;
    let mut open_flags = OpenFlags::RDONLY;
    if nonblock {
        open_flags |= OpenFlags::NONBLOCK;
    }
    let file = Arc::new(OpenFile::new(inode_dyn, open_flags));
    let key = Arc::as_ptr(&file.inode) as *const () as usize;
    PIDFD_INDEX.lock().insert(key, target);
    sched::with_current_fds(|t| t.install_from(file, 0, vfs::fd::FD_CLOEXEC)).map_err(|e| e as i64)
}

pub(super) fn sys_pidfd_open(pid: u64, flags: u64) -> i64 {
    if (flags & !PIDFD_NONBLOCK) != 0 {
        return EINVAL;
    }
    let target = match sched::caller_local_to_host(pid as u32) {
        Some(p) => p,
        None => return ESRCH,
    };
    if sched::process_state(target).is_none() {
        return ESRCH;
    }
    match install_pidfd(target, (flags & PIDFD_NONBLOCK) != 0) {
        Ok(fd) => fd as i64,
        Err(e) => e,
    }
}

pub(super) fn sys_pidfd_send_signal(pidfd: u64, sig: u64, _info: u64, flags: u64) -> i64 {
    if flags != 0 {
        return EINVAL;
    }
    if sig as u32 >= 64 {
        return EINVAL;
    }
    let file = match sched::with_current_fds(|t| t.get(pidfd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let key = Arc::as_ptr(&file.inode) as *const () as usize;
    let target = match PIDFD_INDEX.lock().get(&key).copied() {
        Some(p) => p,
        None => return EINVAL,
    };
    let caller_snap = sched::with_current_creds(|c| c.clone());
    let permitted =
        sched::with_target_creds(target, |tgt| caller_snap.can_signal(tgt)).unwrap_or(false);
    if !permitted {
        return -1;
    }
    if sig == 0 {
        return 0;
    }
    match sched::send_signal(target, sig as u32) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(super) fn sys_pause() -> i64 {
    if sched::current_signal_pending() {
        return -4;
    }
    sched::park_on_signalfd_wait();
    -4
}

pub(super) fn sys_rt_sigtimedwait(
    set_ptr: u64,
    info_ptr: u64,
    timeout_ptr: u64,
    sigsetsize: u64,
) -> i64 {
    if sigsetsize as usize != 8 {
        return -22;
    }
    if set_ptr == 0 {
        return EFAULT;
    }
    let mut set_buf = [0u8; 8];
    if frame::user::copy_from_user(set_ptr, &mut set_buf).is_err() {
        return EFAULT;
    }
    let set_mask = u64::from_le_bytes(set_buf);

    let deadline_ns: Option<u64> = if timeout_ptr != 0 {
        let mut tbuf = [0u8; 16];
        if frame::user::copy_from_user(timeout_ptr, &mut tbuf).is_err() {
            return EFAULT;
        }
        let secs = u64::from_le_bytes(tbuf[0..8].try_into().unwrap());
        let nsec = u64::from_le_bytes(tbuf[8..16].try_into().unwrap());
        let total = secs.saturating_mul(1_000_000_000).saturating_add(nsec);
        if total == 0 {
            Some(0)
        } else {
            let now = frame::cpu::clock::nanos_since_boot();
            Some(now.saturating_add(total))
        }
    } else {
        None
    };

    loop {
        let pending = sched::current_pending_in_mask(set_mask);
        if pending != 0 {
            let signum = pending.trailing_zeros();
            let (si_code, _aux) = sched::consume_pending_signal(signum);
            if info_ptr != 0 {
                let mut buf = [0u8; 128];
                buf[0..4].copy_from_slice(&(signum as i32).to_le_bytes());
                buf[4..8].copy_from_slice(&0i32.to_le_bytes());
                buf[8..12].copy_from_slice(&si_code.to_le_bytes());
                if frame::user::copy_to_user(info_ptr, &buf).is_err() {
                    return EFAULT;
                }
            }
            return signum as i64;
        }
        if let Some(d) = deadline_ns {
            let now = frame::cpu::clock::nanos_since_boot();
            if d == 0 || d <= now {
                return -11;
            }
        }
        if let Some(d) = deadline_ns {
            crate::core::timeout::register(d, sched::current_pid());
        }
        sched::park_on_signalfd_wait();
        if deadline_ns.is_some() {
            let _ = crate::core::timeout::unregister(sched::current_pid());
        }
    }
}

pub(super) fn sys_rt_sigsuspend(mask_ptr: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    let mut buf = [0u8; 8];
    if frame::user::copy_from_user(mask_ptr, &mut buf).is_err() {
        return EFAULT;
    }
    let new_mask = u64::from_ne_bytes(buf);
    let cur = sched::current_pid();
    let old_mask = sched::with_signal(cur, |s| s.blocked()).unwrap_or(0);
    sched::with_signal_mut(cur, |s| {
        s.set_blocked(
            new_mask
                & !((1u64 << crate::process_model::SIGKILL)
                    | (1u64 << crate::process_model::SIGSTOP)),
        );
    });
    sched::sleep_until_signal();
    sched::with_signal_mut(cur, |s| {
        s.set_blocked(old_mask);
    });
    EINTR
}

pub(super) fn sys_rt_sigpending(set_ptr: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    if set_ptr == 0 {
        return EFAULT;
    }
    let pending: u64 = sched::with_signal(sched::current_pid(), |s| s.pending()).unwrap_or(0);
    if frame::user::copy_to_user(set_ptr, &pending.to_ne_bytes()).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_rt_sigqueueinfo(local_pid: u64, sig: u64, info_ptr: u64) -> i64 {
    if sig >= crate::process_model::NSIG as u64 {
        return EINVAL;
    }
    let target_host = match sched::caller_local_to_host(local_pid as u32) {
        Some(p) => p,
        None => return ESRCH,
    };
    let mut buf = [0u8; 128];
    if frame::user::copy_from_user(info_ptr, &mut buf).is_err() {
        return EFAULT;
    }
    let mut si_code_bytes = [0u8; 4];
    si_code_bytes.copy_from_slice(&buf[8..12]);
    let si_code = i32::from_ne_bytes(si_code_bytes);
    if si_code >= 0 {
        let euid = sched::with_target_creds(sched::current_pid(), |c| c.euid).unwrap_or(0);
        if euid != 0 {
            return EPERM;
        }
    }
    let sival = u64::from_ne_bytes(buf[24..32].try_into().unwrap());
    let sender_local = target_host_pid_in_ns_of(sched::current_pid(), target_host).unwrap_or(0);
    let info = crate::core::signal::SigInfo::for_queue(sig as u32, si_code, sender_local, sival);
    match sched::send_signal_with_info(target_host, sig as u32, info) {
        Ok(()) => 0,
        Err(cyphera_kapi::Errno::AGAIN) => EAGAIN,
        Err(_) => ESRCH,
    }
}

pub(super) fn sys_rt_tgsigqueueinfo(
    local_tgid: u64,
    local_tid: u64,
    sig: u64,
    info_ptr: u64,
) -> i64 {
    if sig >= crate::process_model::NSIG as u64 {
        return EINVAL;
    }
    let target_tid = match sched::caller_local_to_host(local_tid as u32) {
        Some(p) => p,
        None => return ESRCH,
    };
    let target_tgid_host = match sched::caller_local_to_host(local_tgid as u32) {
        Some(p) => p,
        None => return ESRCH,
    };
    let actual_tgid = sched::process_tgid(target_tid).map(|p| p.0);
    if actual_tgid != Some(target_tgid_host.0) {
        return ESRCH;
    }
    let mut buf = [0u8; 128];
    if frame::user::copy_from_user(info_ptr, &mut buf).is_err() {
        return EFAULT;
    }
    let mut si_code_bytes = [0u8; 4];
    si_code_bytes.copy_from_slice(&buf[8..12]);
    let si_code = i32::from_ne_bytes(si_code_bytes);
    if si_code >= 0 {
        let euid = sched::with_target_creds(sched::current_pid(), |c| c.euid).unwrap_or(0);
        if euid != 0 {
            return EPERM;
        }
    }
    let sival = u64::from_ne_bytes(buf[24..32].try_into().unwrap());
    let sender_local = target_host_pid_in_ns_of(sched::current_pid(), target_tid).unwrap_or(0);
    let info = crate::core::signal::SigInfo::for_queue(sig as u32, si_code, sender_local, sival);
    match sched::send_signal_with_info(target_tid, sig as u32, info) {
        Ok(()) => 0,
        Err(cyphera_kapi::Errno::AGAIN) => EAGAIN,
        Err(_) => ESRCH,
    }
}
