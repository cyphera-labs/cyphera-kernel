use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::user::TrapFrame;

use crate::core as sched;
use crate::errno::{EFAULT, EINVAL, ENOSYS, EPERM, ESRCH};

const CAPABILITY_VERSION_3: u32 = 0x20080522;

pub(super) fn sys_capget(hdr_ptr: u64, data_ptr: u64) -> i64 {
    if hdr_ptr == 0 {
        return EFAULT;
    }
    let mut hdr = [0u8; 8];
    if frame::user::copy_from_user(hdr_ptr, &mut hdr).is_err() {
        return EFAULT;
    }
    let version = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let pid_arg = i32::from_le_bytes(hdr[4..8].try_into().unwrap());
    if version != CAPABILITY_VERSION_3 {
        let want = CAPABILITY_VERSION_3.to_le_bytes();
        let _ = frame::user::copy_to_user(hdr_ptr, &want);
        return EINVAL;
    }
    let target_pid = if pid_arg == 0 {
        sched::current_pid()
    } else {
        crate::process_model::Pid(pid_arg as u32)
    };
    let snap = sched::with_target_creds(target_pid, |c| c.clone());
    let creds = match snap {
        Some(c) => c,
        None => return ESRCH,
    };
    if data_ptr == 0 {
        return 0;
    }
    let mut buf = [0u8; 24];
    let eff_lo = (creds.caps_eff & 0xffff_ffff) as u32;
    let eff_hi = (creds.caps_eff >> 32) as u32;
    let perm_lo = (creds.caps_perm & 0xffff_ffff) as u32;
    let perm_hi = (creds.caps_perm >> 32) as u32;
    let inh_lo = (creds.caps_inh & 0xffff_ffff) as u32;
    let inh_hi = (creds.caps_inh >> 32) as u32;
    buf[0..4].copy_from_slice(&eff_lo.to_le_bytes());
    buf[4..8].copy_from_slice(&perm_lo.to_le_bytes());
    buf[8..12].copy_from_slice(&inh_lo.to_le_bytes());
    buf[12..16].copy_from_slice(&eff_hi.to_le_bytes());
    buf[16..20].copy_from_slice(&perm_hi.to_le_bytes());
    buf[20..24].copy_from_slice(&inh_hi.to_le_bytes());
    if frame::user::copy_to_user(data_ptr, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_capset(hdr_ptr: u64, data_ptr: u64) -> i64 {
    if hdr_ptr == 0 || data_ptr == 0 {
        return EFAULT;
    }
    let mut hdr = [0u8; 8];
    if frame::user::copy_from_user(hdr_ptr, &mut hdr).is_err() {
        return EFAULT;
    }
    let version = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    let pid_arg = i32::from_le_bytes(hdr[4..8].try_into().unwrap());
    if version != CAPABILITY_VERSION_3 {
        let want = CAPABILITY_VERSION_3.to_le_bytes();
        let _ = frame::user::copy_to_user(hdr_ptr, &want);
        return EINVAL;
    }
    if pid_arg != 0 && pid_arg as u32 != sched::current_pid().raw() {
        return EPERM;
    }
    let mut buf = [0u8; 24];
    if frame::user::copy_from_user(data_ptr, &mut buf).is_err() {
        return EFAULT;
    }
    let eff_lo = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let perm_lo = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let inh_lo = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let eff_hi = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let perm_hi = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let inh_hi = u32::from_le_bytes(buf[20..24].try_into().unwrap());
    let new_eff = ((eff_hi as u64) << 32) | (eff_lo as u64);
    let new_perm = ((perm_hi as u64) << 32) | (perm_lo as u64);
    let new_inh = ((inh_hi as u64) << 32) | (inh_lo as u64);
    match crate::security::capset(new_eff, new_perm, new_inh) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

const SECCOMP_SET_MODE_STRICT: u64 = 0;
const SECCOMP_SET_MODE_FILTER: u64 = 1;
const SECCOMP_GET_ACTION_AVAIL: u64 = 2;
const SECCOMP_GET_NOTIF_SIZES: u64 = 3;

const SECCOMP_FILTER_FLAG_TSYNC: u64 = 1;
const SECCOMP_FILTER_FLAG_LOG: u64 = 2;
const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u64 = 4;

pub(super) fn sys_seccomp(operation: u64, flags: u64, args: u64) -> i64 {
    use crate::security::bpf::{BpfProgram, SockFilter};

    match operation {
        SECCOMP_SET_MODE_STRICT => {
            let prog = strict_mode_program();
            let prog = match BpfProgram::verify(prog, crate::security::seccomp::SeccompData::SIZE) {
                Ok(p) => p,
                Err(_) => return EINVAL,
            };
            if !sched::current_no_new_privs()
                && !crate::security::has_cap(crate::process_model::CAP_SYS_ADMIN)
            {
                return EPERM;
            }
            crate::security::seccomp::install_filter(Arc::new(prog));
            0
        }
        SECCOMP_SET_MODE_FILTER => {
            if (flags
                & !(SECCOMP_FILTER_FLAG_TSYNC
                    | SECCOMP_FILTER_FLAG_LOG
                    | SECCOMP_FILTER_FLAG_SPEC_ALLOW))
                != 0
            {
                return EINVAL;
            }
            if !sched::current_no_new_privs()
                && !crate::security::has_cap(crate::process_model::CAP_SYS_ADMIN)
            {
                return EPERM;
            }
            let mut hdr = [0u8; 16];
            if frame::user::copy_from_user(args, &mut hdr).is_err() {
                return EFAULT;
            }
            let len = u16::from_le_bytes(hdr[0..2].try_into().unwrap()) as usize;
            let filter_ptr = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
            if len == 0 || len > 4096 {
                return EINVAL;
            }
            let bytes_total: usize = len.checked_mul(8).unwrap_or(0);
            if bytes_total == 0 {
                return EINVAL;
            }
            let mut buf: Vec<u8> = alloc::vec![0u8; bytes_total];
            if frame::user::copy_from_user(filter_ptr, &mut buf).is_err() {
                return EFAULT;
            }
            let mut insns: Vec<SockFilter> = Vec::with_capacity(len);
            for i in 0..len {
                let off = i * 8;
                insns.push(SockFilter {
                    code: u16::from_le_bytes(buf[off..off + 2].try_into().unwrap()),
                    jt: buf[off + 2],
                    jf: buf[off + 3],
                    k: u32::from_le_bytes(buf[off + 4..off + 8].try_into().unwrap()),
                });
            }
            let prog = match BpfProgram::verify(insns, crate::security::seccomp::SeccompData::SIZE)
            {
                Ok(p) => p,
                Err(_) => return EINVAL,
            };
            let prog = Arc::new(prog);
            if flags & SECCOMP_FILTER_FLAG_TSYNC != 0 {
                crate::security::seccomp::install_filter_all_threads(prog);
            } else {
                crate::security::seccomp::install_filter(prog);
            }
            0
        }
        SECCOMP_GET_ACTION_AVAIL => {
            let mut a = [0u8; 4];
            if frame::user::copy_from_user(args, &mut a).is_err() {
                return EFAULT;
            }
            let action = u32::from_le_bytes(a);
            let supported = [
                crate::security::seccomp::SECCOMP_RET_KILL_PROCESS,
                crate::security::seccomp::SECCOMP_RET_KILL_THREAD,
                crate::security::seccomp::SECCOMP_RET_TRAP,
                crate::security::seccomp::SECCOMP_RET_ERRNO,
                crate::security::seccomp::SECCOMP_RET_LOG,
                crate::security::seccomp::SECCOMP_RET_ALLOW,
            ];
            if supported.contains(&action) {
                0
            } else {
                EINVAL
            }
        }
        SECCOMP_GET_NOTIF_SIZES => EINVAL,
        _ => EINVAL,
    }
}

fn strict_mode_program() -> Vec<crate::security::bpf::SockFilter> {
    use crate::security::bpf::SockFilter;
    let kill = crate::security::seccomp::SECCOMP_RET_KILL_PROCESS;
    let allow = crate::security::seccomp::SECCOMP_RET_ALLOW;
    alloc::vec![
        SockFilter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0
        },
        SockFilter {
            code: 0x05 | 0x10,
            jt: 5,
            jf: 0,
            k: 0
        },
        SockFilter {
            code: 0x05 | 0x10,
            jt: 4,
            jf: 0,
            k: 1
        },
        SockFilter {
            code: 0x05 | 0x10,
            jt: 3,
            jf: 0,
            k: 15
        },
        SockFilter {
            code: 0x05 | 0x10,
            jt: 2,
            jf: 0,
            k: 60
        },
        SockFilter {
            code: 0x05 | 0x10,
            jt: 1,
            jf: 0,
            k: 231
        },
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: kill
        },
        SockFilter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: allow
        },
    ]
}

pub(super) fn apply_seccomp(tf: &mut TrapFrame) -> bool {
    use crate::security::seccomp::*;
    let r = evaluate_for_syscall(tf);
    let action = r & SECCOMP_RET_ACTION;
    let data = r & SECCOMP_RET_DATA;
    if action == SECCOMP_RET_ALLOW {
        return true;
    }
    if action == SECCOMP_RET_LOG {
        frame::println!(
            "[seccomp] log: pid={} nr={} action=LOG",
            sched::current_pid().raw(),
            tf.syscall_nr()
        );
        return true;
    }
    if action == SECCOMP_RET_ERRNO {
        let errno = data.min(4095) as i64;
        tf.set_ret((-errno) as u64);
        return false;
    }
    if action == SECCOMP_RET_TRAP {
        let pid = sched::current_pid();
        let info = crate::core::signal::SigInfo::for_seccomp(
            tf.user_ip(),
            tf.orig_nr() as u32,
            data as u16,
        );
        let _ = sched::send_signal_with_info(pid, 31, info);
        tf.set_ret(ENOSYS as u64);
        sched::deliver_pending_signals(tf);
        return false;
    }
    if action == SECCOMP_RET_KILL_THREAD || action == SECCOMP_RET_KILL_PROCESS {
        sched::terminate_current_with_signal(9);
    }
    sched::terminate_current_with_signal(9);
}

pub(super) fn sys_sethostname(name: u64, len: u64) -> i64 {
    if len > 64 || name == 0 {
        return EINVAL;
    }
    let uts_owner = sched::with_current_uts(|n| n.owner_user_ns.clone());
    if !crate::security::capable_in(crate::process_model::CAP_SYS_ADMIN, uts_owner.as_ref()) {
        return EPERM;
    }
    let mut buf = [0u8; 64];
    if frame::user::copy_from_user(name, &mut buf[..len as usize]).is_err() {
        return EFAULT;
    }
    let s = match core::str::from_utf8(&buf[..len as usize]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    sched::with_current_uts(|n| {
        *n.hostname.lock() = String::from(s);
    });
    0
}

pub(super) fn sys_setdomainname(name: u64, len: u64) -> i64 {
    if len > 64 || name == 0 {
        return EINVAL;
    }
    let uts_owner = sched::with_current_uts(|n| n.owner_user_ns.clone());
    if !crate::security::capable_in(crate::process_model::CAP_SYS_ADMIN, uts_owner.as_ref()) {
        return EPERM;
    }
    let mut buf = [0u8; 64];
    if frame::user::copy_from_user(name, &mut buf[..len as usize]).is_err() {
        return EFAULT;
    }
    let s = match core::str::from_utf8(&buf[..len as usize]) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    sched::with_current_uts(|n| {
        *n.domainname.lock() = String::from(s);
    });
    0
}

pub(super) fn sys_getresuid(r_ptr: u64, e_ptr: u64, s_ptr: u64) -> i64 {
    let (ruid, euid, suid) = sched::with_current_creds(|c| {
        (
            c.uid_from_kernel(c.ruid),
            c.uid_from_kernel(c.euid),
            c.uid_from_kernel(c.suid),
        )
    });
    if r_ptr != 0 && frame::user::copy_to_user(r_ptr, &ruid.to_le_bytes()).is_err() {
        return EFAULT;
    }
    if e_ptr != 0 && frame::user::copy_to_user(e_ptr, &euid.to_le_bytes()).is_err() {
        return EFAULT;
    }
    if s_ptr != 0 && frame::user::copy_to_user(s_ptr, &suid.to_le_bytes()).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_getresgid(r_ptr: u64, e_ptr: u64, s_ptr: u64) -> i64 {
    let (rgid, egid, sgid) = sched::with_current_creds(|c| {
        (
            c.gid_from_kernel(c.rgid),
            c.gid_from_kernel(c.egid),
            c.gid_from_kernel(c.sgid),
        )
    });
    if r_ptr != 0 && frame::user::copy_to_user(r_ptr, &rgid.to_le_bytes()).is_err() {
        return EFAULT;
    }
    if e_ptr != 0 && frame::user::copy_to_user(e_ptr, &egid.to_le_bytes()).is_err() {
        return EFAULT;
    }
    if s_ptr != 0 && frame::user::copy_to_user(s_ptr, &sgid.to_le_bytes()).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_getgroups(size: u64, list: u64) -> i64 {
    let groups = sched::with_current_creds(|c| {
        c.groups
            .iter()
            .map(|&g| c.gid_from_kernel(g))
            .collect::<Vec<u32>>()
    });
    let n = groups.len();
    if size == 0 {
        return n as i64;
    }
    if (size as usize) < n {
        return crate::errno::ERANGE;
    }
    let mut buf = Vec::with_capacity(n * 4);
    for g in &groups {
        buf.extend_from_slice(&g.to_le_bytes());
    }
    if !buf.is_empty() && frame::user::copy_to_user(list, &buf).is_err() {
        return EFAULT;
    }
    n as i64
}

pub(super) fn sys_setgroups(size: u64, list: u64) -> i64 {
    let (priv_, gate_denied) = sched::with_current_creds(|c| {
        let denied = match &c.user_ns {
            Some(ns) => !ns
                .setgroups_allowed
                .load(core::sync::atomic::Ordering::Acquire),
            None => false,
        };
        (c.has_cap(crate::process_model::CAP_SETGID), denied)
    });
    if gate_denied || !priv_ {
        return EPERM;
    }
    let n = size as usize;
    if n > crate::process_model::MAX_SUPP_GROUPS {
        return EINVAL;
    }
    if n == 0 {
        sched::with_current_creds_mut(crate::security::setid::clear_supplementary_groups);
        return 0;
    }
    let mut buf = alloc::vec![0u8; n * 4];
    if frame::user::copy_from_user(list, &mut buf).is_err() {
        return EFAULT;
    }
    let supplied: Vec<u32> = (0..n)
        .map(|i| u32::from_le_bytes(buf[i * 4..i * 4 + 4].try_into().unwrap()))
        .collect();
    match sched::with_current_creds_mut(|c| {
        crate::security::setid::set_supplementary_groups(c, &supplied)
    }) {
        Ok(()) => 0,
        Err(e) => e,
    }
}
