use crate::errno::{EINVAL, EPERM};
use crate::process::SETID_KEEP;
use crate::sched;

fn check_setid_transition(
    current: u32,
    new: u32,
    ruid: u32,
    euid: u32,
    suid: u32,
    privileged: bool,
) -> bool {
    if new == SETID_KEEP {
        return true;
    }
    if privileged {
        return true;
    }
    new == ruid || new == euid || new == suid || new == current
}

fn map_setuid_in(c: &crate::process::Credentials, id: u32) -> Option<u32> {
    if id == SETID_KEEP {
        Some(SETID_KEEP)
    } else {
        c.uid_into_kernel(id)
    }
}

fn map_setgid_in(c: &crate::process::Credentials, id: u32) -> Option<u32> {
    if id == SETID_KEEP {
        Some(SETID_KEEP)
    } else {
        c.gid_into_kernel(id)
    }
}

pub(crate) fn sys_setresuid(new_ruid: u32, new_euid: u32, new_suid: u32) -> i64 {
    sched::with_current_creds_mut(|c| {
        let (k_ruid, k_euid, k_suid) = match (
            map_setuid_in(c, new_ruid),
            map_setuid_in(c, new_euid),
            map_setuid_in(c, new_suid),
        ) {
            (Some(r), Some(e), Some(s)) => (r, e, s),
            _ => return EINVAL,
        };
        let priv_ = c.has_cap(crate::process::CAP_SETUID);
        if !check_setid_transition(c.ruid, k_ruid, c.ruid, c.euid, c.suid, priv_)
            || !check_setid_transition(c.euid, k_euid, c.ruid, c.euid, c.suid, priv_)
            || !check_setid_transition(c.suid, k_suid, c.ruid, c.euid, c.suid, priv_)
        {
            return EPERM;
        }
        let (or, oe, os, of) = (c.ruid, c.euid, c.suid, c.fsuid);
        if k_ruid != SETID_KEEP {
            c.ruid = k_ruid;
        }
        if k_euid != SETID_KEEP {
            c.euid = k_euid;
            c.fsuid = k_euid;
        }
        if k_suid != SETID_KEEP {
            c.suid = k_suid;
        }
        c.apply_uid_change_caps(or, oe, os, of);
        0
    })
}

pub(crate) fn sys_setresgid(new_rgid: u32, new_egid: u32, new_sgid: u32) -> i64 {
    sched::with_current_creds_mut(|c| {
        let (k_rgid, k_egid, k_sgid) = match (
            map_setgid_in(c, new_rgid),
            map_setgid_in(c, new_egid),
            map_setgid_in(c, new_sgid),
        ) {
            (Some(r), Some(e), Some(s)) => (r, e, s),
            _ => return EINVAL,
        };
        let priv_ = c.has_cap(crate::process::CAP_SETGID);
        if !check_setid_transition(c.rgid, k_rgid, c.rgid, c.egid, c.sgid, priv_)
            || !check_setid_transition(c.egid, k_egid, c.rgid, c.egid, c.sgid, priv_)
            || !check_setid_transition(c.sgid, k_sgid, c.rgid, c.egid, c.sgid, priv_)
        {
            return EPERM;
        }
        if k_rgid != SETID_KEEP {
            c.rgid = k_rgid;
        }
        if k_egid != SETID_KEEP {
            c.egid = k_egid;
            c.fsgid = k_egid;
        }
        if k_sgid != SETID_KEEP {
            c.sgid = k_sgid;
        }
        0
    })
}

pub(crate) fn sys_setuid(uid: u32) -> i64 {
    sched::with_current_creds_mut(|c| {
        let ku = match c.uid_into_kernel(uid) {
            Some(k) => k,
            None => return EINVAL,
        };
        let (or, oe, os, of) = (c.ruid, c.euid, c.suid, c.fsuid);
        if c.has_cap(crate::process::CAP_SETUID) {
            c.ruid = ku;
            c.euid = ku;
            c.suid = ku;
            c.fsuid = ku;
            c.apply_uid_change_caps(or, oe, os, of);
            return 0;
        }
        if ku == c.ruid || ku == c.euid || ku == c.suid {
            c.euid = ku;
            c.fsuid = ku;
            c.apply_uid_change_caps(or, oe, os, of);
            return 0;
        }
        EPERM
    })
}

pub(crate) fn sys_setgid(gid: u32) -> i64 {
    sched::with_current_creds_mut(|c| {
        let kg = match c.gid_into_kernel(gid) {
            Some(k) => k,
            None => return EINVAL,
        };
        if c.has_cap(crate::process::CAP_SETGID) {
            c.rgid = kg;
            c.egid = kg;
            c.sgid = kg;
            c.fsgid = kg;
            return 0;
        }
        if kg == c.rgid || kg == c.egid || kg == c.sgid {
            c.egid = kg;
            c.fsgid = kg;
            return 0;
        }
        EPERM
    })
}

pub(crate) fn sys_setreuid(new_ruid: u32, new_euid: u32) -> i64 {
    sched::with_current_creds_mut(|c| {
        let (k_ruid, k_euid) = match (map_setuid_in(c, new_ruid), map_setuid_in(c, new_euid)) {
            (Some(r), Some(e)) => (r, e),
            _ => return EINVAL,
        };
        let priv_ = c.has_cap(crate::process::CAP_SETUID);
        if !check_setid_transition(c.ruid, k_ruid, c.ruid, c.euid, c.suid, priv_)
            || !check_setid_transition(c.euid, k_euid, c.ruid, c.euid, c.suid, priv_)
        {
            return EPERM;
        }
        let (or, oe, os, of) = (c.ruid, c.euid, c.suid, c.fsuid);
        let ruid_changing = k_ruid != SETID_KEEP && k_ruid != c.ruid;
        let euid_changing = k_euid != SETID_KEEP && k_euid != c.euid;
        if k_ruid != SETID_KEEP {
            c.ruid = k_ruid;
        }
        if k_euid != SETID_KEEP {
            c.euid = k_euid;
            c.fsuid = k_euid;
        }
        if ruid_changing || (euid_changing && k_euid != c.suid) {
            c.suid = c.euid;
        }
        c.apply_uid_change_caps(or, oe, os, of);
        0
    })
}

pub(crate) fn sys_setregid(new_rgid: u32, new_egid: u32) -> i64 {
    sched::with_current_creds_mut(|c| {
        let (k_rgid, k_egid) = match (map_setgid_in(c, new_rgid), map_setgid_in(c, new_egid)) {
            (Some(r), Some(e)) => (r, e),
            _ => return EINVAL,
        };
        let priv_ = c.has_cap(crate::process::CAP_SETGID);
        if !check_setid_transition(c.rgid, k_rgid, c.rgid, c.egid, c.sgid, priv_)
            || !check_setid_transition(c.egid, k_egid, c.rgid, c.egid, c.sgid, priv_)
        {
            return EPERM;
        }
        let rgid_changing = k_rgid != SETID_KEEP && k_rgid != c.rgid;
        let egid_changing = k_egid != SETID_KEEP && k_egid != c.egid;
        if k_rgid != SETID_KEEP {
            c.rgid = k_rgid;
        }
        if k_egid != SETID_KEEP {
            c.egid = k_egid;
            c.fsgid = k_egid;
        }
        if rgid_changing || (egid_changing && k_egid != c.sgid) {
            c.sgid = c.egid;
        }
        0
    })
}

pub(crate) fn sys_setfsuid(new_fsuid: u32) -> i64 {
    sched::with_current_creds_mut(|c| {
        let old = c.uid_from_kernel(c.fsuid);
        let k_new = match map_setuid_in(c, new_fsuid) {
            Some(k) => k,
            None => return old as i64,
        };
        let allowed = c.has_cap(crate::process::CAP_SETUID)
            || k_new == c.ruid
            || k_new == c.euid
            || k_new == c.suid
            || k_new == c.fsuid;
        if allowed && k_new != SETID_KEEP {
            c.fsuid = k_new;
        }
        old as i64
    })
}

pub(crate) fn sys_setfsgid(new_fsgid: u32) -> i64 {
    sched::with_current_creds_mut(|c| {
        let old = c.gid_from_kernel(c.fsgid);
        let k_new = match map_setgid_in(c, new_fsgid) {
            Some(k) => k,
            None => return old as i64,
        };
        let allowed = c.has_cap(crate::process::CAP_SETGID)
            || k_new == c.rgid
            || k_new == c.egid
            || k_new == c.sgid
            || k_new == c.fsgid;
        if allowed && k_new != SETID_KEEP {
            c.fsgid = k_new;
        }
        old as i64
    })
}

pub struct ExecCredTransition {
    pub post_euid: u32,
    pub post_egid: u32,
    pub secure: bool,
    pub suid_owner: Option<u32>,
    pub sgid_owner: Option<u32>,
}

#[allow(clippy::too_many_arguments)]
pub fn exec_transition(
    file_mode: u16,
    file_uid: u32,
    file_gid: u32,
    ruid: u32,
    pre_euid: u32,
    rgid: u32,
    pre_egid: u32,
    nosuid: bool,
) -> ExecCredTransition {
    let suid_owner = if !nosuid && file_mode & 0o4000 != 0 {
        Some(file_uid)
    } else {
        None
    };
    let sgid_owner = if !nosuid && file_mode & 0o2000 != 0 {
        Some(file_gid)
    } else {
        None
    };
    let post_euid = suid_owner.unwrap_or(pre_euid);
    let post_egid = sgid_owner.unwrap_or(pre_egid);
    let secure = ruid != post_euid
        || rgid != post_egid
        || matches!(suid_owner, Some(u) if u != ruid)
        || matches!(sgid_owner, Some(g) if g != rgid);
    ExecCredTransition {
        post_euid,
        post_egid,
        secure,
        suid_owner,
        sgid_owner,
    }
}

pub fn apply_exec_transition(c: &mut crate::process::Credentials, t: &ExecCredTransition) {
    if let Some(uid) = t.suid_owner {
        c.euid = uid;
        c.suid = uid;
        c.fsuid = uid;
    }
    if let Some(gid) = t.sgid_owner {
        c.egid = gid;
        c.sgid = gid;
        c.fsgid = gid;
    }
}
