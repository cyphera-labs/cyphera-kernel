pub mod setid;

use crate::sched;

pub fn capable(cap: u32) -> bool {
    sched::with_current_creds(|c| c.capable_host(cap))
}

pub fn has_cap(cap: u32) -> bool {
    sched::with_current_creds(|c| c.has_cap(cap))
}

pub fn target_capable(pid: crate::process::Pid, cap: u32) -> bool {
    sched::with_target_creds(pid, |c| c.capable_host(cap)).unwrap_or(false)
}

pub fn capset(new_eff: u64, new_perm: u64, new_inh: u64) -> Result<(), i64> {
    sched::with_current_creds_mut(|c| {
        if (new_perm & !c.caps_perm) != 0 {
            return Err(crate::errno::EPERM);
        }
        if (new_eff & !new_perm) != 0 {
            return Err(crate::errno::EPERM);
        }
        if (new_inh & !(c.caps_inh | c.caps_perm)) != 0 {
            return Err(crate::errno::EPERM);
        }
        if (new_inh & !(c.caps_bnd | c.caps_inh)) != 0 {
            return Err(crate::errno::EPERM);
        }
        let mask = crate::process::ALL_CAPS_MASK;
        c.caps_eff = new_eff & mask;
        c.caps_perm = new_perm & mask;
        c.caps_inh = new_inh & mask;
        Ok(())
    })
}

pub fn capbset_read(cap: u32) -> bool {
    sched::with_current_creds(|c| c.caps_bnd & (1u64 << cap) != 0)
}

pub fn capbset_drop(cap: u32) {
    sched::with_current_creds_mut(|c| c.caps_bnd &= !(1u64 << cap));
}
