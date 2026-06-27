use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use frame::sync::SpinIrq;

use super::GLOBAL;
use crate::process_model::{Pid, ProcessState, SIGCONT, SIGHUP, SIGINT, SIGTSTP, SIGTTIN, SIGTTOU};

const SIGQUIT: u32 = 3;

pub(crate) const DEFAULT_TERMIOS: [u8; 36] = {
    let mut t = [0u8; 36];
    t[0] = 0x00;
    t[1] = 0x05;
    t[2] = 0x00;
    t[3] = 0x00;
    t[4] = 0x05;
    t[5] = 0x00;
    t[6] = 0x00;
    t[7] = 0x00;
    t[8] = 0xbd;
    t[9] = 0x0b;
    t[10] = 0x00;
    t[11] = 0x00;
    t[12] = 0x8b;
    t[13] = 0x00;
    t[14] = 0x00;
    t[15] = 0x00;
    t
};

pub(crate) const DEFAULT_WINSIZE: [u8; 8] = [24, 0, 80, 0, 0, 0, 0, 0];

pub const CONSOLE_INODE_ID: u64 = 0xC0_05_01;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TtyId {
    Console,
    Pty(u32),
}

pub fn tty_id_for_inode(inode_id: u64) -> TtyId {
    const MASTER_BIT: u64 = 1u64 << 62;
    const SLAVE_BIT: u64 = 1u64 << 63;
    if inode_id & (MASTER_BIT | SLAVE_BIT) != 0 {
        TtyId::Pty((inode_id & !(0b11u64 << 62)) as u32)
    } else {
        TtyId::Console
    }
}

struct Ctty {
    session: Pid,
    foreground_pgrp: Pid,
    termios: [u8; 36],
    winsize: [u8; 8],
}

impl Ctty {
    fn new() -> Self {
        Self {
            session: Pid(0),
            foreground_pgrp: Pid(0),
            termios: DEFAULT_TERMIOS,
            winsize: DEFAULT_WINSIZE,
        }
    }
}

static CTTYS: SpinIrq<BTreeMap<TtyId, Ctty>> = SpinIrq::new(BTreeMap::new());

fn with_ctty<R>(tty: TtyId, f: impl FnOnce(&mut Ctty) -> R) -> R {
    let mut g = CTTYS.lock();
    f(g.entry(tty).or_insert_with(Ctty::new))
}

pub fn termios_get(inode_id: u64) -> [u8; 36] {
    let tty = tty_id_for_inode(inode_id);
    let g = CTTYS.lock();
    g.get(&tty).map(|c| c.termios).unwrap_or(DEFAULT_TERMIOS)
}

pub fn termios_set(inode_id: u64, t: [u8; 36]) {
    with_ctty(tty_id_for_inode(inode_id), |c| c.termios = t);
}

pub fn winsize_get(inode_id: u64) -> [u8; 8] {
    let tty = tty_id_for_inode(inode_id);
    let g = CTTYS.lock();
    g.get(&tty).map(|c| c.winsize).unwrap_or(DEFAULT_WINSIZE)
}

pub fn winsize_set(inode_id: u64, w: [u8; 8]) {
    with_ctty(tty_id_for_inode(inode_id), |c| c.winsize = w);
}

pub fn release(tty: TtyId) {
    CTTYS.lock().remove(&tty);
}

pub fn foreground_pgrp(tty: TtyId) -> Pid {
    let g = CTTYS.lock();
    g.get(&tty).map(|c| c.foreground_pgrp).unwrap_or(Pid(0))
}

pub fn session(tty: TtyId) -> Pid {
    let g = CTTYS.lock();
    g.get(&tty).map(|c| c.session).unwrap_or(Pid(0))
}

pub fn maybe_acquire_on_open(tty: TtyId, noctty: bool) {
    if noctty {
        return;
    }
    let pid = match crate::core::current_pid_opt() {
        Some(p) => p,
        None => return,
    };
    let (sid, pgid, has_ctty) = {
        let g = GLOBAL.lock();
        match g.processes.get(&pid) {
            Some(p) => (p.identity.sid(), p.identity.pgid(), p.identity.ctty()),
            None => return,
        }
    };
    if sid != pid || has_ctty.is_some() {
        return;
    }
    if session(tty).0 != 0 {
        return;
    }
    let _ = acquire(tty, sid, pgid);
}

pub fn acquire(tty: TtyId, sid: Pid, leader_pgid: Pid) -> Result<(), i64> {
    let mut g = CTTYS.lock();
    let c = g.entry(tty).or_insert_with(Ctty::new);
    if c.session.0 != 0 && c.session != sid {
        return Err(crate::errno::EPERM);
    }
    c.session = sid;
    if c.foreground_pgrp.0 == 0 {
        c.foreground_pgrp = leader_pgid;
    }
    drop(g);
    set_session_ctty(sid, Some(tty));
    Ok(())
}

pub fn set_foreground(tty: TtyId, sid: Pid, pgrp: Pid) -> Result<(), i64> {
    let mut g = CTTYS.lock();
    let c = g.entry(tty).or_insert_with(Ctty::new);
    if c.session.0 != 0 && c.session != sid {
        return Err(crate::errno::EPERM);
    }
    if c.session.0 == 0 {
        c.session = sid;
    }
    c.foreground_pgrp = pgrp;
    Ok(())
}

pub fn drop_session(tty: TtyId) {
    let sid = {
        let mut g = CTTYS.lock();
        match g.get_mut(&tty) {
            Some(c) => {
                let s = c.session;
                c.session = Pid(0);
                c.foreground_pgrp = Pid(0);
                s
            }
            None => Pid(0),
        }
    };
    if sid.0 != 0 {
        clear_session_ctty(sid);
    }
}

fn set_session_ctty(sid: Pid, tty: Option<TtyId>) {
    let mut g = GLOBAL.lock();
    for (pid, p) in g.processes.iter_mut() {
        if p.identity.sid() == sid && p.tgid == *pid {
            p.identity.set_ctty(tty);
        }
    }
}

fn clear_session_ctty(sid: Pid) {
    set_session_ctty(sid, None);
}

pub fn ctty_for(pid: Pid) -> Option<TtyId> {
    let g = GLOBAL.lock();
    g.processes.get(&pid).and_then(|p| p.identity.ctty())
}

fn session_pgrps(sid: Pid) -> Vec<Pid> {
    let g = GLOBAL.lock();
    let mut pgrps: Vec<Pid> = Vec::new();
    for (tgid, p) in g.processes.iter() {
        if p.identity.sid() == sid && p.tgid == *tgid {
            let pg = p.identity.pgid();
            if !pgrps.contains(&pg) {
                pgrps.push(pg);
            }
        }
    }
    pgrps
}

pub fn hangup(tty: TtyId) {
    let (sid, fg) = {
        let g = CTTYS.lock();
        match g.get(&tty) {
            Some(c) => (c.session, c.foreground_pgrp),
            None => return,
        }
    };
    if fg.0 != 0 {
        let info = crate::core::signal::SigInfo::for_kill(SIGHUP, 0);
        let _ = crate::core::send_group_signal(fg, SIGHUP, info);
        let info = crate::core::signal::SigInfo::for_kill(SIGCONT, 0);
        let _ = crate::core::send_group_signal(fg, SIGCONT, info);
    }
    if sid.0 != 0 {
        for pg in session_pgrps(sid) {
            if pg == fg {
                continue;
            }
            let info = crate::core::signal::SigInfo::for_kill(SIGHUP, 0);
            let _ = crate::core::send_group_signal(pg, SIGHUP, info);
            let info = crate::core::signal::SigInfo::for_kill(SIGCONT, 0);
            let _ = crate::core::send_group_signal(pg, SIGCONT, info);
        }
    }
    drop_session(tty);
}

pub fn session_leader_exit(leader: Pid) {
    let (sid, has_ctty) = {
        let g = GLOBAL.lock();
        match g.processes.get(&leader) {
            Some(p) => (p.identity.sid(), p.identity.ctty()),
            None => return,
        }
    };
    if sid != leader {
        return;
    }
    if let Some(tty) = has_ctty {
        if session(tty) == sid {
            hangup(tty);
        }
    }
}

fn pgrp_is_orphaned(sid: Pid, pgrp: Pid, dying: Pid) -> bool {
    let g = GLOBAL.lock();
    for p in g.processes.values() {
        if p.identity.pgid() != pgrp || p.identity.sid() != sid {
            continue;
        }
        if matches!(
            p.state.0,
            ProcessState::Zombie(_)
                | ProcessState::KilledByFault { .. }
                | ProcessState::KilledBySignal { .. }
        ) {
            continue;
        }
        let parent = match p.parent {
            Some(pp) => pp,
            None => continue,
        };
        if parent == dying {
            continue;
        }
        if let Some(pp) = g.processes.get(&parent) {
            if pp.identity.sid() == sid && pp.identity.pgid() != pgrp {
                return false;
            }
        }
    }
    true
}

fn pgrp_has_stopped(pgrp: Pid) -> bool {
    let g = GLOBAL.lock();
    g.processes
        .values()
        .any(|p| p.identity.pgid() == pgrp && p.state.0 == ProcessState::Stopped)
}

pub fn handle_orphaned_pgrps_on_exit(dying: Pid) {
    let (dying_pgrp, dying_sid, children_pgrps) = {
        let g = GLOBAL.lock();
        let p = match g.processes.get(&dying) {
            Some(p) => p,
            None => return,
        };
        let dpg = p.identity.pgid();
        let dsid = p.identity.sid();
        let mut cpgs: Vec<Pid> = Vec::new();
        for child in p.children.iter() {
            if let Some(c) = g.processes.get(child) {
                let cpg = c.identity.pgid();
                if cpg != dpg && c.identity.sid() == dsid && !cpgs.contains(&cpg) {
                    cpgs.push(cpg);
                }
            }
        }
        (dpg, dsid, cpgs)
    };
    let mut candidates = children_pgrps;
    if !candidates.contains(&dying_pgrp) {
        candidates.push(dying_pgrp);
    }
    for pg in candidates {
        if !pgrp_has_stopped(pg) {
            continue;
        }
        if pgrp_is_orphaned(dying_sid, pg, dying) {
            let info = crate::core::signal::SigInfo::for_kill(SIGHUP, 0);
            let _ = crate::core::send_group_signal(pg, SIGHUP, info);
            let info = crate::core::signal::SigInfo::for_kill(SIGCONT, 0);
            let _ = crate::core::send_group_signal(pg, SIGCONT, info);
        }
    }
}

fn signal_is_passive(pid: Pid, signal: u32) -> bool {
    let g = GLOBAL.lock();
    let p = match g.processes.get(&pid) {
        Some(p) => p,
        None => return true,
    };
    let blocked = p.signals.blocked() & (1u64 << signal) != 0;
    let ignored = p.sigactions.lock()[signal as usize].handler == 1;
    blocked || ignored
}

pub enum BgIo {
    Allow,
    Stop,
    Eio,
}

fn bg_pgrp_action(tty: TtyId, signal: u32) -> BgIo {
    let pid = match crate::core::current_pid_opt() {
        Some(p) => p,
        None => return BgIo::Allow,
    };
    let (caller_pgrp, caller_sid) = {
        let g = GLOBAL.lock();
        match g.processes.get(&pid) {
            Some(p) => (p.identity.pgid(), p.identity.sid()),
            None => return BgIo::Allow,
        }
    };
    let fg = foreground_pgrp(tty);
    let owner = session(tty);
    if owner.0 == 0 || owner != caller_sid {
        return BgIo::Allow;
    }
    if fg.0 == 0 || fg == caller_pgrp {
        return BgIo::Allow;
    }
    if signal_is_passive(pid, signal) {
        return if signal == SIGTTIN {
            BgIo::Eio
        } else {
            BgIo::Allow
        };
    }
    if pgrp_is_orphaned(caller_sid, caller_pgrp, Pid(0)) {
        return BgIo::Eio;
    }
    BgIo::Stop
}

pub fn background_read_guard(inode_id: u64) -> Result<(), cyphera_kapi::Errno> {
    bg_io_guard(inode_id, SIGTTIN)
}

pub fn background_write_guard(inode_id: u64) -> Result<(), cyphera_kapi::Errno> {
    bg_io_guard(inode_id, SIGTTOU)
}

fn bg_io_guard(inode_id: u64, signal: u32) -> Result<(), cyphera_kapi::Errno> {
    let tty = tty_id_for_inode(inode_id);
    match bg_pgrp_action(tty, signal) {
        BgIo::Allow => Ok(()),
        BgIo::Eio => Err(cyphera_kapi::Errno::IO),
        BgIo::Stop => {
            let pgrp = crate::core::current_pgid();
            let info = crate::core::signal::SigInfo::for_kill(signal, 0);
            let _ = crate::core::send_group_signal(pgrp, signal, info);
            Err(cyphera_kapi::Errno::INTR)
        }
    }
}

pub fn deliver_input_signal(tty: TtyId, byte_signal: u32) {
    let fg = foreground_pgrp(tty);
    let signal = match byte_signal {
        0 => SIGINT,
        1 => SIGQUIT,
        2 => SIGTSTP,
        _ => return,
    };
    if fg.0 != 0 {
        let info = crate::core::signal::SigInfo::for_fault(signal, 0);
        let _ = crate::core::send_group_signal(fg, signal, info);
    }
}
