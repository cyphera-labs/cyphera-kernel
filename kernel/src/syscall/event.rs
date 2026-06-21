use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::errno::{EBADF, EFAULT, EINTR, EINVAL};
use crate::sched;
use crate::vfs::{self, Inode, OpenFile, OpenFlags};

static EPOLL_INDEX: frame::sync::SpinIrq<BTreeMap<usize, Arc<crate::net::epoll::EpollInstance>>> =
    frame::sync::SpinIrq::new(BTreeMap::new());

static SIGNALFD_INDEX: frame::sync::SpinIrq<BTreeMap<usize, Arc<crate::fdtypes::SignalFdInode>>> =
    frame::sync::SpinIrq::new(BTreeMap::new());

static TIMERFD_FD_INDEX: frame::sync::SpinIrq<BTreeMap<usize, Arc<crate::fdtypes::TimerFdInode>>> =
    frame::sync::SpinIrq::new(BTreeMap::new());

fn lookup_epoll(fd: i32) -> Option<Arc<crate::net::epoll::EpollInstance>> {
    let file = sched::with_current_fds(|t| t.get(fd))?;
    let key = Arc::as_ptr(&file.inode) as *const () as usize;
    EPOLL_INDEX.lock().get(&key).cloned()
}

fn lookup_timerfd(fd: i32) -> Option<Arc<crate::fdtypes::TimerFdInode>> {
    let file = sched::with_current_fds(|t| t.get(fd))?;
    let key = Arc::as_ptr(&file.inode) as *const () as usize;
    TIMERFD_FD_INDEX.lock().get(&key).cloned()
}

pub(super) const FD_SETSIZE: usize = 1024;

pub(super) fn sys_poll(fds: u64, nfds: u64, timeout_ms: u64) -> i64 {
    if nfds as usize > FD_SETSIZE {
        return EINVAL;
    }
    let total = (nfds as usize).saturating_mul(8);
    let mut buf = alloc::vec![0u8; total];
    if total > 0 && frame::user::copy_from_user(fds, &mut buf).is_err() {
        return EFAULT;
    }

    let timeout = timeout_ms as i32;
    let deadline = if timeout > 0 {
        Some(
            frame::cpu::clock::nanos_since_boot()
                .saturating_add((timeout as u64).saturating_mul(1_000_000)),
        )
    } else {
        None
    };

    let r = poll_wait(&mut buf, nfds as usize, deadline, timeout == 0);
    if r >= 0 && total > 0 {
        let _ = frame::user::copy_to_user(fds, &buf[..total]);
    }
    r
}

fn poll_wait(buf: &mut [u8], nfds: usize, deadline: Option<u64>, immediate: bool) -> i64 {
    let pid = sched::current_pid();
    if let Some(d) = deadline {
        crate::timeout::register(d, pid);
    }

    let mut files: alloc::vec::Vec<Option<alloc::sync::Arc<crate::vfs::OpenFile>>> =
        alloc::vec::Vec::with_capacity(nfds);
    for i in 0..nfds {
        let off = i * 8;
        let fd = i32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        files.push(sched::with_current_fds(|t| t.get(fd)));
    }

    loop {
        for file in files.iter().flatten() {
            file.inode
                .clone()
                .for_each_wait_queue(&mut |wq| wq.enqueue(pid));
        }

        let mut ready = 0i64;
        for (i, file_opt) in files.iter().enumerate() {
            let off = i * 8;
            let events = u16::from_le_bytes(buf[off + 4..off + 6].try_into().unwrap());
            let revents = match file_opt {
                Some(file) => {
                    let r = file.inode.clone().poll().bits() as u16;
                    r & (events | 0x0008 | 0x0010 | 0x0020)
                }
                None => 0x0020,
            };
            buf[off + 6..off + 8].copy_from_slice(&revents.to_le_bytes());
            if revents != 0 {
                ready += 1;
            }
        }

        let should_return = ready > 0 || immediate;
        if should_return {
            for file in files.iter().flatten() {
                file.inode
                    .clone()
                    .for_each_wait_queue(&mut |wq| wq.dequeue(pid));
            }
            if deadline.is_some() {
                let _ = crate::timeout::unregister(pid);
            }
            return ready;
        }

        let still_queued = || {
            if let Some(d) = deadline {
                if frame::cpu::clock::nanos_since_boot() >= d {
                    return false;
                }
            }
            for file in files.iter().flatten() {
                let mut missing = false;
                file.inode.clone().for_each_wait_queue(&mut |wq| {
                    if !wq.contains(pid) {
                        missing = true;
                    }
                });
                if missing {
                    return false;
                }
            }
            true
        };
        let outcome = crate::wait::wait_guarded("poll/select", deadline, &still_queued);

        for file in files.iter().flatten() {
            file.inode
                .clone()
                .for_each_wait_queue(&mut |wq| wq.dequeue(pid));
        }

        match outcome {
            crate::wait::WaitOutcome::Interrupted => {
                if deadline.is_some() {
                    let _ = crate::timeout::unregister(pid);
                }
                return EINTR;
            }
            crate::wait::WaitOutcome::TimedOut => {
                if deadline.is_some() {
                    let _ = crate::timeout::unregister(pid);
                }
                return 0;
            }
            crate::wait::WaitOutcome::Woken => {}
        }
    }
}

const POLLIN: u16 = 0x1;
const POLLPRI: u16 = 0x2;
const POLLOUT: u16 = 0x4;
const POLLERR: u16 = 0x8;
const POLLHUP: u16 = 0x10;
const POLLNVAL: u16 = 0x20;

fn timeout_deadline(ptr: u64, is_timeval: bool) -> Result<(Option<u64>, bool), i64> {
    if ptr == 0 {
        return Ok((None, false));
    }
    let mut b = [0u8; 16];
    if frame::user::copy_from_user(ptr, &mut b).is_err() {
        return Err(EFAULT);
    }
    let sec = i64::from_le_bytes(b[0..8].try_into().unwrap());
    let frac = i64::from_le_bytes(b[8..16].try_into().unwrap());
    let frac_max: i64 = if is_timeval { 1_000_000 } else { 1_000_000_000 };
    if sec < 0 || frac < 0 || frac >= frac_max {
        return Err(EINVAL);
    }
    let ns = (sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(if is_timeval {
            (frac as u64).saturating_mul(1000)
        } else {
            frac as u64
        });
    if ns == 0 {
        Ok((None, true))
    } else {
        Ok((
            Some(frame::cpu::clock::nanos_since_boot().saturating_add(ns)),
            false,
        ))
    }
}

fn do_select(
    nfds: i64,
    rptr: u64,
    wptr: u64,
    eptr: u64,
    deadline: Option<u64>,
    immediate: bool,
) -> i64 {
    if nfds < 0 || nfds as usize > FD_SETSIZE {
        return EINVAL;
    }
    let n = nfds as usize;
    let setbytes = n.div_ceil(8);
    let (mut rin, mut win, mut ein) = (
        [0u8; FD_SETSIZE / 8],
        [0u8; FD_SETSIZE / 8],
        [0u8; FD_SETSIZE / 8],
    );
    if rptr != 0 && frame::user::copy_from_user(rptr, &mut rin[..setbytes]).is_err() {
        return EFAULT;
    }
    if wptr != 0 && frame::user::copy_from_user(wptr, &mut win[..setbytes]).is_err() {
        return EFAULT;
    }
    if eptr != 0 && frame::user::copy_from_user(eptr, &mut ein[..setbytes]).is_err() {
        return EFAULT;
    }
    let isset = |set: &[u8; FD_SETSIZE / 8], fd: usize| (set[fd / 8] >> (fd % 8)) & 1 != 0;

    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut fdmap: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
    for fd in 0..n {
        let mut events = 0u16;
        if rptr != 0 && isset(&rin, fd) {
            events |= POLLIN;
        }
        if wptr != 0 && isset(&win, fd) {
            events |= POLLOUT;
        }
        if eptr != 0 && isset(&ein, fd) {
            events |= POLLPRI;
        }
        if events == 0 {
            continue;
        }
        buf.extend_from_slice(&(fd as i32).to_le_bytes());
        buf.extend_from_slice(&events.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        fdmap.push(fd);
    }
    let count = fdmap.len();

    let r = poll_wait(&mut buf, count, deadline, immediate);
    if r < 0 {
        return r;
    }

    let (mut rout, mut wout, mut eout) = (
        [0u8; FD_SETSIZE / 8],
        [0u8; FD_SETSIZE / 8],
        [0u8; FD_SETSIZE / 8],
    );
    let mut nset = 0i64;
    for (i, &fd) in fdmap.iter().enumerate() {
        let off = i * 8;
        let revents = u16::from_le_bytes(buf[off + 6..off + 8].try_into().unwrap());
        if revents & POLLNVAL != 0 {
            return EBADF;
        }
        if rptr != 0 && revents & (POLLIN | POLLHUP | POLLERR) != 0 {
            rout[fd / 8] |= 1 << (fd % 8);
            nset += 1;
        }
        if wptr != 0 && revents & (POLLOUT | POLLERR) != 0 {
            wout[fd / 8] |= 1 << (fd % 8);
            nset += 1;
        }
        if eptr != 0 && revents & POLLPRI != 0 {
            eout[fd / 8] |= 1 << (fd % 8);
            nset += 1;
        }
    }
    if rptr != 0 && frame::user::copy_to_user(rptr, &rout[..setbytes]).is_err() {
        return EFAULT;
    }
    if wptr != 0 && frame::user::copy_to_user(wptr, &wout[..setbytes]).is_err() {
        return EFAULT;
    }
    if eptr != 0 && frame::user::copy_to_user(eptr, &eout[..setbytes]).is_err() {
        return EFAULT;
    }
    nset
}

fn run_with_sigmask<F: FnOnce() -> i64>(mask: Option<u64>, f: F) -> i64 {
    let saved = mask.map(|m| {
        let prev = sched::with_signal(sched::current_pid(), |s| s.blocked()).unwrap_or(0);
        sched::with_signal_mut(sched::current_pid(), |s| s.set_blocked(m));
        prev
    });
    let r = f();
    if let Some(prev) = saved {
        sched::with_signal_mut(sched::current_pid(), |s| s.set_blocked(prev));
    }
    r
}

fn read_sigmask(ptr: u64, sigsetsize: u64) -> Result<Option<u64>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    if sigsetsize != 8 {
        return Err(EINVAL);
    }
    let mut b = [0u8; 8];
    if frame::user::copy_from_user(ptr, &mut b).is_err() {
        return Err(EFAULT);
    }
    Ok(Some(u64::from_le_bytes(b)))
}

fn read_pselect_sigmask(arg: u64) -> Result<Option<u64>, i64> {
    if arg == 0 {
        return Ok(None);
    }
    let mut s = [0u8; 16];
    if frame::user::copy_from_user(arg, &mut s).is_err() {
        return Err(EFAULT);
    }
    let ss = u64::from_le_bytes(s[0..8].try_into().unwrap());
    let ss_len = u64::from_le_bytes(s[8..16].try_into().unwrap());
    read_sigmask(ss, ss_len)
}

pub(super) fn sys_select(nfds: u64, readfds: u64, writefds: u64, exceptfds: u64, tv: u64) -> i64 {
    let (deadline, immediate) = match timeout_deadline(tv, true) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let r = do_select(
        nfds as i64,
        readfds,
        writefds,
        exceptfds,
        deadline,
        immediate,
    );
    if tv != 0 && r >= 0 {
        let remaining = deadline
            .map(|d| d.saturating_sub(frame::cpu::clock::nanos_since_boot()))
            .unwrap_or(0);
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&((remaining / 1_000_000_000) as i64).to_le_bytes());
        b[8..16].copy_from_slice(&(((remaining % 1_000_000_000) / 1000) as i64).to_le_bytes());
        let _ = frame::user::copy_to_user(tv, &b);
    }
    r
}

pub(super) fn sys_pselect6(
    nfds: u64,
    readfds: u64,
    writefds: u64,
    exceptfds: u64,
    ts: u64,
    sig: u64,
) -> i64 {
    let (deadline, immediate) = match timeout_deadline(ts, false) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let mask = match read_pselect_sigmask(sig) {
        Ok(m) => m,
        Err(e) => return e,
    };
    run_with_sigmask(mask, || {
        do_select(
            nfds as i64,
            readfds,
            writefds,
            exceptfds,
            deadline,
            immediate,
        )
    })
}

pub(super) fn sys_ppoll(fds: u64, nfds: u64, ts: u64, sigmask: u64, sigsetsize: u64) -> i64 {
    if nfds as usize > FD_SETSIZE {
        return EINVAL;
    }
    let total = (nfds as usize).saturating_mul(8);
    let mut buf = alloc::vec![0u8; total];
    if total > 0 && frame::user::copy_from_user(fds, &mut buf).is_err() {
        return EFAULT;
    }
    let (deadline, immediate) = match timeout_deadline(ts, false) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let mask = match read_sigmask(sigmask, sigsetsize) {
        Ok(m) => m,
        Err(e) => return e,
    };
    let rc = run_with_sigmask(mask, || {
        poll_wait(&mut buf, nfds as usize, deadline, immediate)
    });
    if rc >= 0 && total > 0 {
        let _ = frame::user::copy_to_user(fds, &buf);
    }
    rc
}

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;

pub(super) fn sys_epoll_create1(flags: u64) -> i64 {
    let cloexec = if (flags & 0o2_000_000) != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    let ep = crate::net::epoll::EpollInstance::new();
    let dyn_inode: Arc<dyn Inode> = ep.clone();
    let file = Arc::new(OpenFile::new(dyn_inode, OpenFlags::RDWR));
    EPOLL_INDEX
        .lock()
        .insert(Arc::as_ptr(&file.inode) as *const () as usize, ep);
    match sched::with_current_fds(|t| t.install_from(file, 0, cloexec)) {
        Ok(fd) => fd as i64,
        Err(e) => e as i64,
    }
}

pub(super) fn sys_epoll_ctl(epfd: u64, op: u64, fd: u64, event_ptr: u64) -> i64 {
    let inst = match lookup_epoll(epfd as i32) {
        Some(e) => e,
        None => return EBADF,
    };
    if op == EPOLL_CTL_DEL {
        return match inst.ctl_del(fd as i32) {
            Ok(()) => 0,
            Err(e) => e.errno(),
        };
    }
    let mut ev = [0u8; 12];
    if frame::user::copy_from_user(event_ptr, &mut ev).is_err() {
        return EFAULT;
    }
    let events = u32::from_le_bytes([ev[0], ev[1], ev[2], ev[3]]);
    let user_data = u64::from_le_bytes([ev[4], ev[5], ev[6], ev[7], ev[8], ev[9], ev[10], ev[11]]);
    let res = match op {
        EPOLL_CTL_ADD => inst.ctl_add(fd as i32, events, user_data),
        EPOLL_CTL_MOD => inst.ctl_mod(fd as i32, events, user_data),
        _ => return EINVAL,
    };
    match res {
        Ok(()) => 0,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_epoll_wait(epfd: u64, events_ptr: u64, maxevents: u64, timeout: u64) -> i64 {
    epoll_wait_common(epfd, events_ptr, maxevents, timeout as i32, None)
}

pub(super) fn sys_epoll_pwait(
    epfd: u64,
    events_ptr: u64,
    maxevents: u64,
    timeout_ms: u64,
    sigmask_ptr: u64,
    sigsetsize: u64,
) -> i64 {
    if sigsetsize != 8 && sigmask_ptr != 0 {
        return EINVAL;
    }
    let mask = if sigmask_ptr != 0 {
        let mut buf = [0u8; 8];
        if frame::user::copy_from_user(sigmask_ptr, &mut buf).is_err() {
            return EFAULT;
        }
        Some(u64::from_le_bytes(buf))
    } else {
        None
    };
    epoll_wait_common(epfd, events_ptr, maxevents, timeout_ms as i32, mask)
}

pub(super) fn sys_epoll_pwait2(
    epfd: u64,
    events_ptr: u64,
    maxevents: u64,
    timespec_ptr: u64,
    sigmask_ptr: u64,
    sigsetsize: u64,
) -> i64 {
    let timeout_ms: i32 = if timespec_ptr == 0 {
        -1
    } else {
        let mut tbuf = [0u8; 16];
        if frame::user::copy_from_user(timespec_ptr, &mut tbuf).is_err() {
            return EFAULT;
        }
        let secs = u64::from_le_bytes(tbuf[0..8].try_into().unwrap());
        let nsec = u64::from_le_bytes(tbuf[8..16].try_into().unwrap());
        let total_ns = secs.saturating_mul(1_000_000_000).saturating_add(nsec);
        let ms = total_ns.div_ceil(1_000_000);
        ms.min(i32::MAX as u64) as i32
    };
    if sigsetsize != 8 && sigmask_ptr != 0 {
        return EINVAL;
    }
    let mask = if sigmask_ptr != 0 {
        let mut buf = [0u8; 8];
        if frame::user::copy_from_user(sigmask_ptr, &mut buf).is_err() {
            return EFAULT;
        }
        Some(u64::from_le_bytes(buf))
    } else {
        None
    };
    epoll_wait_common(epfd, events_ptr, maxevents, timeout_ms, mask)
}

fn epoll_wait_common(
    epfd: u64,
    events_ptr: u64,
    maxevents: u64,
    timeout_ms: i32,
    sigmask_override: Option<u64>,
) -> i64 {
    let inst = match lookup_epoll(epfd as i32) {
        Some(e) => e,
        None => return EBADF,
    };
    let max = (maxevents as usize).min(64);

    let saved_mask = if let Some(new_mask) = sigmask_override {
        let prev = sched::with_signal(sched::current_pid(), |s| s.blocked()).unwrap_or(0);
        sched::with_signal_mut(sched::current_pid(), |s| {
            s.set_blocked(new_mask);
        });
        Some(prev)
    } else {
        None
    };

    let result = inst.wait(
        &|fd| sched::with_current_fds(|t| t.get(fd)),
        max,
        timeout_ms,
    );

    if let Some(prev) = saved_mask {
        sched::with_signal_mut(sched::current_pid(), |s| {
            s.set_blocked(prev);
        });
    }

    let ready = match result {
        Ok(r) => r,
        Err(e) => return e,
    };

    let mut out = [0u8; 64 * 12];
    for (i, (events, data)) in ready.iter().enumerate() {
        let off = i * 12;
        out[off..off + 4].copy_from_slice(&events.to_le_bytes());
        out[off + 4..off + 12].copy_from_slice(&data.to_le_bytes());
    }
    let bytes = ready.len() * 12;
    if bytes > 0 && frame::user::copy_to_user(events_ptr, &out[..bytes]).is_err() {
        return EFAULT;
    }
    ready.len() as i64
}

const SFD_NONBLOCK: u64 = 0o4000;
const SFD_CLOEXEC: u64 = 0o2_000_000;

pub(super) fn sys_signalfd4(fd: u64, mask_ptr: u64, sigsetsize: u64, flags: u64) -> i64 {
    if sigsetsize != 8 {
        return EINVAL;
    }
    if (flags & !(SFD_NONBLOCK | SFD_CLOEXEC)) != 0 {
        return EINVAL;
    }
    let mut mask_buf = [0u8; 8];
    if frame::user::copy_from_user(mask_ptr, &mut mask_buf).is_err() {
        return EFAULT;
    }
    let mask = u64::from_le_bytes(mask_buf) & !((1u64 << 9) | (1u64 << 19));

    let fd_signed = fd as i32;
    if fd_signed != -1 {
        let file = match sched::with_current_fds(|t| t.get(fd_signed)) {
            Some(f) => f,
            None => return EBADF,
        };
        let key = Arc::as_ptr(&file.inode) as *const () as usize;
        let sfd = match SIGNALFD_INDEX.lock().get(&key).cloned() {
            Some(s) => s,
            None => return EINVAL,
        };
        sfd.set_mask(mask);
        return fd_signed as i64;
    }

    let typed = crate::fdtypes::SignalFdInode::new(mask);
    let inode_dyn: Arc<dyn Inode> = typed.clone();
    let mut open_flags = OpenFlags::RDONLY;
    if (flags & SFD_NONBLOCK) != 0 {
        open_flags |= OpenFlags::NONBLOCK;
    }
    let file = Arc::new(OpenFile::new(inode_dyn, open_flags));
    let key = Arc::as_ptr(&file.inode) as *const () as usize;
    SIGNALFD_INDEX.lock().insert(key, typed);
    let fd_flags = if (flags & SFD_CLOEXEC) != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    match sched::with_current_fds(|t| t.install_from(file, 0, fd_flags)) {
        Ok(new_fd) => new_fd as i64,
        Err(e) => e as i64,
    }
}

pub(super) fn sys_eventfd2(initval: u64, flags: u64) -> i64 {
    const EFD_SEMAPHORE: u64 = 1;
    const EFD_CLOEXEC: u64 = 0o2_000_000;
    const EFD_NONBLOCK: u64 = 0o4000;

    if (flags & !(EFD_SEMAPHORE | EFD_CLOEXEC | EFD_NONBLOCK)) != 0 {
        return EINVAL;
    }
    let semaphore = (flags & EFD_SEMAPHORE) != 0;
    let typed = crate::fdtypes::EventFdInode::new(initval, semaphore);
    let inode_dyn: Arc<dyn Inode> = typed;
    let mut open_flags = OpenFlags::RDWR;
    if (flags & EFD_NONBLOCK) != 0 {
        open_flags |= OpenFlags::NONBLOCK;
    }
    let file = Arc::new(OpenFile::new(inode_dyn, open_flags));
    let fd_flags = if (flags & EFD_CLOEXEC) != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    match sched::with_current_fds(|t| t.install_from(file, 0, fd_flags)) {
        Ok(fd) => fd as i64,
        Err(e) => e as i64,
    }
}

const TFD_NONBLOCK: u64 = 0o4000;
const TFD_CLOEXEC: u64 = 0o2_000_000;
const TFD_TIMER_ABSTIME: u64 = 1;

pub(super) fn sys_timerfd_create(clockid: u64, flags: u64) -> i64 {
    if (flags & !(TFD_NONBLOCK | TFD_CLOEXEC)) != 0 {
        return EINVAL;
    }
    if clockid > 7 {
        return EINVAL;
    }
    let typed = crate::fdtypes::TimerFdInode::new(clockid as u32);
    let inode_dyn: Arc<dyn Inode> = typed.clone();
    let mut open_flags = OpenFlags::RDONLY;
    if (flags & TFD_NONBLOCK) != 0 {
        open_flags |= OpenFlags::NONBLOCK;
    }
    let file = Arc::new(OpenFile::new(inode_dyn, open_flags));
    let key = Arc::as_ptr(&file.inode) as *const () as usize;
    TIMERFD_FD_INDEX.lock().insert(key, typed);
    let fd_flags = if (flags & TFD_CLOEXEC) != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    match sched::with_current_fds(|t| t.install_from(file, 0, fd_flags)) {
        Ok(fd) => fd as i64,
        Err(e) => e as i64,
    }
}

fn read_itimerspec(addr: u64) -> Result<(u64, u64), i64> {
    let mut buf = [0u8; 32];
    if frame::user::copy_from_user(addr, &mut buf).is_err() {
        return Err(EFAULT);
    }
    let intv_sec = i64::from_le_bytes(buf[0..8].try_into().unwrap()).max(0) as u64;
    let intv_nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap()).max(0) as u64;
    let val_sec = i64::from_le_bytes(buf[16..24].try_into().unwrap()).max(0) as u64;
    let val_nsec = i64::from_le_bytes(buf[24..32].try_into().unwrap()).max(0) as u64;
    let interval = intv_sec
        .saturating_mul(1_000_000_000)
        .saturating_add(intv_nsec);
    let value = val_sec
        .saturating_mul(1_000_000_000)
        .saturating_add(val_nsec);
    Ok((interval, value))
}

fn write_itimerspec(addr: u64, interval_ns: u64, remaining_ns: u64) -> i64 {
    let mut buf = [0u8; 32];
    buf[0..8].copy_from_slice(&((interval_ns / 1_000_000_000) as i64).to_le_bytes());
    buf[8..16].copy_from_slice(&((interval_ns % 1_000_000_000) as i64).to_le_bytes());
    buf[16..24].copy_from_slice(&((remaining_ns / 1_000_000_000) as i64).to_le_bytes());
    buf[24..32].copy_from_slice(&((remaining_ns % 1_000_000_000) as i64).to_le_bytes());
    if frame::user::copy_to_user(addr, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_timerfd_settime(fd: u64, flags: u64, new_value: u64, old_value: u64) -> i64 {
    let timerfd = match lookup_timerfd(fd as i32) {
        Some(t) => t,
        None => return EBADF,
    };
    let (interval_ns, value_ns) = match read_itimerspec(new_value) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if old_value != 0 {
        let s = timerfd.snapshot();
        let now = frame::cpu::clock::nanos_since_boot();
        let remaining = s.deadline.saturating_sub(now);
        let r = write_itimerspec(old_value, s.interval_ns, remaining);
        if r != 0 {
            return r;
        }
    }
    let now = frame::cpu::clock::nanos_since_boot();
    let is_realtime = matches!(
        timerfd.clock_id as u64,
        super::time::CLOCK_REALTIME | super::time::CLOCK_REALTIME_COARSE
    );
    let deadline = if value_ns == 0 {
        0
    } else if (flags & TFD_TIMER_ABSTIME) != 0 {
        if is_realtime {
            let wall = frame::cpu::wall_clock_nanos();
            let wall_now = if wall != 0 { wall } else { now };
            now.saturating_add(value_ns.saturating_sub(wall_now))
        } else {
            value_ns
        }
    } else {
        now.saturating_add(value_ns)
    };
    timerfd.arm(deadline, interval_ns);
    0
}

pub(super) fn sys_timerfd_gettime(fd: u64, curr_value: u64) -> i64 {
    let timerfd = match lookup_timerfd(fd as i32) {
        Some(t) => t,
        None => return EBADF,
    };
    let s = timerfd.snapshot();
    let now = frame::cpu::clock::nanos_since_boot();
    let remaining = s.deadline.saturating_sub(now);
    write_itimerspec(curr_value, s.interval_ns, remaining)
}
