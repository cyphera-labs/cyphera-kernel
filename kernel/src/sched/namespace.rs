use alloc::sync::Arc;

use super::{GLOBAL, current_pid};

fn with_current_ns_mut(f: impl FnOnce(&mut crate::process::NamespaceContext)) {
    let pid = current_pid();
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        f(&mut p.namespaces);
    }
}

pub fn with_current_uts<R>(f: impl FnOnce(&crate::process::UtsNamespace) -> R) -> R {
    let pid = current_pid();
    let ns = {
        let g = GLOBAL.lock();
        let proc = g.processes.get(&pid).expect("with_current_uts: no current");
        proc.namespaces.uts()
    };
    match ns {
        Some(n) => f(&n),
        None => f(&host_uts()),
    }
}

pub fn set_current_uts(ns: Option<Arc<crate::process::UtsNamespace>>) {
    with_current_ns_mut(|n| n.set_uts(ns));
}

pub fn set_current_ipc(ns: Option<Arc<crate::process::IpcNamespace>>) {
    with_current_ns_mut(|n| n.set_ipc(ns));
}

pub fn with_current_ipc<R>(f: impl FnOnce(&crate::process::IpcNamespace) -> R) -> R {
    let pid = current_pid();
    let ns = {
        let g = GLOBAL.lock();
        let proc = g.processes.get(&pid).expect("with_current_ipc: no current");
        proc.namespaces.ipc()
    };
    match ns {
        Some(n) => f(&n),
        None => f(&host_ipc()),
    }
}

pub fn current_ipc_ns() -> Option<Arc<crate::process::IpcNamespace>> {
    let pid = current_pid();
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .and_then(|p| p.namespaces.ipc())
}

pub fn with_current_pid_ns<R>(f: impl FnOnce(&Arc<crate::process::PidNamespace>) -> R) -> R {
    let pid = current_pid();
    let ns = {
        let g = GLOBAL.lock();
        let proc = g
            .processes
            .get(&pid)
            .expect("with_current_pid_ns: no current");
        proc.namespaces.pid()
    };
    match ns {
        Some(n) => f(&n),
        None => f(&host_pid_ns()),
    }
}

pub fn set_current_pid_ns(ns: Option<Arc<crate::process::PidNamespace>>) {
    with_current_ns_mut(|n| n.set_pid(ns));
}

pub fn set_current_cgroup_ns(ns: Option<Arc<crate::process::CgroupNamespace>>) {
    with_current_ns_mut(|n| n.set_cgroup(ns));
}

pub fn set_current_time_ns(ns: Option<Arc<crate::process::TimeNamespace>>) {
    with_current_ns_mut(|n| n.set_time(ns));
}

pub fn current_cgroup_ns_root() -> Arc<crate::cgroup::Cgroup> {
    let pid = current_pid();
    let ns = {
        let g = GLOBAL.lock();
        g.processes.get(&pid).and_then(|p| p.namespaces.cgroup())
    };
    match ns {
        Some(n) => n.root.clone(),
        None => crate::cgroup::root(),
    }
}

pub fn current_net_ns() -> Arc<crate::net::NetNamespace> {
    let pid = current_pid();
    let ns = {
        let g = GLOBAL.lock();
        g.processes.get(&pid).and_then(|p| p.namespaces.net())
    };
    ns.unwrap_or_else(crate::net::host_net_ns)
}

pub fn set_current_net(ns: Option<Arc<crate::net::NetNamespace>>) {
    with_current_ns_mut(|n| n.set_net(ns));
}

pub fn set_current_pending_net_ns(ns: Option<Arc<crate::net::NetNamespace>>) {
    with_current_ns_mut(|n| n.set_pending_net(ns));
}

pub fn ns_handle_for(pid: crate::process::Pid, ty: u64) -> Option<crate::fdtypes::NamespaceHandle> {
    use crate::fdtypes::NamespaceHandle;
    const NEWUTS: u64 = 0x0400_0000;
    const NEWIPC: u64 = 0x0800_0000;
    const NEWPID: u64 = 0x2000_0000;
    const NEWCGROUP: u64 = 0x0200_0000;
    const NEWTIME: u64 = 0x0000_0080;
    const NEWNET: u64 = 0x4000_0000;
    let g = GLOBAL.lock();
    let nsc = &g.processes.get(&pid)?.namespaces;
    let h = match ty {
        NEWUTS => NamespaceHandle::Uts(nsc.uts().unwrap_or_else(host_uts)),
        NEWIPC => NamespaceHandle::Ipc(nsc.ipc().unwrap_or_else(host_ipc)),
        NEWPID => NamespaceHandle::Pid(nsc.pid().unwrap_or_else(host_pid_ns)),
        NEWCGROUP => NamespaceHandle::Cgroup(
            nsc.cgroup()
                .unwrap_or_else(crate::process::CgroupNamespace::host),
        ),
        NEWTIME => NamespaceHandle::Time(
            nsc.time()
                .unwrap_or_else(crate::process::TimeNamespace::host),
        ),
        NEWNET => NamespaceHandle::Net(nsc.net().unwrap_or_else(crate::net::host_net_ns)),
        _ => return None,
    };
    Some(h)
}

fn host_uts() -> Arc<crate::process::UtsNamespace> {
    static HOST: frame::sync::SpinIrq<Option<Arc<crate::process::UtsNamespace>>> =
        frame::sync::SpinIrq::new(None);
    let mut g = HOST.lock();
    if g.is_none() {
        *g = Some(crate::process::UtsNamespace::host());
    }
    g.as_ref().unwrap().clone()
}

pub(crate) fn host_pid_ns() -> Arc<crate::process::PidNamespace> {
    static HOST: frame::sync::SpinIrq<Option<Arc<crate::process::PidNamespace>>> =
        frame::sync::SpinIrq::new(None);
    let mut g = HOST.lock();
    if g.is_none() {
        *g = Some(crate::process::PidNamespace::host());
    }
    g.as_ref().unwrap().clone()
}

fn host_ipc() -> Arc<crate::process::IpcNamespace> {
    static HOST: frame::sync::SpinIrq<Option<Arc<crate::process::IpcNamespace>>> =
        frame::sync::SpinIrq::new(None);
    let mut g = HOST.lock();
    if g.is_none() {
        *g = Some(crate::process::IpcNamespace::host());
    }
    g.as_ref().unwrap().clone()
}
