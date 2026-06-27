use alloc::sync::Arc;

use super::{GLOBAL, current_pid};

fn with_current_ns_mut(f: impl FnOnce(&mut crate::process_model::NamespaceContext)) {
    let pid = current_pid();
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        f(&mut p.namespaces);
    }
}

pub fn with_current_uts<R>(f: impl FnOnce(&crate::process_model::UtsNamespace) -> R) -> R {
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

pub fn set_current_uts(ns: Option<Arc<crate::process_model::UtsNamespace>>) {
    with_current_ns_mut(|n| n.set_uts(ns));
}

pub fn set_current_ipc(ns: Option<Arc<crate::process_model::IpcNamespace>>) {
    with_current_ns_mut(|n| n.set_ipc(ns));
}

pub fn with_current_ipc<R>(f: impl FnOnce(&crate::process_model::IpcNamespace) -> R) -> R {
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

pub fn current_ipc_ns() -> Option<Arc<crate::process_model::IpcNamespace>> {
    let pid = current_pid();
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .and_then(|p| p.namespaces.ipc())
}

pub fn with_current_pid_ns<R>(f: impl FnOnce(&Arc<crate::process_model::PidNamespace>) -> R) -> R {
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

pub fn set_current_pid_ns(ns: Option<Arc<crate::process_model::PidNamespace>>) {
    with_current_ns_mut(|n| n.set_pid(ns));
}

pub fn set_current_cgroup_ns(ns: Option<Arc<crate::process_model::CgroupNamespace>>) {
    with_current_ns_mut(|n| n.set_cgroup(ns));
}

pub fn set_current_time_ns(ns: Option<Arc<crate::process_model::TimeNamespace>>) {
    with_current_ns_mut(|n| n.set_time(ns));
}

pub fn current_time_ns_offsets() -> (i64, i64) {
    let pid = current_pid();
    let ns = {
        let g = GLOBAL.lock();
        g.processes.get(&pid).and_then(|p| p.namespaces.time())
    };
    match ns {
        Some(n) => (n.monotonic_offset_ns, n.boottime_offset_ns),
        None => (0, 0),
    }
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

pub fn set_current_pending_uts_ns(ns: Option<Arc<crate::process_model::UtsNamespace>>) {
    with_current_ns_mut(|n| n.set_pending_uts(ns));
}

pub fn set_current_pending_cgroup_ns(ns: Option<Arc<crate::process_model::CgroupNamespace>>) {
    with_current_ns_mut(|n| n.set_pending_cgroup(ns));
}

pub fn set_current_pending_time_ns(ns: Option<Arc<crate::process_model::TimeNamespace>>) {
    with_current_ns_mut(|n| n.set_pending_time(ns));
}

pub fn set_current_pending_mount_table(table: Option<Arc<crate::vfs::MountTable>>) {
    with_current_ns_mut(|n| n.set_pending_mount(table));
}

pub fn clear_current_pending_ns() {
    with_current_ns_mut(|n| n.clear_pending());
}

#[derive(Default)]
pub struct StagedNamespaces {
    pub uts: Option<Arc<crate::process_model::UtsNamespace>>,
    pub ipc: Option<Arc<crate::process_model::IpcNamespace>>,
    pub net: Option<Arc<crate::net::NetNamespace>>,
    pub pending_pid: Option<Arc<crate::process_model::PidNamespace>>,
    pub cgroup: Option<Arc<crate::process_model::CgroupNamespace>>,
    pub time: Option<Arc<crate::process_model::TimeNamespace>>,
    pub mount_table: Option<Arc<crate::vfs::MountTable>>,
}

pub fn commit_current_ns_set(staged: StagedNamespaces) {
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        if let Some(uts) = staged.uts {
            p.namespaces.set_uts(Some(uts));
        }
        if let Some(ipc) = staged.ipc {
            p.namespaces.set_ipc(Some(ipc));
        }
        if let Some(net) = staged.net {
            p.namespaces.set_net(Some(net));
        }
        if let Some(pid_ns) = staged.pending_pid {
            p.namespaces.set_pending_pid(Some(pid_ns));
        }
        if let Some(cgroup) = staged.cgroup {
            p.namespaces.set_cgroup(Some(cgroup));
        }
        if let Some(time) = staged.time {
            p.namespaces.set_time(Some(time));
        }
        if let Some(mount_table) = staged.mount_table {
            p.files.set_mount_table(Some(mount_table));
        }
    }
}

pub fn ns_handle_for(
    pid: crate::process_model::Pid,
    ty: u64,
) -> Option<crate::ipc::fdtypes::NamespaceHandle> {
    use crate::ipc::fdtypes::NamespaceHandle;
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
                .unwrap_or_else(crate::process_model::CgroupNamespace::host),
        ),
        NEWTIME => NamespaceHandle::Time(
            nsc.time()
                .unwrap_or_else(crate::process_model::TimeNamespace::host),
        ),
        NEWNET => NamespaceHandle::Net(nsc.net().unwrap_or_else(crate::net::host_net_ns)),
        _ => return None,
    };
    Some(h)
}

fn host_uts() -> Arc<crate::process_model::UtsNamespace> {
    static HOST: frame::sync::SpinIrq<Option<Arc<crate::process_model::UtsNamespace>>> =
        frame::sync::SpinIrq::new(None);
    let mut g = HOST.lock();
    if g.is_none() {
        *g = Some(crate::process_model::UtsNamespace::host());
    }
    g.as_ref().unwrap().clone()
}

pub(crate) fn host_pid_ns() -> Arc<crate::process_model::PidNamespace> {
    static HOST: frame::sync::SpinIrq<Option<Arc<crate::process_model::PidNamespace>>> =
        frame::sync::SpinIrq::new(None);
    let mut g = HOST.lock();
    if g.is_none() {
        *g = Some(crate::process_model::PidNamespace::host());
    }
    g.as_ref().unwrap().clone()
}

fn host_ipc() -> Arc<crate::process_model::IpcNamespace> {
    static HOST: frame::sync::SpinIrq<Option<Arc<crate::process_model::IpcNamespace>>> =
        frame::sync::SpinIrq::new(None);
    let mut g = HOST.lock();
    if g.is_none() {
        *g = Some(crate::process_model::IpcNamespace::host());
    }
    g.as_ref().unwrap().clone()
}
