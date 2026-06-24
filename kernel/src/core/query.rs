use super::*;

pub fn cpu_to_nudge(p: &Process) -> u32 {
    match p.sched_owner.0 {
        SchedOwner::Running { cpu } | SchedOwner::Runnable { cpu } => cpu,
        _ => p.sched.home_cpu,
    }
}

pub fn with_target_vmspace(
    target: Pid,
) -> Option<Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>> {
    let g = GLOBAL.lock();
    g.processes.get(&target).and_then(|p| p.vmspace())
}

pub fn find_stale_scheduled(pid: Pid) -> Option<(&'static str, usize)> {
    for (cpu, q_lock) in CPU_QUEUES.iter().enumerate() {
        let q = q_lock.lock();
        if q.current == Some(pid) {
            return Some(("current", cpu));
        }
        if q.runnable.contains_pid(pid) {
            return Some(("runqueue", cpu));
        }
    }
    None
}

pub fn inode_has_shared_writable_mapping(inode_id: u64) -> bool {
    use crate::process_model::{VmaBacking, VmaFlags};
    let spaces: alloc::vec::Vec<_> = {
        let g = GLOBAL.lock();
        g.processes
            .values()
            .filter_map(|p| p.addr_space.clone())
            .collect()
    };
    for addr_space in spaces {
        let mmap = addr_space.mmap.lock();
        for v in &mmap.vmas {
            if v.flags.contains(VmaFlags::SHARED) && v.prot.contains(frame::mm::vm::Perms::WRITE) {
                if let VmaBacking::File { inode, .. } = &v.backing {
                    if inode.inode_id() == inode_id {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub fn sched_class_of_pid(pid: Pid) -> Option<crate::process_model::SchedClass> {
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.sched.sched_class)
}

pub fn pi_blocked_on(pid: Pid) -> Option<cyphera_kapi::WaitKey> {
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .and_then(|p| p.pi_blocked_on)
}

pub fn pi_held_keys(pid: Pid) -> alloc::vec::Vec<cyphera_kapi::WaitKey> {
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.pi_held.clone())
        .unwrap_or_default()
}

pub fn set_pi_blocked_on(pid: Pid, key: cyphera_kapi::WaitKey) {
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        p.pi_blocked_on = Some(key);
    }
}

pub fn clear_pi_blocked_on(pid: Pid) {
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        p.pi_blocked_on = None;
    }
}

pub fn add_pi_held(pid: Pid, key: cyphera_kapi::WaitKey) {
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        if !p.pi_held.contains(&key) {
            p.pi_held.push(key);
        }
    }
}

pub fn remove_pi_held(pid: Pid, key: cyphera_kapi::WaitKey) {
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        p.pi_held.retain(|k| *k != key);
    }
}

pub fn pi_acquired(pid: Pid, key: cyphera_kapi::WaitKey) {
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        p.pi_blocked_on = None;
        if !p.pi_held.contains(&key) {
            p.pi_held.push(key);
        }
    }
}

pub fn process_pid_ns(pid: Pid) -> Option<Arc<crate::process_model::PidNamespace>> {
    let g = GLOBAL.lock();
    g.processes.get(&pid).and_then(|p| p.namespaces.pid())
}

pub fn set_current_pending_pid_ns(ns: Option<Arc<crate::process_model::PidNamespace>>) {
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.namespaces.set_pending_pid(ns);
    }
}

pub fn set_current_pending_ipc_ns(ns: Option<Arc<crate::process_model::IpcNamespace>>) {
    let pid = current_pid();
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.namespaces.set_pending_ipc(ns);
    }
}

pub fn current_local_pid() -> u32 {
    let host = current_pid();
    let ns = match process_pid_ns(host) {
        Some(n) => n,
        None => return host.0,
    };
    ns.host_to_local_in(host)
}

pub fn host_to_caller_local(host: Pid) -> u32 {
    let cur = current_pid();
    let ns = match process_pid_ns(cur) {
        Some(n) => n,
        None => return host.0,
    };
    ns.host_to_local_in(host)
}

pub fn caller_local_to_host(local: u32) -> Option<Pid> {
    let cur = current_pid();
    let ns = match process_pid_ns(cur) {
        Some(n) => n,
        None => return Some(Pid(local)),
    };
    ns.local_to_host_in(local)
}

pub fn caller_visible_pids() -> Vec<(Pid, u32)> {
    let cur = current_pid();
    match process_pid_ns(cur) {
        None => all_pids().into_iter().map(|p| (p, p.0)).collect(),
        Some(ns) => ns
            .host_to_local
            .lock()
            .iter()
            .map(|(host, local)| (*host, *local))
            .collect(),
    }
}

pub fn caller_host_to_local(host: Pid) -> u32 {
    let cur = current_pid();
    match process_pid_ns(cur) {
        Some(ns) => ns.host_to_local_in(host),
        None => host.0,
    }
}

pub fn process_umask(pid: Pid) -> u16 {
    let g = GLOBAL.lock();
    g.processes.get(&pid).map(|p| p.files.umask()).unwrap_or(0)
}

pub fn process_charged_bytes(pid: Pid) -> u64 {
    let g = GLOBAL.lock();
    g.processes
        .get(&pid)
        .map(|p| p.cgroup_charged_bytes)
        .unwrap_or(0)
}

pub fn process_count_alive() -> u64 {
    let g = GLOBAL.lock();
    g.processes
        .values()
        .filter(|p| !matches!(p.state.0, ProcessState::Zombie(_)))
        .count() as u64
}

pub fn current_cgroup() -> Option<Arc<crate::cgroup::Cgroup>> {
    let cpu = this_cpu() as usize;
    let pid = CPU_QUEUES[cpu].lock().current?;
    process_cgroup(pid)
}

pub fn process_cgroup(pid: Pid) -> Option<Arc<crate::cgroup::Cgroup>> {
    let g = GLOBAL.lock();
    g.processes.get(&pid).and_then(|p| p.cgroup.clone())
}

pub fn cpu_affinity(pid: Pid) -> Option<u64> {
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.sched.cpu_affinity)
}

pub fn process_euid(pid: Pid) -> Option<u32> {
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.creds.lock().euid)
}

pub fn set_cpu_affinity(pid: Pid, mask: u64) -> bool {
    let owner = {
        let mut g = GLOBAL.lock();
        let p = match g.processes.get_mut(&pid) {
            Some(p) => p,
            None => return false,
        };
        p.sched.cpu_affinity = mask;
        cpu_to_nudge(p)
    };
    send_resched_ipi_pub(owner);
    true
}

pub fn set_process_cgroup(pid: Pid, cg: Arc<crate::cgroup::Cgroup>) {
    let mut g = GLOBAL.lock();
    if let Some(p) = g.processes.get_mut(&pid) {
        p.cgroup = Some(cg);
    }
}

pub fn process_state(pid: Pid) -> Option<crate::process_model::ProcessState> {
    let g = GLOBAL.lock();
    g.processes.get(&pid).map(|p| p.state.0.clone())
}
