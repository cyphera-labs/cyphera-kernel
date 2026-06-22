use alloc::string::String;

use super::*;

pub struct UtsNamespace {
    pub hostname: frame::sync::SpinIrq<alloc::string::String>,
    pub domainname: frame::sync::SpinIrq<alloc::string::String>,
}

impl UtsNamespace {
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            hostname: frame::sync::SpinIrq::new(String::from("cyphera")),
            domainname: frame::sync::SpinIrq::new(String::from("(none)")),
        })
    }
    pub fn snapshot(&self) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            hostname: frame::sync::SpinIrq::new(self.hostname.lock().clone()),
            domainname: frame::sync::SpinIrq::new(self.domainname.lock().clone()),
        })
    }
}

pub struct IpcNamespace {
    pub shm_table: frame::sync::SpinIrq<
        alloc::collections::BTreeMap<i32, alloc::sync::Arc<crate::ipc::shm::ShmSegment>>,
    >,
    pub key_to_id: frame::sync::SpinIrq<alloc::collections::BTreeMap<i32, i32>>,
    pub shm_next_id: core::sync::atomic::AtomicI32,
}
impl IpcNamespace {
    fn empty() -> Self {
        Self {
            shm_table: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            key_to_id: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            shm_next_id: core::sync::atomic::AtomicI32::new(1),
        }
    }
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self::empty())
    }
    pub fn fresh() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self::empty())
    }
}

pub struct PidNamespace {
    pub level: u32,
    pub parent: Option<alloc::sync::Arc<PidNamespace>>,
    pub local_to_host: frame::sync::SpinIrq<alloc::collections::BTreeMap<u32, Pid>>,
    pub host_to_local: frame::sync::SpinIrq<alloc::collections::BTreeMap<Pid, u32>>,
    pub next_local: core::sync::atomic::AtomicU32,
}
impl PidNamespace {
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            level: 0,
            parent: None,
            local_to_host: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            host_to_local: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            next_local: core::sync::atomic::AtomicU32::new(1),
        })
    }
    pub fn child(parent: alloc::sync::Arc<Self>) -> alloc::sync::Arc<Self> {
        let level = parent.level.saturating_add(1);
        alloc::sync::Arc::new(Self {
            level,
            parent: Some(parent),
            local_to_host: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            host_to_local: frame::sync::SpinIrq::new(alloc::collections::BTreeMap::new()),
            next_local: core::sync::atomic::AtomicU32::new(1),
        })
    }
    pub fn assign(&self, host_pid: Pid) -> u32 {
        if let Some(&existing) = self.host_to_local.lock().get(&host_pid) {
            return existing;
        }
        let local = self
            .next_local
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.local_to_host.lock().insert(local, host_pid);
        self.host_to_local.lock().insert(host_pid, local);
        local
    }
    pub fn assign_chain(self_arc: &alloc::sync::Arc<Self>, host_pid: Pid) {
        let mut cur: Option<alloc::sync::Arc<PidNamespace>> = Some(self_arc.clone());
        while let Some(ns) = cur {
            ns.assign(host_pid);
            cur = ns.parent.clone();
        }
    }
    pub fn drop_chain(self_arc: &alloc::sync::Arc<Self>, host_pid: Pid) {
        let mut cur: Option<alloc::sync::Arc<PidNamespace>> = Some(self_arc.clone());
        while let Some(ns) = cur {
            let local = ns.host_to_local.lock().remove(&host_pid);
            if let Some(l) = local {
                ns.local_to_host.lock().remove(&l);
            }
            cur = ns.parent.clone();
        }
    }
    pub fn host_to_local_in(&self, host_pid: Pid) -> u32 {
        self.host_to_local
            .lock()
            .get(&host_pid)
            .copied()
            .unwrap_or(0)
    }
    pub fn local_to_host_in(&self, local: u32) -> Option<Pid> {
        self.local_to_host.lock().get(&local).copied()
    }
}

pub struct CgroupNamespace {
    pub root: alloc::sync::Arc<crate::cgroup::Cgroup>,
}
impl CgroupNamespace {
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            root: crate::cgroup::root(),
        })
    }
    pub fn new(root: alloc::sync::Arc<crate::cgroup::Cgroup>) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self { root })
    }
}

pub struct TimeNamespace {
    pub monotonic_offset_ns: i64,
    pub boottime_offset_ns: i64,
}
impl TimeNamespace {
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            monotonic_offset_ns: 0,
            boottime_offset_ns: 0,
        })
    }
    pub fn fresh() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            monotonic_offset_ns: 0,
            boottime_offset_ns: 0,
        })
    }
}
