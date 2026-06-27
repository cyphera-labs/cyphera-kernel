extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use cyphera_kapi::{Errno, KResult};
use frame::sync::SpinIrq;

use crate::process_model::Pid;

#[derive(Debug, Default)]
pub struct MemoryController {
    pub current: u64,
    pub peak: u64,
    pub max: Option<u64>,
    pub low: u64,
    pub high: Option<u64>,
    pub events_oom: u64,
    pub events_oom_kill: u64,
}

#[derive(Debug, Default)]
pub struct PidsController {
    pub current: u64,
    pub max: Option<u64>,
}

#[derive(Debug)]
pub struct CpuController {
    pub usage_usec: u64,
    pub user_usec: u64,
    pub system_usec: u64,
    pub max: Option<(u64, u64)>,
    pub weight: u64,
    pub period_start_ns: u64,
    pub period_runtime_ns: u64,
    pub throttled: bool,
}

impl Default for CpuController {
    fn default() -> Self {
        Self {
            usage_usec: 0,
            user_usec: 0,
            system_usec: 0,
            max: None,
            weight: 100,
            period_start_ns: 0,
            period_runtime_ns: 0,
            throttled: false,
        }
    }
}

impl CpuController {
    pub fn charge_cpu_runtime(&mut self, delta_ns: u64, now_ns: u64) -> bool {
        let (quota_us, period_us) = match self.max {
            Some(p) => p,
            None => return false,
        };
        let period_ns = period_us.saturating_mul(1000);
        let quota_ns = quota_us.saturating_mul(1000);
        if period_ns == 0 {
            return false;
        }
        if now_ns.saturating_sub(self.period_start_ns) >= period_ns {
            self.period_start_ns = now_ns;
            self.period_runtime_ns = 0;
        }
        self.period_runtime_ns = self.period_runtime_ns.saturating_add(delta_ns);
        if self.period_runtime_ns >= quota_ns && !self.throttled {
            self.throttled = true;
            return true;
        }
        false
    }

    pub fn period_elapsed(&self, now_ns: u64) -> bool {
        let (_, period_us) = match self.max {
            Some(p) => p,
            None => return false,
        };
        let period_ns = period_us.saturating_mul(1000);
        if period_ns == 0 {
            return false;
        }
        now_ns.saturating_sub(self.period_start_ns) >= period_ns
    }

    pub fn replenish(&mut self, now_ns: u64) {
        self.period_start_ns = now_ns;
        self.period_runtime_ns = 0;
        self.throttled = false;
    }
}

#[derive(Debug)]
pub struct IoController {
    pub rbytes: u64,
    pub wbytes: u64,
    pub rios: u64,
    pub wios: u64,
    pub max_rbps: Option<u64>,
    pub max_wbps: Option<u64>,
    pub max_riops: Option<u64>,
    pub max_wiops: Option<u64>,
    pub weight: u64,
    pub window_start_ns: u64,
    pub window_rbytes: u64,
    pub window_wbytes: u64,
    pub window_rios: u64,
    pub window_wios: u64,
}

impl Default for IoController {
    fn default() -> Self {
        Self {
            rbytes: 0,
            wbytes: 0,
            rios: 0,
            wios: 0,
            max_rbps: None,
            max_wbps: None,
            max_riops: None,
            max_wiops: None,
            weight: 100,
            window_start_ns: 0,
            window_rbytes: 0,
            window_wbytes: 0,
            window_rios: 0,
            window_wios: 0,
        }
    }
}

impl IoController {
    pub const WINDOW_NS: u64 = 1_000_000_000;

    pub fn maybe_reset_window(&mut self, now_ns: u64) {
        if now_ns.saturating_sub(self.window_start_ns) >= Self::WINDOW_NS {
            self.window_start_ns = now_ns;
            self.window_rbytes = 0;
            self.window_wbytes = 0;
            self.window_rios = 0;
            self.window_wios = 0;
        }
    }

    pub fn charge_read(&mut self, bytes: u64, now_ns: u64) -> Result<(), u64> {
        self.maybe_reset_window(now_ns);
        if let Some(max) = self.max_rbps {
            if self.window_rbytes.saturating_add(bytes) > max {
                let retry = self.window_start_ns + Self::WINDOW_NS;
                return Err(retry.saturating_sub(now_ns));
            }
        }
        if let Some(max) = self.max_riops {
            if self.window_rios.saturating_add(1) > max {
                let retry = self.window_start_ns + Self::WINDOW_NS;
                return Err(retry.saturating_sub(now_ns));
            }
        }
        self.window_rbytes = self.window_rbytes.saturating_add(bytes);
        self.window_rios = self.window_rios.saturating_add(1);
        self.rbytes = self.rbytes.saturating_add(bytes);
        self.rios = self.rios.saturating_add(1);
        Ok(())
    }

    pub fn charge_write(&mut self, bytes: u64, now_ns: u64) -> Result<(), u64> {
        self.maybe_reset_window(now_ns);
        if let Some(max) = self.max_wbps {
            if self.window_wbytes.saturating_add(bytes) > max {
                let retry = self.window_start_ns + Self::WINDOW_NS;
                return Err(retry.saturating_sub(now_ns));
            }
        }
        if let Some(max) = self.max_wiops {
            if self.window_wios.saturating_add(1) > max {
                let retry = self.window_start_ns + Self::WINDOW_NS;
                return Err(retry.saturating_sub(now_ns));
            }
        }
        self.window_wbytes = self.window_wbytes.saturating_add(bytes);
        self.window_wios = self.window_wios.saturating_add(1);
        self.wbytes = self.wbytes.saturating_add(bytes);
        self.wios = self.wios.saturating_add(1);
        Ok(())
    }
}

pub const CTRL_CPU: u8 = 1 << 0;
pub const CTRL_IO: u8 = 1 << 1;
pub const CTRL_MEMORY: u8 = 1 << 2;
pub const CTRL_PIDS: u8 = 1 << 3;
pub const CTRL_ALL: u8 = CTRL_CPU | CTRL_IO | CTRL_MEMORY | CTRL_PIDS;

pub fn controller_bit(name: &str) -> Option<u8> {
    match name {
        "cpu" => Some(CTRL_CPU),
        "io" => Some(CTRL_IO),
        "memory" => Some(CTRL_MEMORY),
        "pids" => Some(CTRL_PIDS),
        _ => None,
    }
}

pub fn controllers_string(mask: u8) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if mask & CTRL_CPU != 0 {
        parts.push("cpu");
    }
    if mask & CTRL_IO != 0 {
        parts.push("io");
    }
    if mask & CTRL_MEMORY != 0 {
        parts.push("memory");
    }
    if mask & CTRL_PIDS != 0 {
        parts.push("pids");
    }
    parts.join(" ")
}

pub struct Cgroup {
    pub name: String,
    pub parent: Option<Weak<Cgroup>>,
    pub children: SpinIrq<BTreeMap<String, Arc<Cgroup>>>,
    pub pids: SpinIrq<BTreeSet<Pid>>,
    pub memory: SpinIrq<MemoryController>,
    pub pids_ctl: SpinIrq<PidsController>,
    pub cpu: SpinIrq<CpuController>,
    pub io: SpinIrq<IoController>,
    pub subtree_control: SpinIrq<u8>,
}

impl Cgroup {
    pub fn root() -> Arc<Self> {
        Arc::new(Self {
            name: String::new(),
            parent: None,
            children: SpinIrq::new(BTreeMap::new()),
            pids: SpinIrq::new(BTreeSet::new()),
            memory: SpinIrq::new(MemoryController::default()),
            pids_ctl: SpinIrq::new(PidsController::default()),
            cpu: SpinIrq::new(CpuController::default()),
            io: SpinIrq::new(IoController::default()),
            subtree_control: SpinIrq::new(0),
        })
    }

    fn new_child(parent: &Arc<Self>, name: String) -> Arc<Self> {
        Arc::new(Self {
            name,
            parent: Some(Arc::downgrade(parent)),
            children: SpinIrq::new(BTreeMap::new()),
            pids: SpinIrq::new(BTreeSet::new()),
            memory: SpinIrq::new(MemoryController::default()),
            pids_ctl: SpinIrq::new(PidsController::default()),
            cpu: SpinIrq::new(CpuController::default()),
            io: SpinIrq::new(IoController::default()),
            subtree_control: SpinIrq::new(0),
        })
    }

    pub fn available_controllers(self: &Arc<Self>) -> u8 {
        match self.parent.as_ref().and_then(|w| w.upgrade()) {
            Some(p) => *p.subtree_control.lock(),
            None => CTRL_ALL,
        }
    }

    pub fn has_member_processes(self: &Arc<Self>) -> bool {
        !self.pids.lock().is_empty()
    }

    pub fn has_children(self: &Arc<Self>) -> bool {
        !self.children.lock().is_empty()
    }

    pub fn set_subtree_control(self: &Arc<Self>, text: &str) -> KResult<()> {
        let available = self.available_controllers();
        let mut add: u8 = 0;
        let mut remove: u8 = 0;
        for tok in text.split_ascii_whitespace() {
            let (sign, name) = match tok.split_at(1) {
                ("+", n) => (true, n),
                ("-", n) => (false, n),
                _ => return Err(Errno::INVAL),
            };
            let bit = controller_bit(name).ok_or(Errno::INVAL)?;
            if sign {
                add |= bit;
            } else {
                remove |= bit;
            }
        }
        if add & remove != 0 {
            return Err(Errno::INVAL);
        }
        if add & !available != 0 {
            return Err(Errno::INVAL);
        }
        if add != 0 && self.has_member_processes() {
            return Err(Errno::BUSY);
        }
        let mut cur = self.subtree_control.lock();
        *cur = (*cur | add) & !remove;
        Ok(())
    }

    pub fn create_child(parent: &Arc<Self>, name: &str) -> KResult<Arc<Self>> {
        if name.is_empty() || name.contains('/') {
            return Err(Errno::INVAL);
        }
        let mut children = parent.children.lock();
        if children.contains_key(name) {
            return Err(Errno::EXIST);
        }
        let child = Cgroup::new_child(parent, name.to_string());
        children.insert(name.to_string(), child.clone());
        Ok(child)
    }

    pub fn remove_child(parent: &Arc<Self>, name: &str) -> KResult<()> {
        let mut children = parent.children.lock();
        let child = children.get(name).ok_or(Errno::NOENT)?;
        if !child.pids.lock().is_empty() {
            return Err(Errno::BUSY);
        }
        if !child.children.lock().is_empty() {
            return Err(Errno::BUSY);
        }
        children.remove(name);
        Ok(())
    }

    pub fn attach_pid(self: &Arc<Self>, pid: Pid) -> KResult<()> {
        {
            let mut pc = self.pids_ctl.lock();
            if let Some(max) = pc.max {
                if pc.current + 1 > max {
                    return Err(Errno::AGAIN);
                }
            }
            pc.current += 1;
        }
        self.pids.lock().insert(pid);
        Ok(())
    }

    pub fn detach_pid(self: &Arc<Self>, pid: Pid) {
        let was_present = self.pids.lock().remove(&pid);
        if was_present {
            let mut pc = self.pids_ctl.lock();
            pc.current = pc.current.saturating_sub(1);
        }
    }

    pub fn try_charge_memory(self: &Arc<Self>, bytes: u64) -> KResult<()> {
        let chain = self.ancestor_chain();
        let mut charged: Vec<Arc<Cgroup>> = Vec::new();
        for cg in &chain {
            let mut m = cg.memory.lock();
            let new = m.current.saturating_add(bytes);
            if let Some(max) = m.max {
                if new > max {
                    drop(m);
                    for done in &charged {
                        let mut dm = done.memory.lock();
                        dm.current = dm.current.saturating_sub(bytes);
                    }
                    cg.memory.lock().events_oom += 1;
                    return Err(Errno::NOMEM);
                }
            }
            m.current = new;
            if m.current > m.peak {
                m.peak = m.current;
            }
            charged.push(cg.clone());
        }
        Ok(())
    }

    pub fn uncharge_memory(self: &Arc<Self>, bytes: u64) {
        for cg in self.ancestor_chain() {
            let mut m = cg.memory.lock();
            m.current = m.current.saturating_sub(bytes);
        }
    }

    pub fn charge_tick(self: &Arc<Self>, usec: u64, kernel_mode: bool) {
        for cg in self.ancestor_chain() {
            let mut c = cg.cpu.lock();
            c.usage_usec += usec;
            if kernel_mode {
                c.system_usec += usec;
            } else {
                c.user_usec += usec;
            }
        }
    }

    pub fn oom_kill_one(self: &Arc<Self>) {
        let candidates: Vec<Pid> = self.pids.lock().iter().copied().collect();
        if candidates.is_empty() {
            return;
        }
        let victim = candidates
            .iter()
            .copied()
            .max_by_key(|&p| crate::core::process_charged_bytes(p))
            .unwrap_or(candidates[0]);
        self.memory.lock().events_oom_kill += 1;
        let _ = crate::core::send_signal(victim, 9);
    }

    fn ancestor_chain(self: &Arc<Self>) -> Vec<Arc<Cgroup>> {
        let mut out = Vec::new();
        let mut cur: Option<Arc<Cgroup>> = Some(self.clone());
        while let Some(c) = cur {
            cur = c.parent.as_ref().and_then(|w| w.upgrade());
            out.push(c);
        }
        out
    }

    pub fn path(self: &Arc<Self>) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut cur: Option<Arc<Cgroup>> = Some(self.clone());
        while let Some(c) = cur {
            if c.parent.is_some() {
                parts.push(c.name.clone());
            }
            cur = c.parent.as_ref().and_then(|w| w.upgrade());
        }
        if parts.is_empty() {
            return String::from("/");
        }
        parts.reverse();
        let mut s = String::new();
        for p in parts {
            s.push('/');
            s.push_str(&p);
        }
        s
    }
}

static ROOT_CGROUP: SpinIrq<Option<Arc<Cgroup>>> = SpinIrq::new(None);

pub fn init() {
    let mut g = ROOT_CGROUP.lock();
    if g.is_none() {
        *g = Some(Cgroup::root());
    }
}

pub fn root() -> Arc<Cgroup> {
    ROOT_CGROUP
        .lock()
        .clone()
        .expect("cgroup root not initialized")
}

pub fn resolve(path: &str) -> Option<Arc<Cgroup>> {
    let mut cur = root();
    for part in path.split('/').filter(|s| !s.is_empty()) {
        let next = cur.children.lock().get(part).cloned()?;
        cur = next;
    }
    Some(cur)
}
