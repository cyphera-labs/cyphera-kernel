extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
#[allow(unused_imports)]
use alloc::vec::Vec;

use crate::cgroup::{Cgroup, CgroupError};
use crate::vfs::{DirEntry, FsError, Inode, InodeKind, Stat};

#[derive(Copy, Clone)]
enum ControlFile {
    CgroupControllers,
    CgroupEvents,
    CgroupProcs,
    CgroupSubtreeControl,
    CgroupThreads,
    CgroupType,
    CpuMax,
    CpuStat,
    CpuWeight,
    IoMax,
    IoStat,
    IoWeight,
    MemoryCurrent,
    MemoryEvents,
    MemoryHigh,
    MemoryLow,
    MemoryMax,
    MemoryPeak,
    MemoryStat,
    PidsCurrent,
    PidsMax,
}

const ALL_CONTROL_FILES: &[(&str, ControlFile)] = &[
    ("cgroup.controllers", ControlFile::CgroupControllers),
    ("cgroup.events", ControlFile::CgroupEvents),
    ("cgroup.procs", ControlFile::CgroupProcs),
    ("cgroup.subtree_control", ControlFile::CgroupSubtreeControl),
    ("cgroup.threads", ControlFile::CgroupThreads),
    ("cgroup.type", ControlFile::CgroupType),
    ("cpu.max", ControlFile::CpuMax),
    ("cpu.stat", ControlFile::CpuStat),
    ("cpu.weight", ControlFile::CpuWeight),
    ("io.max", ControlFile::IoMax),
    ("io.stat", ControlFile::IoStat),
    ("io.weight", ControlFile::IoWeight),
    ("memory.current", ControlFile::MemoryCurrent),
    ("memory.events", ControlFile::MemoryEvents),
    ("memory.high", ControlFile::MemoryHigh),
    ("memory.low", ControlFile::MemoryLow),
    ("memory.max", ControlFile::MemoryMax),
    ("memory.peak", ControlFile::MemoryPeak),
    ("memory.stat", ControlFile::MemoryStat),
    ("pids.current", ControlFile::PidsCurrent),
    ("pids.max", ControlFile::PidsMax),
];

fn lookup_control(name: &str) -> Option<ControlFile> {
    ALL_CONTROL_FILES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, f)| *f)
}

pub struct CgroupDir {
    cg: Arc<Cgroup>,
}

impl CgroupDir {
    pub fn new(cg: Arc<Cgroup>) -> Arc<Self> {
        Arc::new(Self { cg })
    }
}

impl Inode for CgroupDir {
    fn kind(&self) -> InodeKind {
        InodeKind::Directory
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Directory, 0, 0o755)
    }
    fn inode_id(&self) -> u64 {
        Arc::as_ptr(&self.cg) as *const () as u64
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        if let Some(child) = self.cg.children.lock().get(name).cloned() {
            return Ok(CgroupDir::new(child));
        }
        if let Some(cf) = lookup_control(name) {
            return Ok(Arc::new(CgroupFile {
                cg: self.cg.clone(),
                file: cf,
            }));
        }
        Err(FsError::NotFound)
    }

    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        let mut out: Vec<DirEntry> = Vec::new();
        for name in self.cg.children.lock().keys() {
            out.push(DirEntry {
                name: name.clone(),
                kind: InodeKind::Directory,
                inode_id: 0,
            });
        }
        for (name, _) in ALL_CONTROL_FILES.iter() {
            out.push(DirEntry {
                name: name.to_string(),
                kind: InodeKind::Regular,
                inode_id: 0,
            });
        }
        Ok(out)
    }

    fn create(&self, name: &str, kind: InodeKind) -> Result<Arc<dyn Inode>, FsError> {
        if kind != InodeKind::Directory {
            return Err(FsError::PermissionDenied);
        }
        let child = Cgroup::create_child(&self.cg, name).map_err(map_err)?;
        Ok(CgroupDir::new(child))
    }

    fn unlink(&self, name: &str) -> Result<(), FsError> {
        if lookup_control(name).is_some() {
            return Err(FsError::PermissionDenied);
        }
        Cgroup::remove_child(&self.cg, name).map_err(map_err)
    }

    fn rmdir(&self, name: &str) -> Result<(), FsError> {
        Cgroup::remove_child(&self.cg, name).map_err(map_err)
    }
}

fn map_err(e: CgroupError) -> FsError {
    match e {
        CgroupError::InvalidName => FsError::InvalidArgument,
        CgroupError::Exists => FsError::Exists,
        CgroupError::NotFound => FsError::NotFound,
        CgroupError::Busy => FsError::NotEmpty,
        CgroupError::PidsLimit => FsError::WouldBlock,
        CgroupError::MemoryLimit => FsError::NoSpace,
    }
}

pub struct CgroupFile {
    cg: Arc<Cgroup>,
    file: ControlFile,
}

impl Inode for CgroupFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o644)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let body = self.render();
        let bytes = body.as_bytes();
        if offset as usize >= bytes.len() {
            return Ok(0);
        }
        let start = offset as usize;
        let n = (bytes.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&bytes[start..start + n]);
        Ok(n)
    }

    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        let s = core::str::from_utf8(buf).map_err(|_| FsError::InvalidArgument)?;
        self.handle_write(s.trim())?;
        Ok(buf.len())
    }

    fn truncate(&self, _len: u64) -> Result<(), FsError> {
        Ok(())
    }
}

impl CgroupFile {
    fn render(&self) -> String {
        match self.file {
            ControlFile::CgroupControllers => String::from("cpu io memory pids\n"),
            ControlFile::CgroupEvents => {
                let pop = !self.cg.pids.lock().is_empty();
                format!("populated {}\nfrozen 0\n", if pop { 1 } else { 0 })
            }
            ControlFile::CgroupProcs => {
                let pids = self.cg.pids.lock();
                let mut out = String::new();
                for p in pids.iter() {
                    let local = crate::sched::host_to_caller_local(*p);
                    if local != 0 {
                        out.push_str(&format!("{}\n", local));
                    }
                }
                out
            }
            ControlFile::CgroupSubtreeControl => String::from("cpu io memory pids\n"),
            ControlFile::CgroupThreads => {
                let pids = self.cg.pids.lock();
                let mut out = String::new();
                for p in pids.iter() {
                    let local = crate::sched::host_to_caller_local(*p);
                    if local != 0 {
                        out.push_str(&format!("{}\n", local));
                    }
                }
                out
            }
            ControlFile::CgroupType => String::from("domain\n"),
            ControlFile::CpuMax => {
                let c = self.cg.cpu.lock();
                match c.max {
                    Some((q, p)) => format!("{} {}\n", q, p),
                    None => String::from("max 100000\n"),
                }
            }
            ControlFile::CpuStat => {
                let c = self.cg.cpu.lock();
                format!(
                    "usage_usec {}\nuser_usec {}\nsystem_usec {}\n",
                    c.usage_usec, c.user_usec, c.system_usec
                )
            }
            ControlFile::CpuWeight => {
                format!("{}\n", self.cg.cpu.lock().weight)
            }
            ControlFile::IoMax => {
                let i = self.cg.io.lock();
                let any = i.max_rbps.is_some()
                    || i.max_wbps.is_some()
                    || i.max_riops.is_some()
                    || i.max_wiops.is_some();
                if !any {
                    String::new()
                } else {
                    let r = i
                        .max_rbps
                        .map(|v| format!("rbps={v}"))
                        .unwrap_or_else(|| String::from("rbps=max"));
                    let w = i
                        .max_wbps
                        .map(|v| format!("wbps={v}"))
                        .unwrap_or_else(|| String::from("wbps=max"));
                    let ri = i
                        .max_riops
                        .map(|v| format!("riops={v}"))
                        .unwrap_or_else(|| String::from("riops=max"));
                    let wi = i
                        .max_wiops
                        .map(|v| format!("wiops={v}"))
                        .unwrap_or_else(|| String::from("wiops=max"));
                    format!("8:0 {r} {w} {ri} {wi}\n")
                }
            }
            ControlFile::IoStat => {
                let i = self.cg.io.lock();
                format!(
                    "rbytes={} wbytes={} rios={} wios={}\n",
                    i.rbytes, i.wbytes, i.rios, i.wios
                )
            }
            ControlFile::IoWeight => {
                format!("default {}\n", self.cg.io.lock().weight)
            }
            ControlFile::MemoryCurrent => {
                format!("{}\n", self.cg.memory.lock().current)
            }
            ControlFile::MemoryEvents => {
                let m = self.cg.memory.lock();
                format!(
                    "low 0\nhigh 0\nmax 0\noom {}\noom_kill {}\noom_group_kill 0\n",
                    m.events_oom, m.events_oom_kill
                )
            }
            ControlFile::MemoryHigh => {
                let m = self.cg.memory.lock();
                match m.high {
                    Some(v) => format!("{}\n", v),
                    None => String::from("max\n"),
                }
            }
            ControlFile::MemoryLow => {
                format!("{}\n", self.cg.memory.lock().low)
            }
            ControlFile::MemoryMax => {
                let m = self.cg.memory.lock();
                match m.max {
                    Some(v) => format!("{}\n", v),
                    None => String::from("max\n"),
                }
            }
            ControlFile::MemoryPeak => {
                format!("{}\n", self.cg.memory.lock().peak)
            }
            ControlFile::MemoryStat => {
                let m = self.cg.memory.lock();
                format!("anon 0\nfile 0\nkernel {}\nslab 0\n", m.current)
            }
            ControlFile::PidsCurrent => {
                format!("{}\n", self.cg.pids_ctl.lock().current)
            }
            ControlFile::PidsMax => {
                let p = self.cg.pids_ctl.lock();
                match p.max {
                    Some(v) => format!("{}\n", v),
                    None => String::from("max\n"),
                }
            }
        }
    }

    fn handle_write(&self, text: &str) -> Result<(), FsError> {
        match self.file {
            ControlFile::CgroupProcs | ControlFile::CgroupThreads => {
                let local: u32 = text.parse().map_err(|_| FsError::InvalidArgument)?;
                let host = crate::sched::caller_local_to_host(local).ok_or(FsError::NotFound)?;
                migrate_pid(host, self.cg.clone()).map_err(map_err)?;
                Ok(())
            }
            ControlFile::MemoryMax => {
                self.cg.memory.lock().max = parse_max(text)?;
                Ok(())
            }
            ControlFile::MemoryHigh => {
                self.cg.memory.lock().high = parse_max(text)?;
                Ok(())
            }
            ControlFile::MemoryLow => {
                self.cg.memory.lock().low = text.parse().map_err(|_| FsError::InvalidArgument)?;
                Ok(())
            }
            ControlFile::PidsMax => {
                self.cg.pids_ctl.lock().max = parse_max(text)?;
                Ok(())
            }
            ControlFile::CpuMax => {
                let mut parts = text.split_ascii_whitespace();
                let q_str = parts.next().ok_or(FsError::InvalidArgument)?;
                let p_str = parts.next().unwrap_or("100000");
                let period: u64 = p_str.parse().map_err(|_| FsError::InvalidArgument)?;
                let mut c = self.cg.cpu.lock();
                if q_str == "max" {
                    c.max = None;
                } else {
                    let quota: u64 = q_str.parse().map_err(|_| FsError::InvalidArgument)?;
                    c.max = Some((quota, period));
                }
                Ok(())
            }
            ControlFile::CpuWeight => {
                let w: u64 = text.parse().map_err(|_| FsError::InvalidArgument)?;
                if !(1..=10_000).contains(&w) {
                    return Err(FsError::InvalidArgument);
                }
                self.cg.cpu.lock().weight = w;
                Ok(())
            }
            ControlFile::IoMax => {
                let mut parts = text.split_ascii_whitespace();
                let _device = parts.next().ok_or(FsError::InvalidArgument)?;
                let mut io = self.cg.io.lock();
                for kv in parts {
                    let (k, v) = kv.split_once('=').ok_or(FsError::InvalidArgument)?;
                    let parsed: Option<u64> = if v == "max" {
                        None
                    } else {
                        Some(v.parse().map_err(|_| FsError::InvalidArgument)?)
                    };
                    match k {
                        "rbps" => io.max_rbps = parsed,
                        "wbps" => io.max_wbps = parsed,
                        "riops" => io.max_riops = parsed,
                        "wiops" => io.max_wiops = parsed,
                        _ => return Err(FsError::InvalidArgument),
                    }
                }
                Ok(())
            }
            ControlFile::IoWeight => {
                let trimmed = text.trim();
                let val_str = trimmed
                    .strip_prefix("default ")
                    .map(|s| s.trim())
                    .unwrap_or(trimmed);
                let w: u64 = val_str.parse().map_err(|_| FsError::InvalidArgument)?;
                if !(1..=10_000).contains(&w) {
                    return Err(FsError::InvalidArgument);
                }
                self.cg.io.lock().weight = w;
                Ok(())
            }
            _ => Err(FsError::PermissionDenied),
        }
    }
}

fn parse_max(text: &str) -> Result<Option<u64>, FsError> {
    if text == "max" {
        return Ok(None);
    }
    text.parse::<u64>()
        .map(Some)
        .map_err(|_| FsError::InvalidArgument)
}

fn migrate_pid(pid: crate::process::Pid, target: Arc<Cgroup>) -> Result<(), CgroupError> {
    let old = match crate::sched::process_cgroup(pid) {
        Some(c) => c,
        None => return Err(CgroupError::NotFound),
    };
    if Arc::ptr_eq(&old, &target) {
        return Ok(());
    }
    old.detach_pid(pid);
    if let Err(e) = target.attach_pid(pid) {
        let _ = old.attach_pid(pid);
        return Err(e);
    }
    let charged = crate::sched::process_charged_bytes(pid);
    if charged > 0 {
        old.uncharge_memory(charged);
        if let Err(e) = target.try_charge_memory(charged) {
            let _ = old.try_charge_memory(charged);
            target.detach_pid(pid);
            let _ = old.attach_pid(pid);
            return Err(e);
        }
    }
    crate::sched::set_process_cgroup(pid, target);
    Ok(())
}

pub fn root() -> Arc<dyn Inode> {
    CgroupDir::new(crate::cgroup::root())
}
