use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::process::Pid;
use crate::vfs::{DirEntry, FsError, Inode, InodeKind, Stat};

const CPUINFO: &str = "processor\t: 0\n\
                       vendor_id\t: CypheraVM\n\
                       cpu family\t: 6\n\
                       model name\t: Cyphera virtual cpu\n\
                       cpu MHz\t\t: 2000.000\n\
                       cache size\t: 0 KB\n\
                       flags\t\t: fpu pae nx lm rdtscp\n\
                       \n";

pub fn root() -> Arc<dyn Inode> {
    Arc::new(ProcRoot)
}

struct ProcRoot;

impl Inode for ProcRoot {
    fn kind(&self) -> InodeKind {
        InodeKind::Directory
    }
    fn stat(&self) -> Stat {
        dir_stat()
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        match name {
            "cpuinfo" => Ok(Arc::new(StaticFile::new(CPUINFO))),
            "meminfo" => Ok(Arc::new(MemInfoFile)),
            "uptime" => Ok(Arc::new(UptimeFile)),
            "self" => Ok(Arc::new(SelfDir)),
            "net" => Ok(Arc::new(NetDir)),
            "stat" => Ok(Arc::new(StatFile)),
            "mounts" => Ok(Arc::new(MountsFile)),
            "version" => Ok(Arc::new(StaticFile::new(VERSION))),
            "loadavg" => Ok(Arc::new(LoadavgFile)),
            "schedstat" => Ok(Arc::new(SchedStatFile)),
            "filesystems" => Ok(Arc::new(StaticFile::new(FILESYSTEMS))),
            "cmdline" => Ok(Arc::new(StaticFile::new(KCMDLINE))),
            "sys" => Ok(Arc::new(SysDir)),
            _ => match name.parse::<u32>() {
                Ok(pid) if crate::sched::process_summary(Pid(pid)).is_some() => {
                    Ok(Arc::new(PidDir { pid: Pid(pid) }))
                }
                _ => Err(FsError::NotFound),
            },
        }
    }

    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        let mut out = Vec::new();
        for (name, kind) in [
            ("cpuinfo", InodeKind::Regular),
            ("meminfo", InodeKind::Regular),
            ("uptime", InodeKind::Regular),
            ("self", InodeKind::Directory),
            ("net", InodeKind::Directory),
            ("stat", InodeKind::Regular),
            ("mounts", InodeKind::Regular),
            ("version", InodeKind::Regular),
            ("loadavg", InodeKind::Regular),
            ("schedstat", InodeKind::Regular),
            ("filesystems", InodeKind::Regular),
            ("cmdline", InodeKind::Regular),
            ("sys", InodeKind::Directory),
        ] {
            out.push(DirEntry {
                name: name.to_string(),
                kind,
                inode_id: hash_str(name),
            });
        }
        for pid in crate::sched::all_pids() {
            out.push(DirEntry {
                name: format!("{}", pid.0),
                kind: InodeKind::Directory,
                inode_id: 0x9000_0000_0000_0000 | pid.0 as u64,
            });
        }
        Ok(out)
    }
}

struct PidDir {
    pid: Pid,
}

impl Inode for PidDir {
    fn kind(&self) -> InodeKind {
        InodeKind::Directory
    }
    fn stat(&self) -> Stat {
        dir_stat()
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        match name {
            "stat" => Ok(Arc::new(PidStatFile { pid: self.pid })),
            "cmdline" => Ok(Arc::new(PidCmdlineFile { pid: self.pid })),
            "maps" => Ok(Arc::new(PidMapsFile { pid: self.pid })),
            "fd" => Ok(Arc::new(PidFdDir { pid: self.pid })),
            "status" => Ok(Arc::new(PidStatusFile { pid: self.pid })),
            "comm" => Ok(Arc::new(PidCommFile { pid: self.pid })),
            "uid_map" => Ok(Arc::new(IdMapFile {
                kind: IdMapKind::Uid,
                pid: self.pid,
            })),
            "gid_map" => Ok(Arc::new(IdMapFile {
                kind: IdMapKind::Gid,
                pid: self.pid,
            })),
            "setgroups" => Ok(Arc::new(SetgroupsFile { pid: self.pid })),
            "loginuid" => Ok(Arc::new(LoginuidFile {})),
            "exe" => {
                let target = crate::sched::process_exe(self.pid).ok_or(FsError::NotFound)?;
                let s = alloc::string::String::from_utf8(target).map_err(|_| FsError::NotFound)?;
                Ok(crate::fs::tmpfs::TmpfsInode::new_symlink(s))
            }
            _ => Err(FsError::NotFound),
        }
    }
    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        let pid = self.pid.0 as u64;
        let mut entries = alloc::vec![
            DirEntry {
                name: "stat".to_string(),
                kind: InodeKind::Regular,
                inode_id: 0xa000_0000_0000_0000 | pid,
            },
            DirEntry {
                name: "cmdline".to_string(),
                kind: InodeKind::Regular,
                inode_id: 0xa100_0000_0000_0000 | pid,
            },
            DirEntry {
                name: "maps".to_string(),
                kind: InodeKind::Regular,
                inode_id: 0xa200_0000_0000_0000 | pid,
            },
            DirEntry {
                name: "fd".to_string(),
                kind: InodeKind::Directory,
                inode_id: 0xa300_0000_0000_0000 | pid,
            },
            DirEntry {
                name: "status".to_string(),
                kind: InodeKind::Regular,
                inode_id: 0xa500_0000_0000_0000 | pid,
            },
            DirEntry {
                name: "comm".to_string(),
                kind: InodeKind::Regular,
                inode_id: 0xa600_0000_0000_0000 | pid,
            },
        ];
        if crate::sched::process_exe(self.pid).is_some() {
            entries.push(DirEntry {
                name: "exe".to_string(),
                kind: InodeKind::Symlink,
                inode_id: 0xa400_0000_0000_0000 | pid,
            });
        }
        Ok(entries)
    }
}

struct NetDir;

impl Inode for NetDir {
    fn kind(&self) -> InodeKind {
        InodeKind::Directory
    }
    fn stat(&self) -> Stat {
        dir_stat()
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        match name {
            "dev" => Ok(Arc::new(NetDevFile)),
            "route" => Ok(Arc::new(NetRouteFile)),
            _ => Err(FsError::NotFound),
        }
    }
    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        Ok(alloc::vec![
            DirEntry {
                name: "dev".to_string(),
                kind: InodeKind::Regular,
                inode_id: hash_str("dev")
            },
            DirEntry {
                name: "route".to_string(),
                kind: InodeKind::Regular,
                inode_id: hash_str("route")
            },
        ])
    }
}

struct NetDevFile;

impl Inode for NetDevFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let mut body = alloc::string::String::new();
        body.push_str(
            "Inter-|   Receive                                                |  Transmit\n",
        );
        body.push_str(" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
        body.push_str("    lo:       0       0    0    0    0     0          0         0       0       0    0    0    0     0       0          0\n");
        if virtio::net_mac().is_some() {
            body.push_str("  eth0:       0       0    0    0    0     0          0         0       0       0    0    0    0     0       0          0\n");
        }
        slice_into(body.as_bytes(), offset, buf)
    }
}

struct NetRouteFile;

impl Inode for NetRouteFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let mut body = alloc::string::String::new();
        body.push_str(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
        );
        if virtio::net_mac().is_some() {
            body.push_str("eth0\t00000000\t0202000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n");
            body.push_str("eth0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n");
        }
        slice_into(body.as_bytes(), offset, buf)
    }
}

struct SelfDir;

impl Inode for SelfDir {
    fn kind(&self) -> InodeKind {
        InodeKind::Directory
    }
    fn stat(&self) -> Stat {
        dir_stat()
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let pid = crate::sched::current_pid();
        PidDir { pid }.lookup(name)
    }
    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        let pid = crate::sched::current_pid();
        PidDir { pid }.list()
    }
}

struct StaticFile {
    body: &'static str,
}

impl StaticFile {
    fn new(body: &'static str) -> Self {
        Self { body }
    }
}

impl Inode for StaticFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, self.body.len() as u64, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        slice_into(self.body.as_bytes(), offset, buf)
    }
}

struct MemInfoFile;

impl Inode for MemInfoFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let s = frame::mm::frame_alloc::stats();
        let total_kb = (s.total * 4) as u64;
        let used_kb = (s.in_use * 4) as u64;
        let free_kb = total_kb.saturating_sub(used_kb);
        let body = format!(
            "MemTotal:       {:>8} kB\n\
             MemFree:        {:>8} kB\n\
             MemAvailable:   {:>8} kB\n\
             Buffers:        {:>8} kB\n\
             Cached:         {:>8} kB\n",
            total_kb, free_kb, free_kb, 0u64, 0u64,
        );
        slice_into(body.as_bytes(), offset, buf)
    }
}

struct UptimeFile;

impl Inode for UptimeFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let nanos = frame::cpu::nanos_since_boot();
        let up_int = nanos / 1_000_000_000;
        let up_frac = (nanos % 1_000_000_000) / 10_000_000;
        let (_user, _nice, _system, idle_jiffies) = crate::sched::jiffies_summary();
        let idle_int = idle_jiffies / 100;
        let idle_frac = idle_jiffies % 100;
        let body = format!("{up_int}.{up_frac:02} {idle_int}.{idle_frac:02}\n");
        slice_into(body.as_bytes(), offset, buf)
    }
}

struct PidCmdlineFile {
    pid: Pid,
}

impl Inode for PidCmdlineFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let body = crate::sched::process_cmdline(self.pid).unwrap_or_default();
        slice_into(&body, offset, buf)
    }
}

struct PidMapsFile {
    pid: Pid,
}

impl Inode for PidMapsFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        use frame::mm::vm::Perms;
        let snap = match crate::sched::process_maps(self.pid) {
            Some(s) => s,
            None => return Err(FsError::NotFound),
        };
        let mut lines: alloc::vec::Vec<(u64, u64, Perms, bool, &str)> = alloc::vec::Vec::new();
        for (start, end, prot, label) in &snap.segments {
            let name = match label {
                crate::process::MapSegLabel::Stack => "[stack]",
                _ => "",
            };
            lines.push((*start, *end, *prot, false, name));
        }
        if snap.brk_cur > snap.brk_start {
            lines.push((
                snap.brk_start,
                snap.brk_cur,
                Perms::READ | Perms::WRITE,
                false,
                "[heap]",
            ));
        }
        for (start, end, prot, shared, label) in &snap.vmas {
            let name = match label {
                crate::sched::MapVmaLabel::Heap => "[heap]",
                crate::sched::MapVmaLabel::Stack => "[stack]",
                _ => "",
            };
            lines.push((*start, *end, *prot, *shared, name));
        }
        lines.sort_by_key(|l| l.0);
        let mut body = alloc::string::String::new();
        for (start, end, prot, shared, name) in lines {
            let r = if prot.contains(Perms::READ) { 'r' } else { '-' };
            let w = if prot.contains(Perms::WRITE) {
                'w'
            } else {
                '-'
            };
            let x = if prot.contains(Perms::EXECUTE) {
                'x'
            } else {
                '-'
            };
            let p = if shared { 's' } else { 'p' };
            if name.is_empty() {
                body.push_str(&format!(
                    "{:016x}-{:016x} {}{}{}{} 00000000 00:00 0\n",
                    start, end, r, w, x, p,
                ));
            } else {
                body.push_str(&format!(
                    "{:016x}-{:016x} {}{}{}{} 00000000 00:00 0                          {}\n",
                    start, end, r, w, x, p, name,
                ));
            }
        }
        slice_into(body.as_bytes(), offset, buf)
    }
}

struct PidFdDir {
    pid: Pid,
}

impl Inode for PidFdDir {
    fn kind(&self) -> InodeKind {
        InodeKind::Directory
    }
    fn stat(&self) -> Stat {
        dir_stat()
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let fd: i32 = name.parse().map_err(|_| FsError::NotFound)?;
        let inode_opt = if self.pid == crate::sched::current_pid() {
            crate::sched::with_current_fds(|t| t.get(fd)).map(|f| f.inode.clone())
        } else {
            let fds = crate::sched::process_open_fds(self.pid).ok_or(FsError::NotFound)?;
            if !fds.contains(&fd) {
                return Err(FsError::NotFound);
            }
            None
        };
        let target = inode_opt
            .as_deref()
            .map(synthesize_fd_link_target)
            .unwrap_or_else(|| alloc::format!("<fd:{fd}>"));
        Ok(Arc::new(MagicFdLink {
            target,
            underlying: inode_opt,
        }))
    }
    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        let fds = crate::sched::process_open_fds(self.pid).ok_or(FsError::NotFound)?;
        Ok(fds
            .into_iter()
            .map(|fd| DirEntry {
                name: alloc::format!("{fd}"),
                kind: InodeKind::Symlink,
                inode_id: (0xb000_0000u64 << 32) | fd as u64,
            })
            .collect())
    }
}

struct SysDir;

impl Inode for SysDir {
    fn kind(&self) -> InodeKind {
        InodeKind::Directory
    }
    fn stat(&self) -> Stat {
        dir_stat()
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        match name {
            "kernel" => Ok(Arc::new(SysKernelDir)),
            "fs" => Ok(Arc::new(SysFsDir)),
            _ => Err(FsError::NotFound),
        }
    }
    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        Ok(alloc::vec![
            DirEntry {
                name: "kernel".to_string(),
                kind: InodeKind::Directory,
                inode_id: 0xc100_0000_0000_0000,
            },
            DirEntry {
                name: "fs".to_string(),
                kind: InodeKind::Directory,
                inode_id: 0xc200_0000_0000_0000,
            },
        ])
    }
}

struct SysKernelDir;

impl Inode for SysKernelDir {
    fn kind(&self) -> InodeKind {
        InodeKind::Directory
    }
    fn stat(&self) -> Stat {
        dir_stat()
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        match name {
            "cap_last_cap" => Ok(Arc::new(StaticFile::new("40\n"))),
            "ostype" => Ok(Arc::new(StaticFile::new("Linux\n"))),
            "osrelease" => Ok(Arc::new(StaticFile::new("6.7.0-cyphera\n"))),
            "version" => Ok(Arc::new(StaticFile::new("#1 SMP Cyphera 0.1.0\n"))),
            "hostname" => Ok(Arc::new(StaticFile::new("cyphera\n"))),
            "pid_max" => Ok(Arc::new(StaticFile::new("32768\n"))),
            "random" => Ok(Arc::new(SysKernelRandomDir)),
            "sched_rt_period_us" => Ok(Arc::new(SchedRtPeriodFile)),
            "sched_rt_runtime_us" => Ok(Arc::new(SchedRtRuntimeFile)),
            _ => Err(FsError::NotFound),
        }
    }
    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        Ok(alloc::vec![
            entry("cap_last_cap", InodeKind::Regular, 0xc101_0001),
            entry("ostype", InodeKind::Regular, 0xc101_0002),
            entry("osrelease", InodeKind::Regular, 0xc101_0003),
            entry("version", InodeKind::Regular, 0xc101_0004),
            entry("hostname", InodeKind::Regular, 0xc101_0005),
            entry("pid_max", InodeKind::Regular, 0xc101_0006),
            entry("random", InodeKind::Directory, 0xc101_0007),
            entry("sched_rt_period_us", InodeKind::Regular, 0xc101_0008),
            entry("sched_rt_runtime_us", InodeKind::Regular, 0xc101_0009),
        ])
    }
}

struct SchedRtPeriodFile;

impl Inode for SchedRtPeriodFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o644)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let (period_ns, _runtime_ns) = crate::sched::rt_bandwidth_cfg();
        let body = format!("{}\n", period_ns / 1_000);
        slice_into(body.as_bytes(), offset, buf)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        let s = core::str::from_utf8(buf).map_err(|_| FsError::InvalidArgument)?;
        let trimmed = s.trim();
        let us: u64 = trimmed.parse().map_err(|_| FsError::InvalidArgument)?;
        if !crate::sched::set_rt_period_ns(us.saturating_mul(1_000)) {
            return Err(FsError::InvalidArgument);
        }
        Ok(buf.len())
    }
}

struct SchedRtRuntimeFile;

impl Inode for SchedRtRuntimeFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o644)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let (_period_ns, runtime_ns) = crate::sched::rt_bandwidth_cfg();
        let body = if runtime_ns == u64::MAX {
            "-1\n".to_string()
        } else {
            format!("{}\n", runtime_ns / 1_000)
        };
        slice_into(body.as_bytes(), offset, buf)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        let s = core::str::from_utf8(buf).map_err(|_| FsError::InvalidArgument)?;
        let trimmed = s.trim();
        if trimmed == "-1" {
            crate::sched::set_rt_runtime_ns(u64::MAX);
        } else {
            let us: i64 = trimmed.parse().map_err(|_| FsError::InvalidArgument)?;
            if us < 0 {
                crate::sched::set_rt_runtime_ns(u64::MAX);
            } else {
                crate::sched::set_rt_runtime_ns((us as u64).saturating_mul(1_000));
            }
        }
        Ok(buf.len())
    }
}

struct SysKernelRandomDir;

impl Inode for SysKernelRandomDir {
    fn kind(&self) -> InodeKind {
        InodeKind::Directory
    }
    fn stat(&self) -> Stat {
        dir_stat()
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        match name {
            "boot_id" => Ok(Arc::new(StaticFile::new(
                "00000000-0000-0000-0000-000000000001\n",
            ))),
            "uuid" => Ok(Arc::new(UuidFile::new())),
            "entropy_avail" => Ok(Arc::new(StaticFile::new("4096\n"))),
            _ => Err(FsError::NotFound),
        }
    }
    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        Ok(alloc::vec![
            entry("boot_id", InodeKind::Regular, 0xc102_0001),
            entry("uuid", InodeKind::Regular, 0xc102_0002),
            entry("entropy_avail", InodeKind::Regular, 0xc102_0003),
        ])
    }
}

struct UuidFile {
    body: alloc::string::String,
}

impl UuidFile {
    fn new() -> Self {
        use core::fmt::Write;
        let mut raw = [0u8; 16];
        let _ = virtio::fill_random(&mut raw);
        raw[6] = (raw[6] & 0x0f) | 0x40;
        raw[8] = (raw[8] & 0x3f) | 0x80;
        let mut body = alloc::string::String::with_capacity(37);
        for (i, b) in raw.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                let _ = body.write_char('-');
            }
            let _ = write!(body, "{b:02x}");
        }
        body.push('\n');
        Self { body }
    }
}

impl Inode for UuidFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, self.body.len() as u64, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        slice_into(self.body.as_bytes(), offset, buf)
    }
}

struct SysFsDir;

impl Inode for SysFsDir {
    fn kind(&self) -> InodeKind {
        InodeKind::Directory
    }
    fn stat(&self) -> Stat {
        dir_stat()
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        match name {
            "nr_open" => Ok(Arc::new(StaticFile::new("1048576\n"))),
            "file-max" => Ok(Arc::new(StaticFile::new("65536\n"))),
            _ => Err(FsError::NotFound),
        }
    }
    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        Ok(alloc::vec![
            entry("nr_open", InodeKind::Regular, 0xc201_0001),
            entry("file-max", InodeKind::Regular, 0xc201_0002),
        ])
    }
}

fn entry(name: &str, kind: InodeKind, inode_id: u64) -> DirEntry {
    DirEntry {
        name: name.to_string(),
        kind,
        inode_id,
    }
}

#[derive(Copy, Clone)]
enum IdMapKind {
    Uid,
    Gid,
}

struct IdMapFile {
    kind: IdMapKind,
    pid: Pid,
}

impl IdMapFile {
    fn target_ns(&self) -> Option<Arc<crate::process::UserNamespace>> {
        crate::sched::with_target_process(self.pid, |p| p.creds.lock().user_ns.clone()).flatten()
    }
}

impl Inode for IdMapFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        let mut st = Stat::fresh(InodeKind::Regular, 0, 0o644);
        st.uid = self.target_ns().map(|ns| ns.creator_uid).unwrap_or(0);
        st
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let mut body = alloc::string::String::new();
        if let Some(ns) = self.target_ns() {
            let map = match self.kind {
                IdMapKind::Uid => ns.uid_map.lock(),
                IdMapKind::Gid => ns.gid_map.lock(),
            };
            for m in map.iter() {
                body.push_str(&format!(
                    "{:>10} {:>10} {:>10}\n",
                    m.inside_start, m.outside_start, m.length
                ));
            }
        }
        slice_into(body.as_bytes(), offset, buf)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        use crate::process::{CAP_SETGID, CAP_SETUID, IdMapping};

        let ns = match self.target_ns() {
            Some(ns) if ns.level > 0 => ns,
            _ => return Err(FsError::PermissionDenied),
        };
        let is_uid = matches!(self.kind, IdMapKind::Uid);

        {
            let existing = if is_uid {
                ns.uid_map.lock()
            } else {
                ns.gid_map.lock()
            };
            if !existing.is_empty() {
                return Err(FsError::PermissionDenied);
            }
        }

        let text = core::str::from_utf8(buf).map_err(|_| FsError::InvalidArgument)?;
        let mut parsed: Vec<IdMapping> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut it = line.split_whitespace();
            let inside = it.next().and_then(|s| s.parse::<u32>().ok());
            let outside = it.next().and_then(|s| s.parse::<u32>().ok());
            let length = it.next().and_then(|s| s.parse::<u32>().ok());
            match (inside, outside, length) {
                (Some(i), Some(o), Some(l)) if l > 0 && it.next().is_none() => {
                    i.checked_add(l).ok_or(FsError::InvalidArgument)?;
                    o.checked_add(l).ok_or(FsError::InvalidArgument)?;
                    parsed.push(IdMapping {
                        inside_start: i,
                        outside_start: o,
                        length: l,
                    });
                }
                _ => return Err(FsError::InvalidArgument),
            }
        }
        if parsed.is_empty() {
            return Err(FsError::InvalidArgument);
        }

        let cap = if is_uid { CAP_SETUID } else { CAP_SETGID };
        let (writer_id, privileged) = crate::sched::with_current_creds(|c| {
            let id = if is_uid { c.euid } else { c.egid };
            (id, c.capable_host(cap))
        });
        if !privileged {
            if parsed.len() != 1 || parsed[0].length != 1 || parsed[0].outside_start != writer_id {
                return Err(FsError::PermissionDenied);
            }
            if !is_uid
                && ns
                    .setgroups_allowed
                    .load(core::sync::atomic::Ordering::Acquire)
            {
                return Err(FsError::PermissionDenied);
            }
        }

        if is_uid {
            *ns.uid_map.lock() = parsed;
        } else {
            *ns.gid_map.lock() = parsed;
        }
        Ok(buf.len())
    }
}

struct SetgroupsFile {
    pid: Pid,
}

impl SetgroupsFile {
    fn target_ns(&self) -> Option<Arc<crate::process::UserNamespace>> {
        crate::sched::with_target_process(self.pid, |p| p.creds.lock().user_ns.clone()).flatten()
    }
}

impl Inode for SetgroupsFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        let mut st = Stat::fresh(InodeKind::Regular, 0, 0o644);
        st.uid = self.target_ns().map(|ns| ns.creator_uid).unwrap_or(0);
        st
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let allowed = match self.target_ns() {
            Some(ns) => ns
                .setgroups_allowed
                .load(core::sync::atomic::Ordering::Acquire),
            None => true,
        };
        slice_into(if allowed { b"allow\n" } else { b"deny\n" }, offset, buf)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        let ns = match self.target_ns() {
            Some(ns) if ns.level > 0 => ns,
            _ => return Err(FsError::PermissionDenied),
        };
        if !ns.gid_map.lock().is_empty() {
            return Err(FsError::PermissionDenied);
        }
        let word = core::str::from_utf8(buf)
            .map_err(|_| FsError::InvalidArgument)?
            .trim();
        let allow = match word {
            "allow" => true,
            "deny" => false,
            _ => return Err(FsError::InvalidArgument),
        };
        ns.setgroups_allowed
            .store(allow, core::sync::atomic::Ordering::Release);
        Ok(buf.len())
    }
}

struct LoginuidFile {}

impl Inode for LoginuidFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o644)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        slice_into(b"4294967295\n", offset, buf)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        Ok(buf.len())
    }
}

struct PidStatFile {
    pid: Pid,
}

impl Inode for PidStatFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let s = match crate::sched::process_summary(self.pid) {
            Some(s) => s,
            None => return Err(FsError::NotFound),
        };
        let comm = crate::sched::process_name(self.pid);
        let comm_end = comm.iter().position(|&b| b == 0).unwrap_or(16);
        let comm_str = core::str::from_utf8(&comm[..comm_end]).unwrap_or("cyphera");
        let comm_str = if comm_str.is_empty() {
            "cyphera"
        } else {
            comm_str
        };
        let body = format!(
            "{} ({}) {} {} {} {} 0 0 0 {} 0 {} 0 {} {} {} {} {} {} {} 0 0 {} {} {} 0 0 0 0 0 0 0 0 0 0 0 17 {} {} {} 0 0 0 0 0 0 0 0 0 0 0\n",
            s.pid.0,
            comm_str,
            s.state_char,
            s.parent_pid,
            s.pgrp,
            s.session,
            s.minflt,
            s.majflt,
            s.utime_clk,
            s.stime_clk,
            s.cutime_clk,
            s.cstime_clk,
            s.priority,
            s.nice,
            s.num_threads,
            s.vsize,
            s.rss_pages,
            u64::MAX,
            s.processor,
            s.rt_priority,
            s.policy,
        );
        slice_into(body.as_bytes(), offset, buf)
    }
}

struct MagicFdLink {
    target: alloc::string::String,
    underlying: Option<Arc<dyn Inode>>,
}

impl Inode for MagicFdLink {
    fn kind(&self) -> InodeKind {
        InodeKind::Symlink
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Symlink, self.target.len() as u64, 0o777)
    }
    fn read_link(&self) -> Result<alloc::string::String, FsError> {
        Ok(self.target.clone())
    }
    fn magic_resolve(&self) -> Option<Arc<dyn Inode>> {
        self.underlying.clone()
    }
}

fn synthesize_fd_link_target(inode: &dyn Inode) -> alloc::string::String {
    match inode.kind() {
        InodeKind::Pipe => alloc::format!("pipe:[{}]", inode.inode_id()),
        InodeKind::CharDevice => alloc::format!("anon_inode:[char:{}]", inode.inode_id()),
        InodeKind::Symlink => alloc::format!("anon_inode:[symlink:{}]", inode.inode_id()),
        InodeKind::Directory => alloc::format!("anon_inode:[dir:{}]", inode.inode_id()),
        InodeKind::Regular => alloc::format!("anon_inode:[file:{}]", inode.inode_id()),
    }
}

fn dir_stat() -> Stat {
    Stat::fresh(InodeKind::Directory, 0, 0o555)
}

fn slice_into(src: &[u8], offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
    if offset >= src.len() as u64 {
        return Ok(0);
    }
    let start = offset as usize;
    let n = (src.len() - start).min(buf.len());
    buf[..n].copy_from_slice(&src[start..start + n]);
    Ok(n)
}

fn hash_str(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

struct StatFile;

impl Inode for StatFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        use core::fmt::Write;
        let (user_total, nice_total, system_total, idle_total) = crate::sched::jiffies_summary();
        let mut body = alloc::string::String::new();
        let _ = writeln!(
            body,
            "cpu  {user_total} {nice_total} {system_total} {idle_total} 0 0 0 0 0 0"
        );
        for cpu in 0..frame::cpu::per_cpu::MAX_CPUS {
            if let Some((u, n, s, i)) = crate::sched::jiffies_for_cpu(cpu) {
                if u == 0 && n == 0 && s == 0 && i == 0 {
                    continue;
                }
                let _ = writeln!(body, "cpu{cpu} {u} {n} {s} {i} 0 0 0 0 0 0");
            }
        }
        let _ = writeln!(body, "intr {}", crate::sched::intr_count());
        let _ = writeln!(body, "ctxt {}", crate::sched::ctxt_switches());
        let _ = writeln!(body, "btime 0");
        let total = crate::sched::all_pids().len() as u64;
        let _ = writeln!(body, "processes {total}");
        let (running, blocked) = crate::sched::procs_running_blocked();
        let _ = writeln!(body, "procs_running {running}");
        let _ = writeln!(body, "procs_blocked {blocked}");
        slice_into(body.as_bytes(), offset, buf)
    }
}

struct MountsFile;

impl Inode for MountsFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let body = "rootfs / tmpfs rw 0 0\ntmpfs /tmp tmpfs rw 0 0\ndevtmpfs /dev devtmpfs rw 0 0\nproc /proc proc rw 0 0\nsysfs /sys sysfs rw 0 0\n";
        slice_into(body.as_bytes(), offset, buf)
    }
}

struct PidStatusFile {
    pid: Pid,
}

impl Inode for PidStatusFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let s = match crate::sched::process_summary(self.pid) {
            Some(s) => s,
            None => return Err(FsError::NotFound),
        };
        let name = crate::sched::process_name(self.pid);
        let n = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let name_str = core::str::from_utf8(&name[..n]).unwrap_or("?");
        let state_str = match s.state_char {
            'R' => "R (running)",
            'S' => "S (sleeping)",
            'Z' => "Z (zombie)",
            'T' => "T (stopped)",
            _ => "? (unknown)",
        };
        let creds = crate::sched::with_target_creds(self.pid, |c| c.clone())
            .unwrap_or_else(crate::process::Credentials::root);
        let no_new_privs = crate::sched::process_no_new_privs(self.pid);
        let seccomp_mode = if crate::sched::process_seccomp_active(self.pid) {
            2
        } else {
            0
        };
        let (vis_ruid, vis_euid, vis_suid, vis_fsuid, vis_rgid, vis_egid, vis_sgid, vis_fsgid) =
            crate::sched::with_current_creds(|r| {
                (
                    r.uid_from_kernel(creds.ruid),
                    r.uid_from_kernel(creds.euid),
                    r.uid_from_kernel(creds.suid),
                    r.uid_from_kernel(creds.fsuid),
                    r.gid_from_kernel(creds.rgid),
                    r.gid_from_kernel(creds.egid),
                    r.gid_from_kernel(creds.sgid),
                    r.gid_from_kernel(creds.fsgid),
                )
            });
        let body = format!(
            "Name:\t{name_str}\n\
             Umask:\t{:04o}\n\
             State:\t{state_str}\n\
             Tgid:\t{}\n\
             Ngid:\t0\n\
             Pid:\t{}\n\
             PPid:\t{}\n\
             TracerPid:\t0\n\
             Uid:\t{}\t{}\t{}\t{}\n\
             Gid:\t{}\t{}\t{}\t{}\n\
             FDSize:\t1024\n\
             Groups:\t\n\
             VmRSS:\t{} kB\n\
             Threads:\t1\n\
             SigPnd:\t0000000000000000\n\
             SigBlk:\t0000000000000000\n\
             CapInh:\t{:016x}\n\
             CapPrm:\t{:016x}\n\
             CapEff:\t{:016x}\n\
             CapBnd:\t{:016x}\n\
             CapAmb:\t0000000000000000\n\
             NoNewPrivs:\t{}\n\
             Seccomp:\t{}\n\
             Cpus_allowed:\tff\n\
             Cpus_allowed_list:\t0-7\n\
             voluntary_ctxt_switches:\t0\n\
             nonvoluntary_ctxt_switches:\t0\n",
            crate::sched::process_umask(self.pid),
            s.pid.0,
            s.pid.0,
            s.parent_pid,
            vis_ruid,
            vis_euid,
            vis_suid,
            vis_fsuid,
            vis_rgid,
            vis_egid,
            vis_sgid,
            vis_fsgid,
            s.brk_bytes / 1024,
            creds.caps_inh,
            creds.caps_perm,
            creds.caps_eff,
            creds.caps_bnd,
            if no_new_privs { 1 } else { 0 },
            seccomp_mode,
        );
        slice_into(body.as_bytes(), offset, buf)
    }
}

struct PidCommFile {
    pid: Pid,
}

impl Inode for PidCommFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o644)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let name = crate::sched::process_name(self.pid);
        let n = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        let mut body = alloc::string::String::from(core::str::from_utf8(&name[..n]).unwrap_or(""));
        body.push('\n');
        slice_into(body.as_bytes(), offset, buf)
    }
}

const VERSION: &str = "Linux version 0.0.1 (rustc nightly) #1 SMP x86_64 Cyphera\n";
struct LoadavgFile;

impl Inode for LoadavgFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        use core::fmt::Write;
        let (l1, l5, l15) = crate::sched::loadavg_fp();
        let (running, _blocked) = crate::sched::procs_running_blocked();
        let total = crate::sched::all_pids().len() as u64;
        let last_pid = crate::sched::last_pid();
        let mut body = alloc::string::String::new();
        let _ = writeln!(
            body,
            "{}.{:02} {}.{:02} {}.{:02} {}/{} {}",
            l1 >> 11,
            ((l1 & 0x7ff) * 100) >> 11,
            l5 >> 11,
            ((l5 & 0x7ff) * 100) >> 11,
            l15 >> 11,
            ((l15 & 0x7ff) * 100) >> 11,
            running,
            total,
            last_pid,
        );
        slice_into(body.as_bytes(), offset, buf)
    }
}
struct SchedStatFile;

impl Inode for SchedStatFile {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, 0, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        use core::fmt::Write;
        let load_ticks = crate::sched::loadavg_tick_count();
        let jiffies = frame::intr::lapic::ticks();
        let resched_ticks = crate::sched::resched_tick_count();
        let mut body = alloc::string::String::new();
        let _ = writeln!(body, "version 15");
        let _ = writeln!(body, "loadavg_ticks {load_ticks}");
        let _ = writeln!(body, "jiffies {jiffies}");
        let _ = writeln!(body, "resched_ticks {resched_ticks}");
        slice_into(body.as_bytes(), offset, buf)
    }
}

const FILESYSTEMS: &str = "nodev\tsysfs\nnodev\tproc\nnodev\ttmpfs\nnodev\tdevtmpfs\n\text4\n";
const KCMDLINE: &str = "console=ttyS0 quiet\n";
