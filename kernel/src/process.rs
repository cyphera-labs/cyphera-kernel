extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;

use frame::cpu::task::Task;
use frame::mm::{PhysFrame, Size4KiB};
use frame::user::TrapFrame;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pid(pub u32);

impl Pid {
    pub fn raw(self) -> u32 {
        self.0
    }
    pub const fn from_raw(raw: u32) -> Self {
        Pid(raw)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedClass {
    Cfs,
    Rt {
        priority: u8,
        round_robin: bool,
    },
    Deadline {
        runtime_ns: u64,
        deadline_ns: u64,
        period_ns: u64,
    },
}

impl SchedClass {
    pub const fn default_cfs() -> Self {
        SchedClass::Cfs
    }

    pub fn band(self) -> u16 {
        match self {
            SchedClass::Deadline { .. } => 300,
            SchedClass::Rt { priority, .. } => 200 + priority as u16,
            SchedClass::Cfs => 0,
        }
    }
}

pub const NICE_0_LOAD: u64 = 1024;

pub const PRIO_TO_WEIGHT: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949,
    11916, 9548, 7620, 6100, 4904, 3906, 3121, 2501, 1991, 1586,
    1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137,
    110, 87, 70, 56, 45, 36, 29, 23, 18, 15,
];

pub fn nice_to_weight(nice: i8) -> u64 {
    let idx = (nice as i32 + 20) as usize;
    if idx < PRIO_TO_WEIGHT.len() {
        PRIO_TO_WEIGHT[idx]
    } else {
        NICE_0_LOAD
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedOwner {
    None,
    Running { cpu: u32 },
    Runnable { cpu: u32 },
    Parked { waitq_addr: usize },
    Stopped,
    Traced,
    Zombie,
    Reaping,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Runnable,
    Running,
    Parked,
    Zombie(i32),
    KilledByFault {
        vector: u8,
        addr: u64,
        error: u64,
    },
    Stopped,
    DlThrottled,
    CgroupThrottled,
    Traced,
    KilledBySignal {
        signal: u32,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TraceStop {
    Attach,
    SyscallEntry,
    SyscallExit,
    Signal(u32),
    EventStop(u32),
}

#[derive(Copy, Clone, Debug)]
pub struct SavedRegs {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
    pub rip: u64,
    pub rflags: u64,
    pub rsp: u64,
}

impl SavedRegs {
    pub fn fresh(entry: u64, user_stack_top: u64) -> Self {
        Self {
            rax: 0,
            rdi: 0,
            rsi: 0,
            rdx: 0,
            r10: 0,
            r8: 0,
            r9: 0,
            rip: entry,
            rflags: 0x202,
            rsp: user_stack_top,
        }
    }

    pub fn from_trap_frame(tf: &TrapFrame) -> Self {
        Self {
            rax: tf.rax,
            rdi: tf.rdi,
            rsi: tf.rsi,
            rdx: tf.rdx,
            r10: tf.r10,
            r8: tf.r8,
            r9: tf.r9,
            rip: tf.rip_user,
            rflags: tf.rflags_user,
            rsp: tf.rsp_user,
        }
    }

    pub fn write_to_trap_frame(&self, tf: &mut TrapFrame) {
        tf.rax = self.rax;
        tf.rdi = self.rdi;
        tf.rsi = self.rsi;
        tf.rdx = self.rdx;
        tf.r10 = self.r10;
        tf.r8 = self.r8;
        tf.r9 = self.r9;
        tf.rip_user = self.rip;
        tf.rflags_user = self.rflags;
        tf.rsp_user = self.rsp;
    }
}

#[derive(Copy, Clone, Debug)]
pub struct BrkState {
    pub start: u64,
    pub current: u64,
    pub max: u64,
}

impl BrkState {
    pub fn new(start: u64) -> Self {
        Self {
            start,
            current: start,
            max: start + 256 * 1024 * 1024,
        }
    }
}

pub struct AddressSpace {
    pub vmspace: alloc::sync::Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>,
    pub mmap: frame::sync::SpinIrq<MmapState>,
    pub brk: frame::sync::SpinIrq<BrkState>,
    pub live_users: core::sync::atomic::AtomicUsize,
}

impl AddressSpace {
    pub fn new(
        vmspace: frame::mm::vm::VmSpace,
        pid: Pid,
        brk_start: u64,
    ) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            vmspace: alloc::sync::Arc::new(frame::sync::SpinIrq::new(vmspace)),
            mmap: frame::sync::SpinIrq::new(MmapState::for_pid(pid)),
            brk: frame::sync::SpinIrq::new(BrkState::new(brk_start)),
            live_users: core::sync::atomic::AtomicUsize::new(1),
        })
    }

    pub fn deep_copy_with_vmspace(
        &self,
        child_vmspace: alloc::sync::Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>,
    ) -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            vmspace: child_vmspace,
            mmap: frame::sync::SpinIrq::new(self.mmap.lock().clone_for_fork()),
            brk: frame::sync::SpinIrq::new(*self.brk.lock()),
            live_users: core::sync::atomic::AtomicUsize::new(1),
        })
    }
}

pub struct MmapState {
    pub vmas: alloc::vec::Vec<Vma>,
    pub last_end: u64,
    pub arena_lo: u64,
    pub arena_hi: u64,
}

#[derive(Clone)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: frame::mm::vm::Perms,
    pub flags: VmaFlags,
    pub backing: VmaBacking,
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct VmaFlags: u32 {
        const SHARED = 0x1;
        const ANON = 0x2;
        const GROWSDOWN = 0x4;
    }
}

#[derive(Clone)]
pub enum VmaBacking {
    Anonymous,
    File {
        inode: alloc::sync::Arc<dyn Inode>,
        file_offset_base: u64,
    },
    Shm {
        segment: alloc::sync::Arc<crate::ipc::shm::ShmSegment>,
    },
}

#[derive(Clone)]
pub struct MapSegment {
    pub start: u64,
    pub end: u64,
    pub prot: frame::mm::vm::Perms,
    pub label: MapSegLabel,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum MapSegLabel {
    Image,
    Interp,
    Stack,
}

#[derive(Clone, Default)]
pub struct MapsLayout {
    pub segments: alloc::vec::Vec<MapSegment>,
}

const MMAP_HINT_BASE: u64 = 0x0000_0080_0000_0000;
const MMAP_PER_PID_STRIDE: u64 = 4 * 1024 * 1024 * 1024;

impl MmapState {
    pub fn for_pid(pid: Pid) -> Self {
        let base = MMAP_HINT_BASE + (pid.0 as u64 - 1) * MMAP_PER_PID_STRIDE;
        Self {
            vmas: alloc::vec::Vec::new(),
            last_end: base,
            arena_lo: base,
            arena_hi: base + MMAP_PER_PID_STRIDE,
        }
    }

    pub fn clone_for_fork(&self) -> Self {
        Self {
            vmas: self.vmas.clone(),
            last_end: self.last_end,
            arena_lo: self.arena_lo,
            arena_hi: self.arena_hi,
        }
    }

    pub fn find_gap(&self, length: u64) -> Option<u64> {
        let lo = self.arena_lo;
        let hi = self.arena_hi;
        let try_find = |start: u64, vmas: &[Vma]| -> Option<u64> {
            let mut prev_end = start;
            for v in vmas {
                if v.end <= prev_end {
                    continue;
                }
                if v.start >= prev_end.saturating_add(length) {
                    return Some(prev_end);
                }
                prev_end = prev_end.max(v.end);
            }
            if prev_end.saturating_add(length) <= hi {
                Some(prev_end)
            } else {
                None
            }
        };
        if let Some(a) = try_find(self.last_end.max(lo), &self.vmas) {
            return Some(a);
        }
        try_find(lo, &self.vmas)
    }

    pub fn insert(&mut self, vma: Vma) {
        let pos = self
            .vmas
            .binary_search_by_key(&vma.start, |v| v.start)
            .unwrap_or_else(|p| p);
        self.last_end = vma.end;
        self.vmas.insert(pos, vma);
    }

    pub fn find_containing(&self, addr: u64) -> Option<&Vma> {
        self.vmas
            .iter()
            .find(|&v| addr >= v.start && addr < v.end)
            .map(|v| v as _)
    }

    pub fn overlaps(&self, lo: u64, hi: u64) -> bool {
        self.vmas.iter().any(|v| v.start < hi && v.end > lo)
    }

    pub fn unmap_range(&mut self, lo: u64, hi: u64) -> alloc::vec::Vec<Vma> {
        let mut removed = alloc::vec::Vec::new();
        let mut new_vmas = alloc::vec::Vec::with_capacity(self.vmas.len());
        for v in self.vmas.drain(..) {
            if v.end <= lo || v.start >= hi {
                new_vmas.push(v);
                continue;
            }
            if v.start >= lo && v.end <= hi {
                removed.push(v);
                continue;
            }
            if v.start < lo && v.end > hi {
                let off_left = lo - v.start;
                let off_mid = hi - v.start;
                let backing_left = v.backing.clone();
                let shift_backing = |delta: u64| match &v.backing {
                    VmaBacking::Anonymous => VmaBacking::Anonymous,
                    VmaBacking::Shm { segment } => VmaBacking::Shm {
                        segment: segment.clone(),
                    },
                    VmaBacking::File {
                        inode,
                        file_offset_base,
                    } => VmaBacking::File {
                        inode: inode.clone(),
                        file_offset_base: file_offset_base + delta,
                    },
                };
                let backing_mid = shift_backing(off_left);
                let backing_right = shift_backing(off_mid);
                new_vmas.push(Vma {
                    start: v.start,
                    end: lo,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_left,
                });
                removed.push(Vma {
                    start: lo,
                    end: hi,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_mid,
                });
                new_vmas.push(Vma {
                    start: hi,
                    end: v.end,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_right,
                });
                continue;
            }
            if v.start < lo {
                let backing_kept = v.backing.clone();
                let off_drop = lo - v.start;
                let backing_drop = match &v.backing {
                    VmaBacking::Anonymous => VmaBacking::Anonymous,
                    VmaBacking::Shm { segment } => VmaBacking::Shm {
                        segment: segment.clone(),
                    },
                    VmaBacking::File {
                        inode,
                        file_offset_base,
                    } => VmaBacking::File {
                        inode: inode.clone(),
                        file_offset_base: file_offset_base + off_drop,
                    },
                };
                new_vmas.push(Vma {
                    start: v.start,
                    end: lo,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_kept,
                });
                removed.push(Vma {
                    start: lo,
                    end: v.end,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_drop,
                });
            } else {
                let off_kept = hi - v.start;
                let backing_kept = match &v.backing {
                    VmaBacking::Anonymous => VmaBacking::Anonymous,
                    VmaBacking::Shm { segment } => VmaBacking::Shm {
                        segment: segment.clone(),
                    },
                    VmaBacking::File {
                        inode,
                        file_offset_base,
                    } => VmaBacking::File {
                        inode: inode.clone(),
                        file_offset_base: file_offset_base + off_kept,
                    },
                };
                let backing_drop = v.backing.clone();
                removed.push(Vma {
                    start: v.start,
                    end: hi,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_drop,
                });
                new_vmas.push(Vma {
                    start: hi,
                    end: v.end,
                    prot: v.prot,
                    flags: v.flags,
                    backing: backing_kept,
                });
            }
        }
        new_vmas.sort_by_key(|v| v.start);
        self.vmas = new_vmas;
        removed
    }

    pub fn protect_range(
        &mut self,
        lo: u64,
        hi: u64,
        new_prot: frame::mm::vm::Perms,
    ) -> alloc::vec::Vec<(u64, u64)> {
        fn shift_backing(b: &VmaBacking, delta: u64) -> VmaBacking {
            match b {
                VmaBacking::Anonymous => VmaBacking::Anonymous,
                VmaBacking::Shm { segment } => VmaBacking::Shm {
                    segment: segment.clone(),
                },
                VmaBacking::File {
                    inode,
                    file_offset_base,
                } => VmaBacking::File {
                    inode: inode.clone(),
                    file_offset_base: file_offset_base + delta,
                },
            }
        }

        let mut new_vmas = alloc::vec::Vec::with_capacity(self.vmas.len() + 2);
        let mut gaps = alloc::vec::Vec::new();
        let mut covered_to = lo;
        for v in self.vmas.drain(..) {
            if v.end <= lo || v.start >= hi {
                new_vmas.push(v);
                continue;
            }
            if v.start > covered_to {
                gaps.push((covered_to, v.start));
            }
            let mid_lo = v.start.max(lo);
            let mid_hi = v.end.min(hi);
            if v.start < mid_lo {
                new_vmas.push(Vma {
                    start: v.start,
                    end: mid_lo,
                    prot: v.prot,
                    flags: v.flags,
                    backing: v.backing.clone(),
                });
            }
            new_vmas.push(Vma {
                start: mid_lo,
                end: mid_hi,
                prot: new_prot,
                flags: v.flags,
                backing: shift_backing(&v.backing, mid_lo - v.start),
            });
            if mid_hi < v.end {
                new_vmas.push(Vma {
                    start: mid_hi,
                    end: v.end,
                    prot: v.prot,
                    flags: v.flags,
                    backing: shift_backing(&v.backing, mid_hi - v.start),
                });
            }
            covered_to = covered_to.max(mid_hi);
        }
        if covered_to < hi {
            gaps.push((covered_to, hi));
        }
        new_vmas.sort_by_key(|v| v.start);
        self.vmas = new_vmas;
        gaps
    }
}

#[derive(Clone)]
pub struct Credentials {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    pub groups: alloc::vec::Vec<u32>,
    pub caps_eff: u64,
    pub caps_perm: u64,
    pub caps_inh: u64,
    pub caps_bnd: u64,
    pub user_ns: Option<alloc::sync::Arc<UserNamespace>>,
}

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
    pub _placeholder: u8,
}
impl CgroupNamespace {
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self { _placeholder: 0 })
    }
    pub fn fresh() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self { _placeholder: 0 })
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

impl core::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credentials")
            .field("ruid", &self.ruid)
            .field("euid", &self.euid)
            .field("suid", &self.suid)
            .field("fsuid", &self.fsuid)
            .field("rgid", &self.rgid)
            .field("egid", &self.egid)
            .field("caps_eff", &self.caps_eff)
            .field("user_ns_present", &self.user_ns.is_some())
            .finish()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UserNsDepthExceeded;

pub struct UserNamespace {
    pub parent: Option<alloc::sync::Arc<UserNamespace>>,
    pub creator_uid: u32,
    pub uid_map: frame::sync::SpinIrq<alloc::vec::Vec<IdMapping>>,
    pub gid_map: frame::sync::SpinIrq<alloc::vec::Vec<IdMapping>>,
    pub level: u32,
    pub setgroups_allowed: core::sync::atomic::AtomicBool,
}

pub const OVERFLOW_UID: u32 = 65534;
pub const OVERFLOW_GID: u32 = 65534;

fn id_map_down(map: &[IdMapping], id: u32) -> Option<u32> {
    map.iter().find_map(|m| {
        let off = id.checked_sub(m.inside_start)?;
        if off < m.length {
            m.outside_start.checked_add(off)
        } else {
            None
        }
    })
}

fn id_map_up(map: &[IdMapping], id: u32) -> Option<u32> {
    map.iter().find_map(|m| {
        let off = id.checked_sub(m.outside_start)?;
        if off < m.length {
            m.inside_start.checked_add(off)
        } else {
            None
        }
    })
}

#[derive(Copy, Clone, Debug)]
pub struct IdMapping {
    pub inside_start: u32,
    pub outside_start: u32,
    pub length: u32,
}

impl UserNamespace {
    pub fn host() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            parent: None,
            creator_uid: 0,
            uid_map: frame::sync::SpinIrq::new(alloc::vec::Vec::new()),
            gid_map: frame::sync::SpinIrq::new(alloc::vec::Vec::new()),
            level: 0,
            setgroups_allowed: core::sync::atomic::AtomicBool::new(true),
        })
    }
    pub fn new_child(
        parent: alloc::sync::Arc<Self>,
        creator_uid: u32,
    ) -> Result<alloc::sync::Arc<Self>, UserNsDepthExceeded> {
        let level = parent.level.saturating_add(1);
        if level > 32 {
            return Err(UserNsDepthExceeded);
        }
        Ok(alloc::sync::Arc::new(Self {
            parent: Some(parent),
            creator_uid,
            uid_map: frame::sync::SpinIrq::new(alloc::vec::Vec::new()),
            gid_map: frame::sync::SpinIrq::new(alloc::vec::Vec::new()),
            level,
            setgroups_allowed: core::sync::atomic::AtomicBool::new(true),
        }))
    }

    pub fn uid_to_kernel(&self, ns_uid: u32) -> Option<u32> {
        if self.level == 0 {
            return Some(ns_uid);
        }
        let parent = self.parent.as_ref()?;
        let parent_uid = id_map_down(&self.uid_map.lock(), ns_uid)?;
        parent.uid_to_kernel(parent_uid)
    }
    pub fn uid_from_kernel(&self, kuid: u32) -> Option<u32> {
        if self.level == 0 {
            return Some(kuid);
        }
        let parent = self.parent.as_ref()?;
        let parent_uid = parent.uid_from_kernel(kuid)?;
        id_map_up(&self.uid_map.lock(), parent_uid)
    }
    pub fn gid_to_kernel(&self, ns_gid: u32) -> Option<u32> {
        if self.level == 0 {
            return Some(ns_gid);
        }
        let parent = self.parent.as_ref()?;
        let parent_gid = id_map_down(&self.gid_map.lock(), ns_gid)?;
        parent.gid_to_kernel(parent_gid)
    }
    pub fn gid_from_kernel(&self, kgid: u32) -> Option<u32> {
        if self.level == 0 {
            return Some(kgid);
        }
        let parent = self.parent.as_ref()?;
        let parent_gid = parent.gid_from_kernel(kgid)?;
        id_map_up(&self.gid_map.lock(), parent_gid)
    }
}

pub const MAX_SUPP_GROUPS: usize = 256;

impl Credentials {
    pub fn root() -> Self {
        Self {
            ruid: 0,
            euid: 0,
            suid: 0,
            fsuid: 0,
            rgid: 0,
            egid: 0,
            sgid: 0,
            fsgid: 0,
            groups: alloc::vec::Vec::new(),
            caps_eff: ALL_CAPS_MASK,
            caps_perm: ALL_CAPS_MASK,
            caps_inh: 0,
            caps_bnd: ALL_CAPS_MASK,
            user_ns: None,
        }
    }
    pub fn has_cap(&self, cap: u32) -> bool {
        if cap > CAP_LAST {
            return false;
        }
        self.caps_eff & (1u64 << cap) != 0
    }
    pub fn in_host_user_ns(&self) -> bool {
        match &self.user_ns {
            None => true,
            Some(ns) => ns.level == 0,
        }
    }
    pub fn capable_host(&self, cap: u32) -> bool {
        self.has_cap(cap) && self.in_host_user_ns()
    }
    pub fn uid_into_kernel(&self, ns_uid: u32) -> Option<u32> {
        match &self.user_ns {
            None => Some(ns_uid),
            Some(ns) => ns.uid_to_kernel(ns_uid),
        }
    }
    pub fn uid_from_kernel(&self, kuid: u32) -> u32 {
        match &self.user_ns {
            None => kuid,
            Some(ns) => ns.uid_from_kernel(kuid).unwrap_or(OVERFLOW_UID),
        }
    }
    pub fn gid_into_kernel(&self, ns_gid: u32) -> Option<u32> {
        match &self.user_ns {
            None => Some(ns_gid),
            Some(ns) => ns.gid_to_kernel(ns_gid),
        }
    }
    pub fn gid_from_kernel(&self, kgid: u32) -> u32 {
        match &self.user_ns {
            None => kgid,
            Some(ns) => ns.gid_from_kernel(kgid).unwrap_or(OVERFLOW_GID),
        }
    }
    pub fn is_privileged(&self) -> bool {
        self.capable_host(CAP_DAC_OVERRIDE)
    }
    pub fn apply_uid_change_caps(
        &mut self,
        old_ruid: u32,
        old_euid: u32,
        old_suid: u32,
        old_fsuid: u32,
    ) {
        let was_any_root = old_ruid == 0 || old_euid == 0 || old_suid == 0 || old_fsuid == 0;
        let now_any_root = self.ruid == 0 || self.euid == 0 || self.suid == 0 || self.fsuid == 0;
        if was_any_root && !now_any_root {
            self.caps_eff = 0;
            self.caps_perm = 0;
            return;
        }
        if old_euid != 0 && self.euid == 0 {
            self.caps_eff = self.caps_perm;
        } else if old_euid == 0 && self.euid != 0 {
            self.caps_eff = 0;
        }
    }
    pub fn is_in_group(&self, gid: u32) -> bool {
        if self.egid == gid {
            return true;
        }
        self.groups.contains(&gid)
    }

    pub fn can_access(&self, file_uid: u32, file_gid: u32, file_mode: u16, mode_req: u8) -> bool {
        if self.is_privileged() {
            return true;
        }
        let class_bits: u16 = if self.euid == file_uid {
            (file_mode >> 6) & 0o7
        } else if self.is_in_group(file_gid) {
            (file_mode >> 3) & 0o7
        } else {
            file_mode & 0o7
        };
        (class_bits as u8) & mode_req == mode_req
    }

    pub fn can_signal(&self, target: &Credentials) -> bool {
        if self.capable_host(CAP_KILL) {
            return true;
        }
        self.ruid == target.ruid
            || self.ruid == target.suid
            || self.euid == target.ruid
            || self.euid == target.suid
    }
}

pub const SETID_KEEP: u32 = u32::MAX;

pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_DAC_READ_SEARCH: u32 = 2;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_FSETID: u32 = 4;
pub const CAP_KILL: u32 = 5;
pub const CAP_SETGID: u32 = 6;
pub const CAP_SETUID: u32 = 7;
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_LINUX_IMMUTABLE: u32 = 9;
pub const CAP_NET_BIND_SERVICE: u32 = 10;
pub const CAP_NET_BROADCAST: u32 = 11;
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_IPC_LOCK: u32 = 14;
pub const CAP_IPC_OWNER: u32 = 15;
pub const CAP_SYS_MODULE: u32 = 16;
pub const CAP_SYS_RAWIO: u32 = 17;
pub const CAP_SYS_CHROOT: u32 = 18;
pub const CAP_SYS_PTRACE: u32 = 19;
pub const CAP_SYS_PACCT: u32 = 20;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_BOOT: u32 = 22;
pub const CAP_SYS_NICE: u32 = 23;
pub const CAP_SYS_RESOURCE: u32 = 24;
pub const CAP_SYS_TIME: u32 = 25;
pub const CAP_SYS_TTY_CONFIG: u32 = 26;
pub const CAP_MKNOD: u32 = 27;
pub const CAP_LEASE: u32 = 28;
pub const CAP_AUDIT_WRITE: u32 = 29;
pub const CAP_AUDIT_CONTROL: u32 = 30;
pub const CAP_SETFCAP: u32 = 31;
pub const CAP_MAC_OVERRIDE: u32 = 32;
pub const CAP_MAC_ADMIN: u32 = 33;
pub const CAP_SYSLOG: u32 = 34;
pub const CAP_WAKE_ALARM: u32 = 35;
pub const CAP_BLOCK_SUSPEND: u32 = 36;
pub const CAP_AUDIT_READ: u32 = 37;
pub const CAP_PERFMON: u32 = 38;
pub const CAP_BPF: u32 = 39;
pub const CAP_CHECKPOINT_RESTORE: u32 = 40;

pub const CAP_LAST: u32 = CAP_CHECKPOINT_RESTORE;
pub const ALL_CAPS_MASK: u64 = (1u64 << (CAP_LAST + 1)) - 1;

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGKILL: u32 = 9;
pub const SIGTRAP: u32 = 5;
pub const SIGSEGV: u32 = 11;
pub const SIGSTOP: u32 = 19;
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;

pub const NSIG: usize = 64;

use crate::vfs::Inode;
pub use crate::vfs::fd::FdTable;

pub struct CwdState {
    pub inode: Arc<dyn Inode>,
    pub path: String,
}

pub enum FirstLaunch {
    Fresh { entry: u64, user_stack_top: u64 },
    Fork { tf: frame::user::TrapFrame },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessKind {
    User,
    Kernel,
}

pub struct Process {
    pub pid: Pid,
    pub tgid: Pid,
    pub pgid: Pid,
    pub sid: Pid,
    pub creds: alloc::sync::Arc<frame::sync::SpinIrq<Credentials>>,
    pub parent: Option<Pid>,
    pub state: ProcessState,
    pub kind: ProcessKind,
    pub saved: SavedRegs,
    pub addr_space: Option<Arc<AddressSpace>>,
    pub maps_layout: MapsLayout,
    pub fds: Arc<FdTable>,
    pub cwd: Option<CwdState>,
    pub fs_root: Option<Arc<dyn Inode>>,
    pub mount_table: Option<Arc<crate::vfs::MountTable>>,
    pub cmdline: alloc::vec::Vec<u8>,
    pub exe_path: alloc::vec::Vec<u8>,
    pub uts_ns: Option<alloc::sync::Arc<UtsNamespace>>,
    pub ipc_ns: Option<alloc::sync::Arc<IpcNamespace>>,
    pub pid_ns: Option<alloc::sync::Arc<PidNamespace>>,
    pub pending_pid_ns: Option<alloc::sync::Arc<PidNamespace>>,
    pub pending_ipc_ns: Option<alloc::sync::Arc<IpcNamespace>>,
    pub cgroup_ns: Option<alloc::sync::Arc<CgroupNamespace>>,
    pub time_ns: Option<alloc::sync::Arc<TimeNamespace>>,
    pub cgroup: Option<alloc::sync::Arc<crate::cgroup::Cgroup>>,
    pub cgroup_charged_bytes: u64,
    pub seccomp_filters: alloc::vec::Vec<alloc::sync::Arc<crate::bpf::BpfProgram>>,
    pub no_new_privs: bool,
    pub pending_signals: u64,
    pub blocked_signals: u64,
    pub sigactions: Arc<frame::sync::SpinIrq<[SigAction; NSIG]>>,
    pub task: Task,
    pub first_launch: Option<FirstLaunch>,
    pub home_cpu: u32,
    pub sched_owner: SchedOwner,
    pub pml4_root: Option<PhysFrame<Size4KiB>>,
    pub children: alloc::vec::Vec<Pid>,
    pub child_exit: crate::wait::WaitQueue,
    pub exit_waiters: crate::wait::WaitQueue,
    pub signalfd_waiters: crate::wait::WaitQueue,
    pub vfork_done: crate::wait::WaitQueue,
    pub vfork_done_set: core::sync::atomic::AtomicBool,
    pub vfork_shared_vm: core::sync::atomic::AtomicBool,
    pub did_memfd_exec: core::sync::atomic::AtomicBool,
    pub child_subreaper: core::sync::atomic::AtomicBool,
    pub pdeathsig: core::sync::atomic::AtomicU32,
    pub dumpable: core::sync::atomic::AtomicU32,
    pub keep_caps: core::sync::atomic::AtomicBool,
    pub fs_base: u64,
    pub clear_child_tid: u64,
    pub robust_list_head: u64,
    pub name: [u8; 16],
    pub rlimits: [Option<Rlimit>; 16],
    pub umask: u16,
    pub rseq_addr: u64,
    pub rseq_len: u32,
    pub rseq_sig: u32,
    pub nice: i8,
    pub sched_class: SchedClass,
    pub vruntime: u64,
    pub weight: u64,
    pub last_run_ns: u64,
    pub pi_blocked_on: Option<crate::futex::Key>,
    pub pi_held: alloc::vec::Vec<crate::futex::Key>,
    pub dl_runtime_remaining: u64,
    pub dl_absolute_deadline: u64,
    pub dl_next_replenish: u64,
    pub dl_throttled: bool,
    pub total_cpu_ns: u64,
    pub total_stime_ns: u64,
    pub total_utime_ns: u64,
    pub minflt: u64,
    pub majflt: u64,
    pub cutime_ns: u64,
    pub cstime_ns: u64,
    pub in_syscall: bool,
    pub itimer_real_interval_ns: u64,
    pub itimer_real_deadline_ns: u64,
    pub pi_orig_class: Option<SchedClass>,
    pub siginfo: [crate::signal::PendingSigInfo; NSIG],
    pub altstack: crate::signal::AltStack,
    pub tracer_pid: Option<Pid>,
    pub tracees: alloc::vec::Vec<Pid>,
    pub trace_stop: Option<TraceStop>,
    pub trace_options: u64,
    pub trace_in_syscall_stop_mode: bool,
    pub pending_event_stop: Option<TraceStop>,
    pub trace_pending_inject: u32,
    pub trace_wait_consumed: bool,
    pub trace_event_msg: u64,
    pub trace_saved_regs: Option<crate::ptrace::UserRegs>,
}

#[derive(Copy, Clone, Debug)]
pub struct Rlimit {
    pub cur: u64,
    pub max: u64,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct SigAction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

pub mod sa {
    pub const SA_NOCLDSTOP: u64 = 0x0000_0001;
    pub const SA_NOCLDWAIT: u64 = 0x0000_0002;
    pub const SA_SIGINFO: u64 = 0x0000_0004;
    pub const SA_RESTORER: u64 = 0x0400_0000;
    pub const SA_ONSTACK: u64 = 0x0800_0000;
    pub const SA_RESTART: u64 = 0x1000_0000;
    pub const SA_NODEFER: u64 = 0x4000_0000;
    pub const SA_RESETHAND: u64 = 0x8000_0000;
}

impl Process {
    pub fn vmspace(
        &self,
    ) -> Option<alloc::sync::Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>> {
        self.addr_space.as_ref().map(|a| a.vmspace.clone())
    }

    pub fn new(pid: Pid, entry: u64, user_stack_top: u64, _brk_start: u64) -> Self {
        let task = Task::spawn(crate::sched::first_launch_trampoline);
        Self {
            pid,
            tgid: pid,
            pgid: pid,
            sid: pid,
            parent: None,
            state: ProcessState::Runnable,
            kind: ProcessKind::User,
            saved: SavedRegs::fresh(entry, user_stack_top),
            addr_space: None,
            maps_layout: MapsLayout::default(),
            fds: Arc::new(FdTable::new()),
            cwd: None,
            fs_root: None,
            mount_table: None,
            cmdline: alloc::vec::Vec::new(),
            exe_path: alloc::vec::Vec::new(),
            uts_ns: None,
            ipc_ns: None,
            pid_ns: None,
            pending_pid_ns: None,
            pending_ipc_ns: None,
            cgroup_ns: None,
            time_ns: None,
            cgroup: None,
            cgroup_charged_bytes: 0,
            seccomp_filters: alloc::vec::Vec::new(),
            no_new_privs: false,
            pending_signals: 0,
            blocked_signals: 0,
            sigactions: Arc::new(frame::sync::SpinIrq::new(
                [SigAction {
                    handler: 0,
                    flags: 0,
                    restorer: 0,
                    mask: 0,
                }; NSIG],
            )),
            creds: alloc::sync::Arc::new(frame::sync::SpinIrq::new(Credentials::root())),
            task,
            first_launch: Some(FirstLaunch::Fresh {
                entry,
                user_stack_top,
            }),
            home_cpu: 0,
            pml4_root: None,
            sched_owner: SchedOwner::None,
            children: alloc::vec::Vec::new(),
            child_exit: crate::wait::WaitQueue::new(),
            exit_waiters: crate::wait::WaitQueue::new(),
            signalfd_waiters: crate::wait::WaitQueue::new(),
            vfork_done: crate::wait::WaitQueue::new(),
            vfork_done_set: core::sync::atomic::AtomicBool::new(false),
            vfork_shared_vm: core::sync::atomic::AtomicBool::new(false),
            did_memfd_exec: core::sync::atomic::AtomicBool::new(false),
            child_subreaper: core::sync::atomic::AtomicBool::new(false),
            pdeathsig: core::sync::atomic::AtomicU32::new(0),
            dumpable: core::sync::atomic::AtomicU32::new(1),
            keep_caps: core::sync::atomic::AtomicBool::new(false),
            fs_base: 0,
            clear_child_tid: 0,
            robust_list_head: 0,
            name: [0u8; 16],
            rlimits: [None; 16],
            umask: 0o022,
            rseq_addr: 0,
            rseq_len: 0,
            rseq_sig: 0,
            nice: 0,
            sched_class: SchedClass::default_cfs(),
            vruntime: 0,
            weight: NICE_0_LOAD,
            last_run_ns: 0,
            pi_blocked_on: None,
            pi_held: alloc::vec::Vec::new(),
            pi_orig_class: None,
            dl_runtime_remaining: 0,
            dl_absolute_deadline: 0,
            dl_next_replenish: 0,
            dl_throttled: false,
            total_cpu_ns: 0,
            total_stime_ns: 0,
            total_utime_ns: 0,
            in_syscall: false,
            minflt: 0,
            majflt: 0,
            cutime_ns: 0,
            cstime_ns: 0,
            itimer_real_interval_ns: 0,
            itimer_real_deadline_ns: 0,
            siginfo: [crate::signal::PendingSigInfo::default(); NSIG],
            altstack: crate::signal::AltStack::disabled(),
            tracer_pid: None,
            tracees: alloc::vec::Vec::new(),
            trace_stop: None,
            trace_options: 0,
            trace_in_syscall_stop_mode: false,
            pending_event_stop: None,
            trace_pending_inject: 0,
            trace_wait_consumed: false,
            trace_saved_regs: None,
            trace_event_msg: 0,
        }
    }

    pub fn new_kthread(pid: Pid, entry: extern "C" fn() -> !) -> Self {
        let task = Task::spawn(entry);
        Self {
            pid,
            tgid: pid,
            pgid: pid,
            sid: pid,
            parent: None,
            state: ProcessState::Runnable,
            kind: ProcessKind::Kernel,
            saved: SavedRegs::fresh(0, 0),
            addr_space: None,
            maps_layout: MapsLayout::default(),
            fds: Arc::new(FdTable::new()),
            cwd: None,
            fs_root: None,
            mount_table: None,
            cmdline: alloc::vec::Vec::new(),
            exe_path: alloc::vec::Vec::new(),
            uts_ns: None,
            ipc_ns: None,
            pid_ns: None,
            pending_pid_ns: None,
            pending_ipc_ns: None,
            cgroup_ns: None,
            time_ns: None,
            cgroup: None,
            cgroup_charged_bytes: 0,
            seccomp_filters: alloc::vec::Vec::new(),
            no_new_privs: false,
            pending_signals: 0,
            blocked_signals: 0,
            sigactions: Arc::new(frame::sync::SpinIrq::new(
                [SigAction {
                    handler: 0,
                    flags: 0,
                    restorer: 0,
                    mask: 0,
                }; NSIG],
            )),
            creds: alloc::sync::Arc::new(frame::sync::SpinIrq::new(Credentials::root())),
            task,
            first_launch: None,
            home_cpu: 0,
            pml4_root: None,
            sched_owner: SchedOwner::None,
            children: alloc::vec::Vec::new(),
            child_exit: crate::wait::WaitQueue::new(),
            exit_waiters: crate::wait::WaitQueue::new(),
            signalfd_waiters: crate::wait::WaitQueue::new(),
            vfork_done: crate::wait::WaitQueue::new(),
            vfork_done_set: core::sync::atomic::AtomicBool::new(false),
            vfork_shared_vm: core::sync::atomic::AtomicBool::new(false),
            did_memfd_exec: core::sync::atomic::AtomicBool::new(false),
            child_subreaper: core::sync::atomic::AtomicBool::new(false),
            pdeathsig: core::sync::atomic::AtomicU32::new(0),
            dumpable: core::sync::atomic::AtomicU32::new(1),
            keep_caps: core::sync::atomic::AtomicBool::new(false),
            fs_base: 0,
            clear_child_tid: 0,
            robust_list_head: 0,
            name: [0u8; 16],
            rlimits: [None; 16],
            umask: 0o022,
            rseq_addr: 0,
            rseq_len: 0,
            rseq_sig: 0,
            nice: 0,
            sched_class: SchedClass::default_cfs(),
            vruntime: 0,
            weight: NICE_0_LOAD,
            last_run_ns: 0,
            pi_blocked_on: None,
            pi_held: alloc::vec::Vec::new(),
            pi_orig_class: None,
            dl_runtime_remaining: 0,
            dl_absolute_deadline: 0,
            dl_next_replenish: 0,
            dl_throttled: false,
            total_cpu_ns: 0,
            total_stime_ns: 0,
            total_utime_ns: 0,
            in_syscall: false,
            minflt: 0,
            majflt: 0,
            cutime_ns: 0,
            cstime_ns: 0,
            itimer_real_interval_ns: 0,
            itimer_real_deadline_ns: 0,
            siginfo: [crate::signal::PendingSigInfo::default(); NSIG],
            altstack: crate::signal::AltStack::disabled(),
            tracer_pid: None,
            tracees: alloc::vec::Vec::new(),
            trace_stop: None,
            trace_options: 0,
            trace_in_syscall_stop_mode: false,
            pending_event_stop: None,
            trace_pending_inject: 0,
            trace_wait_consumed: false,
            trace_saved_regs: None,
            trace_event_msg: 0,
        }
    }
}
