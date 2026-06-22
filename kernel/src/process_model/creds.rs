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
    pub loginuid: u32,
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
            loginuid: u32::MAX,
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
