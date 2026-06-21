pub mod blocking;
pub mod fd;
pub mod locks;
pub mod mount;
pub mod path;
pub mod pipe;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InodeKind {
    Regular,
    Directory,
    CharDevice,
    Symlink,
    Pipe,
    Socket,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct TimeSpec {
    pub sec: i64,
    pub nsec: i32,
}

#[derive(Copy, Clone, Debug)]
pub struct Stat {
    pub size: u64,
    pub kind: InodeKind,
    pub mode: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub inode_id: u64,
    pub dev_id: u64,
    pub blksize: u32,
    pub blocks: u64,
    pub atime: TimeSpec,
    pub mtime: TimeSpec,
    pub ctime: TimeSpec,
}

impl Stat {
    pub const fn fresh(kind: InodeKind, size: u64, mode: u16) -> Self {
        Self {
            size,
            kind,
            mode,
            nlink: 1,
            uid: 0,
            gid: 0,
            inode_id: 0,
            dev_id: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec { sec: 0, nsec: 0 },
            mtime: TimeSpec { sec: 0, nsec: 0 },
            ctime: TimeSpec { sec: 0, nsec: 0 },
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FsError {
    NotFound,
    NotDir,
    NotFile,
    Exists,
    InvalidArgument,
    PermissionDenied,
    Io,
    NotSupported,
    NotEmpty,
    WouldBlock,
    BrokenPipe,
    NameTooLong,
    Interrupted,
    NoSpace,
    Range,
}

impl FsError {
    pub fn errno(self) -> i64 {
        match self {
            FsError::NotFound => -2,
            FsError::Io => -5,
            FsError::PermissionDenied => -13,
            FsError::Exists => -17,
            FsError::NotDir => -20,
            FsError::NotFile => -21,
            FsError::InvalidArgument => -22,
            FsError::WouldBlock => -11,
            FsError::BrokenPipe => -32,
            FsError::NameTooLong => -36,
            FsError::NotEmpty => -39,
            FsError::NotSupported => -38,
            FsError::Interrupted => -4,
            FsError::NoSpace => -28,
            FsError::Range => -34,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub kind: InodeKind,
    pub inode_id: u64,
}

pub trait Inode: Send + Sync {
    fn kind(&self) -> InodeKind;
    fn stat(&self) -> Stat;

    fn inode_id(&self) -> u64 {
        self as *const Self as *const () as u64
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<usize, FsError> {
        Err(FsError::NotFile)
    }

    fn read_at_with_flags(
        &self,
        offset: u64,
        buf: &mut [u8],
        _flags: OpenFlags,
    ) -> Result<usize, FsError> {
        self.read_at(offset, buf)
    }

    fn peek_at(&self, _buf: &mut [u8]) -> Result<usize, FsError> {
        Err(FsError::NotSupported)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<usize, FsError> {
        Err(FsError::NotFile)
    }

    fn write_at_with_flags(
        &self,
        offset: u64,
        buf: &[u8],
        _flags: OpenFlags,
    ) -> Result<usize, FsError> {
        self.write_at(offset, buf)
    }

    fn write_with_fds(&self, buf: &[u8], fds: Vec<Arc<OpenFile>>) -> Result<usize, FsError> {
        if !fds.is_empty() {
            return Err(FsError::NotSupported);
        }
        self.write_at(0, buf)
    }

    fn read_with_fds(&self, buf: &mut [u8]) -> Result<(usize, Vec<Arc<OpenFile>>), FsError> {
        let n = self.read_at(0, buf)?;
        Ok((n, Vec::new()))
    }

    fn truncate(&self, _len: u64) -> Result<(), FsError> {
        Err(FsError::NotFile)
    }

    fn lookup(&self, _name: &str) -> Result<Arc<dyn Inode>, FsError> {
        Err(FsError::NotDir)
    }

    fn create(&self, _name: &str, _kind: InodeKind) -> Result<Arc<dyn Inode>, FsError> {
        Err(FsError::NotDir)
    }

    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        Err(FsError::NotDir)
    }

    fn unlink(&self, _name: &str) -> Result<(), FsError> {
        Err(FsError::NotDir)
    }

    fn attach(&self, _name: &str, _child: Arc<dyn Inode>) -> Result<(), FsError> {
        Err(FsError::NotSupported)
    }

    fn read_link(&self) -> Result<String, FsError> {
        Err(FsError::NotSupported)
    }

    fn magic_resolve(&self) -> Option<Arc<dyn Inode>> {
        None
    }

    fn symlink(&self, _name: &str, _target: &str) -> Result<Arc<dyn Inode>, FsError> {
        Err(FsError::NotDir)
    }

    fn rename(
        &self,
        old_name: &str,
        new_parent: &Arc<dyn Inode>,
        new_name: &str,
    ) -> Result<(), FsError> {
        let inode = self.lookup(old_name)?;
        new_parent.attach(new_name, inode)?;
        self.unlink(old_name)?;
        Ok(())
    }

    fn on_open(&self, _flags: OpenFlags) {}
    fn on_close(&self, _flags: OpenFlags) {}

    fn is_drm_card(&self) -> bool {
        false
    }

    fn set_mode(&self, _mode: u16) -> Result<(), FsError> {
        Err(FsError::NotSupported)
    }

    fn set_owner(&self, _uid: Option<u32>, _gid: Option<u32>) -> Result<(), FsError> {
        Err(FsError::NotSupported)
    }

    fn set_times(&self, _atime: Option<TimeSpec>, _mtime: Option<TimeSpec>) -> Result<(), FsError> {
        Err(FsError::NotSupported)
    }

    fn link(&self, _name: &str, _target: Arc<dyn Inode>) -> Result<(), FsError> {
        Err(FsError::NotSupported)
    }

    fn bump_nlink(&self) {}

    fn drop_nlink(&self) {}

    fn rmdir(&self, name: &str) -> Result<(), FsError> {
        self.unlink(name)
    }

    fn seal_if_empty_dir(&self) -> Result<(), FsError> {
        if self.kind() != InodeKind::Directory {
            return Err(FsError::NotDir);
        }
        if !self.list()?.is_empty() {
            return Err(FsError::NotEmpty);
        }
        Ok(())
    }

    fn unseal_dir(&self) {}

    fn unlink_if_matches(&self, name: &str, _expect: &Arc<dyn Inode>) -> Result<bool, FsError> {
        self.unlink(name).map(|_| true)
    }

    fn mknod(&self, _name: &str, _kind: InodeKind, _dev: u64) -> Result<Arc<dyn Inode>, FsError> {
        Err(FsError::NotSupported)
    }

    fn set_xattr(&self, _name: &str, _value: &[u8], _flags: u32) -> Result<(), FsError> {
        Err(FsError::NotSupported)
    }

    fn get_xattr(&self, _name: &str, _buf: &mut [u8]) -> Result<usize, FsError> {
        Err(FsError::NotSupported)
    }

    fn list_xattr(&self, _buf: &mut [u8]) -> Result<usize, FsError> {
        Err(FsError::NotSupported)
    }

    fn remove_xattr(&self, _name: &str) -> Result<(), FsError> {
        Err(FsError::NotSupported)
    }

    fn poll(&self) -> PollMask {
        PollMask::IN | PollMask::OUT
    }

    fn for_each_wait_queue(&self, _f: &mut dyn FnMut(&crate::wait::WaitQueue)) {}

    fn as_socket(&self) -> Option<&dyn crate::net::Socket> {
        None
    }

    fn as_namespace_handle(&self) -> Option<&crate::fdtypes::NamespaceHandle> {
        None
    }
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct PollMask: u32 {
        const IN  = 0x001;
        const OUT = 0x004;
        const ERR = 0x008;
        const HUP = 0x010;
    }
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct OpenFlags: u32 {
        const RDONLY    = 0o0;
        const WRONLY    = 0o1;
        const RDWR      = 0o2;
        const CREAT     = 0o100;
        const EXCL      = 0o200;
        const TRUNC     = 0o1000;
        const APPEND    = 0o2000;
        const NONBLOCK  = 0o4000;
        const DIRECTORY = 0o200000;
        const NOFOLLOW  = 0o400000;
        const CLOEXEC   = 0o2000000;
        const PATH      = 0o10000000;
    }
}

impl OpenFlags {
    pub fn is_writable(self) -> bool {
        self.contains(OpenFlags::WRONLY) || self.contains(OpenFlags::RDWR)
    }
    pub fn is_readable(self) -> bool {
        !self.contains(OpenFlags::WRONLY)
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Whence {
    Set,
    Cur,
    End,
}

pub struct OpenFile {
    pub inode: Arc<dyn Inode>,
    flags_bits: core::sync::atomic::AtomicU32,
    pub offset: frame::sync::SpinIrq<u64>,
    pub _mount_guard: Option<MountInUseGuard>,
    pub path: String,
}

impl OpenFile {
    pub fn new(inode: Arc<dyn Inode>, flags: OpenFlags) -> Self {
        Self::new_with_mount(inode, flags, None)
    }

    pub fn new_with_mount(
        inode: Arc<dyn Inode>,
        flags: OpenFlags,
        mount_guard: Option<MountInUseGuard>,
    ) -> Self {
        inode.on_open(flags);
        Self {
            inode,
            flags_bits: core::sync::atomic::AtomicU32::new(flags.bits()),
            offset: frame::sync::SpinIrq::new(0),
            _mount_guard: mount_guard,
            path: String::new(),
        }
    }

    pub fn new_no_open(inode: Arc<dyn Inode>, flags: OpenFlags) -> Self {
        Self {
            inode,
            flags_bits: core::sync::atomic::AtomicU32::new(flags.bits()),
            offset: frame::sync::SpinIrq::new(0),
            _mount_guard: None,
            path: String::new(),
        }
    }

    pub fn with_path(mut self, path: String) -> Self {
        self.path = path;
        self
    }

    pub fn flags(&self) -> OpenFlags {
        OpenFlags::from_bits_truncate(self.flags_bits.load(core::sync::atomic::Ordering::Relaxed))
    }

    pub fn set_flags_subset(&self, new_flags: OpenFlags) {
        const MUTABLE: u32 = OpenFlags::APPEND.bits() | OpenFlags::NONBLOCK.bits();
        let new_bits = new_flags.bits() & MUTABLE;
        let cur = self.flags_bits.load(core::sync::atomic::Ordering::Relaxed);
        let next = (cur & !MUTABLE) | new_bits;
        self.flags_bits
            .store(next, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, FsError> {
        let f = self.flags();
        if !f.is_readable() {
            return Err(FsError::PermissionDenied);
        }
        let off = *self.offset.lock();
        let n = self.inode.read_at_with_flags(off, buf, f)?;
        *self.offset.lock() = off.saturating_add(n as u64);
        Ok(n)
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, FsError> {
        let f = self.flags();
        if !f.is_writable() {
            return Err(FsError::PermissionDenied);
        }
        let off = if f.contains(OpenFlags::APPEND) {
            self.inode.stat().size
        } else {
            *self.offset.lock()
        };
        let n = self.inode.write_at_with_flags(off, buf, f)?;
        *self.offset.lock() = off.saturating_add(n as u64);
        Ok(n)
    }

    pub fn seek(&self, whence: Whence, pos: i64) -> Result<u64, FsError> {
        let mut cur = self.offset.lock();
        let new = match whence {
            Whence::Set => pos.max(0) as u64,
            Whence::Cur => (*cur as i64 + pos).max(0) as u64,
            Whence::End => (self.inode.stat().size as i64 + pos).max(0) as u64,
        };
        *cur = new;
        Ok(new)
    }
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        let ofd_key = self as *const OpenFile as usize as u64;
        crate::vfs::locks::bsd::drop_ofd(ofd_key);
        self.inode.on_close(self.flags());
    }
}

mod root {
    use super::*;
    use frame::sync::SpinIrq;

    static ROOT: SpinIrq<Option<Arc<dyn Inode>>> = SpinIrq::new(None);

    pub fn set(inode: Arc<dyn Inode>) {
        *ROOT.lock() = Some(inode);
    }

    pub fn get() -> Arc<dyn Inode> {
        ROOT.lock()
            .as_ref()
            .expect("vfs root not installed")
            .clone()
    }

    pub fn try_get() -> Option<Arc<dyn Inode>> {
        ROOT.lock().as_ref().cloned()
    }
}

pub use root::{get as root_inode, set as set_root, try_get as try_root_inode};

use alloc::collections::BTreeMap;

use frame::sync::SpinIrq as VfsSpinIrq;

pub struct PeerGroup {
    members: VfsSpinIrq<alloc::vec::Vec<(alloc::sync::Weak<MountTable>, String)>>,
    slaves: VfsSpinIrq<alloc::vec::Vec<(alloc::sync::Weak<MountTable>, String)>>,
}

impl PeerGroup {
    pub fn new_empty() -> Arc<Self> {
        Arc::new(Self {
            members: VfsSpinIrq::new(alloc::vec::Vec::new()),
            slaves: VfsSpinIrq::new(alloc::vec::Vec::new()),
        })
    }

    fn add_member(&self, table: alloc::sync::Weak<MountTable>, path: String) {
        let mut g = self.members.lock();
        if !g
            .iter()
            .any(|(t, p)| alloc::sync::Weak::ptr_eq(t, &table) && p == &path)
        {
            g.push((table, path));
        }
    }

    fn add_slave(&self, table: alloc::sync::Weak<MountTable>, path: String) {
        let mut g = self.slaves.lock();
        if !g
            .iter()
            .any(|(t, p)| alloc::sync::Weak::ptr_eq(t, &table) && p == &path)
        {
            g.push((table, path));
        }
    }

    fn remove_member(&self, table: &alloc::sync::Weak<MountTable>, path: &str) {
        self.members
            .lock()
            .retain(|(t, p)| !(alloc::sync::Weak::ptr_eq(t, table) && p == path));
    }

    fn remove_slave(&self, table: &alloc::sync::Weak<MountTable>, path: &str) {
        self.slaves
            .lock()
            .retain(|(t, p)| !(alloc::sync::Weak::ptr_eq(t, table) && p == path));
    }

    pub fn snapshot_members(&self) -> alloc::vec::Vec<(Arc<MountTable>, String)> {
        let mut g = self.members.lock();
        let mut out = alloc::vec::Vec::with_capacity(g.len());
        g.retain(|(weak, path)| {
            if let Some(strong) = weak.upgrade() {
                out.push((strong, path.clone()));
                true
            } else {
                false
            }
        });
        out
    }

    pub fn snapshot_slaves(&self) -> alloc::vec::Vec<(Arc<MountTable>, String)> {
        let mut g = self.slaves.lock();
        let mut out = alloc::vec::Vec::with_capacity(g.len());
        g.retain(|(weak, path)| {
            if let Some(strong) = weak.upgrade() {
                out.push((strong, path.clone()));
                true
            } else {
                false
            }
        });
        out
    }
}

#[derive(Clone)]
pub enum MountPropagation {
    Private,
    Shared(Arc<PeerGroup>),
    Slave(Arc<PeerGroup>),
    Unbindable,
}

impl MountPropagation {
    pub fn is_shared(&self) -> bool {
        matches!(self, MountPropagation::Shared(_))
    }
    pub fn is_slave(&self) -> bool {
        matches!(self, MountPropagation::Slave(_))
    }
    pub fn is_private(&self) -> bool {
        matches!(self, MountPropagation::Private)
    }
    pub fn is_unbindable(&self) -> bool {
        matches!(self, MountPropagation::Unbindable)
    }
    pub fn shared_group(&self) -> Option<Arc<PeerGroup>> {
        if let MountPropagation::Shared(g) = self {
            Some(g.clone())
        } else {
            None
        }
    }
    pub fn slave_group(&self) -> Option<Arc<PeerGroup>> {
        if let MountPropagation::Slave(g) = self {
            Some(g.clone())
        } else {
            None
        }
    }
}

pub struct MountInUseTag {
    refs: core::sync::atomic::AtomicUsize,
}

impl MountInUseTag {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            refs: core::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub fn refs(&self) -> usize {
        self.refs.load(core::sync::atomic::Ordering::SeqCst)
    }
}

pub struct MountInUseGuard {
    tag: Arc<MountInUseTag>,
}

impl MountInUseGuard {
    pub fn new(tag: Arc<MountInUseTag>) -> Self {
        tag.refs.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        Self { tag }
    }
}

impl Drop for MountInUseGuard {
    fn drop(&mut self) {
        self.tag
            .refs
            .fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    }
}

impl Clone for MountInUseGuard {
    fn clone(&self) -> Self {
        Self::new(self.tag.clone())
    }
}

#[derive(Clone)]
pub struct MountEntry {
    pub target_inode_id: u64,
    pub root: Arc<dyn Inode>,
    pub propagation: MountPropagation,
    pub in_use: Arc<MountInUseTag>,
    pub source: String,
    pub fstype: String,
}

struct MountTableInner {
    mounts: BTreeMap<String, MountEntry>,
}

impl MountTableInner {
    const fn new() -> Self {
        Self {
            mounts: BTreeMap::new(),
        }
    }
}

pub struct MountTable {
    inner: VfsSpinIrq<MountTableInner>,
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct InstallEffects {
    pub mirrors: Vec<String>,
}

impl MountTable {
    pub const fn new() -> Self {
        Self {
            inner: VfsSpinIrq::new(MountTableInner::new()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install(
        self: &Arc<Self>,
        target_path: &str,
        target_inode_id: u64,
        root: Arc<dyn Inode>,
        propagation: MountPropagation,
        source: &str,
        fstype: &str,
    ) {
        let weak = Arc::downgrade(self);
        let mut g = self.inner.lock();
        Self::install_locked(
            &mut g,
            &weak,
            target_path,
            target_inode_id,
            root,
            propagation,
            source,
            fstype,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn install_locked(
        g: &mut MountTableInner,
        self_weak: &alloc::sync::Weak<MountTable>,
        target_path: &str,
        target_inode_id: u64,
        root: Arc<dyn Inode>,
        propagation: MountPropagation,
        source: &str,
        fstype: &str,
    ) {
        if let Some(prev) = g.mounts.get(target_path) {
            match &prev.propagation {
                MountPropagation::Shared(pg) => pg.remove_member(self_weak, target_path),
                MountPropagation::Slave(pg) => pg.remove_slave(self_weak, target_path),
                _ => {}
            }
        }
        match &propagation {
            MountPropagation::Shared(pg) => {
                pg.add_member(self_weak.clone(), String::from(target_path));
            }
            MountPropagation::Slave(pg) => {
                pg.add_slave(self_weak.clone(), String::from(target_path));
            }
            _ => {}
        }
        let in_use = match g.mounts.get(target_path) {
            Some(prev) => prev.in_use.clone(),
            None => MountInUseTag::new(),
        };
        g.mounts.insert(
            String::from(target_path),
            MountEntry {
                target_inode_id,
                root,
                propagation,
                in_use,
                source: String::from(source),
                fstype: String::from(fstype),
            },
        );
    }

    pub fn lookup(&self, target_path: &str) -> Option<Arc<dyn Inode>> {
        self.inner
            .lock()
            .mounts
            .get(target_path)
            .map(|e| e.root.clone())
    }

    pub fn snapshot_one(&self, target_path: &str) -> Option<MountEntry> {
        self.inner.lock().mounts.get(target_path).cloned()
    }

    pub fn remove(self: &Arc<Self>, target_path: &str) -> Option<Arc<dyn Inode>> {
        let weak = Arc::downgrade(self);
        let mut g = self.inner.lock();
        Self::remove_locked(&mut g, &weak, target_path)
    }

    fn remove_locked(
        g: &mut MountTableInner,
        self_weak: &alloc::sync::Weak<MountTable>,
        target_path: &str,
    ) -> Option<Arc<dyn Inode>> {
        let entry = g.mounts.remove(target_path)?;
        match &entry.propagation {
            MountPropagation::Shared(pg) => pg.remove_member(self_weak, target_path),
            MountPropagation::Slave(pg) => pg.remove_slave(self_weak, target_path),
            _ => {}
        }
        Some(entry.root)
    }

    pub fn is_mountpoint_inode(&self, inode_id: u64) -> bool {
        let g = self.inner.lock();
        g.mounts.values().any(|e| e.target_inode_id == inode_id)
    }

    pub fn containing_mount(&self, path: &str) -> Option<MountEntry> {
        let g = self.inner.lock();
        Self::containing_mount_locked(&g, path).map(|(_, v)| v.clone())
    }

    pub fn containing_mount_with_path(&self, path: &str) -> Option<(String, MountEntry)> {
        let g = self.inner.lock();
        Self::containing_mount_locked(&g, path).map(|(k, v)| (k.clone(), v.clone()))
    }

    fn containing_mount_locked<'a>(
        g: &'a MountTableInner,
        path: &str,
    ) -> Option<(&'a String, &'a MountEntry)> {
        let mut best: Option<(&String, &MountEntry)> = None;
        for (k, v) in g.mounts.iter() {
            if path == k.as_str()
                || (path.starts_with(k.as_str())
                    && (k == "/" || path.as_bytes().get(k.len()) == Some(&b'/')))
            {
                match best {
                    None => best = Some((k, v)),
                    Some((bk, _)) if k.len() > bk.len() => best = Some((k, v)),
                    _ => {}
                }
            }
        }
        best
    }

    fn proper_containing_mount_locked<'a>(
        g: &'a MountTableInner,
        path: &str,
    ) -> Option<(&'a String, &'a MountEntry)> {
        let mut best: Option<(&String, &MountEntry)> = None;
        for (k, v) in g.mounts.iter() {
            if k.as_str() == path {
                continue;
            }
            if path.starts_with(k.as_str())
                && (k == "/" || path.as_bytes().get(k.len()) == Some(&b'/'))
            {
                match best {
                    None => best = Some((k, v)),
                    Some((bk, _)) if k.len() > bk.len() => best = Some((k, v)),
                    _ => {}
                }
            }
        }
        best
    }

    pub fn proper_containing_mount_with_path(&self, path: &str) -> Option<(String, MountEntry)> {
        let g = self.inner.lock();
        Self::proper_containing_mount_locked(&g, path).map(|(k, v)| (k.clone(), v.clone()))
    }

    pub fn collect_subtree(&self, prefix: &str) -> Vec<(String, MountEntry)> {
        let g = self.inner.lock();
        let mut out = Vec::new();
        for (k, v) in g.mounts.iter() {
            if k.as_str() == prefix {
                out.push((String::new(), v.clone()));
            } else if k.starts_with(prefix)
                && (prefix == "/" || k.as_bytes().get(prefix.len()) == Some(&b'/'))
            {
                let suffix = if prefix == "/" {
                    k.clone()
                } else {
                    String::from(&k[prefix.len()..])
                };
                out.push((suffix, v.clone()));
            }
        }
        out
    }

    pub fn set_propagation(self: &Arc<Self>, path: &str, new_prop: MountPropagation) -> bool {
        let weak = Arc::downgrade(self);
        let mut g = self.inner.lock();
        let existing = match g.mounts.get(path) {
            Some(e) => (
                e.target_inode_id,
                e.root.clone(),
                e.source.clone(),
                e.fstype.clone(),
            ),
            None => return false,
        };
        Self::install_locked(
            &mut g,
            &weak,
            path,
            existing.0,
            existing.1,
            new_prop,
            &existing.2,
            &existing.3,
        );
        true
    }

    pub fn snapshot(self: &Arc<Self>) -> Arc<MountTable> {
        let parent_entries: alloc::vec::Vec<(String, MountEntry)> = {
            let g = self.inner.lock();
            g.mounts
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        Arc::new_cyclic(|child_weak| {
            let mut new_mounts = BTreeMap::new();
            for (path, entry) in parent_entries.iter() {
                match &entry.propagation {
                    MountPropagation::Shared(pg) => {
                        pg.add_member(child_weak.clone(), path.clone());
                    }
                    MountPropagation::Slave(pg) => {
                        pg.add_slave(child_weak.clone(), path.clone());
                    }
                    _ => {}
                }
                new_mounts.insert(path.clone(), entry.clone());
            }
            MountTable {
                inner: VfsSpinIrq::new(MountTableInner { mounts: new_mounts }),
            }
        })
    }
}

static GLOBAL_MOUNTS_SLOT: VfsSpinIrq<Option<Arc<MountTable>>> = VfsSpinIrq::new(None);

pub fn global_mount_table() -> Arc<MountTable> {
    let mut slot = GLOBAL_MOUNTS_SLOT.lock();
    if slot.is_none() {
        *slot = Some(Arc::new(MountTable::new()));
    }
    slot.as_ref().unwrap().clone()
}

pub fn mount_install(
    target_path: &str,
    target_inode_id: u64,
    root: Arc<dyn Inode>,
    propagation: MountPropagation,
    source: &str,
    fstype: &str,
) {
    global_mount_table().install(
        target_path,
        target_inode_id,
        root,
        propagation,
        source,
        fstype,
    );
}

pub fn mount_lookup(target_path: &str) -> Option<Arc<dyn Inode>> {
    global_mount_table().lookup(target_path)
}

pub fn mount_remove(target_path: &str) -> Option<Arc<dyn Inode>> {
    global_mount_table().remove(target_path)
}

pub fn is_mountpoint_inode(per_process: Option<&Arc<MountTable>>, inode_id: u64) -> bool {
    if let Some(m) = per_process {
        if m.is_mountpoint_inode(inode_id) {
            return true;
        }
    }
    global_mount_table().is_mountpoint_inode(inode_id)
}
