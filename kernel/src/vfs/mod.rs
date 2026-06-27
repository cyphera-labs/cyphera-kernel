pub mod blocking;
pub mod fd;
pub mod locks;
pub mod mount;
pub mod path;
pub mod pipe;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use cyphera_kapi::{Errno, KResult};

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
    pub rdev: u64,
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
            rdev: 0,
            blksize: 4096,
            blocks: 0,
            atime: TimeSpec { sec: 0, nsec: 0 },
            mtime: TimeSpec { sec: 0, nsec: 0 },
            ctime: TimeSpec { sec: 0, nsec: 0 },
        }
    }
}

pub const fn makedev(major: u32, minor: u32) -> u64 {
    let major = major as u64;
    let minor = minor as u64;
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32)
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub kind: InodeKind,
    pub inode_id: u64,
}

pub const F_SEAL_SEAL: u32 = 0x0001;
pub const F_SEAL_SHRINK: u32 = 0x0002;
pub const F_SEAL_GROW: u32 = 0x0004;
pub const F_SEAL_WRITE: u32 = 0x0008;
pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;
pub const SEAL_MASK: u32 =
    F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE;

pub trait Inode: Send + Sync {
    fn kind(&self) -> InodeKind;
    fn stat(&self) -> Stat;

    fn inode_id(&self) -> u64 {
        self as *const Self as *const () as u64
    }

    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(Errno::ISDIR)
    }

    fn read_at_with_flags(&self, offset: u64, buf: &mut [u8], _flags: OpenFlags) -> KResult<usize> {
        self.read_at(offset, buf)
    }

    fn peek_at(&self, _buf: &mut [u8]) -> KResult<usize> {
        Err(Errno::NOSYS)
    }

    fn write_at(&self, _offset: u64, _buf: &[u8]) -> KResult<usize> {
        Err(Errno::ISDIR)
    }

    fn write_at_with_flags(&self, offset: u64, buf: &[u8], _flags: OpenFlags) -> KResult<usize> {
        self.write_at(offset, buf)
    }

    fn writeback_at(&self, offset: u64, buf: &[u8]) -> KResult<usize> {
        self.write_at(offset, buf)
    }

    fn write_with_fds(
        &self,
        buf: &[u8],
        fds: Vec<Arc<OpenFile>>,
        _nonblock: bool,
    ) -> KResult<usize> {
        if !fds.is_empty() {
            return Err(Errno::NOSYS);
        }
        self.write_at(0, buf)
    }

    fn read_with_fds(
        &self,
        buf: &mut [u8],
        _nonblock: bool,
    ) -> KResult<(usize, Vec<Arc<OpenFile>>)> {
        let n = self.read_at(0, buf)?;
        Ok((n, Vec::new()))
    }

    fn truncate(&self, _len: u64) -> KResult<()> {
        Err(Errno::ISDIR)
    }

    fn memfd_seals(&self) -> Option<u32> {
        None
    }

    fn memfd_add_seals(&self, _add: u32, _writable_mapping_exists: bool) -> KResult<()> {
        Err(Errno::INVAL)
    }

    fn lookup(&self, _name: &str) -> KResult<Arc<dyn Inode>> {
        Err(Errno::NOTDIR)
    }

    fn create(&self, _name: &str, _kind: InodeKind) -> KResult<Arc<dyn Inode>> {
        Err(Errno::NOTDIR)
    }

    fn list(&self) -> KResult<Vec<DirEntry>> {
        Err(Errno::NOTDIR)
    }

    fn unlink(&self, _name: &str) -> KResult<()> {
        Err(Errno::NOTDIR)
    }

    fn attach(&self, _name: &str, _child: Arc<dyn Inode>) -> KResult<()> {
        Err(Errno::NOSYS)
    }

    fn read_link(&self) -> KResult<String> {
        Err(Errno::NOSYS)
    }

    fn magic_resolve(&self) -> Option<Arc<dyn Inode>> {
        None
    }

    fn symlink(&self, _name: &str, _target: &str) -> KResult<Arc<dyn Inode>> {
        Err(Errno::NOTDIR)
    }

    fn rename(&self, old_name: &str, new_parent: &Arc<dyn Inode>, new_name: &str) -> KResult<()> {
        let inode = self.lookup(old_name)?;
        new_parent.attach(new_name, inode)?;
        self.unlink(old_name)?;
        Ok(())
    }

    fn rename_exchange(
        &self,
        _old_name: &str,
        _new_parent: &Arc<dyn Inode>,
        _new_name: &str,
    ) -> KResult<()> {
        Err(Errno::NOSYS)
    }

    fn fs_id(&self) -> usize {
        0
    }

    fn check_open(&self, _flags: OpenFlags) -> KResult<()> {
        Ok(())
    }

    fn on_open(&self, _flags: OpenFlags) {}
    fn on_close(&self, _flags: OpenFlags) {}

    fn is_drm_card(&self) -> bool {
        false
    }

    fn is_drm_render(&self) -> bool {
        false
    }

    fn alsa_kind(&self) -> Option<u8> {
        None
    }

    fn evdev_idx(&self) -> Option<usize> {
        None
    }

    fn set_mode(&self, _mode: u16) -> KResult<()> {
        Err(Errno::NOSYS)
    }

    fn set_owner(&self, _uid: Option<u32>, _gid: Option<u32>) -> KResult<()> {
        Err(Errno::NOSYS)
    }

    fn set_times(&self, _atime: Option<TimeSpec>, _mtime: Option<TimeSpec>) -> KResult<()> {
        Err(Errno::NOSYS)
    }

    fn link(&self, _name: &str, _target: Arc<dyn Inode>) -> KResult<()> {
        Err(Errno::NOSYS)
    }

    fn bump_nlink(&self) {}

    fn drop_nlink(&self) {}

    fn rmdir(&self, name: &str) -> KResult<()> {
        self.unlink(name)
    }

    fn seal_if_empty_dir(&self) -> KResult<()> {
        if self.kind() != InodeKind::Directory {
            return Err(Errno::NOTDIR);
        }
        if !self.list()?.is_empty() {
            return Err(Errno::NOTEMPTY);
        }
        Ok(())
    }

    fn unseal_dir(&self) {}

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        None
    }

    fn unlink_if_matches(&self, name: &str, _expect: &Arc<dyn Inode>) -> KResult<bool> {
        self.unlink(name).map(|_| true)
    }

    fn mknod(&self, _name: &str, _kind: InodeKind, _dev: u64) -> KResult<Arc<dyn Inode>> {
        Err(Errno::NOSYS)
    }

    fn set_xattr(&self, _name: &str, _value: &[u8], _flags: u32) -> KResult<()> {
        Err(Errno::NOSYS)
    }

    fn get_xattr(&self, _name: &str, _buf: &mut [u8]) -> KResult<usize> {
        Err(Errno::NOSYS)
    }

    fn list_xattr(&self, _buf: &mut [u8]) -> KResult<usize> {
        Err(Errno::NOSYS)
    }

    fn remove_xattr(&self, _name: &str) -> KResult<()> {
        Err(Errno::NOSYS)
    }

    fn poll(&self) -> PollMask {
        PollMask::IN | PollMask::OUT
    }

    fn for_each_wait_queue(&self, _f: &mut dyn FnMut(&crate::core::wait::WaitQueue)) {}

    fn as_socket(&self) -> Option<&dyn crate::net::Socket> {
        None
    }

    fn as_pipe(&self) -> Option<&crate::vfs::pipe::Pipe> {
        None
    }

    fn as_namespace_handle(&self) -> Option<&crate::ipc::fdtypes::NamespaceHandle> {
        None
    }
}

pub use cyphera_kapi::{OpenFlags, PollMask};

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

    pub fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        let f = self.flags();
        if !f.is_readable() {
            return Err(Errno::ACCES);
        }
        let off = *self.offset.lock();
        let n = self.inode.read_at_with_flags(off, buf, f)?;
        *self.offset.lock() = off.saturating_add(n as u64);
        Ok(n)
    }

    pub fn write(&self, buf: &[u8]) -> KResult<usize> {
        let f = self.flags();
        if !f.is_writable() {
            return Err(Errno::ACCES);
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

    pub fn seek(&self, whence: Whence, pos: i64) -> KResult<u64> {
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
        let flags = self.flags();
        self.inode.on_close(flags);
        if crate::fsnotify::watching() && matches!(self.inode.kind(), InodeKind::Regular) {
            let mask = if flags.is_writable() {
                crate::fsnotify::IN_CLOSE_WRITE
            } else {
                crate::fsnotify::IN_CLOSE_NOWRITE
            };
            crate::fsnotify::self_event(self.inode.as_ref(), mask);
        }
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
    flags: core::sync::atomic::AtomicU64,
}

impl MountInUseTag {
    pub fn new() -> Arc<Self> {
        Self::new_with_flags(0)
    }

    pub fn new_with_flags(flags: u64) -> Arc<Self> {
        Arc::new(Self {
            refs: core::sync::atomic::AtomicUsize::new(0),
            flags: core::sync::atomic::AtomicU64::new(flags),
        })
    }

    pub fn refs(&self) -> usize {
        self.refs.load(core::sync::atomic::Ordering::SeqCst)
    }

    pub fn flags(&self) -> u64 {
        self.flags.load(core::sync::atomic::Ordering::Acquire)
    }

    pub fn set_flags(&self, flags: u64) {
        self.flags
            .store(flags, core::sync::atomic::Ordering::Release);
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

    pub fn flags(&self) -> u64 {
        self.tag.flags()
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

#[derive(Clone)]
struct NodeData {
    target_inode_id: u64,
    root: Arc<dyn Inode>,
    propagation: MountPropagation,
    in_use: Arc<MountInUseTag>,
    source: String,
    fstype: String,
}

impl NodeData {
    fn to_entry(&self) -> MountEntry {
        MountEntry {
            target_inode_id: self.target_inode_id,
            root: self.root.clone(),
            propagation: self.propagation.clone(),
            in_use: self.in_use.clone(),
            source: self.source.clone(),
            fstype: self.fstype.clone(),
        }
    }
}

pub struct MountNode {
    mountpoint: VfsSpinIrq<String>,
    data: VfsSpinIrq<NodeData>,
    parent: VfsSpinIrq<alloc::sync::Weak<MountNode>>,
    children: VfsSpinIrq<Vec<Arc<MountNode>>>,
    shadowed: VfsSpinIrq<Vec<NodeData>>,
}

impl MountNode {
    fn new(mountpoint: String, data: NodeData) -> Arc<Self> {
        Arc::new(Self {
            mountpoint: VfsSpinIrq::new(mountpoint),
            data: VfsSpinIrq::new(data),
            parent: VfsSpinIrq::new(alloc::sync::Weak::new()),
            children: VfsSpinIrq::new(Vec::new()),
            shadowed: VfsSpinIrq::new(Vec::new()),
        })
    }

    fn mountpoint(&self) -> String {
        self.mountpoint.lock().clone()
    }

    fn entry(&self) -> MountEntry {
        self.data.lock().to_entry()
    }

    fn collect_descendants(self: &Arc<Self>, out: &mut Vec<Arc<MountNode>>) {
        for child in self.children.lock().iter() {
            out.push(child.clone());
            child.collect_descendants(out);
        }
    }
}

struct MountTableInner {
    roots: Vec<Arc<MountNode>>,
    by_path: BTreeMap<String, Arc<MountNode>>,
}

impl MountTableInner {
    const fn new() -> Self {
        Self {
            roots: Vec::new(),
            by_path: BTreeMap::new(),
        }
    }

    fn is_descendant_path(child: &str, ancestor: &str) -> bool {
        if ancestor == "/" {
            return child != "/";
        }
        child.starts_with(ancestor) && child.as_bytes().get(ancestor.len()) == Some(&b'/')
    }

    fn deepest_existing_ancestor(&self, path: &str) -> Option<Arc<MountNode>> {
        let mut best: Option<&Arc<MountNode>> = None;
        for (k, v) in self.by_path.iter() {
            if Self::is_descendant_path(path, k) {
                match best {
                    None => best = Some(v),
                    Some(b) if k.len() > b.mountpoint.lock().len() => best = Some(v),
                    _ => {}
                }
            }
        }
        best.cloned()
    }

    fn link_into_tree(&mut self, node: &Arc<MountNode>) {
        let path = node.mountpoint();
        let parent = self.deepest_existing_ancestor(&path);
        let reparent: Vec<Arc<MountNode>> = match &parent {
            Some(p) => {
                let mut moved = Vec::new();
                p.children.lock().retain(|c| {
                    if Self::is_descendant_path(&c.mountpoint(), &path) {
                        moved.push(c.clone());
                        false
                    } else {
                        true
                    }
                });
                moved
            }
            None => {
                let mut moved = Vec::new();
                self.roots.retain(|c| {
                    if Self::is_descendant_path(&c.mountpoint(), &path) {
                        moved.push(c.clone());
                        false
                    } else {
                        true
                    }
                });
                moved
            }
        };
        for c in reparent.iter() {
            *c.parent.lock() = Arc::downgrade(node);
            node.children.lock().push(c.clone());
        }
        match &parent {
            Some(p) => {
                *node.parent.lock() = Arc::downgrade(p);
                p.children.lock().push(node.clone());
            }
            None => {
                *node.parent.lock() = alloc::sync::Weak::new();
                self.roots.push(node.clone());
            }
        }
    }

    fn unlink_from_tree(&mut self, node: &Arc<MountNode>) {
        let parent = node.parent.lock().upgrade();
        let promoted: Vec<Arc<MountNode>> = node.children.lock().drain(..).collect();
        match &parent {
            Some(p) => {
                p.children.lock().retain(|c| !Arc::ptr_eq(c, node));
                for c in promoted.iter() {
                    *c.parent.lock() = Arc::downgrade(p);
                    p.children.lock().push(c.clone());
                }
            }
            None => {
                self.roots.retain(|c| !Arc::ptr_eq(c, node));
                for c in promoted.iter() {
                    *c.parent.lock() = alloc::sync::Weak::new();
                    self.roots.push(c.clone());
                }
            }
        }
        *node.parent.lock() = alloc::sync::Weak::new();
    }
}

pub struct MountTable {
    inner: VfsSpinIrq<MountTableInner>,
    owner_user_ns: Option<Arc<crate::process_model::UserNamespace>>,
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
            owner_user_ns: None,
        }
    }

    pub fn owner_user_ns(&self) -> Option<Arc<crate::process_model::UserNamespace>> {
        self.owner_user_ns.clone()
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub fn install(
        self: &Arc<Self>,
        target_path: &str,
        target_inode_id: u64,
        root: Arc<dyn Inode>,
        propagation: MountPropagation,
        source: &str,
        fstype: &str,
        mount_flags: u64,
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
            mount_flags,
            false,
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
        mount_flags: u64,
        preserve_tag: bool,
    ) {
        match &propagation {
            MountPropagation::Shared(pg) => {
                pg.add_member(self_weak.clone(), String::from(target_path));
            }
            MountPropagation::Slave(pg) => {
                pg.add_slave(self_weak.clone(), String::from(target_path));
            }
            _ => {}
        }

        if let Some(existing) = g.by_path.get(target_path).cloned() {
            let mut old = existing.data.lock();
            match &old.propagation {
                MountPropagation::Shared(pg) => pg.remove_member(self_weak, target_path),
                MountPropagation::Slave(pg) => pg.remove_slave(self_weak, target_path),
                _ => {}
            }
            let in_use = if preserve_tag {
                old.in_use.set_flags(mount_flags);
                old.in_use.clone()
            } else {
                existing.shadowed.lock().push(old.clone());
                MountInUseTag::new_with_flags(mount_flags)
            };
            *old = NodeData {
                target_inode_id,
                root,
                propagation,
                in_use,
                source: String::from(source),
                fstype: String::from(fstype),
            };
            return;
        }

        let data = NodeData {
            target_inode_id,
            root,
            propagation,
            in_use: MountInUseTag::new_with_flags(mount_flags),
            source: String::from(source),
            fstype: String::from(fstype),
        };
        let node = MountNode::new(String::from(target_path), data);
        g.link_into_tree(&node);
        g.by_path.insert(String::from(target_path), node);
    }

    pub fn lookup(&self, target_path: &str) -> Option<Arc<dyn Inode>> {
        self.inner
            .lock()
            .by_path
            .get(target_path)
            .map(|n| n.data.lock().root.clone())
    }

    pub fn set_flags_at(&self, target_path: &str, mount_flags: u64) -> bool {
        match self.inner.lock().by_path.get(target_path) {
            Some(n) => {
                n.data.lock().in_use.set_flags(mount_flags);
                true
            }
            None => false,
        }
    }

    pub fn set_flags_by_inode(&self, inode_id: u64, mount_flags: u64) -> bool {
        let g = self.inner.lock();
        let mut hit: Option<Arc<MountInUseTag>> = None;
        for n in g.by_path.values() {
            let d = n.data.lock();
            if d.root.inode_id() == inode_id {
                if hit.is_some() {
                    return false;
                }
                hit = Some(d.in_use.clone());
            }
        }
        match hit {
            Some(tag) => {
                tag.set_flags(mount_flags);
                true
            }
            None => false,
        }
    }

    pub fn snapshot_one(&self, target_path: &str) -> Option<MountEntry> {
        self.inner
            .lock()
            .by_path
            .get(target_path)
            .map(|n| n.entry())
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
        let node = g.by_path.get(target_path).cloned()?;
        let removed_root;
        let restore = {
            let mut d = node.data.lock();
            match &d.propagation {
                MountPropagation::Shared(pg) => pg.remove_member(self_weak, target_path),
                MountPropagation::Slave(pg) => pg.remove_slave(self_weak, target_path),
                _ => {}
            }
            removed_root = d.root.clone();
            let next = node.shadowed.lock().pop();
            if let Some(under) = next {
                match &under.propagation {
                    MountPropagation::Shared(pg) => {
                        pg.add_member(self_weak.clone(), String::from(target_path));
                    }
                    MountPropagation::Slave(pg) => {
                        pg.add_slave(self_weak.clone(), String::from(target_path));
                    }
                    _ => {}
                }
                *d = under;
                true
            } else {
                false
            }
        };
        if !restore {
            g.unlink_from_tree(&node);
            g.by_path.remove(target_path);
        }
        Some(removed_root)
    }

    pub fn is_mountpoint_inode(&self, inode_id: u64) -> bool {
        let g = self.inner.lock();
        g.by_path
            .values()
            .any(|n| n.data.lock().target_inode_id == inode_id)
    }

    pub fn containing_mount(&self, path: &str) -> Option<MountEntry> {
        self.containing_mount_with_path(path).map(|(_, v)| v)
    }

    pub fn containing_mount_with_path(&self, path: &str) -> Option<(String, MountEntry)> {
        let g = self.inner.lock();
        if let Some(n) = g.by_path.get(path) {
            return Some((path.into(), n.entry()));
        }
        g.deepest_existing_ancestor(path)
            .map(|n| (n.mountpoint(), n.entry()))
    }

    pub fn proper_containing_mount_with_path(&self, path: &str) -> Option<(String, MountEntry)> {
        let g = self.inner.lock();
        g.deepest_existing_ancestor(path)
            .map(|n| (n.mountpoint(), n.entry()))
    }

    pub fn has_child_mount(&self, path: &str) -> bool {
        let g = self.inner.lock();
        match g.by_path.get(path) {
            Some(n) => !n.children.lock().is_empty(),
            None => g
                .by_path
                .keys()
                .any(|k| MountTableInner::is_descendant_path(k, path)),
        }
    }

    pub fn collect_subtree(&self, path: &str) -> Vec<(String, MountEntry)> {
        let g = self.inner.lock();
        let mut out = Vec::new();
        let root = match g.by_path.get(path) {
            Some(n) => n.clone(),
            None => {
                for (k, n) in g.by_path.iter() {
                    if MountTableInner::is_descendant_path(k, path) {
                        let suffix = if path == "/" {
                            k.clone()
                        } else {
                            String::from(&k[path.len()..])
                        };
                        out.push((suffix, n.entry()));
                    }
                }
                return out;
            }
        };
        out.push((String::new(), root.entry()));
        let mut descendants = Vec::new();
        root.collect_descendants(&mut descendants);
        for n in descendants.iter() {
            let mp = n.mountpoint();
            let suffix = if path == "/" {
                mp
            } else {
                String::from(&mp[path.len()..])
            };
            out.push((suffix, n.entry()));
        }
        out
    }

    pub fn set_propagation(self: &Arc<Self>, path: &str, new_prop: MountPropagation) -> bool {
        let weak = Arc::downgrade(self);
        let g = self.inner.lock();
        let node = match g.by_path.get(path) {
            Some(n) => n.clone(),
            None => return false,
        };
        let mut d = node.data.lock();
        match &d.propagation {
            MountPropagation::Shared(pg) => pg.remove_member(&weak, path),
            MountPropagation::Slave(pg) => pg.remove_slave(&weak, path),
            _ => {}
        }
        match &new_prop {
            MountPropagation::Shared(pg) => pg.add_member(weak.clone(), String::from(path)),
            MountPropagation::Slave(pg) => pg.add_slave(weak.clone(), String::from(path)),
            _ => {}
        }
        d.propagation = new_prop;
        true
    }

    pub fn snapshot(
        self: &Arc<Self>,
        owner_user_ns: Option<Arc<crate::process_model::UserNamespace>>,
    ) -> Arc<MountTable> {
        let parent_entries: Vec<(String, NodeData)> = {
            let g = self.inner.lock();
            let mut ordered: Vec<Arc<MountNode>> = Vec::new();
            for n in g.roots.iter() {
                ordered.push(n.clone());
                n.collect_descendants(&mut ordered);
            }
            ordered
                .iter()
                .map(|n| (n.mountpoint(), n.data.lock().clone()))
                .collect()
        };
        Arc::new_cyclic(|child_weak| {
            let mut inner = MountTableInner::new();
            for (path, data) in parent_entries.iter() {
                match &data.propagation {
                    MountPropagation::Shared(pg) => {
                        pg.add_member(child_weak.clone(), path.clone());
                    }
                    MountPropagation::Slave(pg) => {
                        pg.add_slave(child_weak.clone(), path.clone());
                    }
                    _ => {}
                }
                let mut child_data = data.clone();
                child_data.in_use = MountInUseTag::new_with_flags(data.in_use.flags());
                let node = MountNode::new(path.clone(), child_data);
                inner.link_into_tree(&node);
                inner.by_path.insert(path.clone(), node);
            }
            MountTable {
                inner: VfsSpinIrq::new(inner),
                owner_user_ns: owner_user_ns.clone(),
            }
        })
    }

    pub fn is_stacked(&self, path: &str) -> bool {
        match self.inner.lock().by_path.get(path) {
            Some(n) => !n.shadowed.lock().is_empty(),
            None => false,
        }
    }

    pub fn mount_path_for_root_inode(&self, inode_id: u64) -> Option<String> {
        let g = self.inner.lock();
        let mut best: Option<String> = None;
        for (k, n) in g.by_path.iter() {
            if n.data.lock().root.inode_id() == inode_id {
                match &best {
                    None => best = Some(k.clone()),
                    Some(b) if k.len() > b.len() => best = Some(k.clone()),
                    _ => {}
                }
            }
        }
        best
    }

    pub fn pivot_root(self: &Arc<Self>, new_root: &str, put_old: &str) -> Result<(), Errno> {
        if new_root == "/" {
            return Err(Errno::INVAL);
        }
        let under_new = |p: &str| -> bool {
            p == new_root
                || (p.starts_with(new_root) && p.as_bytes().get(new_root.len()) == Some(&b'/'))
        };
        if !(put_old == new_root || under_new(put_old)) {
            return Err(Errno::INVAL);
        }

        let weak = Arc::downgrade(self);
        let mut g = self.inner.lock();

        let put_old_rebased = strip_prefix_path(put_old, new_root);

        let mut ordered: Vec<Arc<MountNode>> = Vec::new();
        for n in g.roots.iter() {
            ordered.push(n.clone());
            n.collect_descendants(&mut ordered);
        }

        let same_dir = put_old == new_root;
        let old_root_data = ordered
            .iter()
            .find(|n| n.mountpoint() == "/")
            .map(|n| n.data.lock().clone());

        let mut keep: Vec<(Arc<MountNode>, String)> = Vec::new();
        let mut stack_old: Vec<(String, NodeData)> = Vec::new();
        for node in ordered.iter() {
            let old_path = node.mountpoint();
            {
                let d = node.data.lock();
                match &d.propagation {
                    MountPropagation::Shared(pg) => pg.remove_member(&weak, &old_path),
                    MountPropagation::Slave(pg) => pg.remove_slave(&weak, &old_path),
                    _ => {}
                }
            }
            if under_new(&old_path) {
                keep.push((node.clone(), strip_prefix_path(&old_path, new_root)));
            } else if !same_dir {
                stack_old.push((
                    rebase_into(&put_old_rebased, &old_path),
                    node.data.lock().clone(),
                ));
            }
        }
        if same_dir {
            if let Some(data) = old_root_data {
                stack_old.push((String::from("/"), data));
            }
        }

        let mut rebuilt = MountTableInner::new();
        keep.sort_by_key(|e| e.1.len());
        for (node, path) in keep.iter() {
            node.children.lock().clear();
            *node.parent.lock() = alloc::sync::Weak::new();
            *node.mountpoint.lock() = path.clone();
        }
        for (node, path) in keep.iter() {
            {
                let d = node.data.lock();
                match &d.propagation {
                    MountPropagation::Shared(pg) => pg.add_member(weak.clone(), path.clone()),
                    MountPropagation::Slave(pg) => pg.add_slave(weak.clone(), path.clone()),
                    _ => {}
                }
            }
            rebuilt.link_into_tree(node);
            rebuilt.by_path.insert(path.clone(), node.clone());
        }

        stack_old.sort_by_key(|e| e.0.len());
        for (path, mut data) in stack_old.into_iter() {
            match &data.propagation {
                MountPropagation::Shared(pg) => pg.add_member(weak.clone(), path.clone()),
                MountPropagation::Slave(pg) => pg.add_slave(weak.clone(), path.clone()),
                _ => {}
            }
            if let Some(existing) = rebuilt.by_path.get(&path).cloned() {
                let mut d = existing.data.lock();
                let prev = core::mem::replace(&mut *d, data);
                existing.shadowed.lock().push(prev);
            } else {
                data.in_use = MountInUseTag::new_with_flags(data.in_use.flags());
                let node = MountNode::new(path.clone(), data);
                rebuilt.link_into_tree(&node);
                rebuilt.by_path.insert(path, node);
            }
        }

        *g = rebuilt;
        Ok(())
    }
}

fn strip_prefix_path(path: &str, prefix: &str) -> String {
    if path == prefix {
        return String::from("/");
    }
    match path.strip_prefix(prefix) {
        Some(rest) if rest.starts_with('/') => String::from(rest),
        _ => String::from(path),
    }
}

fn rebase_into(base: &str, path: &str) -> String {
    if path == "/" {
        return String::from(base);
    }
    if base == "/" {
        return String::from(path);
    }
    let mut s = String::from(base);
    s.push_str(path);
    s
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
        0,
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
