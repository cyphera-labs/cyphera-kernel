extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};

use frame::sync::SpinIrq;

use crate::vfs::{DirEntry, FsError, Inode, InodeKind, OpenFlags, Stat, TimeSpec};

static NEXT_TMPFS_INODE_ID: AtomicU64 = AtomicU64::new(1);

fn alloc_tmpfs_inode_id() -> u64 {
    let n = NEXT_TMPFS_INODE_ID.fetch_add(1, Ordering::Relaxed);
    0x7f00_0000_0000_0000 | n
}

fn now() -> TimeSpec {
    let nanos = frame::cpu::clock::wall_clock_nanos();
    TimeSpec {
        sec: (nanos / 1_000_000_000) as i64,
        nsec: (nanos % 1_000_000_000) as i32,
    }
}

static NEXT_TMPFS_DEV_ID: AtomicU64 = AtomicU64::new(1);

fn alloc_tmpfs_dev_id() -> u64 {
    NEXT_TMPFS_DEV_ID.fetch_add(1, Ordering::Relaxed)
}

pub struct TmpfsInode {
    kind: InodeKind,
    id: u64,
    dev_id: u64,
    mode: AtomicU16,
    uid: AtomicU32,
    gid: AtomicU32,
    nlink: AtomicU32,
    fifo_readers: AtomicU32,
    fifo_writers: AtomicU32,
    fifo_read_waiters: crate::wait::WaitQueue,
    fifo_write_waiters: crate::wait::WaitQueue,
    fifo_open_read_waiters: crate::wait::WaitQueue,
    fifo_open_write_waiters: crate::wait::WaitQueue,
    rdev: AtomicU64,
    atime: SpinIrq<TimeSpec>,
    mtime: SpinIrq<TimeSpec>,
    ctime: SpinIrq<TimeSpec>,
    xattrs: SpinIrq<BTreeMap<String, Vec<u8>>>,
    state: SpinIrq<TmpfsData>,
    dir_removed: core::sync::atomic::AtomicBool,
}

enum TmpfsData {
    Regular(Vec<u8>),
    Directory(BTreeMap<String, Arc<dyn Inode>>),
    Symlink(String),
    CharDevice,
    Fifo(alloc::collections::VecDeque<u8>),
}

const DEFAULT_FIFO_CAPACITY: usize = 4096;

fn default_mode_for(kind: InodeKind) -> u16 {
    match kind {
        InodeKind::Directory => 0o755,
        InodeKind::Regular => 0o644,
        InodeKind::CharDevice => 0o666,
        InodeKind::Symlink => 0o777,
        InodeKind::Pipe => 0o600,
    }
}

fn validate_and_seal_overwrite(src: &Arc<dyn Inode>, dst: &Arc<dyn Inode>) -> Result<(), FsError> {
    let src_dir = src.kind() == InodeKind::Directory;
    let dst_dir = dst.kind() == InodeKind::Directory;
    match (src_dir, dst_dir) {
        (false, true) => Err(FsError::NotFile),
        (true, false) => Err(FsError::NotDir),
        (true, true) => dst.seal_if_empty_dir(),
        (false, false) => Ok(()),
    }
}

fn default_nlink_for(kind: InodeKind) -> u32 {
    match kind {
        InodeKind::Directory => 2,
        _ => 1,
    }
}

impl TmpfsInode {
    pub fn new_dir() -> Arc<Self> {
        Self::new_with(InodeKind::Directory, TmpfsData::Directory(BTreeMap::new()))
    }

    pub fn new_file() -> Arc<Self> {
        Self::new_with(InodeKind::Regular, TmpfsData::Regular(Vec::new()))
    }

    pub fn new_symlink(target: String) -> Arc<Self> {
        Self::new_with(InodeKind::Symlink, TmpfsData::Symlink(target))
    }

    pub fn new_char_device(rdev: u64) -> Arc<Self> {
        let i = Self::new_with(InodeKind::CharDevice, TmpfsData::CharDevice);
        i.rdev.store(rdev, Ordering::Release);
        i
    }

    pub fn new_fifo() -> Arc<Self> {
        Self::new_with(
            InodeKind::Pipe,
            TmpfsData::Fifo(alloc::collections::VecDeque::new()),
        )
    }

    fn new_with(kind: InodeKind, data: TmpfsData) -> Arc<Self> {
        let t = now();
        Arc::new(Self {
            kind,
            id: alloc_tmpfs_inode_id(),
            dev_id: 0,
            mode: AtomicU16::new(default_mode_for(kind)),
            uid: AtomicU32::new(0),
            gid: AtomicU32::new(0),
            nlink: AtomicU32::new(default_nlink_for(kind)),
            fifo_readers: AtomicU32::new(0),
            fifo_writers: AtomicU32::new(0),
            fifo_read_waiters: crate::wait::WaitQueue::new(),
            fifo_write_waiters: crate::wait::WaitQueue::new(),
            fifo_open_read_waiters: crate::wait::WaitQueue::new(),
            fifo_open_write_waiters: crate::wait::WaitQueue::new(),
            rdev: AtomicU64::new(0),
            atime: SpinIrq::new(t),
            mtime: SpinIrq::new(t),
            ctime: SpinIrq::new(t),
            xattrs: SpinIrq::new(BTreeMap::new()),
            state: SpinIrq::new(data),
            dir_removed: core::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn new_mount_root() -> Arc<Self> {
        let root = Self::new_dir();
        let dev = alloc_tmpfs_dev_id();
        let _ = root;
        let mut once_root = Self::new_dir();
        if let Some(r) = Arc::get_mut(&mut once_root) {
            r.dev_id = dev;
        }
        once_root
    }

    pub fn attach_inherent(&self, name: &str, child: Arc<dyn Inode>) -> Result<(), FsError> {
        let mut g = self.state.lock();
        let TmpfsData::Directory(map) = &mut *g else {
            return Err(FsError::NotDir);
        };
        if self.dir_removed.load(Ordering::Relaxed) {
            return Err(FsError::NotFound);
        }
        if map.contains_key(name) {
            return Err(FsError::Exists);
        }
        map.insert(name.to_string(), child);
        self.touch_ctime();
        Ok(())
    }

    fn touch_atime(&self) {
        *self.atime.lock() = now();
    }

    fn touch_mtime(&self) {
        let t = now();
        *self.mtime.lock() = t;
        *self.ctime.lock() = t;
    }

    fn touch_ctime(&self) {
        *self.ctime.lock() = now();
    }
}

impl Inode for TmpfsInode {
    fn kind(&self) -> InodeKind {
        self.kind
    }

    fn inode_id(&self) -> u64 {
        self.id
    }

    fn stat(&self) -> Stat {
        let g = self.state.lock();
        let size = match &*g {
            TmpfsData::Regular(v) => v.len() as u64,
            TmpfsData::Directory(_) => 0,
            TmpfsData::Symlink(s) => s.len() as u64,
            TmpfsData::CharDevice => 0,
            TmpfsData::Fifo(ring) => ring.len() as u64,
        };
        drop(g);
        Stat {
            size,
            kind: self.kind,
            mode: self.mode.load(Ordering::Acquire),
            nlink: self.nlink.load(Ordering::Acquire),
            uid: self.uid.load(Ordering::Acquire),
            gid: self.gid.load(Ordering::Acquire),
            inode_id: self.id,
            dev_id: self.dev_id,
            blksize: 4096,
            blocks: size.div_ceil(512),
            atime: *self.atime.lock(),
            mtime: *self.mtime.lock(),
            ctime: *self.ctime.lock(),
        }
    }

    fn set_mode(&self, mode: u16) -> Result<(), FsError> {
        self.mode.store(mode & 0o7777, Ordering::Release);
        self.touch_ctime();
        Ok(())
    }

    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), FsError> {
        if let Some(u) = uid {
            self.uid.store(u, Ordering::Release);
        }
        if let Some(g) = gid {
            self.gid.store(g, Ordering::Release);
        }
        self.touch_ctime();
        Ok(())
    }

    fn set_times(&self, atime: Option<TimeSpec>, mtime: Option<TimeSpec>) -> Result<(), FsError> {
        if let Some(a) = atime {
            *self.atime.lock() = a;
        }
        if let Some(m) = mtime {
            *self.mtime.lock() = m;
        }
        self.touch_ctime();
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let g = self.state.lock();
        match &*g {
            TmpfsData::Regular(data) => {
                if offset >= data.len() as u64 {
                    drop(g);
                    self.touch_atime();
                    return Ok(0);
                }
                let start = offset as usize;
                let n = (data.len() - start).min(buf.len());
                buf[..n].copy_from_slice(&data[start..start + n]);
                drop(g);
                self.touch_atime();
                Ok(n)
            }
            TmpfsData::Symlink(_) => Err(FsError::InvalidArgument),
            TmpfsData::Directory(_) => Err(FsError::NotFile),
            TmpfsData::CharDevice => Err(FsError::NotSupported),
            TmpfsData::Fifo(_) => {
                drop(g);
                self.fifo_read(buf, false)
            }
        }
    }

    fn read_at_with_flags(
        &self,
        offset: u64,
        buf: &mut [u8],
        flags: OpenFlags,
    ) -> Result<usize, FsError> {
        if matches!(*self.state.lock(), TmpfsData::Fifo(_)) {
            return self.fifo_read(buf, flags.contains(OpenFlags::NONBLOCK));
        }
        self.read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        let mut g = self.state.lock();
        match &mut *g {
            TmpfsData::Regular(data) => {
                let end = (offset as usize).saturating_add(buf.len());
                if end > data.len() {
                    data.resize(end, 0);
                }
                data[offset as usize..end].copy_from_slice(buf);
                drop(g);
                self.touch_mtime();
                crate::fs::pagecache::write_through(self.id, offset, buf);
                Ok(buf.len())
            }
            TmpfsData::Fifo(_) => {
                drop(g);
                self.fifo_write(buf)
            }
            TmpfsData::Symlink(_) | TmpfsData::Directory(_) | TmpfsData::CharDevice => {
                Err(FsError::NotFile)
            }
        }
    }

    fn truncate(&self, len: u64) -> Result<(), FsError> {
        let mut g = self.state.lock();
        let TmpfsData::Regular(data) = &mut *g else {
            return Err(FsError::NotFile);
        };
        let old_len = data.len();
        data.resize(len as usize, 0);
        drop(g);
        self.touch_mtime();
        if (len as usize) < old_len {
            crate::fs::pagecache::invalidate_range(self.id, len, u64::MAX);
        }
        Ok(())
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        let g = self.state.lock();
        let TmpfsData::Directory(map) = &*g else {
            return Err(FsError::NotDir);
        };
        map.get(name).cloned().ok_or(FsError::NotFound)
    }

    fn create(&self, name: &str, kind: InodeKind) -> Result<Arc<dyn Inode>, FsError> {
        let new: Arc<dyn Inode> = match kind {
            InodeKind::Regular => Self::new_file(),
            InodeKind::Directory => Self::new_dir(),
            InodeKind::Symlink => {
                return Err(FsError::InvalidArgument);
            }
            InodeKind::CharDevice => Self::new_char_device(0),
            InodeKind::Pipe => Self::new_fifo(),
        };
        let mut g = self.state.lock();
        let TmpfsData::Directory(map) = &mut *g else {
            return Err(FsError::NotDir);
        };
        if self.dir_removed.load(Ordering::Relaxed) {
            return Err(FsError::NotFound);
        }
        if map.contains_key(name) {
            return Err(FsError::Exists);
        }
        map.insert(name.to_string(), new.clone());
        if kind == InodeKind::Directory {
            self.nlink.fetch_add(1, Ordering::AcqRel);
        }
        drop(g);
        self.touch_mtime();
        Ok(new)
    }

    fn mknod(&self, name: &str, kind: InodeKind, dev: u64) -> Result<Arc<dyn Inode>, FsError> {
        let new: Arc<dyn Inode> = match kind {
            InodeKind::CharDevice => Self::new_char_device(dev),
            InodeKind::Pipe => Self::new_fifo(),
            InodeKind::Regular => Self::new_file(),
            _ => return Err(FsError::InvalidArgument),
        };
        let mut g = self.state.lock();
        let TmpfsData::Directory(map) = &mut *g else {
            return Err(FsError::NotDir);
        };
        if self.dir_removed.load(Ordering::Relaxed) {
            return Err(FsError::NotFound);
        }
        if map.contains_key(name) {
            return Err(FsError::Exists);
        }
        map.insert(name.to_string(), new.clone());
        drop(g);
        self.touch_mtime();
        Ok(new)
    }

    fn symlink(&self, name: &str, target: &str) -> Result<Arc<dyn Inode>, FsError> {
        let new = Self::new_symlink(target.to_string());
        let mut g = self.state.lock();
        let TmpfsData::Directory(map) = &mut *g else {
            return Err(FsError::NotDir);
        };
        if self.dir_removed.load(Ordering::Relaxed) {
            return Err(FsError::NotFound);
        }
        if map.contains_key(name) {
            return Err(FsError::Exists);
        }
        let new_dyn: Arc<dyn Inode> = new.clone();
        map.insert(name.to_string(), new_dyn);
        drop(g);
        self.touch_mtime();
        Ok(new)
    }

    fn read_link(&self) -> Result<String, FsError> {
        let g = self.state.lock();
        match &*g {
            TmpfsData::Symlink(t) => Ok(t.clone()),
            _ => Err(FsError::InvalidArgument),
        }
    }

    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        let g = self.state.lock();
        let TmpfsData::Directory(map) = &*g else {
            return Err(FsError::NotDir);
        };
        Ok(map
            .iter()
            .map(|(name, inode)| DirEntry {
                name: name.clone(),
                kind: inode.kind(),
                inode_id: inode.inode_id(),
            })
            .collect())
    }

    fn unlink(&self, name: &str) -> Result<(), FsError> {
        let mut g = self.state.lock();
        let TmpfsData::Directory(map) = &mut *g else {
            return Err(FsError::NotDir);
        };
        let removed = map.remove(name).ok_or(FsError::NotFound)?;
        if removed.kind() == InodeKind::Directory {
            self.nlink.fetch_sub(1, Ordering::AcqRel);
        }
        drop(g);
        self.touch_mtime();
        removed.drop_nlink();
        Ok(())
    }

    fn seal_if_empty_dir(&self) -> Result<(), FsError> {
        let g = self.state.lock();
        let TmpfsData::Directory(map) = &*g else {
            return Err(FsError::NotDir);
        };
        if !map.is_empty() {
            return Err(FsError::NotEmpty);
        }
        self.dir_removed.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn unseal_dir(&self) {
        let _g = self.state.lock();
        self.dir_removed.store(false, Ordering::Relaxed);
    }

    fn unlink_if_matches(&self, name: &str, expect: &Arc<dyn Inode>) -> Result<bool, FsError> {
        let mut g = self.state.lock();
        let TmpfsData::Directory(map) = &mut *g else {
            return Err(FsError::NotDir);
        };
        if !map.get(name).is_some_and(|cur| Arc::ptr_eq(cur, expect)) {
            return Ok(false);
        }
        let removed = map.remove(name).unwrap_or_else(|| expect.clone());
        if removed.kind() == InodeKind::Directory {
            self.nlink.fetch_sub(1, Ordering::AcqRel);
        }
        drop(g);
        self.touch_mtime();
        removed.drop_nlink();
        Ok(true)
    }

    fn rmdir(&self, name: &str) -> Result<(), FsError> {
        let target = self.lookup(name)?;
        if target.kind() != InodeKind::Directory {
            return Err(FsError::NotDir);
        }
        target.seal_if_empty_dir()?;
        match self.unlink_if_matches(name, &target) {
            Ok(true) => Ok(()),
            Ok(false) => {
                target.unseal_dir();
                Err(FsError::NotFound)
            }
            Err(e) => {
                target.unseal_dir();
                Err(e)
            }
        }
    }

    fn link(&self, name: &str, target: Arc<dyn Inode>) -> Result<(), FsError> {
        if target.kind() == InodeKind::Directory {
            return Err(FsError::PermissionDenied);
        }
        let mut g = self.state.lock();
        let TmpfsData::Directory(map) = &mut *g else {
            return Err(FsError::NotDir);
        };
        if self.dir_removed.load(Ordering::Relaxed) {
            return Err(FsError::NotFound);
        }
        if map.contains_key(name) {
            return Err(FsError::Exists);
        }
        map.insert(name.to_string(), target.clone());
        drop(g);
        self.touch_mtime();
        target.bump_nlink();
        Ok(())
    }

    fn attach(&self, name: &str, child: Arc<dyn Inode>) -> Result<(), FsError> {
        TmpfsInode::attach_inherent(self, name, child)
    }

    fn rename(
        &self,
        old_name: &str,
        new_parent: &Arc<dyn Inode>,
        new_name: &str,
    ) -> Result<(), FsError> {
        if Arc::as_ptr(new_parent) as *const () == self as *const _ as *const () {
            if old_name == new_name {
                let g = self.state.lock();
                let TmpfsData::Directory(map) = &*g else {
                    return Err(FsError::NotDir);
                };
                return if map.contains_key(old_name) {
                    Ok(())
                } else {
                    Err(FsError::NotFound)
                };
            }
            for _attempt in 0..64 {
                let (src, dst) = {
                    let g = self.state.lock();
                    let TmpfsData::Directory(map) = &*g else {
                        return Err(FsError::NotDir);
                    };
                    let src = map.get(old_name).cloned().ok_or(FsError::NotFound)?;
                    let dst = map.get(new_name).cloned();
                    (src, dst)
                };
                if let Some(ref d) = dst {
                    if Arc::ptr_eq(&src, d) {
                        return Ok(());
                    }
                    validate_and_seal_overwrite(&src, d)?;
                }
                let mut g = self.state.lock();
                let TmpfsData::Directory(map) = &mut *g else {
                    return Err(FsError::NotDir);
                };
                let src_ok = map.get(old_name).is_some_and(|cur| Arc::ptr_eq(cur, &src));
                let cur_dst = map.get(new_name).cloned();
                let dst_ok = match (&dst, &cur_dst) {
                    (None, None) => true,
                    (Some(d), Some(c)) => Arc::ptr_eq(d, c),
                    _ => false,
                };
                if !src_ok {
                    drop(g);
                    if let Some(d) = &dst {
                        d.unseal_dir();
                    }
                    return Err(FsError::NotFound);
                }
                if !dst_ok {
                    drop(g);
                    if let Some(d) = &dst {
                        d.unseal_dir();
                    }
                    continue;
                }
                let removed_target = map.remove(new_name);
                let entry = map.remove(old_name).unwrap_or_else(|| src.clone());
                map.insert(new_name.to_string(), entry);
                drop(g);
                self.touch_mtime();
                if let Some(t) = removed_target {
                    if t.kind() == InodeKind::Directory {
                        self.nlink.fetch_sub(1, Ordering::AcqRel);
                    }
                    t.drop_nlink();
                }
                return Ok(());
            }
            return Err(FsError::NotFound);
        }

        if let Ok(dst) = new_parent.lookup(new_name) {
            let src = self.lookup(old_name)?;
            if Arc::ptr_eq(&src, &dst) {
                return Ok(());
            }
            validate_and_seal_overwrite(&src, &dst)?;
            drop(src);
            match new_parent.unlink_if_matches(new_name, &dst) {
                Ok(true) => {}
                Ok(false) => dst.unseal_dir(),
                Err(e) => {
                    dst.unseal_dir();
                    return Err(e);
                }
            }
        }
        let entry = {
            let mut g = self.state.lock();
            let TmpfsData::Directory(map) = &mut *g else {
                return Err(FsError::NotDir);
            };
            map.remove(old_name).ok_or(FsError::NotFound)?
        };
        let moved_is_dir = entry.kind() == InodeKind::Directory;
        match new_parent.attach(new_name, entry.clone()) {
            Ok(()) => {
                self.touch_mtime();
                if moved_is_dir {
                    self.drop_nlink();
                    new_parent.bump_nlink();
                }
                Ok(())
            }
            Err(e) => {
                let mut g = self.state.lock();
                if let TmpfsData::Directory(map) = &mut *g {
                    map.insert(old_name.to_string(), entry);
                }
                Err(e)
            }
        }
    }

    fn on_open(&self, flags: OpenFlags) {
        if !matches!(*self.state.lock(), TmpfsData::Fifo(_)) {
            return;
        }
        let readable = flags.is_readable();
        let writable = flags.is_writable();
        if writable {
            self.fifo_writers.fetch_add(1, Ordering::AcqRel);
        }
        if readable {
            self.fifo_readers.fetch_add(1, Ordering::AcqRel);
        }
        if writable {
            self.fifo_open_read_waiters.wake_all();
        }
        if readable {
            self.fifo_open_write_waiters.wake_all();
        }
        if flags.contains(OpenFlags::NONBLOCK) || (readable && writable) {
            return;
        }
        let cur = crate::sched::current_pid();
        if readable {
            loop {
                self.fifo_open_read_waiters.enqueue(cur);
                if self.fifo_writers.load(Ordering::Acquire) > 0 {
                    self.fifo_open_read_waiters.dequeue(cur);
                    return;
                }
                crate::sched::park_on_pre_enqueued(&self.fifo_open_read_waiters);
                self.fifo_open_read_waiters.dequeue(cur);
                if crate::sched::current_signal_pending() {
                    return;
                }
            }
        } else if writable {
            loop {
                self.fifo_open_write_waiters.enqueue(cur);
                if self.fifo_readers.load(Ordering::Acquire) > 0 {
                    self.fifo_open_write_waiters.dequeue(cur);
                    return;
                }
                crate::sched::park_on_pre_enqueued(&self.fifo_open_write_waiters);
                self.fifo_open_write_waiters.dequeue(cur);
                if crate::sched::current_signal_pending() {
                    return;
                }
            }
        }
    }

    fn on_close(&self, flags: OpenFlags) {
        if matches!(*self.state.lock(), TmpfsData::Fifo(_)) {
            if flags.is_writable() {
                self.fifo_writers.fetch_sub(1, Ordering::AcqRel);
                self.fifo_read_waiters.wake_all();
            }
            if flags.is_readable() {
                self.fifo_readers.fetch_sub(1, Ordering::AcqRel);
                self.fifo_write_waiters.wake_all();
            }
        }
    }

    fn bump_nlink(&self) {
        self.nlink.fetch_add(1, Ordering::AcqRel);
        self.touch_ctime();
    }

    fn drop_nlink(&self) {
        self.nlink.fetch_sub(1, Ordering::AcqRel);
        self.touch_ctime();
    }

    fn set_xattr(&self, name: &str, value: &[u8], flags: u32) -> Result<(), FsError> {
        const XATTR_CREATE: u32 = 1;
        const XATTR_REPLACE: u32 = 2;
        let mut t = self.xattrs.lock();
        let exists = t.contains_key(name);
        if flags & XATTR_CREATE != 0 && exists {
            return Err(FsError::Exists);
        }
        if flags & XATTR_REPLACE != 0 && !exists {
            return Err(FsError::NotFound);
        }
        t.insert(name.to_string(), value.to_vec());
        drop(t);
        self.touch_ctime();
        Ok(())
    }

    fn get_xattr(&self, name: &str, buf: &mut [u8]) -> Result<usize, FsError> {
        let t = self.xattrs.lock();
        let v = t.get(name).ok_or(FsError::NotFound)?;
        if buf.is_empty() {
            return Ok(v.len());
        }
        let n = buf.len().min(v.len());
        buf[..n].copy_from_slice(&v[..n]);
        Ok(v.len())
    }

    fn list_xattr(&self, buf: &mut [u8]) -> Result<usize, FsError> {
        let t = self.xattrs.lock();
        let total: usize = t.keys().map(|n| n.len() + 1).sum();
        if buf.is_empty() {
            return Ok(total);
        }
        if buf.len() < total {
            return Err(FsError::Range);
        }
        let mut off = 0;
        for k in t.keys() {
            let bytes = k.as_bytes();
            buf[off..off + bytes.len()].copy_from_slice(bytes);
            buf[off + bytes.len()] = 0;
            off += bytes.len() + 1;
        }
        Ok(total)
    }

    fn remove_xattr(&self, name: &str) -> Result<(), FsError> {
        let mut t = self.xattrs.lock();
        t.remove(name).ok_or(FsError::NotFound)?;
        drop(t);
        self.touch_ctime();
        Ok(())
    }
}

impl TmpfsInode {
    fn fifo_read(&self, buf: &mut [u8], nonblock: bool) -> Result<usize, FsError> {
        loop {
            {
                let mut g = self.state.lock();
                let TmpfsData::Fifo(ring) = &mut *g else {
                    return Err(FsError::NotSupported);
                };
                if !ring.is_empty() {
                    let n = buf.len().min(ring.len());
                    for slot in &mut buf[..n] {
                        *slot = ring.pop_front().unwrap();
                    }
                    drop(g);
                    self.fifo_write_waiters.wake_all();
                    self.touch_atime();
                    return Ok(n);
                }
                if self.fifo_writers.load(Ordering::Acquire) == 0 {
                    return Ok(0);
                }
                if nonblock {
                    return Err(FsError::WouldBlock);
                }
            }
            self.fifo_read_waiters.park();
            if crate::sched::current_signal_pending() {
                return Err(FsError::Interrupted);
            }
        }
    }

    fn fifo_write(&self, buf: &[u8]) -> Result<usize, FsError> {
        loop {
            {
                let mut g = self.state.lock();
                let TmpfsData::Fifo(ring) = &mut *g else {
                    return Err(FsError::NotSupported);
                };
                if self.fifo_readers.load(Ordering::Acquire) == 0 {
                    return Err(FsError::BrokenPipe);
                }
                let room = DEFAULT_FIFO_CAPACITY.saturating_sub(ring.len());
                if room > 0 {
                    let n = buf.len().min(room);
                    ring.extend(buf[..n].iter().copied());
                    drop(g);
                    self.fifo_read_waiters.wake_all();
                    self.touch_mtime();
                    return Ok(n);
                }
            }
            self.fifo_write_waiters.park();
            if crate::sched::current_signal_pending() {
                return Err(FsError::Interrupted);
            }
        }
    }
}
