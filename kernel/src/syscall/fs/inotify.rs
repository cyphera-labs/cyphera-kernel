use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};

use frame::sync::SpinIrq;

use crate::errno::{EBADF, EINVAL};
use crate::fsnotify::{IN_CLOEXEC, IN_NONBLOCK, InotifyInode};
use crate::vfs::{self, Inode, OpenFile, OpenFlags};

use super::AT_FDCWD;
use super::resolve_path;

const IN_DONT_FOLLOW: u32 = 0x0200_0000;

static INOTIFY_INDEX: SpinIrq<BTreeMap<usize, Weak<InotifyInode>>> = SpinIrq::new(BTreeMap::new());

fn lookup_inotify(fd: i32) -> Option<Arc<InotifyInode>> {
    let file = crate::core::with_current_fds(|t| t.get(fd))?;
    let key = Arc::as_ptr(&file.inode) as *const () as usize;
    INOTIFY_INDEX.lock().get(&key)?.upgrade()
}

pub(crate) fn sys_inotify_init1(flags: u64) -> i64 {
    let flags = flags as u32;
    if flags & !(IN_NONBLOCK | IN_CLOEXEC) != 0 {
        return EINVAL;
    }
    let inst = InotifyInode::new();
    let weak = Arc::downgrade(&inst);
    let dyn_inode: Arc<dyn Inode> = inst;
    let mut open_flags = OpenFlags::RDONLY;
    if flags & IN_NONBLOCK != 0 {
        open_flags |= OpenFlags::NONBLOCK;
    }
    let file = Arc::new(OpenFile::new(dyn_inode, open_flags));
    let key = Arc::as_ptr(&file.inode) as *const () as usize;
    {
        let mut index = INOTIFY_INDEX.lock();
        index.retain(|_, w| w.strong_count() > 0);
        index.insert(key, weak);
    }
    let fd_flags = if flags & IN_CLOEXEC != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    match crate::core::with_current_fds(|t| t.install_from(file, 0, fd_flags)) {
        Ok(fd) => fd as i64,
        Err(e) => e as i64,
    }
}

pub(crate) fn sys_inotify_init() -> i64 {
    sys_inotify_init1(0)
}

pub(crate) fn sys_inotify_add_watch(fd: u64, pathname: u64, mask: u64) -> i64 {
    let inst = match lookup_inotify(fd as i32) {
        Some(i) => i,
        None => return EBADF,
    };
    let mask = mask as u32;
    let follow = mask & IN_DONT_FOLLOW == 0;
    let inode = match resolve_path(AT_FDCWD as u64, pathname, follow) {
        Ok(i) => i,
        Err(e) => return e,
    };
    match inst.add_watch(inode, mask) {
        Ok(wd) => wd as i64,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_inotify_rm_watch(fd: u64, wd: u64) -> i64 {
    let inst = match lookup_inotify(fd as i32) {
        Some(i) => i,
        None => return EBADF,
    };
    match inst.rm_watch(wd as i32) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}
