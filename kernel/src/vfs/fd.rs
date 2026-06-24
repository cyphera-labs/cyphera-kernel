use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use frame::sync::SpinIrq;

use super::OpenFile;

pub const MAX_FDS: usize = 1024;

pub const HARD_MAX_FDS: usize = 65536;

pub const FD_CLOEXEC: u8 = 1;

struct Slot {
    file: Option<Arc<OpenFile>>,
    fd_flags: u8,
}

impl Slot {
    const fn empty() -> Self {
        Self {
            file: None,
            fd_flags: 0,
        }
    }
}

pub struct FdTable {
    inner: SpinIrq<Vec<Slot>>,
    soft_cap: AtomicUsize,
}

impl FdTable {
    pub const fn new() -> Self {
        Self {
            inner: SpinIrq::new(Vec::new()),
            soft_cap: AtomicUsize::new(MAX_FDS),
        }
    }

    pub fn soft_cap(&self) -> usize {
        self.soft_cap.load(Ordering::Acquire)
    }

    pub fn set_soft_cap(&self, new: usize) -> usize {
        let clamped = new.min(HARD_MAX_FDS);
        self.soft_cap.store(clamped, Ordering::Release);
        clamped
    }

    fn ensure_len(slots: &mut Vec<Slot>, len: usize) {
        if slots.len() < len {
            slots.resize_with(len, Slot::empty);
        }
    }

    pub fn install(&self, file: Arc<OpenFile>) -> Result<i32, i32> {
        self.install_from(file, 0, 0)
    }

    pub fn install_from(&self, file: Arc<OpenFile>, min_fd: i32, fd_flags: u8) -> Result<i32, i32> {
        let cap = self.soft_cap.load(Ordering::Acquire);
        if min_fd < 0 || (min_fd as usize) >= cap {
            return Err(crate::errno::EINVAL as i32);
        }
        let mut t = self.inner.lock();
        let start = min_fd as usize;
        for (i, slot) in t.iter_mut().enumerate().skip(start) {
            if slot.file.is_none() {
                slot.file = Some(file);
                slot.fd_flags = fd_flags;
                return Ok(i as i32);
            }
        }
        let i = t.len().max(start);
        if i >= cap {
            return Err(crate::errno::EMFILE as i32);
        }
        Self::ensure_len(&mut t, i + 1);
        t[i].file = Some(file);
        t[i].fd_flags = fd_flags;
        Ok(i as i32)
    }

    pub fn install_at(&self, fd: i32, file: Arc<OpenFile>) {
        self.install_at_with(fd, file, 0);
    }

    pub fn install_at_with(&self, fd: i32, file: Arc<OpenFile>, fd_flags: u8) {
        let cap = self.soft_cap.load(Ordering::Acquire);
        if fd < 0 || (fd as usize) >= cap {
            return;
        }
        let mut t = self.inner.lock();
        Self::ensure_len(&mut t, fd as usize + 1);
        t[fd as usize].file = Some(file);
        t[fd as usize].fd_flags = fd_flags;
    }

    pub fn get(&self, fd: i32) -> Option<Arc<OpenFile>> {
        if fd < 0 {
            return None;
        }
        let t = self.inner.lock();
        t.get(fd as usize).and_then(|s| s.file.clone())
    }

    pub fn remove(&self, fd: i32) -> Option<Arc<OpenFile>> {
        if fd < 0 {
            return None;
        }
        let mut t = self.inner.lock();
        let slot = t.get_mut(fd as usize)?;
        slot.fd_flags = 0;
        slot.file.take()
    }

    pub fn dup_to(&self, src: i32, dst: i32, fd_flags: u8) -> Result<i32, i32> {
        let cap = self.soft_cap.load(Ordering::Acquire);
        if src < 0 || (src as usize) >= cap || dst < 0 || (dst as usize) >= cap {
            return Err(crate::errno::EBADF as i32);
        }
        let mut t = self.inner.lock();
        let entry = t
            .get(src as usize)
            .and_then(|s| s.file.clone())
            .ok_or(crate::errno::EBADF as i32)?;
        if src != dst {
            Self::ensure_len(&mut t, dst as usize + 1);
            t[dst as usize].file = Some(entry);
            t[dst as usize].fd_flags = fd_flags;
        }
        Ok(dst)
    }

    pub fn fd_flags(&self, fd: i32) -> Option<u8> {
        if fd < 0 {
            return None;
        }
        let t = self.inner.lock();
        t.get(fd as usize).and_then(|s| {
            if s.file.is_some() {
                Some(s.fd_flags)
            } else {
                None
            }
        })
    }

    pub fn set_fd_flags(&self, fd: i32, flags: u8) -> Result<(), i32> {
        if fd < 0 {
            return Err(crate::errno::EBADF as i32);
        }
        let mut t = self.inner.lock();
        let slot = t.get_mut(fd as usize).ok_or(crate::errno::EBADF as i32)?;
        if slot.file.is_none() {
            return Err(crate::errno::EBADF as i32);
        }
        slot.fd_flags = flags;
        Ok(())
    }

    pub fn close_cloexec(&self) {
        let mut t = self.inner.lock();
        for slot in t.iter_mut() {
            if slot.file.is_some() && (slot.fd_flags & FD_CLOEXEC) != 0 {
                slot.file = None;
                slot.fd_flags = 0;
            }
        }
    }

    pub fn close_all(&self) {
        let mut taken = alloc::vec::Vec::new();
        {
            let mut t = self.inner.lock();
            for slot in t.iter_mut() {
                if let Some(f) = slot.file.take() {
                    taken.push(f);
                }
                slot.fd_flags = 0;
            }
        }
        drop(taken);
    }

    pub fn clone_for_child(&self) -> FdTable {
        let src = self.inner.lock();
        let mut dst: Vec<Slot> = Vec::with_capacity(src.len());
        for s in src.iter() {
            dst.push(Slot {
                file: s.file.clone(),
                fd_flags: s.fd_flags,
            });
        }
        FdTable {
            inner: SpinIrq::new(dst),
            soft_cap: AtomicUsize::new(self.soft_cap.load(Ordering::Acquire)),
        }
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}
