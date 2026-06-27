use frame::user::TrapFrame;

use super::*;
use crate::vfs::Inode;

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
    vmas: alloc::vec::Vec<Vma>,
    last_end: u64,
    arena_lo: u64,
    arena_hi: u64,
    generation: u64,
    mlockall_flags: u32,
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
        const LOCKED = 0x8;
        const RESERVED = 0x10;
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
        offset: u64,
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
            generation: 0,
            mlockall_flags: 0,
        }
    }

    pub fn clone_for_fork(&self) -> Self {
        Self {
            vmas: self.vmas.clone(),
            last_end: self.last_end,
            arena_lo: self.arena_lo,
            arena_hi: self.arena_hi,
            generation: 0,
            mlockall_flags: 0,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn vmas(&self) -> &[Vma] {
        &self.vmas
    }

    pub fn arena_lo(&self) -> u64 {
        self.arena_lo
    }

    pub fn arena_hi(&self) -> u64 {
        self.arena_hi
    }

    pub fn mlockall_flags(&self) -> u32 {
        self.mlockall_flags
    }

    pub fn set_mlockall(&mut self, flags: u32) {
        self.mlockall_flags = flags;
    }

    fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    fn bump_last_end(&mut self, new_end: u64) {
        if new_end > self.last_end {
            self.last_end = new_end;
        }
    }

    pub fn extend_vma_end(&mut self, start: u64, new_end: u64) -> bool {
        let old_end = match self.vmas.iter().find(|v| v.start == start) {
            Some(v) => v.end,
            None => return false,
        };
        if new_end <= old_end || new_end > self.arena_hi {
            return false;
        }
        if self.overlaps(old_end, new_end) {
            return false;
        }
        if let Some(v) = self.vmas.iter_mut().find(|v| v.start == start) {
            v.end = new_end;
        } else {
            return false;
        }
        self.bump_last_end(new_end);
        self.bump_generation();
        true
    }

    pub fn truncate_vma_end(&mut self, start: u64, new_end: u64) -> bool {
        let ok = match self.vmas.iter_mut().find(|v| v.start == start) {
            Some(v) if new_end > v.start && new_end < v.end => {
                v.end = new_end;
                true
            }
            _ => false,
        };
        if ok {
            self.bump_generation();
        }
        ok
    }

    pub fn remove_vma_at(&mut self, start: u64) -> Option<Vma> {
        let pos = self.vmas.iter().position(|v| v.start == start)?;
        let removed = self.vmas.remove(pos);
        self.bump_generation();
        Some(removed)
    }

    pub fn drain_vmas_where<F: FnMut(&Vma) -> bool>(
        &mut self,
        mut pred: F,
    ) -> alloc::vec::Vec<Vma> {
        let mut removed = alloc::vec::Vec::new();
        let mut kept = alloc::vec::Vec::with_capacity(self.vmas.len());
        for v in self.vmas.drain(..) {
            if pred(&v) {
                removed.push(v);
            } else {
                kept.push(v);
            }
        }
        self.vmas = kept;
        if !removed.is_empty() {
            self.bump_generation();
        }
        removed
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
        self.bump_generation();
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
                if let VmaBacking::Shm { segment, .. } = &v.backing {
                    segment
                        .attached
                        .fetch_add(2, core::sync::atomic::Ordering::AcqRel);
                }
                let off_left = lo - v.start;
                let off_mid = hi - v.start;
                let backing_left = v.backing.clone();
                let shift_backing = |delta: u64| match &v.backing {
                    VmaBacking::Anonymous => VmaBacking::Anonymous,
                    VmaBacking::Shm { segment, offset } => VmaBacking::Shm {
                        segment: segment.clone(),
                        offset: offset + delta,
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
                if let VmaBacking::Shm { segment, .. } = &v.backing {
                    segment
                        .attached
                        .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
                }
                let backing_kept = v.backing.clone();
                let off_drop = lo - v.start;
                let backing_drop = match &v.backing {
                    VmaBacking::Anonymous => VmaBacking::Anonymous,
                    VmaBacking::Shm { segment, offset } => VmaBacking::Shm {
                        segment: segment.clone(),
                        offset: offset + off_drop,
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
                if let VmaBacking::Shm { segment, .. } = &v.backing {
                    segment
                        .attached
                        .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
                }
                let off_kept = hi - v.start;
                let backing_kept = match &v.backing {
                    VmaBacking::Anonymous => VmaBacking::Anonymous,
                    VmaBacking::Shm { segment, offset } => VmaBacking::Shm {
                        segment: segment.clone(),
                        offset: offset + off_kept,
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
        self.bump_generation();
        removed
    }

    pub fn reserve(&mut self, lo: u64, hi: u64) {
        let pos = self
            .vmas
            .binary_search_by_key(&lo, |v| v.start)
            .unwrap_or_else(|p| p);
        self.vmas.insert(
            pos,
            Vma {
                start: lo,
                end: hi,
                prot: frame::mm::vm::Perms::USER,
                flags: VmaFlags::RESERVED,
                backing: VmaBacking::Anonymous,
            },
        );
        if hi > self.last_end {
            self.last_end = hi;
        }
        self.bump_generation();
    }

    pub fn unmap_range_reserve(&mut self, lo: u64, hi: u64) -> alloc::vec::Vec<Vma> {
        let removed = self.unmap_range(lo, hi);
        self.reserve(lo, hi);
        removed
    }

    pub fn release_reservation(&mut self, lo: u64, hi: u64) {
        self.vmas
            .retain(|v| !(v.start == lo && v.end == hi && v.flags.contains(VmaFlags::RESERVED)));
        self.bump_generation();
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
                VmaBacking::Shm { segment, offset } => VmaBacking::Shm {
                    segment: segment.clone(),
                    offset: offset + delta,
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
            if let VmaBacking::Shm { segment, .. } = &v.backing {
                let extra = (v.start < mid_lo) as u32 + (mid_hi < v.end) as u32;
                if extra > 0 {
                    segment
                        .attached
                        .fetch_add(extra, core::sync::atomic::Ordering::AcqRel);
                }
            }
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
        self.bump_generation();
        gaps
    }

    pub fn lock_range(&mut self, lo: u64, hi: u64, set: bool) -> alloc::vec::Vec<(u64, u64)> {
        fn shift_backing(b: &VmaBacking, delta: u64) -> VmaBacking {
            match b {
                VmaBacking::Anonymous => VmaBacking::Anonymous,
                VmaBacking::Shm { segment, offset } => VmaBacking::Shm {
                    segment: segment.clone(),
                    offset: offset + delta,
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
            if let VmaBacking::Shm { segment, .. } = &v.backing {
                let extra = (v.start < mid_lo) as u32 + (mid_hi < v.end) as u32;
                if extra > 0 {
                    segment
                        .attached
                        .fetch_add(extra, core::sync::atomic::Ordering::AcqRel);
                }
            }
            if v.start < mid_lo {
                new_vmas.push(Vma {
                    start: v.start,
                    end: mid_lo,
                    prot: v.prot,
                    flags: v.flags,
                    backing: v.backing.clone(),
                });
            }
            let mid_flags = if set {
                v.flags | VmaFlags::LOCKED
            } else {
                v.flags & !VmaFlags::LOCKED
            };
            new_vmas.push(Vma {
                start: mid_lo,
                end: mid_hi,
                prot: v.prot,
                flags: mid_flags,
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
        self.bump_generation();
        gaps
    }
}
