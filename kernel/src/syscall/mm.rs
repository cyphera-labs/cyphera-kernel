use alloc::sync::Arc;

use frame::mm::vm::{Perms, VmSpace};
use frame::mm::{Page, Size4KiB, VirtAddr};

use crate::errno::{EBADF, EFAULT, EINVAL, ENOMEM, EPERM, ESRCH};
use crate::sched;
use crate::vfs::Inode;

const PROT_NONE: u64 = 0;
const PROT_READ_BIT: u64 = 1;
const PROT_WRITE_BIT: u64 = 2;
const PROT_EXEC_BIT: u64 = 4;

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_FIXED: u64 = 0x10;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;

fn align_up_page(addr: u64) -> u64 {
    (addr + 0xfff) & !0xfff
}

fn prot_to_perms(prot: u64) -> Perms {
    let mut p = Perms::USER;
    if prot & PROT_READ != 0 {
        p |= Perms::READ;
    }
    if prot & PROT_WRITE != 0 {
        p |= Perms::WRITE;
    }
    if prot & PROT_EXEC != 0 {
        p |= Perms::EXECUTE;
    }
    p
}

pub(super) fn sys_mprotect(addr: u64, length: u64, prot: u64) -> i64 {
    if sched::current_is_vfork_borrower() {
        return ENOMEM;
    }
    if length == 0 || addr & 0xfff != 0 {
        return EINVAL;
    }
    if prot & !(PROT_READ_BIT | PROT_WRITE_BIT | PROT_EXEC_BIT) != 0 {
        return EINVAL;
    }
    let pages = length.div_ceil(4096) as usize;
    let length_aligned = (pages as u64) * 4096;
    let hi = match addr.checked_add(length_aligned) {
        Some(h) => h,
        None => return ENOMEM,
    };
    let mut perms = Perms::USER;
    if prot == PROT_NONE {
    } else {
        if prot & PROT_READ_BIT != 0 {
            perms |= Perms::READ;
        }
        if prot & PROT_WRITE_BIT != 0 {
            perms |= Perms::WRITE;
        }
        if prot & PROT_EXEC_BIT != 0 {
            perms |= Perms::EXECUTE;
        }
    }

    let gaps = sched::with_current_mmap_mut(|m| m.protect_range(addr, hi, perms));

    let mut vmspace = VmSpace::current();
    let not_present = match vmspace.change_perms(VirtAddr::new(addr), pages, perms) {
        Ok(n) => n,
        Err(_) => return EINVAL,
    };

    if not_present > 0 && !gaps.is_empty() {
        for (g_lo, g_hi) in gaps {
            let mut p = g_lo;
            while p < g_hi {
                if vmspace.translate(VirtAddr::new(p)).is_none() {
                    return ENOMEM;
                }
                p += 4096;
            }
        }
    }
    0
}

pub(super) fn sys_brk(addr: u64) -> u64 {
    let cur = sched::current_brk();
    if sched::current_is_vfork_borrower() {
        return cur.current;
    }
    let target = if addr == 0 { cur.current } else { addr };

    if target <= cur.current {
        return sched::set_current_brk(target);
    }

    let from = align_up_page(cur.current);
    let to = align_up_page(target);
    if to > cur.max {
        return cur.current;
    }

    let mut vmspace = VmSpace::current();
    let pages = ((to - from) / 4096) as usize;
    if pages > 0
        && vmspace
            .map_anon(VirtAddr::new(from), pages, Perms::USER_RW)
            .is_err()
    {
        return cur.current;
    }
    sched::set_current_brk(target)
}

pub(super) fn sys_mmap(addr: u64, length: u64, prot: u64, flags: u64, fd: u64, offset: u64) -> i64 {
    use crate::process::{Vma, VmaBacking, VmaFlags};
    if sched::current_is_vfork_borrower() {
        return ENOMEM;
    }
    if length == 0 {
        return EINVAL;
    }
    if addr & 0xfff != 0 && (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) != 0 {
        return EINVAL;
    }
    let pages = length.div_ceil(4096) as usize;
    let length_aligned = (pages * 4096) as u64;
    let perms = prot_to_perms(prot);

    let is_anon = (flags & MAP_ANONYMOUS) != 0;
    let is_shared = (flags & MAP_SHARED) != 0;
    let _ = MAP_PRIVATE;

    let backing = if is_anon {
        VmaBacking::Anonymous
    } else {
        if (fd as i64) == -1 {
            return EINVAL;
        }
        let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
            Some(f) => f,
            None => return EBADF,
        };
        if !file.flags().is_readable() {
            return EBADF;
        }
        VmaBacking::File {
            inode: file.inode.clone(),
            file_offset_base: offset,
        }
    };

    let picked = sched::with_current_mmap_mut(|m| -> Result<(u64, alloc::vec::Vec<Vma>), i64> {
        if (flags & MAP_FIXED_NOREPLACE) != 0 {
            if m.overlaps(addr, addr + length_aligned) {
                return Err(-17);
            }
            Ok((addr, alloc::vec::Vec::new()))
        } else if (flags & MAP_FIXED) != 0 {
            let dropped = m.unmap_range(addr, addr + length_aligned);
            Ok((addr, dropped))
        } else if addr != 0
            && addr >= m.arena_lo
            && addr + length_aligned <= m.arena_hi
            && !m.overlaps(addr, addr + length_aligned)
        {
            Ok((addr, alloc::vec::Vec::new()))
        } else {
            m.find_gap(length_aligned)
                .map(|a| (a, alloc::vec::Vec::new()))
                .ok_or(ENOMEM)
        }
    });
    let (vaddr, fixed_dropped) = match picked {
        Ok(v) => v,
        Err(e) => return e,
    };

    if (flags & MAP_FIXED) != 0 {
        let mut vmspace = VmSpace::current();
        detach_shared_dropped(&mut vmspace, &fixed_dropped, vaddr, vaddr + length_aligned);
        vmspace.unmap_pages(VirtAddr::new(vaddr), pages);
    }

    if is_anon && is_shared {
        let segment = match crate::ipc::shm::create_anon_shared(length_aligned as usize) {
            Some(s) => s,
            None => return ENOMEM,
        };
        let vm_arc = match sched::with_current_process(|p| p.vmspace()) {
            Some(Some(v)) => v,
            _ => return EINVAL,
        };
        {
            let mut vm = vm_arc.lock();
            let mut mapped = 0usize;
            let mut failed = false;
            for (i, frame) in segment.frames.iter().enumerate() {
                let page = match Page::<Size4KiB>::from_start_address(VirtAddr::new(
                    vaddr + (i * 4096) as u64,
                )) {
                    Ok(p) => p,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                };
                if vm.map_one_frame(page, *frame, perms).is_err() {
                    failed = true;
                    break;
                }
                mapped += 1;
            }
            if failed {
                for j in 0..mapped {
                    vm.unmap_keep_frame(VirtAddr::new(vaddr + (j * 4096) as u64));
                }
                return ENOMEM;
            }
        }
        sched::with_current_mmap_mut(|m| {
            m.insert(Vma {
                start: vaddr,
                end: vaddr + length_aligned,
                prot: perms,
                flags: VmaFlags::SHARED,
                backing: VmaBacking::Shm {
                    segment: segment.clone(),
                },
            });
        });
        segment
            .attached
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
        return vaddr as i64;
    }

    let mut vflags = VmaFlags::empty();
    if is_anon {
        vflags |= VmaFlags::ANON;
    }
    if is_shared {
        vflags |= VmaFlags::SHARED;
    }
    sched::with_current_mmap_mut(|m| {
        m.insert(Vma {
            start: vaddr,
            end: vaddr + length_aligned,
            prot: perms,
            flags: vflags,
            backing,
        });
    });

    vaddr as i64
}

fn detach_shared_dropped(
    vmspace: &mut VmSpace,
    dropped: &[crate::process::Vma],
    addr: u64,
    end: u64,
) {
    use crate::process::{VmaBacking, VmaFlags};
    for vma in dropped {
        match &vma.backing {
            VmaBacking::File {
                inode,
                file_offset_base,
            } if vma.flags.contains(VmaFlags::SHARED) => {
                let lo = vma.start.max(addr);
                let hi = vma.end.min(end);
                let inode_id = inode.inode_id();
                let mut p = lo & !0xfff;
                while p < hi {
                    if vmspace.translate(VirtAddr::new(p)).is_some() {
                        vmspace.unmap_keep_frame(VirtAddr::new(p));
                        crate::fs::pagecache::unpin(inode_id, file_offset_base + (p - vma.start));
                    }
                    p += 4096;
                }
            }
            VmaBacking::Shm { segment } => {
                let pages_in_vma = ((vma.end - vma.start) / 4096) as usize;
                for i in 0..pages_in_vma {
                    vmspace.unmap_keep_frame(VirtAddr::new(vma.start + (i * 4096) as u64));
                }
                let prev = segment
                    .attached
                    .fetch_sub(1, core::sync::atomic::Ordering::AcqRel);
                if prev == 1
                    && segment
                        .marked_rmid
                        .load(core::sync::atomic::Ordering::Acquire)
                {
                    let id = segment.id;
                    let key = segment.key;
                    crate::ipc::shm::remove_table_entry(id, key);
                }
            }
            _ => {}
        }
    }
}

pub(super) fn sys_munmap(addr: u64, length: u64) -> i64 {
    if sched::current_is_vfork_borrower() {
        return ENOMEM;
    }
    if length == 0 || addr & 0xfff != 0 {
        return EINVAL;
    }
    let length_aligned = (length + 0xfff) & !0xfff;
    let pages = (length_aligned / 4096) as usize;
    let present_pages = {
        let mut vmspace = VmSpace::current();
        let mut n = 0usize;
        let mut p = 0usize;
        while p < pages {
            if vmspace
                .translate(VirtAddr::new(addr + (p as u64) * 4096))
                .is_some()
            {
                n += 1;
            }
            p += 1;
        }
        n
    };
    let dropped = sched::with_current_mmap_mut(|m| m.unmap_range(addr, addr + length_aligned));
    for vma in &dropped {
        if let crate::process::VmaBacking::File {
            inode,
            file_offset_base,
        } = &vma.backing
        {
            if vma.flags.contains(crate::process::VmaFlags::SHARED) {
                let lo = vma.start.max(addr);
                let hi = vma.end.min(addr + length_aligned);
                if lo < hi {
                    let file_lo = file_offset_base + (lo - vma.start);
                    let file_hi = file_lo + (hi - lo);
                    let _ = crate::fs::pagecache::writeback(
                        inode.inode_id(),
                        file_lo,
                        file_hi,
                        &**inode,
                    );
                }
            }
        }
    }
    let mut vmspace = VmSpace::current();
    detach_shared_dropped(&mut vmspace, &dropped, addr, addr + length_aligned);
    vmspace.unmap_pages(VirtAddr::new(addr), pages);
    if present_pages > 0 {
        sched::sub_cgroup_charge((present_pages as u64) * 4096);
    }
    0
}

const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;

pub(super) fn sys_mremap(
    old_addr: u64,
    old_size: u64,
    new_size: u64,
    flags: u64,
    _new_addr: u64,
) -> i64 {
    use crate::process::{Vma, VmaFlags};

    if sched::current_is_vfork_borrower() {
        return ENOMEM;
    }
    if old_addr & 0xfff != 0 || new_size == 0 {
        return EINVAL;
    }
    if flags & MREMAP_FIXED != 0 {
        return EINVAL;
    }
    let old_pages = old_size.div_ceil(4096) as usize;
    let new_pages = new_size.div_ceil(4096) as usize;
    let old_aligned = (old_pages * 4096) as u64;
    let new_aligned = (new_pages * 4096) as u64;

    let (vma_flags, perms, backing) =
        match sched::with_current_mmap(|m| m.find_containing(old_addr).cloned()) {
            Some(v) if v.start == old_addr && v.end - v.start == old_aligned => {
                (v.flags, v.prot, v.backing)
            }
            Some(_) => return EINVAL,
            None => return EFAULT,
        };

    if !vma_flags.contains(VmaFlags::ANON) && new_aligned != old_aligned {
        return EINVAL;
    }

    if new_aligned == old_aligned {
        return old_addr as i64;
    }

    if new_aligned < old_aligned {
        let drop_lo = old_addr + new_aligned;
        let drop_hi = old_addr + old_aligned;
        let _dropped = sched::with_current_mmap_mut(|m| m.unmap_range(drop_lo, drop_hi));
        let mut vmspace = VmSpace::current();
        let drop_pages = ((drop_hi - drop_lo) / 4096) as usize;
        let present = count_present(&mut vmspace, drop_lo, drop_pages);
        vmspace.unmap_pages(VirtAddr::new(drop_lo), drop_pages);
        if present > 0 {
            sched::sub_cgroup_charge((present as u64) * 4096);
        }
        return old_addr as i64;
    }

    let tail_lo = old_addr + old_aligned;
    let tail_hi = old_addr + new_aligned;
    let in_place =
        sched::with_current_mmap(|m| tail_hi <= m.arena_hi && !m.overlaps(tail_lo, tail_hi));
    if in_place {
        sched::with_current_mmap_mut(|m| {
            for v in m.vmas.iter_mut() {
                if v.start == old_addr {
                    v.end = tail_hi;
                    m_last_end_bump(m, tail_hi);
                    break;
                }
            }
        });
        return old_addr as i64;
    }

    if flags & MREMAP_MAYMOVE == 0 {
        return ENOMEM;
    }

    let dest = match sched::with_current_mmap_mut(|m| m.find_gap(new_aligned).ok_or(ENOMEM)) {
        Ok(a) => a,
        Err(e) => return e,
    };

    sched::with_current_mmap_mut(|m| {
        m.insert(Vma {
            start: dest,
            end: dest + new_aligned,
            prot: perms,
            flags: vma_flags,
            backing: backing.clone(),
        });
    });

    let copy_len = old_aligned.min(new_aligned) as usize;
    let mut buf = [0u8; 4096];
    let mut off = 0usize;
    while off < copy_len {
        let chunk = (copy_len - off).min(buf.len());
        if frame::user::copy_from_user(old_addr + off as u64, &mut buf[..chunk]).is_err() {
            return EFAULT;
        }
        if frame::user::copy_to_user(dest + off as u64, &buf[..chunk]).is_err() {
            return EFAULT;
        }
        off += chunk;
    }

    let _dropped =
        sched::with_current_mmap_mut(|m| m.unmap_range(old_addr, old_addr + old_aligned));
    let mut vmspace = VmSpace::current();
    let present = count_present(&mut vmspace, old_addr, old_pages);
    vmspace.unmap_pages(VirtAddr::new(old_addr), old_pages);
    drop(vmspace);
    if present > 0 {
        sched::sub_cgroup_charge((present as u64) * 4096);
    }

    dest as i64
}

fn count_present(vmspace: &mut VmSpace, base: u64, pages: usize) -> usize {
    let mut n = 0usize;
    for i in 0..pages {
        if vmspace
            .translate(VirtAddr::new(base + (i as u64) * 4096))
            .is_some()
        {
            n += 1;
        }
    }
    n
}

fn m_last_end_bump(m: &mut crate::process::MmapState, new_end: u64) {
    if new_end > m.last_end {
        m.last_end = new_end;
    }
}

pub(super) fn sys_msync(addr: u64, length: u64, _flags: u64) -> i64 {
    if length == 0 || addr & 0xfff != 0 {
        return EINVAL;
    }
    let length_aligned = (length + 0xfff) & !0xfff;
    let end = addr.saturating_add(length_aligned);
    type MsyncTarget = (u64, u64, u64, u64, Arc<dyn Inode>);
    let targets: alloc::vec::Vec<MsyncTarget> = sched::with_current_mmap(|m| {
        m.vmas
            .iter()
            .filter(|v| v.flags.contains(crate::process::VmaFlags::SHARED))
            .filter(|v| v.start < end && addr < v.end)
            .filter_map(|v| {
                if let crate::process::VmaBacking::File {
                    inode,
                    file_offset_base,
                } = &v.backing
                {
                    let lo = v.start.max(addr);
                    let hi = v.end.min(end);
                    let file_lo = file_offset_base + (lo - v.start);
                    let file_hi = file_offset_base + (hi - v.start);
                    Some((v.start, v.end, file_lo, file_hi, inode.clone()))
                } else {
                    None
                }
            })
            .collect()
    });
    for (_vstart, _vend, file_lo, file_hi, inode) in targets {
        let inode_id = inode.inode_id();
        if let Err(_e) = crate::fs::pagecache::writeback(inode_id, file_lo, file_hi, &*inode) {
            return -5;
        }
    }
    0
}

const MADV_NORMAL: u64 = 0;
const MADV_RANDOM: u64 = 1;
const MADV_SEQUENTIAL: u64 = 2;
const MADV_WILLNEED: u64 = 3;
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;
const MADV_REMOVE: u64 = 9;
const MADV_DONTFORK: u64 = 10;
const MADV_DOFORK: u64 = 11;
const MADV_MERGEABLE: u64 = 12;
const MADV_UNMERGEABLE: u64 = 13;
const MADV_HUGEPAGE: u64 = 14;
const MADV_NOHUGEPAGE: u64 = 15;
const MADV_DONTDUMP: u64 = 16;
const MADV_DODUMP: u64 = 17;
const MADV_WIPEONFORK: u64 = 18;
const MADV_KEEPONFORK: u64 = 19;
const MADV_COLD: u64 = 20;
const MADV_PAGEOUT: u64 = 21;
const MADV_POPULATE_READ: u64 = 22;
const MADV_POPULATE_WRITE: u64 = 23;

pub(super) fn sys_madvise(addr: u64, len: u64, advice: u64) -> i64 {
    if !matches!(
        advice,
        MADV_NORMAL
            | MADV_RANDOM
            | MADV_SEQUENTIAL
            | MADV_WILLNEED
            | MADV_DONTNEED
            | MADV_FREE
            | MADV_REMOVE
            | MADV_DONTFORK
            | MADV_DOFORK
            | MADV_MERGEABLE
            | MADV_UNMERGEABLE
            | MADV_HUGEPAGE
            | MADV_NOHUGEPAGE
            | MADV_DONTDUMP
            | MADV_DODUMP
            | MADV_WIPEONFORK
            | MADV_KEEPONFORK
            | MADV_COLD
            | MADV_PAGEOUT
            | MADV_POPULATE_READ
            | MADV_POPULATE_WRITE
    ) {
        return EINVAL;
    }
    if advice != MADV_DONTNEED && advice != MADV_FREE {
        return 0;
    }
    if sched::current_is_vfork_borrower() {
        return 0;
    }
    if addr & 0xfff != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let pages = len.div_ceil(4096) as usize;
    let end = match (pages as u64)
        .checked_mul(4096)
        .and_then(|bytes| addr.checked_add(bytes))
    {
        Some(e) => e,
        None => return EINVAL,
    };
    let ranges: alloc::vec::Vec<(u64, u64)> = sched::with_current_mmap(|m| {
        m.vmas
            .iter()
            .filter(|v| v.start < end && addr < v.end)
            .filter(|v| {
                v.flags.contains(crate::process::VmaFlags::ANON)
                    || (matches!(v.backing, crate::process::VmaBacking::File { .. })
                        && !v.flags.contains(crate::process::VmaFlags::SHARED))
            })
            .map(|v| (v.start.max(addr), v.end.min(end)))
            .collect()
    });
    let mut vmspace = VmSpace::current();
    let mut freed_pages = 0usize;
    for (lo, hi) in ranges {
        let rpages = ((hi - lo) / 4096) as usize;
        freed_pages += count_present(&mut vmspace, lo, rpages);
        vmspace.unmap_pages(VirtAddr::new(lo), rpages);
    }
    if freed_pages > 0 {
        sched::sub_cgroup_charge((freed_pages as u64) * 4096);
    }
    0
}

pub(super) fn sys_membarrier(cmd: u64, _flags: u64, _cpu_id: u64) -> i64 {
    const MEMBARRIER_CMD_QUERY: u64 = 0;
    const MEMBARRIER_CMD_SUPPORTED: u64 = 0b1110_1011;
    match cmd {
        MEMBARRIER_CMD_QUERY => MEMBARRIER_CMD_SUPPORTED as i64,
        1 | 2 | 8 | 32 => {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            0
        }
        3 | 16 | 64 => {
            0
        }
        _ => EINVAL,
    }
}

pub(super) fn sys_mlock(addr: u64, len: u64) -> i64 {
    mlock_validate(addr, len)
}

pub(super) fn sys_munlock(addr: u64, len: u64) -> i64 {
    mlock_validate(addr, len)
}

pub(super) fn sys_mlock2(addr: u64, len: u64, flags: u64) -> i64 {
    if flags & !1u64 != 0 {
        return EINVAL;
    }
    mlock_validate(addr, len)
}

fn mlock_validate(addr: u64, len: u64) -> i64 {
    if len == 0 {
        return 0;
    }
    let end = match addr.checked_add(len) {
        Some(e) => e,
        None => return EINVAL,
    };
    let ok = sched::with_current_mmap(|m| {
        let mut cur = addr & !0xfff;
        while cur < end {
            if m.find_containing(cur).is_none() {
                return false;
            }
            cur += 4096;
        }
        true
    });
    if !ok {
        return ENOMEM;
    }
    0
}

pub(super) fn sys_mlockall(flags: u64) -> i64 {
    if flags == 0 || flags & !0b111 != 0 {
        return EINVAL;
    }
    0
}

pub(super) fn sys_munlockall() -> i64 {
    0
}

pub(super) fn sys_mincore(addr: u64, len: u64, vec: u64) -> i64 {
    if addr & 0xfff != 0 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    let end = match addr.checked_add(len) {
        Some(e) => e,
        None => return EINVAL,
    };
    let pages = ((end - addr).saturating_add(4095) / 4096) as usize;
    let all_in_vma = sched::with_current_mmap(|m| {
        let mut cur = addr;
        while cur < end {
            if m.find_containing(cur).is_none() {
                return false;
            }
            cur = cur.saturating_add(4096);
        }
        true
    });
    if !all_in_vma {
        return ENOMEM;
    }
    let mut out = alloc::vec![0u8; pages];
    {
        let vm_arc =
            match sched::with_target_process(sched::current_pid(), |p| p.vmspace()).flatten() {
                Some(v) => v,
                None => return ENOMEM,
            };
        let mut vm = vm_arc.lock();
        for (i, slot) in out.iter_mut().enumerate().take(pages) {
            let va = addr + (i as u64) * 4096;
            if vm.translate(frame::mm::VirtAddr::new(va)).is_some() {
                *slot = 1;
            }
        }
    }
    if frame::user::copy_to_user(vec, &out).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_process_vm_readv(
    local_pid: u64,
    local_iov: u64,
    liovcnt: u64,
    remote_iov: u64,
    riovcnt: u64,
    _flags: u64,
) -> i64 {
    process_vm_iov(local_pid, local_iov, liovcnt, remote_iov, riovcnt, false)
}

pub(super) fn sys_process_vm_writev(
    local_pid: u64,
    local_iov: u64,
    liovcnt: u64,
    remote_iov: u64,
    riovcnt: u64,
    _flags: u64,
) -> i64 {
    process_vm_iov(local_pid, local_iov, liovcnt, remote_iov, riovcnt, true)
}

fn process_vm_iov(
    local_pid: u64,
    local_iov_ptr: u64,
    liovcnt: u64,
    remote_iov_ptr: u64,
    riovcnt: u64,
    write: bool,
) -> i64 {
    if liovcnt > 1024 || riovcnt > 1024 {
        return EINVAL;
    }
    let target = match sched::caller_local_to_host(local_pid as u32) {
        Some(p) => p,
        None => return ESRCH,
    };
    let caller_pid = sched::current_pid();
    if target != caller_pid {
        let cu: u32 = sched::with_target_process(caller_pid, |c| c.creds.lock().euid).unwrap_or(0);
        let allowed = if cu == 0 {
            true
        } else {
            sched::with_target_process(target, |t| {
                t.creds.lock().euid == cu
                    && t.dumpable.load(core::sync::atomic::Ordering::Relaxed) != 0
            })
            .unwrap_or(false)
        };
        if !allowed {
            return EPERM;
        }
    }
    let mut local_iov = alloc::vec::Vec::with_capacity(liovcnt as usize);
    let mut remote_iov = alloc::vec::Vec::with_capacity(riovcnt as usize);
    for i in 0..liovcnt as usize {
        let mut buf = [0u8; 16];
        if frame::user::copy_from_user(local_iov_ptr + (i * 16) as u64, &mut buf).is_err() {
            return EFAULT;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[0..8]);
        let base = u64::from_ne_bytes(b);
        b.copy_from_slice(&buf[8..16]);
        let len = u64::from_ne_bytes(b) as usize;
        local_iov.push((base, len));
    }
    for i in 0..riovcnt as usize {
        let mut buf = [0u8; 16];
        if frame::user::copy_from_user(remote_iov_ptr + (i * 16) as u64, &mut buf).is_err() {
            return EFAULT;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&buf[0..8]);
        let base = u64::from_ne_bytes(b);
        b.copy_from_slice(&buf[8..16]);
        let len = u64::from_ne_bytes(b) as usize;
        remote_iov.push((base, len));
    }
    let target_vm = match sched::with_target_vmspace(target) {
        Some(v) => v,
        None => return ESRCH,
    };
    let mut copied: usize = 0;
    let mut li = 0usize;
    let mut lo = 0usize;
    let mut ri = 0usize;
    let mut ro = 0usize;
    let mut tmp = [0u8; 4096];
    while li < local_iov.len() && ri < remote_iov.len() {
        let l_remaining = local_iov[li].1 - lo;
        let r_remaining = remote_iov[ri].1 - ro;
        let chunk = l_remaining.min(r_remaining).min(tmp.len());
        if chunk == 0 {
            if l_remaining == 0 {
                li += 1;
                lo = 0;
            }
            if r_remaining == 0 {
                ri += 1;
                ro = 0;
            }
            continue;
        }
        let r_addr = remote_iov[ri].0 + ro as u64;
        let l_addr = local_iov[li].0 + lo as u64;
        if write {
            if frame::user::copy_from_user(l_addr, &mut tmp[..chunk]).is_err() {
                break;
            }
            let mut vm = target_vm.lock();
            if frame::user::poke_other_vmspace(&mut vm, r_addr, &tmp[..chunk]).is_err() {
                break;
            }
        } else {
            {
                let mut vm = target_vm.lock();
                if frame::user::peek_other_vmspace(&mut vm, r_addr, &mut tmp[..chunk]).is_err() {
                    break;
                }
            }
            if frame::user::copy_to_user(l_addr, &tmp[..chunk]).is_err() {
                break;
            }
        }
        lo += chunk;
        ro += chunk;
        copied += chunk;
    }
    copied as i64
}

const MPOL_DEFAULT: u64 = 0;
const MPOL_PREFERRED: u64 = 1;
const MPOL_BIND: u64 = 2;
const MPOL_INTERLEAVE: u64 = 3;
const MPOL_LOCAL: u64 = 4;

pub(super) fn sys_mbind(
    _addr: u64,
    _len: u64,
    mode: u64,
    nodemask: u64,
    maxnode: u64,
    _flags: u64,
) -> i64 {
    if !matches!(
        mode,
        MPOL_DEFAULT | MPOL_PREFERRED | MPOL_BIND | MPOL_INTERLEAVE | MPOL_LOCAL
    ) {
        return EINVAL;
    }
    if mode != MPOL_DEFAULT && mode != MPOL_LOCAL && nodemask != 0 && maxnode > 0 {
        let mut buf = [0u8; 8];
        if frame::user::copy_from_user(nodemask, &mut buf).is_err() {
            return EFAULT;
        }
        let mask = u64::from_ne_bytes(buf);
        let bits_to_check = maxnode.min(64);
        let valid_mask: u64 = if bits_to_check >= 64 {
            u64::MAX
        } else {
            (1u64 << bits_to_check) - 1
        };
        if (mask & valid_mask) & !1u64 != 0 {
            return EINVAL;
        }
    }
    0
}

pub(super) fn sys_set_mempolicy(mode: u64, nodemask: u64, maxnode: u64) -> i64 {
    sys_mbind(0, 0, mode, nodemask, maxnode, 0)
}

pub(super) fn sys_get_mempolicy(
    mode_ptr: u64,
    nodemask: u64,
    maxnode: u64,
    _addr: u64,
    flags: u64,
) -> i64 {
    const MPOL_F_NODE: u64 = 1;
    let mode_value: i32 = if flags & MPOL_F_NODE != 0 {
        0
    } else {
        MPOL_DEFAULT as i32
    };
    if mode_ptr != 0 && frame::user::copy_to_user(mode_ptr, &mode_value.to_ne_bytes()).is_err() {
        return EFAULT;
    }
    if nodemask != 0 && maxnode > 0 {
        let bytes_needed = maxnode.div_ceil(8).min(8) as usize;
        let mut buf = [0u8; 8];
        buf[0] = 0b0000_0001;
        if frame::user::copy_to_user(nodemask, &buf[..bytes_needed]).is_err() {
            return EFAULT;
        }
    }
    0
}

pub(super) fn sys_set_mempolicy_home_node(
    _start: u64,
    _len: u64,
    home_node: u64,
    _flags: u64,
) -> i64 {
    if home_node != 0 {
        return EINVAL;
    }
    0
}
