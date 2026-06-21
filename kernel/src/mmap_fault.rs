extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use frame::mm::{
    Page, PhysFrame, Size4KiB, VirtAddr, frame_alloc, vm::VmSpace, write_to_frame, zero_frame,
};

use crate::process::{VmaBacking, VmaFlags};
use crate::sched;
use crate::vfs::Inode;

pub fn detach_shared_file_current() {
    if sched::with_current_lifecycle(|l| l.vfork_shared_vm()).unwrap_or(false) {
        return;
    }
    let Some(addr_space) = sched::current_addr_space_opt() else {
        return;
    };
    detach_shared_file_for(&addr_space);
}

pub fn detach_shared_file_for(addr_space: &crate::process::AddressSpace) {
    let detached: Vec<(u64, u64, Arc<dyn Inode>, u64)> = {
        let mut m = addr_space.mmap.lock();
        let mut out = Vec::new();
        let mut i = 0;
        while i < m.vmas.len() {
            let v = &m.vmas[i];
            if v.flags.contains(VmaFlags::SHARED) {
                if let VmaBacking::File {
                    inode,
                    file_offset_base,
                } = &v.backing
                {
                    out.push((v.start, v.end, inode.clone(), *file_offset_base));
                    m.vmas.remove(i);
                    continue;
                }
            }
            i += 1;
        }
        out
    };

    if detached.is_empty() {
        return;
    }

    for (start, end, inode, offset_base) in &detached {
        let file_lo = *offset_base;
        let file_hi = *offset_base + (*end - *start);
        let _ = crate::fs::pagecache::writeback(inode.inode_id(), file_lo, file_hi, &**inode);
    }

    {
        let mut vm = addr_space.vmspace.lock();
        for (start, end, inode, offset_base) in &detached {
            let mut p = *start;
            while p < *end {
                if vm.translate(VirtAddr::new(p)).is_some() {
                    vm.unmap_keep_frame(VirtAddr::new(p));
                    crate::fs::pagecache::unpin(inode.inode_id(), offset_base + (p - start));
                }
                p += 4096;
            }
        }
    }
}

const PF_PRESENT: u64 = 1 << 0;
const PF_WRITE: u64 = 1 << 1;

pub fn try_handle(cr2: u64, error: u64) -> bool {
    if sched::current_pid_opt().is_none() {
        return false;
    }
    let page_addr = cr2 & !0xfff;
    let is_write = (error & PF_WRITE) != 0;

    if (error & PF_PRESENT) != 0 {
        if is_write {
            return try_break_cow(page_addr);
        }
        return false;
    }

    let snap = match sched::with_current_mmap(|m| {
        let generation = m.generation();
        m.find_containing(page_addr).map(|v| {
            (
                v.start,
                v.end,
                v.prot,
                v.flags,
                v.backing.clone(),
                generation,
            )
        })
    }) {
        Some(v) => v,
        None => {
            const USER_STACK_BASE: u64 = 0x7000_0000_0000;
            const USER_STACK_MAX_GROWTH: u64 = 8 * 1024 * 1024;
            if (USER_STACK_BASE - USER_STACK_MAX_GROWTH..USER_STACK_BASE).contains(&page_addr) {
                return grow_stack(page_addr);
            }
            return false;
        }
    };
    let (vma_start, _vma_end, prot, vma_flags, backing, snap_generation) = snap;

    if !prot.intersects(
        frame::mm::vm::Perms::READ
            .union(frame::mm::vm::Perms::WRITE)
            .union(frame::mm::vm::Perms::EXECUTE),
    ) {
        return false;
    }

    if is_write && !prot.contains(frame::mm::vm::Perms::WRITE) {
        return false;
    }

    let is_shared_file =
        vma_flags.contains(VmaFlags::SHARED) && matches!(backing, VmaBacking::File { .. });

    let frame: PhysFrame<Size4KiB> = if is_shared_file {
        let cg = sched::current_cgroup();
        if let Some(cg) = &cg {
            if cg.try_charge_memory(4096).is_err() {
                cg.oom_kill_one();
                return false;
            }
        }
        let (inode, file_offset_base) = match &backing {
            VmaBacking::File {
                inode,
                file_offset_base,
            } => (inode, *file_offset_base),
            _ => unreachable!(),
        };
        let page_off_in_file = file_offset_base + (page_addr - vma_start);
        let inode_id = inode.inode_id();
        match crate::fs::pagecache::pin_or_load(inode_id, page_off_in_file, &**inode) {
            Some(f) => {
                if prot.contains(frame::mm::vm::Perms::WRITE) {
                    crate::fs::pagecache::mark_dirty(inode_id, page_off_in_file);
                }
                let _ = is_write;
                sched::add_cgroup_charge(4096);
                f
            }
            None => {
                if let Some(cg) = &cg {
                    cg.uncharge_memory(4096);
                }
                return false;
            }
        }
    } else {
        let cg = sched::current_cgroup();
        if let Some(cg) = &cg {
            if cg.try_charge_memory(4096).is_err() {
                cg.oom_kill_one();
                return false;
            }
        }
        let frame: PhysFrame<Size4KiB> = match frame_alloc::alloc_frame() {
            Some(f) => f,
            None => {
                if let Some(cg) = &cg {
                    cg.uncharge_memory(4096);
                }
                return false;
            }
        };
        sched::add_cgroup_charge(4096);
        match &backing {
            VmaBacking::Anonymous => {
                zero_frame(frame);
            }
            VmaBacking::File {
                inode,
                file_offset_base,
            } => {
                zero_frame(frame);
                if !fill_from_file(frame, inode, *file_offset_base, page_addr - vma_start) {
                    frame_alloc::free_frame(frame);
                    return false;
                }
            }
            VmaBacking::Shm { .. } => {
                frame_alloc::free_frame(frame);
                return false;
            }
        }
        frame
    };

    let page = match Page::<Size4KiB>::from_start_address(VirtAddr::new(page_addr)) {
        Ok(p) => p,
        Err(_) => {
            if is_shared_file {
                if let VmaBacking::File {
                    inode,
                    file_offset_base,
                } = &backing
                {
                    crate::fs::pagecache::unpin(
                        inode.inode_id(),
                        file_offset_base + (page_addr - vma_start),
                    );
                }
            } else {
                frame_alloc::free_frame(frame);
            }
            return false;
        }
    };
    let release = || {
        if is_shared_file {
            if let VmaBacking::File {
                inode,
                file_offset_base,
            } = &backing
            {
                crate::fs::pagecache::unpin(
                    inode.inode_id(),
                    file_offset_base + (page_addr - vma_start),
                );
            }
        } else {
            frame_alloc::free_frame(frame);
        }
        sched::sub_cgroup_charge(4096);
    };
    let Some(addr_space) = sched::current_addr_space_opt() else {
        release();
        return false;
    };
    let install = {
        let mut vmspace = addr_space.vmspace.lock();
        let install_prot = {
            let mmap = addr_space.mmap.lock();
            if mmap.generation() == snap_generation {
                Some(prot)
            } else {
                mmap.find_containing(page_addr).and_then(|v| {
                    let perm_ok = if is_write {
                        v.prot.contains(frame::mm::vm::Perms::WRITE)
                    } else {
                        v.prot.intersects(
                            frame::mm::vm::Perms::READ
                                .union(frame::mm::vm::Perms::WRITE)
                                .union(frame::mm::vm::Perms::EXECUTE),
                        )
                    };
                    let backing_ok = match (&backing, &v.backing) {
                        (VmaBacking::Anonymous, VmaBacking::Anonymous) => true,
                        (
                            VmaBacking::File {
                                inode: a,
                                file_offset_base: ao,
                            },
                            VmaBacking::File {
                                inode: b,
                                file_offset_base: bo,
                            },
                        ) => a.inode_id() == b.inode_id() && ao == bo && v.start == vma_start,
                        _ => false,
                    };
                    (perm_ok && backing_ok).then_some(v.prot)
                })
            }
        };
        let Some(install_prot) = install_prot else {
            release();
            return false;
        };
        vmspace.map_one_frame(page, frame, install_prot)
    };
    match install {
        Ok(()) => {}
        Err(frame::mm::vm::MapError::AlreadyMapped) => {
            release();
            return true;
        }
        Err(_) => {
            release();
            return false;
        }
    }
    let was_major = !is_shared_file && matches!(backing, VmaBacking::File { .. });
    if was_major {
        sched::record_major_fault();
    } else {
        sched::record_minor_fault();
    }
    true
}

fn try_break_cow(page_addr: u64) -> bool {
    let vma_prot = sched::with_current_mmap(|m| m.find_containing(page_addr).map(|v| v.prot));
    if let Some(prot) = vma_prot {
        if !prot.contains(frame::mm::vm::Perms::WRITE) {
            return false;
        }
    }

    let Some(addr_space) = sched::current_addr_space_opt() else {
        return false;
    };

    let cg = sched::current_cgroup();
    if let Some(cg) = &cg {
        if cg.try_charge_memory(4096).is_err() {
            cg.oom_kill_one();
            return false;
        }
    }

    let outcome = {
        let mut vmspace = addr_space.vmspace.lock();
        vmspace.break_cow(VirtAddr::new(page_addr), None)
    };

    match outcome {
        Ok(frame::mm::vm::CowBreak::Broken { old_frame }) => {
            frame::cpu::tlb::shootdown_all();
            frame_alloc::free_frame(old_frame);
            sched::add_cgroup_charge(4096);
            sched::record_minor_fault();
            true
        }
        Ok(frame::mm::vm::CowBreak::BrokenInPlace) => {
            frame::cpu::tlb::shootdown_all();
            if let Some(cg) = &cg {
                cg.uncharge_memory(4096);
            }
            sched::record_minor_fault();
            true
        }
        Ok(frame::mm::vm::CowBreak::AlreadyWritable) => {
            frame::cpu::tlb::flush_local_page(page_addr);
            if let Some(cg) = &cg {
                cg.uncharge_memory(4096);
            }
            true
        }
        _ => {
            if let Some(cg) = &cg {
                cg.uncharge_memory(4096);
            }
            false
        }
    }
}

fn grow_stack(page_addr: u64) -> bool {
    use frame::mm::vm::Perms;
    let cg = sched::current_cgroup();
    if let Some(cg) = &cg {
        if cg.try_charge_memory(4096).is_err() {
            cg.oom_kill_one();
            return false;
        }
    }
    let frame: PhysFrame<Size4KiB> = match frame_alloc::alloc_frame() {
        Some(f) => f,
        None => {
            if let Some(cg) = &cg {
                cg.uncharge_memory(4096);
            }
            return false;
        }
    };
    sched::add_cgroup_charge(4096);
    zero_frame(frame);
    let page = match Page::<Size4KiB>::from_start_address(VirtAddr::new(page_addr)) {
        Ok(p) => p,
        Err(_) => {
            frame_alloc::free_frame(frame);
            return false;
        }
    };
    let mut vmspace = VmSpace::current();
    if vmspace.map_one_frame(page, frame, Perms::USER_RW).is_err() {
        frame_alloc::free_frame(frame);
        return false;
    }
    sched::record_minor_fault();
    true
}

fn fill_from_file(
    frame: PhysFrame<Size4KiB>,
    inode: &Arc<dyn Inode>,
    file_offset_base: u64,
    page_off: u64,
) -> bool {
    let mut buf = [0u8; 4096];
    let off = file_offset_base + page_off;
    match inode.read_at(off, &mut buf) {
        Ok(n) => {
            write_to_frame(frame, 0, &buf[..n]);
            true
        }
        Err(_) => false,
    }
}
