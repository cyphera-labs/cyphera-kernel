use alloc::sync::Arc;

use super::{GLOBAL, current_pid};
use crate::process::{BrkState, MmapState, Pid};

fn with_memory_mut(pid: Pid, f: impl FnOnce(&mut crate::process::MemoryContext)) {
    if let Some(p) = GLOBAL.lock().processes.get_mut(&pid) {
        f(&mut p.memory);
    }
}

pub fn set_fs_base(pid: Pid, addr: u64) {
    with_memory_mut(pid, |m| m.set_fs_base(addr));
}

pub fn set_current_fs_base(addr: u64) {
    set_fs_base(current_pid(), addr);
}

pub fn set_clear_child_tid(pid: Pid, addr: u64) {
    with_memory_mut(pid, |m| m.set_clear_child_tid(addr));
}

pub fn set_current_clear_child_tid(addr: u64) {
    set_clear_child_tid(current_pid(), addr);
}

pub fn set_current_robust_list(head: u64) {
    with_memory_mut(current_pid(), |m| m.set_robust_list_head(head));
}

fn current_addr_space() -> Arc<crate::process::AddressSpace> {
    let pid = current_pid();
    let g = GLOBAL.lock();
    g.processes
        .get(&pid)
        .unwrap()
        .addr_space
        .clone()
        .expect("current task has no address space")
}

pub fn current_addr_space_opt() -> Option<Arc<crate::process::AddressSpace>> {
    let pid = current_pid();
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .and_then(|p| p.addr_space.clone())
}

pub fn current_vmspace() -> Option<Arc<frame::sync::SpinIrq<frame::mm::vm::VmSpace>>> {
    super::with_target_vmspace(current_pid())
}

pub fn with_current_memory_mut<R>(
    f: impl FnOnce(&mut crate::process::MemoryContext) -> R,
) -> Option<R> {
    let pid = current_pid();
    GLOBAL
        .lock()
        .processes
        .get_mut(&pid)
        .map(|p| f(&mut p.memory))
}

pub fn current_brk() -> BrkState {
    *current_addr_space().brk.lock()
}

pub fn set_current_brk(addr: u64) -> u64 {
    let addr_space = current_addr_space();
    let mut brk = addr_space.brk.lock();
    let new = addr.clamp(brk.start, brk.max);
    brk.current = new;
    new
}

pub fn alloc_current_mmap(len: u64) -> Option<u64> {
    let len = (len + 0xfff) & !0xfff;
    current_addr_space().mmap.lock().find_gap(len)
}

pub fn with_current_mmap_mut<R>(f: impl FnOnce(&mut MmapState) -> R) -> R {
    let pid = current_pid();
    let (addr_space, is_vfork_borrower) = {
        let g = GLOBAL.lock();
        let proc = g.processes.get(&pid).unwrap();
        (
            proc.addr_space
                .clone()
                .expect("with_current_mmap_mut: no address space"),
            proc.lifecycle.vfork_shared_vm(),
        )
    };
    assert!(
        !is_vfork_borrower,
        "[VFORK_LEASE] VMA-topology mutation reached with_current_mmap_mut under a live vfork lease (pid {})",
        pid.0,
    );
    let mut mmap = addr_space.mmap.lock();
    f(&mut mmap)
}

pub fn with_current_mmap<R>(f: impl FnOnce(&MmapState) -> R) -> R {
    let addr_space = current_addr_space();
    let mmap = addr_space.mmap.lock();
    f(&mmap)
}

pub fn current_vmspace_id() -> u64 {
    let pid = current_pid();
    let g = GLOBAL.lock();
    g.processes
        .get(&pid)
        .and_then(|p| p.pml4_root.map(|f| f.start_address().as_u64()))
        .unwrap_or(0)
}

pub enum MapVmaLabel {
    Heap,
    Stack,
    Anon,
    File,
}

pub struct MapsSnapshot {
    pub brk_start: u64,
    pub brk_cur: u64,
    pub vmas: alloc::vec::Vec<(u64, u64, frame::mm::vm::Perms, bool, MapVmaLabel)>,
    pub segments: alloc::vec::Vec<(u64, u64, frame::mm::vm::Perms, crate::process::MapSegLabel)>,
}

pub fn process_maps(pid: Pid) -> Option<MapsSnapshot> {
    let g = GLOBAL.lock();
    let proc = g.processes.get(&pid)?;
    let addr_space = proc.addr_space.as_ref()?;
    let m = addr_space.mmap.lock();
    let brk = *addr_space.brk.lock();
    let mut vmas = alloc::vec::Vec::with_capacity(m.vmas.len());
    for v in &m.vmas {
        let label = match &v.backing {
            crate::process::VmaBacking::File { .. } => MapVmaLabel::File,
            crate::process::VmaBacking::Shm { .. } | crate::process::VmaBacking::Anonymous => {
                MapVmaLabel::Anon
            }
        };
        vmas.push((
            v.start,
            v.end,
            v.prot,
            v.flags.contains(crate::process::VmaFlags::SHARED),
            label,
        ));
    }
    let segments = proc
        .memory
        .maps_layout()
        .segments
        .iter()
        .map(|s| (s.start, s.end, s.prot, s.label))
        .collect();
    Some(MapsSnapshot {
        brk_start: brk.start,
        brk_cur: brk.current,
        vmas,
        segments,
    })
}

pub fn set_maps_layout(pid: Pid, layout: crate::process::MapsLayout) {
    with_memory_mut(pid, |m| m.set_maps_layout(layout));
}
