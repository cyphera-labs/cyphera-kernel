use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use frame::mm::{Page, PhysFrame, Size4KiB, VirtAddr, frame_alloc, vm::Perms};

use crate::process::{Vma, VmaBacking, VmaFlags};
use crate::sched;

const PAGE_SIZE: usize = 4096;

const IPC_PRIVATE: i32 = 0;
const IPC_RMID: i32 = 0;
const IPC_SET: i32 = 1;
const IPC_STAT: i32 = 2;
const IPC_CREAT: u32 = 0o1000;
const IPC_EXCL: u32 = 0o2000;
const SHM_RDONLY: u32 = 0o010000;

use crate::errno::{EACCES, EEXIST, EFAULT, EINVAL, ENOENT, ENOMEM, EPERM};

const SHM_MAX_BYTES: usize = 1 << 30;

pub struct ShmSegment {
    pub id: i32,
    pub key: i32,
    pub size: usize,
    pub mode: AtomicU32,
    pub uid: AtomicU32,
    pub gid: AtomicU32,
    pub creator_uid: u32,
    pub creator_gid: u32,
    pub cpid: u32,
    pub lpid: AtomicU32,
    pub atime: AtomicU64,
    pub dtime: AtomicU64,
    pub ctime: AtomicU64,
    pub frames: Vec<PhysFrame<Size4KiB>>,
    pub attached: AtomicU32,
    pub marked_rmid: AtomicBool,
}

impl Drop for ShmSegment {
    fn drop(&mut self) {
        for f in self.frames.drain(..) {
            frame_alloc::free_frame(f);
        }
    }
}

pub fn create_anon_shared(size: usize) -> Option<Arc<ShmSegment>> {
    if size == 0 || size > SHM_MAX_BYTES {
        return None;
    }
    let pages = size.div_ceil(PAGE_SIZE);
    let mut frames: Vec<PhysFrame<Size4KiB>> = Vec::with_capacity(pages);
    for _ in 0..pages {
        let Some(f) = frame_alloc::alloc_frame() else {
            for fr in frames.drain(..) {
                frame_alloc::free_frame(fr);
            }
            return None;
        };
        frame::mm::zero_frame(f);
        frames.push(f);
    }
    let (uid, gid) = sched::with_current_creds(|c| (c.euid, c.egid));
    Some(Arc::new(ShmSegment {
        id: -1,
        key: IPC_PRIVATE,
        size,
        mode: AtomicU32::new(0o600),
        uid: AtomicU32::new(uid),
        gid: AtomicU32::new(gid),
        creator_uid: uid,
        creator_gid: gid,
        cpid: sched::current_tgid().raw(),
        lpid: AtomicU32::new(0),
        atime: AtomicU64::new(0),
        dtime: AtomicU64::new(0),
        ctime: AtomicU64::new(now_secs()),
        frames,
        attached: AtomicU32::new(0),
        marked_rmid: AtomicBool::new(false),
    }))
}

pub fn shmget(key: i32, size: usize, flags: u32) -> i64 {
    if size == 0 || size > SHM_MAX_BYTES {
        return EINVAL;
    }
    sched::with_current_ipc(|ns| {
        if key != IPC_PRIVATE {
            if let Some(id) = ns.key_to_id.lock().get(&key).copied() {
                if (flags & IPC_CREAT) != 0 && (flags & IPC_EXCL) != 0 {
                    return EEXIST;
                }
                return id as i64;
            }
            if (flags & IPC_CREAT) == 0 {
                return ENOENT;
            }
        }

        let pages = size.div_ceil(PAGE_SIZE);
        let mut frames: Vec<PhysFrame<Size4KiB>> = Vec::with_capacity(pages);
        for _ in 0..pages {
            let Some(f) = frame_alloc::alloc_frame() else {
                for fr in frames.drain(..) {
                    frame_alloc::free_frame(fr);
                }
                return ENOMEM;
            };
            frame::mm::zero_frame(f);
            frames.push(f);
        }

        let (uid, gid) = sched::with_current_creds(|c| (c.euid, c.egid));
        let mode = flags & 0o777;
        let id = ns.shm_next_id.fetch_add(1, Ordering::Relaxed);
        let segment = Arc::new(ShmSegment {
            id,
            key,
            size,
            mode: AtomicU32::new(mode),
            uid: AtomicU32::new(uid),
            gid: AtomicU32::new(gid),
            creator_uid: uid,
            creator_gid: gid,
            cpid: sched::current_tgid().raw(),
            lpid: AtomicU32::new(0),
            atime: AtomicU64::new(0),
            dtime: AtomicU64::new(0),
            ctime: AtomicU64::new(now_secs()),
            frames,
            attached: AtomicU32::new(0),
            marked_rmid: AtomicBool::new(false),
        });
        ns.shm_table.lock().insert(id, segment);
        if key != IPC_PRIVATE {
            ns.key_to_id.lock().insert(key, id);
        }
        id as i64
    })
}

pub fn shmat(shmid: i32, addr: u64, flags: u32) -> i64 {
    let seg = match sched::with_current_ipc(|ns| ns.shm_table.lock().get(&shmid).cloned()) {
        Some(s) => s,
        None => return EINVAL,
    };

    if !check_access(&seg, flags) {
        return EACCES;
    }

    let pages = seg.frames.len();
    let length = (pages * PAGE_SIZE) as u64;
    let mut perms = Perms::READ | Perms::USER;
    if (flags & SHM_RDONLY) == 0 {
        perms |= Perms::WRITE;
    }

    let mapping_addr = sched::current_addr_space_opt().and_then(|a| pick_address(&a, addr, length));
    let vaddr = match mapping_addr {
        Some(a) => a,
        None => return EINVAL,
    };

    let vm_arc = match sched::current_vmspace() {
        Some(v) => v,
        None => return EINVAL,
    };
    {
        let mut vm = vm_arc.lock();
        let mut mapped = 0usize;
        let mut failed = false;
        for (i, frame) in seg.frames.iter().enumerate() {
            let page_addr = VirtAddr::new(vaddr + (i * PAGE_SIZE) as u64);
            let page = match Page::<Size4KiB>::from_start_address(page_addr) {
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
                vm.unmap_keep_frame(VirtAddr::new(vaddr + (j * PAGE_SIZE) as u64));
            }
            return ENOMEM;
        }
    }

    {
        let vma = Vma {
            start: vaddr,
            end: vaddr + length,
            prot: perms,
            flags: VmaFlags::SHARED,
            backing: VmaBacking::Shm {
                segment: seg.clone(),
            },
        };
        let addr_space = sched::current_addr_space_opt().expect("shmat: no address space");
        let mut m = addr_space.mmap.lock();
        let pos = m
            .vmas
            .binary_search_by_key(&vaddr, |v| v.start)
            .unwrap_or_else(|e| e);
        m.vmas.insert(pos, vma);
        let new_end = vaddr + length;
        if new_end > m.last_end {
            m.last_end = new_end;
        }
    }
    seg.attached.fetch_add(1, Ordering::AcqRel);
    seg.atime.store(now_secs(), Ordering::Relaxed);
    seg.lpid
        .store(sched::current_tgid().raw(), Ordering::Relaxed);
    vaddr as i64
}

pub fn shmdt(addr: u64) -> i64 {
    let detached = sched::current_addr_space_opt().and_then(|addr_space| {
        let mut m = addr_space.mmap.lock();
        let pos = m.vmas.iter().position(|v| v.start == addr)?;
        let vma = &m.vmas[pos];
        match &vma.backing {
            VmaBacking::Shm { segment } => {
                let length = vma.end - vma.start;
                let segment = segment.clone();
                m.vmas.remove(pos);
                Some((segment, length))
            }
            _ => None,
        }
    });
    let (segment, length) = match detached {
        Some(t) => t,
        None => return EINVAL,
    };

    let vm_arc = match sched::current_vmspace() {
        Some(v) => v,
        None => return EINVAL,
    };
    {
        let mut vm = vm_arc.lock();
        let pages = (length / PAGE_SIZE as u64) as usize;
        for i in 0..pages {
            vm.unmap_keep_frame(VirtAddr::new(addr + (i * PAGE_SIZE) as u64));
        }
    }

    segment.dtime.store(now_secs(), Ordering::Relaxed);
    segment
        .lpid
        .store(sched::current_tgid().raw(), Ordering::Relaxed);
    let prev = segment.attached.fetch_sub(1, Ordering::AcqRel);
    if prev == 1 && segment.marked_rmid.load(Ordering::Acquire) {
        sched::with_current_ipc(|ns| remove_segment_if_member(ns, &segment));
    }
    0
}

pub fn detach_all_current() {
    if sched::with_current_lifecycle(|l| l.vfork_shared_vm()).unwrap_or(false) {
        return;
    }
    let Some(addr_space) = sched::current_addr_space_opt() else {
        return;
    };
    let ipc_ns = sched::current_ipc_ns();
    detach_all_for(&addr_space, ipc_ns.as_ref());
}

pub fn detach_all_for(
    addr_space: &crate::process::AddressSpace,
    ipc_ns: Option<&Arc<crate::process::IpcNamespace>>,
) {
    let detached: Vec<(Arc<ShmSegment>, u64, u64)> = {
        let mut m = addr_space.mmap.lock();
        let mut out = Vec::new();
        let mut i = 0;
        while i < m.vmas.len() {
            if let VmaBacking::Shm { segment } = &m.vmas[i].backing {
                let v = &m.vmas[i];
                out.push((segment.clone(), v.start, v.end - v.start));
                m.vmas.remove(i);
            } else {
                i += 1;
            }
        }
        out
    };

    if detached.is_empty() {
        return;
    }

    {
        let mut vm = addr_space.vmspace.lock();
        for (_seg, addr, length) in &detached {
            let pages = (*length / PAGE_SIZE as u64) as usize;
            for i in 0..pages {
                vm.unmap_keep_frame(VirtAddr::new(*addr + (i * PAGE_SIZE) as u64));
            }
        }
    }

    for (segment, _addr, _length) in detached {
        let prev = segment.attached.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 && segment.marked_rmid.load(Ordering::Acquire) {
            if let Some(ns) = ipc_ns {
                remove_segment_if_member(ns, &segment);
            }
        }
    }
}

fn remove_segment_if_member(ns: &crate::process::IpcNamespace, segment: &Arc<ShmSegment>) {
    let mut table = ns.shm_table.lock();
    if table
        .get(&segment.id)
        .map(|e| Arc::ptr_eq(e, segment))
        .unwrap_or(false)
    {
        table.remove(&segment.id);
        drop(table);
        if segment.key != IPC_PRIVATE {
            ns.key_to_id.lock().remove(&segment.key);
        }
    }
}

pub fn remove_table_entry(shmid: i32, key: i32) {
    sched::with_current_ipc(|ns| {
        ns.shm_table.lock().remove(&shmid);
        if key != IPC_PRIVATE {
            ns.key_to_id.lock().remove(&key);
        }
    });
}

pub fn shmctl(shmid: i32, cmd: i32, buf: u64) -> i64 {
    match cmd {
        IPC_RMID => {
            let seg = match sched::with_current_ipc(|ns| ns.shm_table.lock().get(&shmid).cloned()) {
                Some(s) => s,
                None => return EINVAL,
            };
            if !ipc_owner_or_admin(&seg) {
                return EPERM;
            }
            seg.marked_rmid.store(true, Ordering::Release);
            if seg.attached.load(Ordering::Acquire) == 0 {
                sched::with_current_ipc(|ns| {
                    ns.shm_table.lock().remove(&shmid);
                    if seg.key != IPC_PRIVATE {
                        ns.key_to_id.lock().remove(&seg.key);
                    }
                });
            }
            0
        }
        IPC_STAT => {
            let seg = match sched::with_current_ipc(|ns| ns.shm_table.lock().get(&shmid).cloned()) {
                Some(s) => s,
                None => return EINVAL,
            };
            if !stat_access(&seg) {
                return EACCES;
            }
            let (uid, gid, cuid, cgid) = sched::with_current_creds(|c| {
                (
                    c.uid_from_kernel(seg.uid.load(Ordering::Relaxed)),
                    c.gid_from_kernel(seg.gid.load(Ordering::Relaxed)),
                    c.uid_from_kernel(seg.creator_uid),
                    c.gid_from_kernel(seg.creator_gid),
                )
            });
            let mut ds = [0u8; SHMID_DS_LEN];
            ds[0..4].copy_from_slice(&seg.key.to_le_bytes());
            ds[4..8].copy_from_slice(&uid.to_le_bytes());
            ds[8..12].copy_from_slice(&gid.to_le_bytes());
            ds[12..16].copy_from_slice(&cuid.to_le_bytes());
            ds[16..20].copy_from_slice(&cgid.to_le_bytes());
            let mode = (seg.mode.load(Ordering::Relaxed) & 0o777) as u16;
            ds[20..22].copy_from_slice(&mode.to_le_bytes());
            ds[48..56].copy_from_slice(&(seg.size as u64).to_le_bytes());
            ds[56..64].copy_from_slice(&(seg.atime.load(Ordering::Relaxed) as i64).to_le_bytes());
            ds[64..72].copy_from_slice(&(seg.dtime.load(Ordering::Relaxed) as i64).to_le_bytes());
            ds[72..80].copy_from_slice(&(seg.ctime.load(Ordering::Relaxed) as i64).to_le_bytes());
            let cpid_local = sched::host_to_caller_local(crate::process::Pid(seg.cpid));
            ds[80..84].copy_from_slice(&(cpid_local as i32).to_le_bytes());
            let lpid_raw = seg.lpid.load(Ordering::Relaxed);
            let lpid_local = if lpid_raw == 0 {
                0
            } else {
                sched::host_to_caller_local(crate::process::Pid(lpid_raw))
            };
            ds[84..88].copy_from_slice(&(lpid_local as i32).to_le_bytes());
            let nattch = seg.attached.load(Ordering::Acquire) as u64;
            ds[88..96].copy_from_slice(&nattch.to_le_bytes());
            if frame::user::copy_to_user(buf, &ds).is_err() {
                return EFAULT;
            }
            0
        }
        IPC_SET => {
            let seg = match sched::with_current_ipc(|ns| ns.shm_table.lock().get(&shmid).cloned()) {
                Some(s) => s,
                None => return EINVAL,
            };
            if !ipc_owner_or_admin(&seg) {
                return EPERM;
            }
            let mut ds = [0u8; SHMID_DS_LEN];
            if frame::user::copy_from_user(buf, &mut ds).is_err() {
                return EFAULT;
            }
            let new_uid = u32::from_le_bytes(ds[4..8].try_into().unwrap());
            let new_gid = u32::from_le_bytes(ds[8..12].try_into().unwrap());
            let new_mode = (u16::from_le_bytes(ds[20..22].try_into().unwrap()) & 0o777) as u32;
            let (new_uid_k, new_gid_k) = match sched::with_current_creds(|c| {
                Some((c.uid_into_kernel(new_uid)?, c.gid_into_kernel(new_gid)?))
            }) {
                Some(p) => p,
                None => return EINVAL,
            };
            seg.uid.store(new_uid_k, Ordering::Relaxed);
            seg.gid.store(new_gid_k, Ordering::Relaxed);
            seg.mode.store(new_mode, Ordering::Relaxed);
            seg.ctime.store(now_secs(), Ordering::Relaxed);
            0
        }
        _ => EINVAL,
    }
}

const SHMID_DS_LEN: usize = 112;

fn now_secs() -> u64 {
    let wall = frame::cpu::clock::wall_clock_nanos();
    let ns = if wall != 0 {
        wall
    } else {
        frame::cpu::clock::nanos_since_boot()
    };
    ns / 1_000_000_000
}

fn pick_address(addr_space: &crate::process::AddressSpace, addr: u64, length: u64) -> Option<u64> {
    let m = addr_space.mmap.lock();
    if addr != 0 {
        if (addr & 0xfff) != 0 {
            return None;
        }
        for vma in &m.vmas {
            if !(vma.end <= addr || vma.start >= addr + length) {
                return None;
            }
        }
        Some(addr)
    } else {
        m.find_gap(length)
    }
}

fn check_access(seg: &ShmSegment, flags: u32) -> bool {
    if sched::with_current_creds(|c| c.is_privileged()) {
        return true;
    }
    let want = if (flags & SHM_RDONLY) != 0 {
        0o4u32
    } else {
        0o6u32
    };
    let (caller_uid, caller_gid) = sched::with_current_creds(|c| (c.euid, c.egid));
    let mode = seg.mode.load(Ordering::Relaxed);
    let class_bits = if caller_uid == seg.uid.load(Ordering::Relaxed) {
        (mode >> 6) & 0o7
    } else if caller_gid == seg.gid.load(Ordering::Relaxed) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    class_bits & want == want
}

fn ipc_owner_or_admin(seg: &ShmSegment) -> bool {
    sched::with_current_creds(|c| {
        c.capable_host(crate::process::CAP_SYS_ADMIN)
            || c.euid == seg.uid.load(Ordering::Relaxed)
            || c.euid == seg.creator_uid
    })
}

fn stat_access(seg: &ShmSegment) -> bool {
    if sched::with_current_creds(|c| c.is_privileged()) {
        return true;
    }
    let (caller_uid, caller_gid) = sched::with_current_creds(|c| (c.euid, c.egid));
    let mode = seg.mode.load(Ordering::Relaxed);
    let class_bits = if caller_uid == seg.uid.load(Ordering::Relaxed) {
        (mode >> 6) & 0o7
    } else if caller_gid == seg.gid.load(Ordering::Relaxed) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };
    (class_bits & 0o4) == 0o4
}
