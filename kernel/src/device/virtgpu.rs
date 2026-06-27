extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::sync::SpinIrq;

use crate::errno::*;
use crate::ipc::shm::{ShmSegment, create_anon_shared, create_device_region};
use crate::vfs::{Inode, InodeKind, OpenFlags, PollMask, Stat};

const NR_VERSION: u32 = 0x00;
const NR_GEM_CLOSE: u32 = 0x09;
const NR_GET_CAP: u32 = 0x0c;
const NR_SET_CLIENT_CAP: u32 = 0x0d;

const DRM_COMMAND_BASE: u32 = 0x40;
const NR_MAP: u32 = DRM_COMMAND_BASE + 0x01;
const NR_EXECBUFFER: u32 = DRM_COMMAND_BASE + 0x02;
const NR_GETPARAM: u32 = DRM_COMMAND_BASE + 0x03;
const NR_RESOURCE_CREATE: u32 = DRM_COMMAND_BASE + 0x04;
const NR_RESOURCE_INFO: u32 = DRM_COMMAND_BASE + 0x05;
const NR_TRANSFER_FROM_HOST: u32 = DRM_COMMAND_BASE + 0x06;
const NR_TRANSFER_TO_HOST: u32 = DRM_COMMAND_BASE + 0x07;
const NR_WAIT: u32 = DRM_COMMAND_BASE + 0x08;
const NR_GET_CAPS: u32 = DRM_COMMAND_BASE + 0x09;
const NR_RESOURCE_CREATE_BLOB: u32 = DRM_COMMAND_BASE + 0x0a;

const BLOB_MEM_HOST3D: u32 = 0x0002;

const VIRTGPU_PARAM_3D_FEATURES: u64 = 1;
const VIRTGPU_PARAM_CAPSET_QUERY_FIX: u64 = 2;
const VIRTGPU_PARAM_RESOURCE_BLOB: u64 = 3;
const VIRTGPU_PARAM_HOST_VISIBLE: u64 = 4;
const VIRTGPU_PARAM_CROSS_DEVICE: u64 = 5;
const VIRTGPU_PARAM_CONTEXT_INIT: u64 = 6;
const VIRTGPU_PARAM_SUPPORTED_CAPSET_IDS: u64 = 7;

const CAPSET_VIRGL: u32 = 1;
const CAPSET_VIRGL2: u32 = 2;

const CLIENT_CAP_STEREO_3D: u64 = 1;
const CLIENT_CAP_UNIVERSAL_PLANES: u64 = 2;

const VIRGL_RES_BASE: u32 = 0x1_0000;
const IMPLICIT_CTX_ID: u32 = 1;

fn rd64(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}
fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn wr32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn wr64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

pub fn ioctl(cmd: u32, arg: u64) -> i64 {
    let nr = cmd & 0xff;
    match nr {
        NR_VERSION => ioctl_version(arg),
        NR_GET_CAP => ioctl_get_cap(arg),
        NR_SET_CLIENT_CAP => ioctl_set_client_cap(arg),
        NR_GEM_CLOSE => ioctl_gem_close(arg),
        NR_GETPARAM => ioctl_getparam(arg),
        NR_GET_CAPS => ioctl_get_caps(arg),
        NR_RESOURCE_CREATE => ioctl_resource_create(arg),
        NR_RESOURCE_INFO => ioctl_resource_info(arg),
        NR_MAP => ioctl_map(arg),
        NR_TRANSFER_TO_HOST => ioctl_transfer(arg, true),
        NR_TRANSFER_FROM_HOST => ioctl_transfer(arg, false),
        NR_EXECBUFFER => ioctl_execbuffer(cmd, arg),
        NR_WAIT => ioctl_wait(arg),
        NR_RESOURCE_CREATE_BLOB => ioctl_resource_create_blob(arg),
        _ => ENOTTY,
    }
}

fn ioctl_version(arg: u64) -> i64 {
    let mut b = [0u8; 64];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    wr32(&mut b, 0, 0);
    wr32(&mut b, 4, 1);
    wr32(&mut b, 8, 0);
    let fields: [(usize, usize, &[u8]); 3] = [
        (16, 24, b"virtio_gpu"),
        (32, 40, b"0"),
        (48, 56, b"virgl render node"),
    ];
    for (len_off, ptr_off, s) in fields {
        let cap = rd64(&b, len_off) as usize;
        let ptr = rd64(&b, ptr_off);
        if ptr != 0 && cap > 0 {
            let n = cap.min(s.len());
            if frame::user::copy_to_user(ptr, &s[..n]).is_err() {
                return EFAULT;
            }
        }
        wr64(&mut b, len_off, s.len() as u64);
    }
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_get_cap(arg: u64) -> i64 {
    let mut b = [0u8; 16];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    wr64(&mut b, 8, 0);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_set_client_cap(arg: u64) -> i64 {
    let mut b = [0u8; 16];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    match rd64(&b, 0) {
        CLIENT_CAP_STEREO_3D | CLIENT_CAP_UNIVERSAL_PLANES => 0,
        _ => EOPNOTSUPP,
    }
}

fn ioctl_getparam(arg: u64) -> i64 {
    let mut b = [0u8; 16];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let param = rd64(&b, 0);
    let out_ptr = rd64(&b, 8);
    let value: u32 = match param {
        VIRTGPU_PARAM_3D_FEATURES => virgl_3d_features() as u32,
        VIRTGPU_PARAM_CAPSET_QUERY_FIX => 1,
        VIRTGPU_PARAM_SUPPORTED_CAPSET_IDS => supported_capset_ids() as u32,
        VIRTGPU_PARAM_RESOURCE_BLOB | VIRTGPU_PARAM_HOST_VISIBLE => {
            if ::virtio::gpu_blob_supported() { 1 } else { 0 }
        }
        VIRTGPU_PARAM_CROSS_DEVICE | VIRTGPU_PARAM_CONTEXT_INIT => 0,
        _ => return EINVAL,
    };
    if out_ptr == 0 {
        return EINVAL;
    }
    if frame::user::copy_to_user(out_ptr, &value.to_le_bytes()).is_err() {
        return EFAULT;
    }
    0
}

fn virgl_3d_features() -> u64 {
    if ::virtio::gpu_virgl_enabled() { 1 } else { 0 }
}

fn supported_capset_ids() -> u64 {
    let mut mask = 0u64;
    if ::virtio::gpu_has_capset(CAPSET_VIRGL) {
        mask |= 1 << CAPSET_VIRGL;
    }
    if ::virtio::gpu_has_capset(CAPSET_VIRGL2) {
        mask |= 1 << CAPSET_VIRGL2;
    }
    mask
}

fn ioctl_get_caps(arg: u64) -> i64 {
    let mut b = [0u8; 24];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let cap_set_id = rd32(&b, 0);
    let addr = rd64(&b, 8);
    let size = rd32(&b, 16) as usize;

    let (_ver, blob) = match ::virtio::gpu_capset(cap_set_id) {
        Some(c) => c,
        None => return EINVAL,
    };
    if addr == 0 || size == 0 {
        return EINVAL;
    }
    let n = size.min(blob.len());
    if frame::user::copy_to_user(addr, &blob[..n]).is_err() {
        return EFAULT;
    }
    0
}

struct Resource {
    res_id: u32,
    size: usize,
    seg: Option<Arc<ShmSegment>>,
    map_offset: u64,
    host_region: Option<(u64, u64)>,
}

struct VirtgpuState {
    opens: u32,
    ctx_created: bool,
    next_res: u32,
    next_map_off: u64,
    resources: BTreeMap<u32, Resource>,
    blob_free: Vec<(u64, u64)>,
    blob_seeded: bool,
}

impl VirtgpuState {
    const fn new() -> Self {
        Self {
            opens: 0,
            ctx_created: false,
            next_res: VIRGL_RES_BASE,
            next_map_off: 0x8_0000_0000,
            resources: BTreeMap::new(),
            blob_free: Vec::new(),
            blob_seeded: false,
        }
    }

    fn alloc_blob_region(&mut self, win_len: u64, size: u64) -> Option<u64> {
        if !self.blob_seeded {
            self.blob_free.clear();
            self.blob_free.push((0, win_len));
            self.blob_seeded = true;
        }
        for i in 0..self.blob_free.len() {
            let (off, flen) = self.blob_free[i];
            if flen >= size {
                if flen == size {
                    self.blob_free.remove(i);
                } else {
                    self.blob_free[i] = (off + size, flen - size);
                }
                return Some(off);
            }
        }
        None
    }

    fn free_blob_region(&mut self, off: u64, size: u64) {
        self.blob_free.push((off, size));
        self.blob_free.sort_unstable_by_key(|r| r.0);
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.blob_free.len());
        for (o, l) in self.blob_free.drain(..) {
            if let Some(last) = merged.last_mut() {
                if last.0 + last.1 == o {
                    last.1 += l;
                    continue;
                }
            }
            merged.push((o, l));
        }
        self.blob_free = merged;
    }

    fn alloc_res_id(&mut self) -> u32 {
        loop {
            let id = self.next_res;
            self.next_res = self.next_res.wrapping_add(1);
            if id != 0 && !self.resources.contains_key(&id) {
                return id;
            }
        }
    }
}

static VIRTGPU: SpinIrq<VirtgpuState> = SpinIrq::new(VirtgpuState::new());

fn ensure_ctx() -> Result<u32, i64> {
    let mut st = VIRTGPU.lock();
    if st.ctx_created {
        return Ok(IMPLICIT_CTX_ID);
    }
    match ::virtio::gpu_ctx_create(IMPLICIT_CTX_ID) {
        Ok(()) => {
            st.ctx_created = true;
            Ok(IMPLICIT_CTX_ID)
        }
        Err(_) => Err(EIO),
    }
}

fn ioctl_resource_create(arg: u64) -> i64 {
    let mut b = [0u8; 56];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let size = rd32(&b, 48) as usize;

    let ctx = match ensure_ctx() {
        Ok(c) => c,
        Err(e) => return e,
    };

    let res_id = VIRTGPU.lock().alloc_res_id();

    let args = ::virtio::gpu3d::ResourceCreate3d {
        resource_id: res_id,
        target: rd32(&b, 0),
        format: rd32(&b, 4),
        bind: rd32(&b, 8),
        width: rd32(&b, 12),
        height: rd32(&b, 16),
        depth: rd32(&b, 20),
        array_size: rd32(&b, 24),
        last_level: rd32(&b, 28),
        nr_samples: rd32(&b, 32),
        flags: rd32(&b, 36),
    };
    if ::virtio::gpu_create_resource_3d(&args).is_err() {
        return EIO;
    }

    let seg = if size != 0 {
        let s = match create_anon_shared(size) {
            Some(s) => s,
            None => {
                let _ = ::virtio::gpu_unref_resource(res_id);
                return ENOMEM;
            }
        };
        let entries: Vec<(u64, u32)> = s
            .frames
            .iter()
            .map(|f| (f.start_address().as_u64(), 4096u32))
            .collect();
        if ::virtio::gpu_attach_backing(res_id, &entries).is_err() {
            let _ = ::virtio::gpu_unref_resource(res_id);
            return EIO;
        }
        Some(s)
    } else {
        None
    };

    if ::virtio::gpu_ctx_attach_resource(ctx, res_id).is_err() {
        let _ = ::virtio::gpu_unref_resource(res_id);
        return EIO;
    }

    VIRTGPU.lock().resources.insert(
        res_id,
        Resource {
            res_id,
            size,
            seg,
            map_offset: 0,
            host_region: None,
        },
    );

    wr32(&mut b, 40, res_id);
    wr32(&mut b, 44, res_id);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_resource_create_blob(arg: u64) -> i64 {
    let mut b = [0u8; 48];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let blob_mem = rd32(&b, 0);
    let blob_flags = rd32(&b, 4);
    let size = rd64(&b, 16);
    let cmd_size = rd32(&b, 28) as usize;
    let cmd_ptr = rd64(&b, 32);
    let blob_id = rd64(&b, 40);

    if blob_mem != BLOB_MEM_HOST3D || size == 0 {
        return EINVAL;
    }
    let (win_phys, win_len) = match ::virtio::gpu_host_visible_region() {
        Some(r) => r,
        None => return EOPNOTSUPP,
    };
    let size_aligned = (size + 0xfff) & !0xfff;
    if size_aligned > win_len {
        return EINVAL;
    }

    let cmd = if cmd_size > 0 && cmd_ptr != 0 {
        if cmd_size > MAX_SUBMIT_BYTES {
            return EINVAL;
        }
        let mut c = alloc::vec![0u8; cmd_size];
        if frame::user::copy_from_user(cmd_ptr, &mut c).is_err() {
            return EFAULT;
        }
        Some(c)
    } else {
        None
    };

    let ctx = match ensure_ctx() {
        Ok(c) => c,
        Err(e) => return e,
    };

    let (res_id, region_off) = {
        let mut st = VIRTGPU.lock();
        let off = match st.alloc_blob_region(win_len, size_aligned) {
            Some(o) => o,
            None => return ENOMEM,
        };
        (st.alloc_res_id(), off)
    };

    let r_submit = match cmd.as_deref() {
        Some(c) => ::virtio::gpu_submit_3d(ctx, c),
        None => Ok(()),
    };
    let r_create = if r_submit.is_ok() {
        ::virtio::gpu_resource_create_blob(ctx, res_id, blob_mem, blob_flags, blob_id, size)
    } else {
        Ok(())
    };
    if r_submit.is_ok() && r_create.is_ok() {
        let _ = ::virtio::gpu_ctx_attach_resource(ctx, res_id);
    }
    let r_map = if r_submit.is_ok() && r_create.is_ok() {
        ::virtio::gpu_resource_map_blob(res_id, region_off).map(|_| ())
    } else {
        Ok(())
    };
    let ok = r_submit.is_ok() && r_create.is_ok() && r_map.is_ok();
    if !ok {
        VIRTGPU.lock().free_blob_region(region_off, size_aligned);
        let _ = ::virtio::gpu_resource_unmap_blob(res_id);
        let _ = ::virtio::gpu_unref_resource(res_id);
        return EIO;
    }

    let seg = match create_device_region(win_phys + region_off, size_aligned as usize) {
        Some(s) => s,
        None => {
            let _ = ::virtio::gpu_resource_unmap_blob(res_id);
            let _ = ::virtio::gpu_unref_resource(res_id);
            VIRTGPU.lock().free_blob_region(region_off, size_aligned);
            return ENOMEM;
        }
    };

    VIRTGPU.lock().resources.insert(
        res_id,
        Resource {
            res_id,
            size: size_aligned as usize,
            seg: Some(seg),
            map_offset: 0,
            host_region: Some((region_off, size_aligned)),
        },
    );

    wr32(&mut b, 8, res_id);
    wr32(&mut b, 12, res_id);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_resource_info(arg: u64) -> i64 {
    let mut b = [0u8; 16];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let handle = rd32(&b, 0);
    let st = VIRTGPU.lock();
    let res = match st.resources.get(&handle) {
        Some(r) => r,
        None => return ENOENT,
    };
    wr32(&mut b, 4, res.res_id);
    wr32(&mut b, 8, res.size as u32);
    wr32(&mut b, 12, 0);
    drop(st);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_map(arg: u64) -> i64 {
    let mut b = [0u8; 16];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let handle = rd32(&b, 8);
    let mut st = VIRTGPU.lock();
    let next = st.next_map_off;
    let res = match st.resources.get_mut(&handle) {
        Some(r) => r,
        None => return ENOENT,
    };
    if res.seg.is_none() {
        return EINVAL;
    }
    let off = if res.map_offset != 0 {
        res.map_offset
    } else {
        let pages = res.size.div_ceil(4096) as u64;
        res.map_offset = next;
        st.next_map_off = next + pages * 4096;
        next
    };
    drop(st);
    wr64(&mut b, 0, off);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_transfer(arg: u64, to_host: bool) -> i64 {
    let mut b = [0u8; 44];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let handle = rd32(&b, 0);
    let (res_id, size) = {
        let st = VIRTGPU.lock();
        match st.resources.get(&handle) {
            Some(r) => (r.res_id, r.size),
            None => return ENOENT,
        }
    };
    let ctx = match ensure_ctx() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let t = ::virtio::gpu3d::Transfer3d {
        resource_id: res_id,
        x: rd32(&b, 4),
        y: rd32(&b, 8),
        z: rd32(&b, 12),
        w: rd32(&b, 16),
        h: rd32(&b, 20),
        d: rd32(&b, 24),
        level: rd32(&b, 28),
        offset: rd32(&b, 32) as u64,
        stride: rd32(&b, 36),
        layer_stride: rd32(&b, 40),
    };
    let extent = (t.h as u64)
        .saturating_mul(t.stride as u64)
        .max((t.d as u64).saturating_mul(t.layer_stride as u64));
    if t.offset.saturating_add(extent) > size as u64 {
        return EINVAL;
    }
    let r = if to_host {
        ::virtio::gpu_transfer_to_host_3d(ctx, &t)
    } else {
        ::virtio::gpu_transfer_from_host_3d(ctx, &t)
    };
    if r.is_err() { EIO } else { 0 }
}

const MAX_SUBMIT_BYTES: usize = 16 * 1024 * 1024;

fn ioctl_execbuffer(cmd: u32, arg: u64) -> i64 {
    let len = ((cmd >> 16) & 0x3fff) as usize;
    if len < 32 {
        return EINVAL;
    }
    let mut b = [0u8; 64];
    let n = len.min(64);
    if frame::user::copy_from_user(arg, &mut b[..n]).is_err() {
        return EFAULT;
    }
    let size = rd32(&b, 4) as usize;
    let cmd_ptr = rd64(&b, 8);
    if size == 0 || cmd_ptr == 0 {
        return 0;
    }
    if size > MAX_SUBMIT_BYTES {
        return EINVAL;
    }
    let mut blob = alloc::vec![0u8; size];
    if frame::user::copy_from_user(cmd_ptr, &mut blob).is_err() {
        return EFAULT;
    }
    let ctx = match ensure_ctx() {
        Ok(c) => c,
        Err(e) => return e,
    };
    let bo_ptr = rd64(&b, 16);
    let num_bo = rd32(&b, 24) as usize;
    if num_bo > 0 && bo_ptr != 0 {
        if num_bo > 1024 {
            return EINVAL;
        }
        let mut handles = alloc::vec![0u8; num_bo * 4];
        if frame::user::copy_from_user(bo_ptr, &mut handles).is_err() {
            return EFAULT;
        }
        for i in 0..num_bo {
            let res_id = VIRTGPU
                .lock()
                .resources
                .get(&rd32(&handles, i * 4))
                .map(|r| r.res_id);
            if let Some(rid) = res_id {
                let _ = ::virtio::gpu_ctx_attach_resource(ctx, rid);
            }
        }
    }
    if ::virtio::gpu_submit_3d(ctx, &blob).is_err() {
        return EIO;
    }
    0
}

fn ioctl_wait(arg: u64) -> i64 {
    let mut b = [0u8; 8];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let handle = rd32(&b, 0);
    if VIRTGPU.lock().resources.contains_key(&handle) {
        0
    } else {
        ENOENT
    }
}

fn ioctl_gem_close(arg: u64) -> i64 {
    let mut b = [0u8; 8];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    free_resource(rd32(&b, 0));
    0
}

pub fn free_resource(handle: u32) {
    let res = VIRTGPU.lock().resources.remove(&handle);
    if let Some(r) = res {
        if let Some((off, len)) = r.host_region {
            let _ = ::virtio::gpu_resource_unmap_blob(r.res_id);
            if window_region_quiescent(&r.seg) {
                VIRTGPU.lock().free_blob_region(off, len);
            }
        } else if r.seg.is_some() {
            let _ = ::virtio::gpu_detach_backing(r.res_id);
        }
        let _ = ::virtio::gpu_unref_resource(r.res_id);
    }
}

fn window_region_quiescent(seg: &Option<Arc<ShmSegment>>) -> bool {
    match seg {
        Some(s) => Arc::strong_count(s) == 1,
        None => true,
    }
}

pub fn segment_for_mmap(offset: u64, len: usize) -> Option<Arc<ShmSegment>> {
    let st = VIRTGPU.lock();
    for r in st.resources.values() {
        if r.map_offset != 0 && r.map_offset == offset {
            if let Some(seg) = &r.seg {
                if len <= seg.size.div_ceil(4096) * 4096 {
                    return Some(seg.clone());
                }
            }
        }
    }
    None
}

pub fn is_resource(handle: u32) -> bool {
    VIRTGPU.lock().resources.contains_key(&handle)
}

pub fn scanout_present(handle: u32, w: u32, h: u32) -> bool {
    let res_id = match VIRTGPU.lock().resources.get(&handle) {
        Some(r) => r.res_id,
        None => return false,
    };
    ::virtio::gpu_present_resource(res_id, w, h).is_ok()
}

pub fn on_open() {
    VIRTGPU.lock().opens += 1;
}

pub fn on_close() {
    let (resources, had_ctx) = {
        let mut st = VIRTGPU.lock();
        st.opens = st.opens.saturating_sub(1);
        if st.opens != 0 {
            return;
        }
        let had_ctx = st.ctx_created;
        st.ctx_created = false;
        st.next_res = VIRGL_RES_BASE;
        st.next_map_off = 0x8_0000_0000;
        (core::mem::take(&mut st.resources), had_ctx)
    };
    let mut retained: Vec<(u64, u64)> = Vec::new();
    for r in resources.values() {
        if let Some((off, len)) = r.host_region {
            let _ = ::virtio::gpu_resource_unmap_blob(r.res_id);
            if !window_region_quiescent(&r.seg) {
                retained.push((off, len));
            }
        } else if r.seg.is_some() {
            let _ = ::virtio::gpu_detach_backing(r.res_id);
        }
        let _ = ::virtio::gpu_unref_resource(r.res_id);
    }
    {
        let mut st = VIRTGPU.lock();
        if retained.is_empty() {
            st.blob_free.clear();
            st.blob_seeded = false;
        } else if let Some((_, win_len)) = ::virtio::gpu_host_visible_region() {
            retained.sort_unstable_by_key(|r| r.0);
            let mut free: Vec<(u64, u64)> = Vec::new();
            let mut cursor = 0u64;
            for (off, len) in retained {
                if off > cursor {
                    free.push((cursor, off - cursor));
                }
                cursor = cursor.max(off + len);
            }
            if cursor < win_len {
                free.push((cursor, win_len - cursor));
            }
            st.blob_free = free;
            st.blob_seeded = true;
        }
    }
    if had_ctx {
        let _ = ::virtio::gpu_ctx_destroy(IMPLICIT_CTX_ID);
        let _ = ::virtio::gpu_restore_console_scanout();
    }
}

struct Render;

pub fn render_d128() -> Arc<dyn Inode> {
    Arc::new(Render)
}

impl Inode for Render {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        let mut s = Stat::fresh(InodeKind::CharDevice, 0, 0o666);
        s.rdev = crate::vfs::makedev(226, 128);
        s
    }
    fn is_drm_render(&self) -> bool {
        true
    }
    fn on_open(&self, _flags: OpenFlags) {
        on_open();
    }
    fn on_close(&self, _flags: OpenFlags) {
        on_close();
    }
    fn poll(&self) -> PollMask {
        PollMask::empty()
    }
}
