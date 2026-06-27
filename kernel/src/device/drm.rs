extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;

use alloc::vec::Vec;
use frame::sync::SpinIrq;

use cyphera_kapi::{Errno, KResult};

use crate::core::wait::WaitQueue;
use crate::errno::*;
use crate::ipc::shm::ShmSegment;
use crate::vfs::blocking::{IoAttempt, block_io};
use crate::vfs::{Inode, InodeKind, OpenFlags, PollMask, Stat};

static DRM_WAIT: WaitQueue = WaitQueue::new();

const NR_VERSION: u32 = 0x00;
const NR_GEM_CLOSE: u32 = 0x09;
const NR_SET_MASTER: u32 = 0x1e;
const NR_DROP_MASTER: u32 = 0x1f;
const NR_GET_CAP: u32 = 0x0c;
const NR_SET_CLIENT_CAP: u32 = 0x0d;
const NR_GETRESOURCES: u32 = 0xa0;
const NR_GETCRTC: u32 = 0xa1;
const NR_SETCRTC: u32 = 0xa2;
const NR_GETENCODER: u32 = 0xa6;
const NR_GETCONNECTOR: u32 = 0xa7;
const NR_ADDFB: u32 = 0xae;
const NR_RMFB: u32 = 0xaf;
const NR_PAGE_FLIP: u32 = 0xb0;
const NR_GETPLANERESOURCES: u32 = 0xb5;
const NR_CREATE_DUMB: u32 = 0xb2;
const NR_MAP_DUMB: u32 = 0xb3;
const NR_DESTROY_DUMB: u32 = 0xb4;
const NR_ADDFB2: u32 = 0xb8;
const NR_OBJ_GETPROPERTIES: u32 = 0xb9;
const NR_GET_MAGIC: u32 = 0x02;
const NR_AUTH_MAGIC: u32 = 0x11;
const NR_CURSOR: u32 = 0xa3;

const CONNECTOR_ID: u32 = 1;
const ENCODER_ID: u32 = 1;
const CRTC_ID: u32 = 1;

const PAGE_FLIP_EVENT: u32 = 0x1;
const DRM_EVENT_FLIP_COMPLETE: u32 = 2;
const EVENT_LEN: usize = 32;
const MAX_QUEUED_EVENTS: usize = 64;

const CAP_DUMB_BUFFER: u64 = 0x1;
const CLIENT_CAP_STEREO_3D: u64 = 1;
const CLIENT_CAP_UNIVERSAL_PLANES: u64 = 2;

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd64(b: &[u8], o: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(v)
}
fn wr16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn wr32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn wr64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

struct Dumb {
    height: u32,
    pitch: u32,
    size: usize,
    seg: Arc<ShmSegment>,
    map_offset: u64,
}

struct Fb {
    pitch: u32,
    handle: u32,
    virgl: bool,
}

struct DrmState {
    opens: u32,
    next_handle: u32,
    next_fb: u32,
    next_map_off: u64,
    dumbs: BTreeMap<u32, Dumb>,
    fbs: BTreeMap<u32, Fb>,
    scanout_fb: u32,
    mode: [u8; 68],
    mode_valid: bool,
    events: Vec<[u8; EVENT_LEN]>,
    flip_seq: u32,
}

impl DrmState {
    const fn new() -> Self {
        Self {
            opens: 0,
            next_handle: 1,
            next_fb: 1,
            next_map_off: 0x1_0000_0000,
            dumbs: BTreeMap::new(),
            fbs: BTreeMap::new(),
            scanout_fb: 0,
            mode: [0u8; 68],
            mode_valid: false,
            events: Vec::new(),
            flip_seq: 0,
        }
    }
}

static DRM: SpinIrq<DrmState> = SpinIrq::new(DrmState::new());

fn scanout_dims() -> (u32, u32) {
    match ::virtio::framebuffer_info() {
        Some((_, _, w, h)) => (w, h),
        None => (1024, 768),
    }
}

fn make_mode(w: u32, h: u32) -> [u8; 68] {
    let mut m = [0u8; 68];
    let clock = ((w as u64 + 200) * (h as u64 + 45) * 60 / 1000) as u32;
    wr32(&mut m, 0, clock);
    wr16(&mut m, 4, w as u16);
    wr16(&mut m, 6, (w + 16) as u16);
    wr16(&mut m, 8, (w + 16 + 96) as u16);
    wr16(&mut m, 10, (w + 200) as u16);
    wr16(&mut m, 12, 0);
    wr16(&mut m, 14, h as u16);
    wr16(&mut m, 16, (h + 10) as u16);
    wr16(&mut m, 18, (h + 12) as u16);
    wr16(&mut m, 20, (h + 45) as u16);
    wr16(&mut m, 22, 0);
    wr32(&mut m, 24, 60);
    wr32(&mut m, 28, 0);
    wr32(&mut m, 32, 0x48);
    let name = format!("{w}x{h}");
    let nb = name.as_bytes();
    let n = nb.len().min(31);
    m[36..36 + n].copy_from_slice(&nb[..n]);
    m
}

fn seg_read(seg: &ShmSegment, off: usize, buf: &mut [u8]) -> usize {
    let mut done = 0usize;
    while done < buf.len() {
        let lin = off + done;
        let fidx = lin / 4096;
        let foff = lin % 4096;
        if fidx >= seg.frames.len() {
            break;
        }
        let n = (4096 - foff).min(buf.len() - done);
        frame::mm::read_from_frame(seg.frames[fidx], foff, &mut buf[done..done + n]);
        done += n;
    }
    done
}

enum PresentPlan {
    Virgl {
        handle: u32,
    },
    Dumb {
        seg: Arc<ShmSegment>,
        src_pitch: usize,
        height: u32,
    },
}

fn resolve_present(st: &DrmState, fb_id: u32) -> Result<PresentPlan, i64> {
    let fb = match st.fbs.get(&fb_id) {
        Some(f) => f,
        None => return Err(ENOENT),
    };
    if fb.virgl {
        return Ok(PresentPlan::Virgl { handle: fb.handle });
    }
    let dumb = match st.dumbs.get(&fb.handle) {
        Some(d) => d,
        None => return Err(ENOENT),
    };
    let src_pitch = if fb.pitch != 0 { fb.pitch } else { dumb.pitch } as usize;
    Ok(PresentPlan::Dumb {
        seg: dumb.seg.clone(),
        src_pitch,
        height: dumb.height,
    })
}

fn present(plan: &PresentPlan) -> i64 {
    match plan {
        PresentPlan::Virgl { handle } => {
            let (w, h) = scanout_dims();
            if crate::device::virtgpu::scanout_present(*handle, w, h) {
                0
            } else {
                EINVAL
            }
        }
        PresentPlan::Dumb {
            seg,
            src_pitch,
            height,
        } => {
            let src_pitch = *src_pitch;
            let (sw, sh) = match ::virtio::framebuffer_info() {
                Some((_, _, w, h)) => (w, h),
                None => return ENOTTY,
            };
            let dst_pitch = (sw as usize) * 4;
            let rows = (*height as usize).min(sh as usize);
            let rowbytes = src_pitch.min(dst_pitch).min(MAX_ROW);
            let mut row = [0u8; MAX_ROW];
            for y in 0..rows {
                let got = seg_read(seg, y * src_pitch, &mut row[..rowbytes]);
                ::virtio::fb_write(y * dst_pitch, &row[..got]);
            }
            let _ = ::virtio::gpu_flush();
            0
        }
    }
}

const MAX_ROW: usize = 8192;

pub fn segment_for_mmap(offset: u64, len: usize) -> Option<Arc<ShmSegment>> {
    let st = DRM.lock();
    for d in st.dumbs.values() {
        if d.map_offset == offset && len <= d.size.div_ceil(4096) * 4096 {
            return Some(d.seg.clone());
        }
    }
    None
}

pub fn on_open() {
    DRM.lock().opens += 1;
}
pub fn on_close() {
    let mut st = DRM.lock();
    st.opens = st.opens.saturating_sub(1);
    if st.opens == 0 {
        st.dumbs.clear();
        st.fbs.clear();
        st.events.clear();
        st.scanout_fb = 0;
        st.mode_valid = false;
        crate::console::suspend_fb_sink(false);
    }
}

pub fn ioctl(cmd: u32, arg: u64) -> i64 {
    let nr = cmd & 0xff;
    match nr {
        NR_VERSION => ioctl_version(arg),
        NR_GEM_CLOSE => ioctl_gem_close(arg),
        NR_GET_CAP => ioctl_get_cap(arg),
        NR_SET_CLIENT_CAP => ioctl_set_client_cap(arg),
        NR_SET_MASTER => {
            crate::console::suspend_fb_sink(true);
            0
        }
        NR_DROP_MASTER => {
            crate::console::suspend_fb_sink(false);
            0
        }
        NR_GETRESOURCES => ioctl_getresources(arg),
        NR_GETCONNECTOR => ioctl_getconnector(arg),
        NR_GETENCODER => ioctl_getencoder(arg),
        NR_GETCRTC => ioctl_getcrtc(arg),
        NR_SETCRTC => ioctl_setcrtc(arg),
        NR_CREATE_DUMB => ioctl_create_dumb(arg),
        NR_MAP_DUMB => ioctl_map_dumb(arg),
        NR_DESTROY_DUMB => ioctl_destroy_dumb(arg),
        NR_ADDFB => ioctl_addfb(arg),
        NR_ADDFB2 => ioctl_addfb2(arg),
        NR_RMFB => ioctl_rmfb(arg),
        NR_PAGE_FLIP => ioctl_page_flip(arg),
        NR_OBJ_GETPROPERTIES => ioctl_obj_getproperties(arg),
        NR_GETPLANERESOURCES => ioctl_getplaneresources(arg),
        NR_GET_MAGIC => ioctl_get_magic(arg),
        NR_AUTH_MAGIC => 0,
        NR_CURSOR => 0,
        0x40..=0x5f => crate::device::virtgpu::ioctl(cmd, arg),
        _ => ENOTTY,
    }
}

fn ioctl_get_magic(arg: u64) -> i64 {
    let magic: u32 = 1;
    if frame::user::copy_to_user(arg, &magic.to_le_bytes()).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_obj_getproperties(arg: u64) -> i64 {
    let mut b = [0u8; 32];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    wr32(&mut b, 16, 0);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_getplaneresources(arg: u64) -> i64 {
    let mut b = [0u8; 16];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    wr32(&mut b, 8, 0);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
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
        (48, 56, b"virtio gpu"),
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
    let cap = rd64(&b, 0);
    let value: u64 = if cap == CAP_DUMB_BUFFER { 1 } else { 0 };
    wr64(&mut b, 8, value);
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

fn ioctl_getresources(arg: u64) -> i64 {
    let mut b = [0u8; 64];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let fb_ptr = rd64(&b, 0);
    let crtc_ptr = rd64(&b, 8);
    let conn_ptr = rd64(&b, 16);
    let enc_ptr = rd64(&b, 24);
    let cap_fbs = rd32(&b, 32);
    let cap_crtcs = rd32(&b, 36);
    let cap_conns = rd32(&b, 40);
    let cap_encs = rd32(&b, 44);

    if crtc_ptr != 0 && cap_crtcs >= 1 && write_id(crtc_ptr, CRTC_ID).is_err() {
        return EFAULT;
    }
    if conn_ptr != 0 && cap_conns >= 1 && write_id(conn_ptr, CONNECTOR_ID).is_err() {
        return EFAULT;
    }
    if enc_ptr != 0 && cap_encs >= 1 && write_id(enc_ptr, ENCODER_ID).is_err() {
        return EFAULT;
    }
    let _ = (fb_ptr, cap_fbs);

    let (w, h) = scanout_dims();
    wr32(&mut b, 32, 0);
    wr32(&mut b, 36, 1);
    wr32(&mut b, 40, 1);
    wr32(&mut b, 44, 1);
    wr32(&mut b, 48, 0);
    wr32(&mut b, 52, w);
    wr32(&mut b, 56, 0);
    wr32(&mut b, 60, h);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_getconnector(arg: u64) -> i64 {
    let mut b = [0u8; 80];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let enc_ptr = rd64(&b, 0);
    let modes_ptr = rd64(&b, 8);
    let cap_modes = rd32(&b, 32);
    let cap_encs = rd32(&b, 40);

    let (w, h) = scanout_dims();
    if modes_ptr != 0 && cap_modes >= 1 {
        let m = make_mode(w, h);
        if frame::user::copy_to_user(modes_ptr, &m).is_err() {
            return EFAULT;
        }
    }
    if enc_ptr != 0 && cap_encs >= 1 && write_id(enc_ptr, ENCODER_ID).is_err() {
        return EFAULT;
    }

    wr32(&mut b, 32, 1);
    wr32(&mut b, 36, 0);
    wr32(&mut b, 40, 1);
    wr32(&mut b, 44, ENCODER_ID);
    wr32(&mut b, 48, CONNECTOR_ID);
    wr32(&mut b, 52, 0);
    wr32(&mut b, 56, 1);
    wr32(&mut b, 60, 1);
    wr32(&mut b, 64, 0);
    wr32(&mut b, 68, 0);
    wr32(&mut b, 72, 0);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_getencoder(arg: u64) -> i64 {
    let mut b = [0u8; 20];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    wr32(&mut b, 0, ENCODER_ID);
    wr32(&mut b, 4, 0);
    wr32(&mut b, 8, CRTC_ID);
    wr32(&mut b, 12, 1);
    wr32(&mut b, 16, 0);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_getcrtc(arg: u64) -> i64 {
    let mut b = [0u8; 104];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let st = DRM.lock();
    wr64(&mut b, 0, 0);
    wr32(&mut b, 8, 0);
    wr32(&mut b, 12, CRTC_ID);
    wr32(&mut b, 16, st.scanout_fb);
    wr32(&mut b, 20, 0);
    wr32(&mut b, 24, 0);
    wr32(&mut b, 28, 256);
    wr32(&mut b, 32, st.mode_valid as u32);
    if st.mode_valid {
        b[36..104].copy_from_slice(&st.mode);
    } else {
        for x in &mut b[36..104] {
            *x = 0;
        }
    }
    drop(st);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_setcrtc(arg: u64) -> i64 {
    let mut b = [0u8; 104];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let fb_id = rd32(&b, 16);
    let mode_valid = rd32(&b, 32) != 0;

    let mut st = DRM.lock();
    if fb_id == 0 {
        st.scanout_fb = 0;
        st.mode_valid = false;
        return 0;
    }
    if !st.fbs.contains_key(&fb_id) {
        return EINVAL;
    }
    if mode_valid {
        st.mode.copy_from_slice(&b[36..104]);
        st.mode_valid = true;
    }
    let plan = match resolve_present(&st, fb_id) {
        Ok(p) => p,
        Err(e) => return e,
    };
    drop(st);

    let rc = present(&plan);
    if rc == 0 {
        DRM.lock().scanout_fb = fb_id;
        crate::console::suspend_fb_sink(true);
    }
    rc
}

fn ioctl_create_dumb(arg: u64) -> i64 {
    let mut b = [0u8; 32];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let height = rd32(&b, 0);
    let width = rd32(&b, 4);
    let bpp = rd32(&b, 8);
    if width == 0 || height == 0 || bpp == 0 || bpp > 32 {
        return EINVAL;
    }
    let pitch = width
        .checked_mul(bpp.div_ceil(8))
        .filter(|p| *p > 0)
        .unwrap_or(0);
    if pitch == 0 {
        return EINVAL;
    }
    let size = (pitch as usize)
        .checked_mul(height as usize)
        .filter(|s| *s > 0)
        .unwrap_or(0);
    if size == 0 {
        return EINVAL;
    }
    let seg = match crate::ipc::shm::create_anon_shared(size) {
        Some(s) => s,
        None => return ENOMEM,
    };
    let mut st = DRM.lock();
    let handle = st.next_handle;
    st.next_handle += 1;
    let pages = size.div_ceil(4096) as u64;
    let map_offset = st.next_map_off;
    st.next_map_off += pages * 4096;
    st.dumbs.insert(
        handle,
        Dumb {
            height,
            pitch,
            size,
            seg,
            map_offset,
        },
    );
    drop(st);

    wr32(&mut b, 16, handle);
    wr32(&mut b, 20, pitch);
    wr64(&mut b, 24, size as u64);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_map_dumb(arg: u64) -> i64 {
    let mut b = [0u8; 16];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let handle = rd32(&b, 0);
    let st = DRM.lock();
    let off = match st.dumbs.get(&handle) {
        Some(d) => d.map_offset,
        None => return ENOENT,
    };
    drop(st);
    wr64(&mut b, 8, off);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn remove_dumb_locked(st: &mut DrmState, handle: u32) {
    let dead: alloc::vec::Vec<u32> = st
        .fbs
        .iter()
        .filter(|(_, f)| f.handle == handle)
        .map(|(id, _)| *id)
        .collect();
    for id in dead {
        st.fbs.remove(&id);
        if st.scanout_fb == id {
            st.scanout_fb = 0;
        }
    }
    st.dumbs.remove(&handle);
}

fn ioctl_destroy_dumb(arg: u64) -> i64 {
    let mut b = [0u8; 4];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let handle = rd32(&b, 0);
    let mut st = DRM.lock();
    remove_dumb_locked(&mut st, handle);
    0
}

fn ioctl_gem_close(arg: u64) -> i64 {
    let mut b = [0u8; 8];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let handle = rd32(&b, 0);
    if crate::device::virtgpu::is_resource(handle) {
        crate::device::virtgpu::free_resource(handle);
    } else {
        let mut st = DRM.lock();
        remove_dumb_locked(&mut st, handle);
    }
    0
}

fn ioctl_addfb(arg: u64) -> i64 {
    let mut b = [0u8; 28];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let pitch = rd32(&b, 12);
    let handle = rd32(&b, 24);
    let mut st = DRM.lock();
    let virgl = !st.dumbs.contains_key(&handle);
    if virgl && !crate::device::virtgpu::is_resource(handle) {
        return EINVAL;
    }
    let fb_id = st.next_fb;
    st.next_fb += 1;
    st.fbs.insert(
        fb_id,
        Fb {
            pitch,
            handle,
            virgl,
        },
    );
    drop(st);
    wr32(&mut b, 0, fb_id);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_addfb2(arg: u64) -> i64 {
    let mut b = [0u8; 104];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let handle = rd32(&b, 20);
    let pitch = rd32(&b, 36);
    let mut st = DRM.lock();
    let virgl = !st.dumbs.contains_key(&handle);
    if virgl && !crate::device::virtgpu::is_resource(handle) {
        return EINVAL;
    }
    let fb_id = st.next_fb;
    st.next_fb += 1;
    st.fbs.insert(
        fb_id,
        Fb {
            pitch,
            handle,
            virgl,
        },
    );
    drop(st);
    wr32(&mut b, 0, fb_id);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn ioctl_rmfb(arg: u64) -> i64 {
    let mut b = [0u8; 4];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let fb_id = rd32(&b, 0);
    let mut st = DRM.lock();
    st.fbs.remove(&fb_id);
    if st.scanout_fb == fb_id {
        st.scanout_fb = 0;
    }
    0
}

fn ioctl_page_flip(arg: u64) -> i64 {
    let mut b = [0u8; 24];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let crtc_id = rd32(&b, 0);
    let fb_id = rd32(&b, 4);
    let flags = rd32(&b, 8);
    let user_data = rd64(&b, 16);

    let st = DRM.lock();
    if !st.fbs.contains_key(&fb_id) {
        return EINVAL;
    }
    let plan = match resolve_present(&st, fb_id) {
        Ok(p) => p,
        Err(e) => return e,
    };
    drop(st);

    let rc = present(&plan);
    if rc != 0 {
        return rc;
    }

    let mut st = DRM.lock();
    st.scanout_fb = fb_id;
    crate::console::suspend_fb_sink(true);

    if flags & PAGE_FLIP_EVENT != 0 {
        let seq = st.flip_seq.wrapping_add(1);
        st.flip_seq = seq;
        let now = frame::cpu::clock::nanos_since_boot();
        let mut ev = [0u8; EVENT_LEN];
        wr32(&mut ev, 0, DRM_EVENT_FLIP_COMPLETE);
        wr32(&mut ev, 4, EVENT_LEN as u32);
        wr64(&mut ev, 8, user_data);
        wr32(&mut ev, 16, (now / 1_000_000_000) as u32);
        wr32(&mut ev, 20, ((now / 1_000) % 1_000_000) as u32);
        wr32(&mut ev, 24, seq);
        wr32(&mut ev, 28, crtc_id);
        if st.events.len() >= MAX_QUEUED_EVENTS {
            st.events.remove(0);
        }
        st.events.push(ev);
        drop(st);
        DRM_WAIT.wake_all();
    }
    0
}

fn drain_events(buf: &mut [u8]) -> usize {
    let mut st = DRM.lock();
    let mut written = 0usize;
    while !st.events.is_empty() && written + EVENT_LEN <= buf.len() {
        let ev = st.events.remove(0);
        buf[written..written + EVENT_LEN].copy_from_slice(&ev);
        written += EVENT_LEN;
    }
    written
}

fn write_id(ptr: u64, id: u32) -> Result<(), ()> {
    frame::user::copy_to_user(ptr, &id.to_le_bytes()).map_err(|_| ())
}

struct Card;

pub fn card0() -> Arc<dyn Inode> {
    Arc::new(Card)
}

impl Inode for Card {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        let mut s = Stat::fresh(InodeKind::CharDevice, 0, 0o666);
        s.rdev = crate::vfs::makedev(226, 0);
        s
    }
    fn is_drm_card(&self) -> bool {
        true
    }
    fn on_open(&self, _flags: crate::vfs::OpenFlags) {
        on_open();
        crate::device::virtgpu::on_open();
    }
    fn on_close(&self, _flags: crate::vfs::OpenFlags) {
        on_close();
        crate::device::virtgpu::on_close();
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read_at_with_flags(offset, buf, OpenFlags::empty())
    }
    fn read_at_with_flags(&self, _offset: u64, buf: &mut [u8], flags: OpenFlags) -> KResult<usize> {
        if buf.len() < EVENT_LEN {
            return Err(Errno::INVAL);
        }
        block_io(
            "drm_read",
            &DRM_WAIT,
            flags.contains(OpenFlags::NONBLOCK),
            None,
            || match drain_events(buf) {
                0 => IoAttempt::WouldBlock,
                n => IoAttempt::Ready(n),
            },
        )
    }
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> KResult<usize> {
        Err(Errno::NOSYS)
    }
    fn poll(&self) -> PollMask {
        if DRM.lock().events.is_empty() {
            PollMask::empty()
        } else {
            PollMask::IN
        }
    }
    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&WaitQueue)) {
        f(&DRM_WAIT);
    }
}
