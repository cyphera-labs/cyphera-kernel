use core::ptr::NonNull;

use alloc::vec;
use alloc::vec::Vec;

use virtio_drivers::queue::VirtQueue;
use virtio_drivers::transport::mmio::{MmioError, MmioTransport, VirtIOHeader};
use virtio_drivers::transport::pci::PciTransport;
use virtio_drivers::transport::{DeviceStatus, Transport};
use virtio_drivers::{BufferDirection, Error as VdError, Hal, PAGE_SIZE};

use crate::hal::FrameHal;

const F_VIRGL: u64 = 1 << 0;
const F_EDID: u64 = 1 << 1;
const F_RESOURCE_BLOB: u64 = 1 << 3;
const F_VERSION_1: u64 = 1 << 32;

const QUEUE_CONTROL: u16 = 0;
const QUEUE_SIZE: usize = 4;

const PAGE: usize = 4096;
const CTRL_HDR_LEN: usize = 24;

const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const CMD_RESOURCE_UNREF: u32 = 0x0102;
const CMD_SET_SCANOUT: u32 = 0x0103;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
const CMD_GET_CAPSET_INFO: u32 = 0x0108;
const CMD_GET_CAPSET: u32 = 0x0109;
const CMD_RESOURCE_CREATE_BLOB: u32 = 0x010c;

const CMD_CTX_CREATE: u32 = 0x0200;
const CMD_CTX_DESTROY: u32 = 0x0201;
const CMD_CTX_ATTACH_RESOURCE: u32 = 0x0202;
const CMD_CTX_DETACH_RESOURCE: u32 = 0x0203;
const CMD_RESOURCE_CREATE_3D: u32 = 0x0204;
const CMD_TRANSFER_TO_HOST_3D: u32 = 0x0205;
const CMD_TRANSFER_FROM_HOST_3D: u32 = 0x0206;
const CMD_SUBMIT_3D: u32 = 0x0207;
const CMD_RESOURCE_MAP_BLOB: u32 = 0x0208;
const CMD_RESOURCE_UNMAP_BLOB: u32 = 0x0209;

const FLAG_FENCE: u32 = 1 << 0;

const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
const RESP_OK_CAPSET_INFO: u32 = 0x1102;
const RESP_OK_CAPSET: u32 = 0x1103;
const RESP_OK_MAP_INFO: u32 = 0x1106;

const FORMAT_B8G8R8A8_UNORM: u32 = 1;
const SCANOUT_ID: u32 = 0;
const RESOURCE_ID_FB: u32 = 0xbabe;

#[derive(Debug)]
pub enum Gpu3dError {
    Mmio(MmioError),
    Driver(VdError),
    Protocol,
}

impl From<VdError> for Gpu3dError {
    fn from(e: VdError) -> Self {
        Gpu3dError::Driver(e)
    }
}

pub struct Capset {
    pub id: u32,
    pub version: u32,
    pub data: Vec<u8>,
}

struct DmaBuf {
    paddr: u64,
    vaddr: usize,
    pages: usize,
}

impl DmaBuf {
    fn new(pages: usize) -> Result<Self, Gpu3dError> {
        let (paddr, vaddr) = FrameHal::dma_alloc(pages, BufferDirection::DriverToDevice);
        if paddr == 0 {
            return Err(Gpu3dError::Driver(VdError::DmaError));
        }
        Ok(Self {
            paddr,
            vaddr: vaddr.as_ptr() as usize,
            pages,
        })
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `dma_alloc` returned `pages * PAGE` bytes of zeroed, writable,
        // non-aliased DRAM at `vaddr` (the direct-map alias of the contiguous
        // frames); we hold the only reference for the lifetime of `&mut self`.
        unsafe { core::slice::from_raw_parts_mut(self.vaddr as *mut u8, self.pages * PAGE) }
    }
}

impl Drop for DmaBuf {
    fn drop(&mut self) {
        let vaddr = NonNull::new(self.vaddr as *mut u8).expect("DmaBuf vaddr non-null");
        // SAFETY: `paddr`/`vaddr`/`pages` are exactly the values returned by the
        // `dma_alloc` in `new` and not freed since, matching `dma_dealloc`'s
        // contract.
        unsafe {
            FrameHal::dma_dealloc(self.paddr, vaddr, self.pages);
        }
    }
}

pub struct Gpu3d {
    inner: Inner,
    width: u32,
    height: u32,
    virgl: bool,
    blob: bool,
    host_visible: Option<(u64, u64)>,
    capsets: Vec<Capset>,
}

enum Inner {
    Mmio(Driver<MmioTransport<'static>>),
    Pci(Driver<PciTransport>),
}

pub fn transport_offers_virgl<T: Transport>(transport: &mut T) -> bool {
    transport.read_device_features() & F_VIRGL != 0
}

pub fn mmio_offers_virgl(mmio_base: u64) -> bool {
    let header = match NonNull::new(mmio_base as *mut VirtIOHeader) {
        Some(h) => h,
        None => return false,
    };
    // SAFETY: same mapped-MMIO-window contract as `new_mmio` and the other
    // mmio drivers; the transport is dropped at the end of this function having
    // only read the feature register.
    let mut transport = match unsafe { MmioTransport::new(header, 0x200) } {
        Ok(t) => t,
        Err(_) => return false,
    };
    transport_offers_virgl(&mut transport)
}

impl Gpu3d {
    pub fn new_mmio(mmio_base: u64) -> Result<Self, Gpu3dError> {
        let header = NonNull::new(mmio_base as *mut VirtIOHeader).expect("base non-null");
        // SAFETY: identical contract to gpu.rs and the other mmio drivers —
        // `header` is non-null and names the GPU device's virtio-mmio register
        // window identified by the probe; the boot stub permanently maps the
        // device-area phys range covering it at high VA, and 0x200 matches the
        // per-device virtio-mmio register stride, so the transport's register
        // accesses stay inside that mapped window.
        let transport = unsafe { MmioTransport::new(header, 0x200) }.map_err(Gpu3dError::Mmio)?;
        let drv = Driver::new(transport)?;
        Ok(Self::wrap(Inner::Mmio(drv), None))
    }

    pub fn new_pci(
        transport: PciTransport,
        host_visible: Option<(u64, u64)>,
    ) -> Result<Self, Gpu3dError> {
        let drv = Driver::new(transport)?;
        Ok(Self::wrap(Inner::Pci(drv), host_visible))
    }

    fn wrap(inner: Inner, host_visible: Option<(u64, u64)>) -> Self {
        let (width, height, virgl, blob, capsets) = match &inner {
            Inner::Mmio(d) => (d.width, d.height, d.virgl, d.blob, d.clone_capsets()),
            Inner::Pci(d) => (d.width, d.height, d.virgl, d.blob, d.clone_capsets()),
        };
        Self {
            inner,
            width,
            height,
            virgl,
            blob,
            host_visible,
            capsets,
        }
    }

    pub fn blob_supported(&self) -> bool {
        self.blob && self.host_visible.is_some()
    }

    pub fn host_visible_region(&self) -> Option<(u64, u64)> {
        self.host_visible
    }

    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
    pub fn virgl_enabled(&self) -> bool {
        self.virgl
    }

    pub fn setup_framebuffer(&mut self) -> Result<&mut [u8], Gpu3dError> {
        match &mut self.inner {
            Inner::Mmio(d) => d.setup_framebuffer(),
            Inner::Pci(d) => d.setup_framebuffer(),
        }
    }

    pub fn flush(&mut self) -> Result<(), Gpu3dError> {
        match &mut self.inner {
            Inner::Mmio(d) => d.flush(),
            Inner::Pci(d) => d.flush(),
        }
    }

    pub fn ack_interrupt(&mut self) -> bool {
        match &mut self.inner {
            Inner::Mmio(d) => !d.transport.ack_interrupt().is_empty(),
            Inner::Pci(d) => !d.transport.ack_interrupt().is_empty(),
        }
    }

    pub fn capset(&self, id: u32) -> Option<(u32, &[u8])> {
        self.capsets
            .iter()
            .find(|c| c.id == id)
            .map(|c| (c.version, c.data.as_slice()))
    }

    pub fn ctl(&mut self) -> &mut dyn Gpu3dCtl {
        match &mut self.inner {
            Inner::Mmio(d) => d as &mut dyn Gpu3dCtl,
            Inner::Pci(d) => d as &mut dyn Gpu3dCtl,
        }
    }
}

struct Driver<T: Transport> {
    transport: T,
    control: VirtQueue<FrameHal, QUEUE_SIZE>,
    width: u32,
    height: u32,
    virgl: bool,
    blob: bool,
    capsets: Vec<Capset>,
    fb: Option<DmaBuf>,
    next_fence: u64,
}

impl<T: Transport> Driver<T> {
    fn new(mut transport: T) -> Result<Self, Gpu3dError> {
        let supported = F_VIRGL | F_EDID | F_RESOURCE_BLOB | F_VERSION_1;
        transport.set_status(DeviceStatus::empty());
        transport.set_status(DeviceStatus::ACKNOWLEDGE | DeviceStatus::DRIVER);
        let device_features = transport.read_device_features();
        let negotiated = device_features & supported;
        transport.write_driver_features(negotiated);
        transport.set_status(
            DeviceStatus::ACKNOWLEDGE | DeviceStatus::DRIVER | DeviceStatus::FEATURES_OK,
        );
        transport.set_guest_page_size(PAGE_SIZE as u32);

        let control = VirtQueue::new(&mut transport, QUEUE_CONTROL, false, false)?;
        transport.finish_init();

        let virgl = negotiated & F_VIRGL != 0;
        let blob = negotiated & F_RESOURCE_BLOB != 0;

        let mut drv = Self {
            transport,
            control,
            width: 0,
            height: 0,
            virgl,
            blob,
            capsets: Vec::new(),
            fb: None,
            next_fence: 1,
        };

        let (w, h) = drv.get_display_info()?;
        drv.width = w;
        drv.height = h;

        if virgl {
            drv.fetch_capsets();
        }

        Ok(drv)
    }

    fn clone_capsets(&self) -> Vec<Capset> {
        self.capsets
            .iter()
            .map(|c| Capset {
                id: c.id,
                version: c.version,
                data: c.data.clone(),
            })
            .collect()
    }

    fn request(&mut self, req: &[u8], resp_len: usize) -> Result<Vec<u8>, Gpu3dError> {
        self.request_multi(&[req], resp_len)
    }

    fn request_multi(&mut self, parts: &[&[u8]], resp_len: usize) -> Result<Vec<u8>, Gpu3dError> {
        let mut resp = vec![0u8; resp_len];
        self.control
            .add_notify_wait_pop(parts, &mut [resp.as_mut_slice()], &mut self.transport)?;
        Ok(resp)
    }

    fn get_display_info(&mut self) -> Result<(u32, u32), Gpu3dError> {
        let req = ctrl_hdr(CMD_GET_DISPLAY_INFO);
        let resp = self.request(&req, CTRL_HDR_LEN + 16 * 24)?;
        if rd32(&resp, 0) != RESP_OK_DISPLAY_INFO {
            return Err(Gpu3dError::Protocol);
        }
        let width = rd32(&resp, CTRL_HDR_LEN + 8);
        let height = rd32(&resp, CTRL_HDR_LEN + 12);
        let (w, h) = if width == 0 || height == 0 {
            (1024, 768)
        } else {
            (width, height)
        };
        Ok((w, h))
    }

    fn fetch_capsets(&mut self) {
        let num = self
            .transport
            .read_config_space::<u32>(12)
            .unwrap_or_default();
        for idx in 0..num {
            if let Some(cap) = self.fetch_one_capset(idx) {
                self.capsets.push(cap);
            }
        }
    }

    fn fetch_one_capset(&mut self, idx: u32) -> Option<Capset> {
        let mut req = ctrl_hdr_vec(CMD_GET_CAPSET_INFO, CTRL_HDR_LEN + 16);
        wr32(&mut req, CTRL_HDR_LEN, idx);
        let info = self.request(&req, CTRL_HDR_LEN + 16).ok()?;
        if rd32(&info, 0) != RESP_OK_CAPSET_INFO {
            return None;
        }
        let id = rd32(&info, CTRL_HDR_LEN);
        let max_version = rd32(&info, CTRL_HDR_LEN + 4);
        let max_size = rd32(&info, CTRL_HDR_LEN + 8) as usize;
        if max_size == 0 || max_size > 256 * 1024 {
            return None;
        }

        let mut req = ctrl_hdr_vec(CMD_GET_CAPSET, CTRL_HDR_LEN + 8);
        wr32(&mut req, CTRL_HDR_LEN, id);
        wr32(&mut req, CTRL_HDR_LEN + 4, max_version);
        let resp = self.request(&req, CTRL_HDR_LEN + max_size).ok()?;
        if rd32(&resp, 0) != RESP_OK_CAPSET {
            return None;
        }
        Some(Capset {
            id,
            version: max_version,
            data: resp[CTRL_HDR_LEN..CTRL_HDR_LEN + max_size].to_vec(),
        })
    }

    fn setup_framebuffer(&mut self) -> Result<&mut [u8], Gpu3dError> {
        if self.fb.is_none() {
            let (w, h) = (self.width, self.height);
            let size = (w as usize) * (h as usize) * 4;
            let pages = size.div_ceil(PAGE);
            let buf = DmaBuf::new(pages)?;
            let paddr = buf.paddr;

            self.resource_create_2d(RESOURCE_ID_FB, w, h)?;
            self.resource_attach_backing(RESOURCE_ID_FB, paddr, size as u32)?;
            self.set_scanout(SCANOUT_ID, RESOURCE_ID_FB, w, h)?;

            self.fb = Some(buf);
        }
        Ok(self.fb.as_mut().unwrap().as_mut_slice())
    }

    fn flush(&mut self) -> Result<(), Gpu3dError> {
        let (w, h) = (self.width, self.height);
        self.transfer_to_host_2d(RESOURCE_ID_FB, w, h)?;
        self.resource_flush(RESOURCE_ID_FB, w, h)
    }

    fn resource_create_2d(&mut self, res: u32, w: u32, h: u32) -> Result<(), Gpu3dError> {
        let mut req = ctrl_hdr_vec(CMD_RESOURCE_CREATE_2D, CTRL_HDR_LEN + 16);
        wr32(&mut req, CTRL_HDR_LEN, res);
        wr32(&mut req, CTRL_HDR_LEN + 4, FORMAT_B8G8R8A8_UNORM);
        wr32(&mut req, CTRL_HDR_LEN + 8, w);
        wr32(&mut req, CTRL_HDR_LEN + 12, h);
        self.expect_nodata(&req)
    }

    fn resource_attach_backing(&mut self, res: u32, addr: u64, len: u32) -> Result<(), Gpu3dError> {
        let mut req = ctrl_hdr_vec(CMD_RESOURCE_ATTACH_BACKING, CTRL_HDR_LEN + 24);
        wr32(&mut req, CTRL_HDR_LEN, res);
        wr32(&mut req, CTRL_HDR_LEN + 4, 1);
        wr64(&mut req, CTRL_HDR_LEN + 8, addr);
        wr32(&mut req, CTRL_HDR_LEN + 16, len);
        self.expect_nodata(&req)
    }

    fn set_scanout(&mut self, scanout: u32, res: u32, w: u32, h: u32) -> Result<(), Gpu3dError> {
        let mut req = ctrl_hdr_vec(CMD_SET_SCANOUT, CTRL_HDR_LEN + 24);
        wr_rect(&mut req, CTRL_HDR_LEN, 0, 0, w, h);
        wr32(&mut req, CTRL_HDR_LEN + 16, scanout);
        wr32(&mut req, CTRL_HDR_LEN + 20, res);
        self.expect_nodata(&req)
    }

    fn transfer_to_host_2d(&mut self, res: u32, w: u32, h: u32) -> Result<(), Gpu3dError> {
        let mut req = ctrl_hdr_vec(CMD_TRANSFER_TO_HOST_2D, CTRL_HDR_LEN + 32);
        wr_rect(&mut req, CTRL_HDR_LEN, 0, 0, w, h);
        wr64(&mut req, CTRL_HDR_LEN + 16, 0);
        wr32(&mut req, CTRL_HDR_LEN + 24, res);
        self.expect_nodata(&req)
    }

    fn resource_flush(&mut self, res: u32, w: u32, h: u32) -> Result<(), Gpu3dError> {
        let mut req = ctrl_hdr_vec(CMD_RESOURCE_FLUSH, CTRL_HDR_LEN + 24);
        wr_rect(&mut req, CTRL_HDR_LEN, 0, 0, w, h);
        wr32(&mut req, CTRL_HDR_LEN + 16, res);
        self.expect_nodata(&req)
    }

    fn expect_nodata(&mut self, req: &[u8]) -> Result<(), Gpu3dError> {
        self.expect_nodata_parts(&[req])
    }

    fn expect_nodata_parts(&mut self, parts: &[&[u8]]) -> Result<(), Gpu3dError> {
        let resp = self.request_multi(parts, CTRL_HDR_LEN)?;
        if rd32(&resp, 0) == RESP_OK_NODATA {
            Ok(())
        } else {
            Err(Gpu3dError::Protocol)
        }
    }

    fn alloc_fence(&mut self) -> u64 {
        let f = self.next_fence;
        self.next_fence = self.next_fence.wrapping_add(1).max(1);
        f
    }
}

#[derive(Clone, Copy)]
pub struct ResourceCreate3d {
    pub resource_id: u32,
    pub target: u32,
    pub format: u32,
    pub bind: u32,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub array_size: u32,
    pub last_level: u32,
    pub nr_samples: u32,
    pub flags: u32,
}

#[derive(Clone, Copy)]
pub struct Transfer3d {
    pub resource_id: u32,
    pub x: u32,
    pub y: u32,
    pub z: u32,
    pub w: u32,
    pub h: u32,
    pub d: u32,
    pub offset: u64,
    pub level: u32,
    pub stride: u32,
    pub layer_stride: u32,
}

pub trait Gpu3dCtl {
    fn ctx_create(&mut self, ctx_id: u32) -> Result<(), Gpu3dError>;
    fn ctx_destroy(&mut self, ctx_id: u32) -> Result<(), Gpu3dError>;
    fn ctx_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> Result<(), Gpu3dError>;
    fn ctx_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> Result<(), Gpu3dError>;
    fn create_resource_3d(&mut self, args: &ResourceCreate3d) -> Result<(), Gpu3dError>;
    fn attach_backing(
        &mut self,
        resource_id: u32,
        entries: &[(u64, u32)],
    ) -> Result<(), Gpu3dError>;
    fn detach_backing(&mut self, resource_id: u32) -> Result<(), Gpu3dError>;
    fn unref_resource(&mut self, resource_id: u32) -> Result<(), Gpu3dError>;
    fn transfer_to_host_3d(&mut self, ctx_id: u32, t: &Transfer3d) -> Result<(), Gpu3dError>;
    fn transfer_from_host_3d(&mut self, ctx_id: u32, t: &Transfer3d) -> Result<(), Gpu3dError>;
    fn submit_3d(&mut self, ctx_id: u32, blob: &[u8]) -> Result<(), Gpu3dError>;
    fn resource_create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        blob_mem: u32,
        blob_flags: u32,
        blob_id: u64,
        size: u64,
    ) -> Result<(), Gpu3dError>;
    fn resource_map_blob(&mut self, resource_id: u32, offset: u64) -> Result<u32, Gpu3dError>;
    fn resource_unmap_blob(&mut self, resource_id: u32) -> Result<(), Gpu3dError>;
    fn present_resource(&mut self, resource_id: u32, w: u32, h: u32) -> Result<(), Gpu3dError>;
    fn restore_console(&mut self) -> Result<(), Gpu3dError>;
}

impl<T: Transport> Gpu3dCtl for Driver<T> {
    fn ctx_create(&mut self, ctx_id: u32) -> Result<(), Gpu3dError> {
        let name = b"gl";
        let mut req = hdr3d_vec(CMD_CTX_CREATE, ctx_id, 0, CTRL_HDR_LEN + 8 + 64);
        wr32(&mut req, CTRL_HDR_LEN, name.len() as u32);
        req[CTRL_HDR_LEN + 8..CTRL_HDR_LEN + 8 + name.len()].copy_from_slice(name);
        self.expect_nodata(&req)
    }

    fn ctx_destroy(&mut self, ctx_id: u32) -> Result<(), Gpu3dError> {
        let req = hdr3d_vec(CMD_CTX_DESTROY, ctx_id, 0, CTRL_HDR_LEN);
        self.expect_nodata(&req)
    }

    fn ctx_attach_resource(&mut self, ctx_id: u32, resource_id: u32) -> Result<(), Gpu3dError> {
        let mut req = hdr3d_vec(CMD_CTX_ATTACH_RESOURCE, ctx_id, 0, CTRL_HDR_LEN + 8);
        wr32(&mut req, CTRL_HDR_LEN, resource_id);
        self.expect_nodata(&req)
    }

    fn ctx_detach_resource(&mut self, ctx_id: u32, resource_id: u32) -> Result<(), Gpu3dError> {
        let mut req = hdr3d_vec(CMD_CTX_DETACH_RESOURCE, ctx_id, 0, CTRL_HDR_LEN + 8);
        wr32(&mut req, CTRL_HDR_LEN, resource_id);
        self.expect_nodata(&req)
    }

    fn create_resource_3d(&mut self, a: &ResourceCreate3d) -> Result<(), Gpu3dError> {
        let mut req = hdr3d_vec(CMD_RESOURCE_CREATE_3D, 0, 0, CTRL_HDR_LEN + 48);
        wr32(&mut req, CTRL_HDR_LEN, a.resource_id);
        wr32(&mut req, CTRL_HDR_LEN + 4, a.target);
        wr32(&mut req, CTRL_HDR_LEN + 8, a.format);
        wr32(&mut req, CTRL_HDR_LEN + 12, a.bind);
        wr32(&mut req, CTRL_HDR_LEN + 16, a.width);
        wr32(&mut req, CTRL_HDR_LEN + 20, a.height);
        wr32(&mut req, CTRL_HDR_LEN + 24, a.depth);
        wr32(&mut req, CTRL_HDR_LEN + 28, a.array_size);
        wr32(&mut req, CTRL_HDR_LEN + 32, a.last_level);
        wr32(&mut req, CTRL_HDR_LEN + 36, a.nr_samples);
        wr32(&mut req, CTRL_HDR_LEN + 40, a.flags);
        self.expect_nodata(&req)
    }

    fn attach_backing(
        &mut self,
        resource_id: u32,
        entries: &[(u64, u32)],
    ) -> Result<(), Gpu3dError> {
        let mut req = hdr3d_vec(
            CMD_RESOURCE_ATTACH_BACKING,
            0,
            0,
            CTRL_HDR_LEN + 8 + entries.len() * 16,
        );
        wr32(&mut req, CTRL_HDR_LEN, resource_id);
        wr32(&mut req, CTRL_HDR_LEN + 4, entries.len() as u32);
        let mut o = CTRL_HDR_LEN + 8;
        for (addr, len) in entries {
            wr64(&mut req, o, *addr);
            wr32(&mut req, o + 8, *len);
            o += 16;
        }
        self.expect_nodata(&req)
    }

    fn detach_backing(&mut self, resource_id: u32) -> Result<(), Gpu3dError> {
        let mut req = hdr3d_vec(CMD_RESOURCE_DETACH_BACKING, 0, 0, CTRL_HDR_LEN + 8);
        wr32(&mut req, CTRL_HDR_LEN, resource_id);
        self.expect_nodata(&req)
    }

    fn unref_resource(&mut self, resource_id: u32) -> Result<(), Gpu3dError> {
        let mut req = hdr3d_vec(CMD_RESOURCE_UNREF, 0, 0, CTRL_HDR_LEN + 8);
        wr32(&mut req, CTRL_HDR_LEN, resource_id);
        self.expect_nodata(&req)
    }

    fn transfer_to_host_3d(&mut self, ctx_id: u32, t: &Transfer3d) -> Result<(), Gpu3dError> {
        let fence = self.alloc_fence();
        let req = transfer_3d_req(CMD_TRANSFER_TO_HOST_3D, ctx_id, fence, t);
        self.expect_nodata(&req)
    }

    fn transfer_from_host_3d(&mut self, ctx_id: u32, t: &Transfer3d) -> Result<(), Gpu3dError> {
        let fence = self.alloc_fence();
        let req = transfer_3d_req(CMD_TRANSFER_FROM_HOST_3D, ctx_id, fence, t);
        self.expect_nodata(&req)
    }

    fn submit_3d(&mut self, ctx_id: u32, blob: &[u8]) -> Result<(), Gpu3dError> {
        let fence = self.alloc_fence();
        let mut hdr = hdr3d_vec(CMD_SUBMIT_3D, ctx_id, fence, CTRL_HDR_LEN + 8);
        wr32(&mut hdr, CTRL_HDR_LEN, blob.len() as u32);
        self.expect_nodata_parts(&[&hdr, blob])
    }

    fn resource_create_blob(
        &mut self,
        ctx_id: u32,
        resource_id: u32,
        blob_mem: u32,
        blob_flags: u32,
        blob_id: u64,
        size: u64,
    ) -> Result<(), Gpu3dError> {
        let fence = self.alloc_fence();
        let mut req = hdr3d_vec(CMD_RESOURCE_CREATE_BLOB, ctx_id, fence, CTRL_HDR_LEN + 32);
        wr32(&mut req, CTRL_HDR_LEN, resource_id);
        wr32(&mut req, CTRL_HDR_LEN + 4, blob_mem);
        wr32(&mut req, CTRL_HDR_LEN + 8, blob_flags);
        wr32(&mut req, CTRL_HDR_LEN + 12, 0);
        wr64(&mut req, CTRL_HDR_LEN + 16, blob_id);
        wr64(&mut req, CTRL_HDR_LEN + 24, size);
        self.expect_nodata(&req)
    }

    fn resource_map_blob(&mut self, resource_id: u32, offset: u64) -> Result<u32, Gpu3dError> {
        let fence = self.alloc_fence();
        let mut req = hdr3d_vec(CMD_RESOURCE_MAP_BLOB, 0, fence, CTRL_HDR_LEN + 16);
        wr32(&mut req, CTRL_HDR_LEN, resource_id);
        wr64(&mut req, CTRL_HDR_LEN + 8, offset);
        let resp = self.request(&req, CTRL_HDR_LEN + 8)?;
        if rd32(&resp, 0) != RESP_OK_MAP_INFO {
            return Err(Gpu3dError::Protocol);
        }
        Ok(rd32(&resp, CTRL_HDR_LEN))
    }

    fn resource_unmap_blob(&mut self, resource_id: u32) -> Result<(), Gpu3dError> {
        let mut req = hdr3d_vec(CMD_RESOURCE_UNMAP_BLOB, 0, 0, CTRL_HDR_LEN + 8);
        wr32(&mut req, CTRL_HDR_LEN, resource_id);
        self.expect_nodata(&req)
    }

    fn present_resource(&mut self, resource_id: u32, w: u32, h: u32) -> Result<(), Gpu3dError> {
        self.set_scanout(SCANOUT_ID, resource_id, w, h)?;
        self.resource_flush(resource_id, w, h)
    }

    fn restore_console(&mut self) -> Result<(), Gpu3dError> {
        let (w, h) = (self.width, self.height);
        self.set_scanout(SCANOUT_ID, RESOURCE_ID_FB, w, h)?;
        self.resource_flush(RESOURCE_ID_FB, w, h)
    }
}

fn ctrl_hdr(cmd: u32) -> Vec<u8> {
    ctrl_hdr_vec(cmd, CTRL_HDR_LEN)
}

fn ctrl_hdr_vec(cmd: u32, total: usize) -> Vec<u8> {
    let mut v = vec![0u8; total];
    wr32(&mut v, 0, cmd);
    v
}

fn hdr3d_vec(cmd: u32, ctx_id: u32, fence_id: u64, total: usize) -> Vec<u8> {
    let mut v = vec![0u8; total];
    wr32(&mut v, 0, cmd);
    if fence_id != 0 {
        wr32(&mut v, 4, FLAG_FENCE);
        wr64(&mut v, 8, fence_id);
    }
    wr32(&mut v, 16, ctx_id);
    v
}

fn transfer_3d_req(cmd: u32, ctx_id: u32, fence_id: u64, t: &Transfer3d) -> Vec<u8> {
    let mut req = hdr3d_vec(cmd, ctx_id, fence_id, CTRL_HDR_LEN + 48);
    wr32(&mut req, CTRL_HDR_LEN, t.x);
    wr32(&mut req, CTRL_HDR_LEN + 4, t.y);
    wr32(&mut req, CTRL_HDR_LEN + 8, t.z);
    wr32(&mut req, CTRL_HDR_LEN + 12, t.w);
    wr32(&mut req, CTRL_HDR_LEN + 16, t.h);
    wr32(&mut req, CTRL_HDR_LEN + 20, t.d);
    wr64(&mut req, CTRL_HDR_LEN + 24, t.offset);
    wr32(&mut req, CTRL_HDR_LEN + 32, t.resource_id);
    wr32(&mut req, CTRL_HDR_LEN + 36, t.level);
    wr32(&mut req, CTRL_HDR_LEN + 40, t.stride);
    wr32(&mut req, CTRL_HDR_LEN + 44, t.layer_stride);
    req
}

fn wr_rect(b: &mut [u8], o: usize, x: u32, y: u32, w: u32, h: u32) {
    wr32(b, o, x);
    wr32(b, o + 4, y);
    wr32(b, o + 8, w);
    wr32(b, o + 12, h);
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
