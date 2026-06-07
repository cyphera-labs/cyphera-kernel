use core::ptr::NonNull;

use virtio_drivers::{
    device::gpu::VirtIOGpu as InnerGpu,
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        pci::PciTransport,
    },
};

use crate::hal::FrameHal;

pub struct Gpu {
    inner: GpuInner,
    width: u32,
    height: u32,
}

enum GpuInner {
    Mmio(InnerGpu<FrameHal, MmioTransport<'static>>),
    Pci(InnerGpu<FrameHal, PciTransport>),
}

#[derive(Debug)]
pub enum GpuError {
    Mmio(virtio_drivers::transport::mmio::MmioError),
    Driver(virtio_drivers::Error),
}

impl Gpu {
    pub fn new_mmio(mmio_base: u64) -> Result<Self, GpuError> {
        let header = NonNull::new(mmio_base as *mut VirtIOHeader).expect("base non-null");
        // SAFETY: `header` is non-null (the expect above discharged that) and
        // points at the GPU device's virtio-mmio register window — the probe
        // identified DEVICE_GPU at this base, and the boot stub permanently
        // maps the device-area phys 0xc000_0000..0x1_0000_0000 (which includes
        // the microvm virtio-mmio range around 0xfeb0_0000) at high VA via
        // PDPT_high[511], so the register window is live for the kernel's
        // lifetime before this is reached; the 0x200 length matches the
        // per-device microvm stride (MICROVM_MMIO_STRIDE), so the transport's
        // register reads/writes stay inside that mapped MMIO window and touch no
        // Rust-visible memory.
        let transport = unsafe { MmioTransport::new(header, 0x200) }.map_err(GpuError::Mmio)?;
        let mut inner = InnerGpu::new(transport).map_err(GpuError::Driver)?;
        let (width, height) = inner.resolution().map_err(GpuError::Driver)?;
        Ok(Self {
            inner: GpuInner::Mmio(inner),
            width,
            height,
        })
    }

    pub fn new_pci(transport: PciTransport) -> Result<Self, GpuError> {
        let mut inner = InnerGpu::new(transport).map_err(GpuError::Driver)?;
        let (width, height) = inner.resolution().map_err(GpuError::Driver)?;
        Ok(Self {
            inner: GpuInner::Pci(inner),
            width,
            height,
        })
    }

    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn setup_framebuffer(&mut self) -> Result<&mut [u8], GpuError> {
        match &mut self.inner {
            GpuInner::Mmio(g) => g.setup_framebuffer().map_err(GpuError::Driver),
            GpuInner::Pci(g) => g.setup_framebuffer().map_err(GpuError::Driver),
        }
    }

    pub fn flush(&mut self) -> Result<(), GpuError> {
        match &mut self.inner {
            GpuInner::Mmio(g) => g.flush().map_err(GpuError::Driver),
            GpuInner::Pci(g) => g.flush().map_err(GpuError::Driver),
        }
    }

    pub fn ack_interrupt(&mut self) -> bool {
        match &mut self.inner {
            GpuInner::Mmio(g) => !g.ack_interrupt().is_empty(),
            GpuInner::Pci(g) => !g.ack_interrupt().is_empty(),
        }
    }
}
