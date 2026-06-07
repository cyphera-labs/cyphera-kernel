use core::ptr::NonNull;

use virtio_drivers::{
    device::rng::VirtIORng,
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        pci::PciTransport,
    },
};

use crate::hal::FrameHal;

pub struct Rng {
    inner: RngInner,
}

enum RngInner {
    Mmio(VirtIORng<FrameHal, MmioTransport<'static>>),
    Pci(VirtIORng<FrameHal, PciTransport>),
}

#[derive(Debug)]
pub enum RngError {
    Mmio(virtio_drivers::transport::mmio::MmioError),
    Driver(virtio_drivers::Error),
}

impl Rng {
    pub fn new_mmio(mmio_base: u64) -> Result<Self, RngError> {
        let header = NonNull::new(mmio_base as *mut VirtIOHeader).expect("base non-null");
        // SAFETY: `header` is non-null (the expect above discharged that) and
        // points at the device's virtio-mmio register window; that window is
        // covered by the boot stub's permanent PDPT_high[511] mapping (so it
        // stays mapped for the kernel's lifetime), and the 0x200 length equals
        // MICROVM_MMIO_STRIDE (the per-device window size), so the transport's
        // reads/writes stay inside that mapped MMIO region.
        let transport = unsafe { MmioTransport::new(header, 0x200) }.map_err(RngError::Mmio)?;
        let inner = VirtIORng::new(transport).map_err(RngError::Driver)?;
        Ok(Self {
            inner: RngInner::Mmio(inner),
        })
    }

    pub fn new_pci(transport: PciTransport) -> Result<Self, RngError> {
        let inner = VirtIORng::new(transport).map_err(RngError::Driver)?;
        Ok(Self {
            inner: RngInner::Pci(inner),
        })
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, virtio_drivers::Error> {
        match &mut self.inner {
            RngInner::Mmio(r) => r.request_entropy(buf),
            RngInner::Pci(r) => r.request_entropy(buf),
        }
    }
}
