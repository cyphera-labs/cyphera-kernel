use core::ptr::NonNull;

use virtio_drivers::{
    device::blk::VirtIOBlk,
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        pci::PciTransport,
    },
};

use crate::hal::FrameHal;

pub const SECTOR_SIZE: usize = 512;

pub struct Blk {
    inner: BlkInner,
}

enum BlkInner {
    Mmio(VirtIOBlk<FrameHal, MmioTransport<'static>>),
    Pci(VirtIOBlk<FrameHal, PciTransport>),
}

#[derive(Debug)]
pub enum BlkError {
    Mmio(virtio_drivers::transport::mmio::MmioError),
    Driver(virtio_drivers::Error),
}

impl Blk {
    pub fn new_mmio(mmio_base: u64) -> Result<Self, BlkError> {
        let header = NonNull::new(mmio_base as *mut VirtIOHeader).expect("base non-null");
        // SAFETY: `NonNull::new(...).expect()` above rejects only null; it
        // says nothing about alignment. Alignment holds because the in-tree
        // caller (`virtio::init` via `mmio::probe`) passes a base of
        // `(MICROVM_MMIO_BASE + i*MICROVM_MMIO_STRIDE) | KERNEL_VMA_OFFSET`
        // (mmio.rs) — a 0x200-aligned address — and `VirtIOHeader` is
        // `#[repr(C)]` (align 4), so `header` is suitably aligned.
        // PRECONDITION (caller-discharged, not checked here): `mmio_base`
        // names a `MICROVM_MMIO_STRIDE` (0x200)-byte microvm virtio-MMIO
        // window. The boot stub maps that window for the kernel's whole
        // lifetime via PDPT_high[511] (`init_mmio_window` is a no-op), and the
        // kernel holds the only `Blk` handle to this device, so this transport
        // is its sole live accessor. The reads/writes `new` performs therefore
        // touch only device registers, never Rust-visible memory.
        let transport = unsafe { MmioTransport::new(header, 0x200) }.map_err(BlkError::Mmio)?;
        let inner = VirtIOBlk::new(transport).map_err(BlkError::Driver)?;
        Ok(Self {
            inner: BlkInner::Mmio(inner),
        })
    }

    pub fn new_pci(transport: PciTransport) -> Result<Self, BlkError> {
        let inner = VirtIOBlk::new(transport).map_err(BlkError::Driver)?;
        Ok(Self {
            inner: BlkInner::Pci(inner),
        })
    }

    pub fn capacity_sectors(&self) -> u64 {
        match &self.inner {
            BlkInner::Mmio(b) => b.capacity(),
            BlkInner::Pci(b) => b.capacity(),
        }
    }

    pub fn read_sectors(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), virtio_drivers::Error> {
        if buf.is_empty() || !buf.len().is_multiple_of(SECTOR_SIZE) {
            return Err(virtio_drivers::Error::InvalidParam);
        }
        match &mut self.inner {
            BlkInner::Mmio(b) => b.read_blocks(lba as usize, buf),
            BlkInner::Pci(b) => b.read_blocks(lba as usize, buf),
        }
    }

    pub fn write_sectors(&mut self, lba: u64, buf: &[u8]) -> Result<(), virtio_drivers::Error> {
        if buf.is_empty() || !buf.len().is_multiple_of(SECTOR_SIZE) {
            return Err(virtio_drivers::Error::InvalidParam);
        }
        match &mut self.inner {
            BlkInner::Mmio(b) => b.write_blocks(lba as usize, buf),
            BlkInner::Pci(b) => b.write_blocks(lba as usize, buf),
        }
    }
}
