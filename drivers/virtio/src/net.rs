use core::ptr::NonNull;

use virtio_drivers::{
    device::net::{RxBuffer, VirtIONet},
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        pci::PciTransport,
    },
};

use crate::hal::FrameHal;

const QUEUE_SIZE: usize = 16;
const BUF_LEN: usize = 2048;

pub struct Net {
    inner: NetInner,
}

enum NetInner {
    Mmio(VirtIONet<FrameHal, MmioTransport<'static>, QUEUE_SIZE>),
    Pci(VirtIONet<FrameHal, PciTransport, QUEUE_SIZE>),
}

#[derive(Debug)]
pub enum NetError {
    Mmio(virtio_drivers::transport::mmio::MmioError),
    Driver(virtio_drivers::Error),
}

impl Net {
    pub fn new_mmio(mmio_base: u64) -> Result<Self, NetError> {
        let header = NonNull::new(mmio_base as *mut VirtIOHeader).expect("base non-null");
        // SAFETY: `header` is non-null (the preceding `expect`; it does not
        // establish alignment). `0x200` is the virtio-MMIO control-register
        // window size (per-device microvm stride, MICROVM_MMIO_STRIDE). The
        // access only touches device MMIO registers, never Rust-visible memory.
        // Precondition (caller-discharged, not checked here): `mmio_base` must
        // name a 0x200-byte, register-backed virtio-MMIO window that no other
        // live transport drives. The in-tree caller `virtio::init` satisfies
        // this by passing a `mmio::probe()` base — a kernel-VA
        // `phys | KERNEL_VMA_OFFSET` (phys = 0xfeb0_0000 + i*0x200, so
        // 0x200-aligned) inside the boot stub's permanent high-half device
        // mapping (PDPT_high[511], kernel-lifetime), probed once before bringup;
        // the kernel holds the only handle to this device.
        let transport = unsafe { MmioTransport::new(header, 0x200) }.map_err(NetError::Mmio)?;
        let inner = VirtIONet::new(transport, BUF_LEN).map_err(NetError::Driver)?;
        Ok(Self {
            inner: NetInner::Mmio(inner),
        })
    }

    pub fn new_pci(transport: PciTransport) -> Result<Self, NetError> {
        let inner = VirtIONet::new(transport, BUF_LEN).map_err(NetError::Driver)?;
        Ok(Self {
            inner: NetInner::Pci(inner),
        })
    }

    pub fn mac(&self) -> [u8; 6] {
        match &self.inner {
            NetInner::Mmio(n) => n.mac_address(),
            NetInner::Pci(n) => n.mac_address(),
        }
    }

    pub fn can_send(&self) -> bool {
        match &self.inner {
            NetInner::Mmio(n) => n.can_send(),
            NetInner::Pci(n) => n.can_send(),
        }
    }

    pub fn can_recv(&self) -> bool {
        match &self.inner {
            NetInner::Mmio(n) => n.can_recv(),
            NetInner::Pci(n) => n.can_recv(),
        }
    }

    pub fn send(&mut self, frame: &[u8]) -> Result<(), virtio_drivers::Error> {
        match &mut self.inner {
            NetInner::Mmio(n) => {
                let mut tx = n.new_tx_buffer(frame.len());
                tx.packet_mut().copy_from_slice(frame);
                n.send(tx)
            }
            NetInner::Pci(n) => {
                let mut tx = n.new_tx_buffer(frame.len());
                tx.packet_mut().copy_from_slice(frame);
                n.send(tx)
            }
        }
    }

    pub fn recv(&mut self) -> Result<RxBuffer, virtio_drivers::Error> {
        match &mut self.inner {
            NetInner::Mmio(n) => n.receive(),
            NetInner::Pci(n) => n.receive(),
        }
    }

    pub fn recycle(&mut self, buf: RxBuffer) -> Result<(), virtio_drivers::Error> {
        match &mut self.inner {
            NetInner::Mmio(n) => n.recycle_rx_buffer(buf),
            NetInner::Pci(n) => n.recycle_rx_buffer(buf),
        }
    }
}
