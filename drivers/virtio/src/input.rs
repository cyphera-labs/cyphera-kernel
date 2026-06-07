use core::ptr::NonNull;

pub use virtio_drivers::device::input::InputEvent;
use virtio_drivers::{
    device::input::VirtIOInput as InnerInput,
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        pci::PciTransport,
    },
};

use crate::hal::FrameHal;

pub struct Input {
    inner: InputInner,
}

enum InputInner {
    Mmio(InnerInput<FrameHal, MmioTransport<'static>>),
    Pci(InnerInput<FrameHal, PciTransport>),
}

#[derive(Debug)]
pub enum InputErr {
    Mmio(virtio_drivers::transport::mmio::MmioError),
    Driver(virtio_drivers::Error),
}

impl Input {
    pub fn new_mmio(mmio_base: u64) -> Result<Self, InputErr> {
        let header = NonNull::new(mmio_base as *mut VirtIOHeader).expect("base non-null");
        // SAFETY: `header` is non-null (the preceding `expect`; `expect`
        // rejects only null, nothing else). `0x200` is the per-device
        // virtio-MMIO window size (MICROVM_MMIO_STRIDE). `mmio_base` is
        // `(0xfeb0_0000 + i*0x200) | KERNEL_VMA_OFFSET` from the probe, so
        // it is 0x200-aligned — exceeding `VirtIOHeader`'s alignment — and
        // the boot stub maps that whole window for the kernel's lifetime via
        // PDPT_high[511], giving `MmioTransport::new` the aligned, valid,
        // 'static-mapped region (header + config space) it requires.
        // PRECONDITION (caller-discharged): `mmio_base` names a register
        // window no other live transport drives. The in-tree caller (the
        // virtio probe loop) brings up at most one transport per distinct
        // probed base, so this transport is the sole accessor of that window.
        // The access touches device registers only, never Rust-visible memory.
        let transport = unsafe { MmioTransport::new(header, 0x200) }.map_err(InputErr::Mmio)?;
        let inner = InnerInput::new(transport).map_err(InputErr::Driver)?;
        Ok(Self {
            inner: InputInner::Mmio(inner),
        })
    }

    pub fn new_pci(transport: PciTransport) -> Result<Self, InputErr> {
        let inner = InnerInput::new(transport).map_err(InputErr::Driver)?;
        Ok(Self {
            inner: InputInner::Pci(inner),
        })
    }

    pub fn pop_event(&mut self) -> Option<InputEvent> {
        match &mut self.inner {
            InputInner::Mmio(i) => i.pop_pending_event(),
            InputInner::Pci(i) => i.pop_pending_event(),
        }
    }

    pub fn ack_interrupt(&mut self) -> bool {
        match &mut self.inner {
            InputInner::Mmio(i) => !i.ack_interrupt().is_empty(),
            InputInner::Pci(i) => !i.ack_interrupt().is_empty(),
        }
    }
}
