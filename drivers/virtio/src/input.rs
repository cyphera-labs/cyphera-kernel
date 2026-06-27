use alloc::string::String;
use alloc::vec::Vec;
use core::ptr::NonNull;

pub use virtio_drivers::device::input::InputEvent;
use virtio_drivers::{
    device::input::{InputConfigSelect, VirtIOInput as InnerInput},
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        pci::PciTransport,
    },
};

use crate::hal::FrameHal;

const EV_KEY: u8 = 1;
const EV_REL: u8 = 2;
const EV_ABS: u8 = 3;

#[derive(Clone, Debug, Default)]
pub struct InputCaps {
    pub name: String,
    pub key_bits: Vec<u8>,
    pub rel_bits: Vec<u8>,
    pub abs_bits: Vec<u8>,
}

pub struct Input {
    inner: InputInner,
    caps: InputCaps,
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
        let mut dev = Self {
            inner: InputInner::Mmio(inner),
            caps: InputCaps::default(),
        };
        dev.caps = dev.read_caps();
        Ok(dev)
    }

    pub fn new_pci(transport: PciTransport) -> Result<Self, InputErr> {
        let inner = InnerInput::new(transport).map_err(InputErr::Driver)?;
        let mut dev = Self {
            inner: InputInner::Pci(inner),
            caps: InputCaps::default(),
        };
        dev.caps = dev.read_caps();
        Ok(dev)
    }

    pub fn query_config(&mut self, select: u8, subsel: u8, out: &mut [u8]) -> u8 {
        let select = match select {
            0x01 => InputConfigSelect::IdName,
            0x02 => InputConfigSelect::IdSerial,
            0x03 => InputConfigSelect::IdDevids,
            0x10 => InputConfigSelect::PropBits,
            0x11 => InputConfigSelect::EvBits,
            0x12 => InputConfigSelect::AbsInfo,
            _ => return 0,
        };
        let r = match &mut self.inner {
            InputInner::Mmio(i) => i.query_config_select(select, subsel, out),
            InputInner::Pci(i) => i.query_config_select(select, subsel, out),
        };
        r.unwrap_or(0)
    }

    fn read_string(&mut self, select: u8, subsel: u8) -> String {
        let mut buf = [0u8; 128];
        let n = self.query_config(select, subsel, &mut buf) as usize;
        let n = n.min(buf.len());
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    fn read_bitmap(&mut self, select: u8, subsel: u8) -> Vec<u8> {
        let mut buf = [0u8; 128];
        let n = self.query_config(select, subsel, &mut buf) as usize;
        let n = n.min(buf.len());
        buf[..n].to_vec()
    }

    fn read_caps(&mut self) -> InputCaps {
        InputCaps {
            name: self.read_string(0x01, 0),
            key_bits: self.read_bitmap(0x11, EV_KEY),
            rel_bits: self.read_bitmap(0x11, EV_REL),
            abs_bits: self.read_bitmap(0x11, EV_ABS),
        }
    }

    pub fn caps(&self) -> &InputCaps {
        &self.caps
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
