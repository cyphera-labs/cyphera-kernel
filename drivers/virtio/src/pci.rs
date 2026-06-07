use alloc::vec::Vec;

use virtio_drivers::transport::{
    DeviceType,
    pci::{
        PciTransport, VirtioPciError,
        bus::{Cam, DeviceFunction, MmioCam, PciRoot},
    },
};

use crate::hal::FrameHal;

const PCIE_HIGH_VA_BASE: u64 = 0xffff_ffff_4000_0000;

const PCIE_HIGH_PA_BASE: u64 = 0x8000_0000;

pub const ECAM_SIZE: u64 = 256 * 1024 * 1024;

const VIRTIO_VENDOR_ID: u16 = 0x1AF4;

pub struct ProbedPciDevice {
    pub device_function: DeviceFunction,
    pub device_type: DeviceType,
    pub transport: PciTransport,
}

impl core::fmt::Debug for ProbedPciDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProbedPciDevice")
            .field("device_function", &self.device_function)
            .field("device_type", &self.device_type)
            .finish()
    }
}

#[inline]
fn ecam_va(phys: u64) -> *mut u8 {
    use frame::boot::KERNEL_VMA_OFFSET;
    if (PCIE_HIGH_PA_BASE..PCIE_HIGH_PA_BASE + 0x4000_0000).contains(&phys) {
        let offset = phys - PCIE_HIGH_PA_BASE;
        (PCIE_HIGH_VA_BASE + offset) as *mut u8
    } else if (0xC000_0000..0x1_0000_0000).contains(&phys) {
        (phys | KERNEL_VMA_OFFSET) as *mut u8
    } else {
        panic!("ECAM pa {phys:#x} not in a mapped device window (need MCFG-discovered range)")
    }
}

pub fn probe() -> Vec<ProbedPciDevice> {
    let mut out = Vec::new();

    let ecam_pa = frame::boot::ecam_base();
    let cam_base = ecam_va(ecam_pa);
    // SAFETY: `cam_base` is the ECAM window mapped PA -> VA via the appropriate
    // high-half device mapping (PDPT_high[509] for the [2 GiB, 3 GiB) range
    // q35+SeaBIOS uses, PDPT_high[511] for the [3 GiB, 4 GiB) range q35+UEFI
    // uses). We never dereference a Rust reference through this pointer; only
    // `MmioCam` reads through it, using MMIO-pure accesses.
    let cam = unsafe { MmioCam::new(cam_base, Cam::Ecam) };

    let mut root = PciRoot::new(cam);

    for (device_function, info) in root.enumerate_bus(0) {
        if info.vendor_id != VIRTIO_VENDOR_ID {
            continue;
        }

        let device_type = match pci_device_id_to_type(info.device_id) {
            Some(dt) => dt,
            None => continue,
        };

        match PciTransport::new::<FrameHal, _>(&mut root, device_function) {
            Ok(transport) => out.push(ProbedPciDevice {
                device_function,
                device_type,
                transport,
            }),
            Err(e) => {
                frame::println!(
                    "[virtio-pci] failed to bring up {:?} (device_id={:#06x}): {:?}",
                    device_function,
                    info.device_id,
                    VirtioPciErrorDbg(&e),
                );
            }
        }
    }

    out
}

fn pci_device_id_to_type(device_id: u16) -> Option<DeviceType> {
    if (0x1040..=0x107F).contains(&device_id) {
        DeviceType::try_from((device_id - 0x1040) as u32).ok()
    } else {
        match device_id {
            0x1000 => Some(DeviceType::Network),
            0x1001 => Some(DeviceType::Block),
            0x1002 => Some(DeviceType::MemoryBallooning),
            0x1003 => Some(DeviceType::Console),
            0x1004 => Some(DeviceType::ScsiHost),
            0x1005 => Some(DeviceType::EntropySource),
            _ => None,
        }
    }
}

pub fn init_ecam_window() {
}

struct VirtioPciErrorDbg<'a>(&'a VirtioPciError);

impl<'a> core::fmt::Debug for VirtioPciErrorDbg<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
