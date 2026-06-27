use alloc::vec::Vec;

use virtio_drivers::transport::{
    DeviceType,
    pci::{
        PciTransport, VirtioPciError,
        bus::{BarInfo, Cam, ConfigurationAccess, DeviceFunction, MmioCam, PciRoot},
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
    pub host_visible: Option<(u64, u64)>,
}

impl core::fmt::Debug for ProbedPciDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProbedPciDevice")
            .field("device_function", &self.device_function)
            .field("device_type", &self.device_type)
            .field("host_visible", &self.host_visible)
            .finish()
    }
}

const PCI_CAP_ID_VNDR: u8 = 0x09;

const VIRTIO_PCI_CAP_SHARED_MEMORY_CFG: u8 = 8;

const VIRTIO_GPU_SHM_ID_HOST_VISIBLE: u8 = 1;

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

        let host_visible = parse_host_visible_region(cam_base, &mut root, device_function);

        match PciTransport::new::<FrameHal, _>(&mut root, device_function) {
            Ok(transport) => out.push(ProbedPciDevice {
                device_function,
                device_type,
                transport,
                host_visible,
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

fn parse_host_visible_region<C: ConfigurationAccess>(
    cam_base: *mut u8,
    root: &mut PciRoot<C>,
    df: DeviceFunction,
) -> Option<(u64, u64)> {
    // SAFETY: a second CAM view over the same ECAM window the primary PciRoot
    // also uses; every access here is a volatile MMIO config read (never a Rust
    // reference), issued sequentially on this probe path and never concurrently
    // with the primary, so there is no aliasing UB.
    let cam = unsafe { MmioCam::new(cam_base, Cam::Ecam) };
    let mut off = (cam.read_word(df, 0x34) & 0xFF) as u8;
    let mut hops = 0;
    while off != 0 && hops < 48 {
        hops += 1;
        if off & 0x3 != 0 || off > 0xEB {
            break;
        }
        let w0 = cam.read_word(df, off);
        let cap_id = (w0 & 0xFF) as u8;
        let next = ((w0 >> 8) & 0xFF) as u8;
        if cap_id == PCI_CAP_ID_VNDR {
            let cap_len = ((w0 >> 16) & 0xFF) as u8;
            let cfg_type = ((w0 >> 24) & 0xFF) as u8;
            let w1 = cam.read_word(df, off + 4);
            let bar = (w1 & 0xFF) as u8;
            let shmid = ((w1 >> 8) & 0xFF) as u8;
            if cfg_type == VIRTIO_PCI_CAP_SHARED_MEMORY_CFG
                && shmid == VIRTIO_GPU_SHM_ID_HOST_VISIBLE
                && cap_len >= 16
            {
                let off_lo = cam.read_word(df, off + 8) as u64;
                let len_lo = cam.read_word(df, off + 12) as u64;
                let (off_hi, len_hi) = if cap_len >= 24 {
                    (
                        cam.read_word(df, off + 16) as u64,
                        cam.read_word(df, off + 20) as u64,
                    )
                } else {
                    (0, 0)
                };
                let region_off = (off_hi << 32) | off_lo;
                let region_len = (len_hi << 32) | len_lo;
                if let Ok(Some(BarInfo::Memory { address, .. })) = root.bar_info(df, bar) {
                    return Some((address + region_off, region_len));
                }
                return None;
            }
        }
        off = next;
    }
    None
}

pub fn init_ecam_window() {}

struct VirtioPciErrorDbg<'a>(&'a VirtioPciError);

impl<'a> core::fmt::Debug for VirtioPciErrorDbg<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
