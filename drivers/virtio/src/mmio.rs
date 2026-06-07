use alloc::vec::Vec;

use frame::boot::KERNEL_VMA_OFFSET;

const MICROVM_MMIO_BASE: u64 = 0xfeb0_0000;
const MICROVM_MMIO_STRIDE: u64 = 0x200;
const MICROVM_MMIO_SLOTS: usize = 24;

const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;

pub const DEVICE_NET: u32 = 1;
pub const DEVICE_BLK: u32 = 2;
pub const DEVICE_CONSOLE: u32 = 3;
pub const DEVICE_RNG: u32 = 4;
pub const DEVICE_BALLOON: u32 = 5;
pub const DEVICE_GPU: u32 = 16;
pub const DEVICE_INPUT: u32 = 18;
pub const DEVICE_SOUND: u32 = 25;

pub fn device_kind(id: u32) -> &'static str {
    match id {
        DEVICE_NET => "net",
        DEVICE_BLK => "block",
        DEVICE_CONSOLE => "console",
        DEVICE_RNG => "rng",
        DEVICE_BALLOON => "balloon",
        DEVICE_GPU => "gpu",
        DEVICE_INPUT => "input",
        DEVICE_SOUND => "sound",
        0 => "(empty)",
        _ => "(unknown)",
    }
}

pub use frame::io::mmio::Mmio;

pub fn init_mmio_window() {}

#[inline]
fn mmio_va(phys: u64) -> u64 {
    phys | KERNEL_VMA_OFFSET
}

#[derive(Copy, Clone, Debug)]
pub struct ProbedDevice {
    pub base: u64,
    pub device_id: u32,
    pub vendor_id: u32,
    pub version: u32,
}

pub fn probe() -> Vec<ProbedDevice> {
    let mut out = Vec::new();
    for i in 0..MICROVM_MMIO_SLOTS {
        let phys = MICROVM_MMIO_BASE + i as u64 * MICROVM_MMIO_STRIDE;
        let base = mmio_va(phys);
        // SAFETY: the boot stub mapped phys 0xc000_0000..0x1_0000_0000
        // at high VA via PDPT_high[511], so this dereference is valid.
        // This fresh handle is the only access path to the MagicValue
        // word and is dropped after the read below — unique, live.
        let regs = unsafe { Mmio::<u32>::new(base as *mut u32) };
        let magic = regs.read();
        if magic != VIRTIO_MMIO_MAGIC {
            continue;
        }
        // SAFETY: `base + 0x004` is the virtio-mmio Version register, inside
        // the same 0x200-byte device window as `base`, hence still covered by
        // the boot-stub high mapping. This fresh handle is the only access path
        // to the word and is dropped after the read below — unique, live.
        let version_regs = unsafe { Mmio::<u32>::new((base + 0x004) as *mut u32) };
        let version = version_regs.read();
        // SAFETY: `base + 0x008` is the virtio-mmio DeviceID register, within
        // the mapped 0x200-byte window; sole live handle to the word, dropped
        // after the read.
        let dev_regs = unsafe { Mmio::<u32>::new((base + 0x008) as *mut u32) };
        let device_id = dev_regs.read();
        // SAFETY: `base + 0x00c` is the virtio-mmio VendorID register, within
        // the mapped 0x200-byte window; sole live handle to the word, dropped
        // after the read.
        let ven_regs = unsafe { Mmio::<u32>::new((base + 0x00c) as *mut u32) };
        let vendor_id = ven_regs.read();
        if device_id == 0 {
            continue;
        }
        out.push(ProbedDevice {
            base,
            device_id,
            vendor_id,
            version,
        });
    }
    out
}
