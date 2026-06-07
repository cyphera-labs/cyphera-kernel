#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

pub mod blk;
pub mod gpu;
pub mod hal;
pub mod input;
pub mod mmio;
pub mod net;
pub mod pci;
pub mod rng;
pub mod sound;

use frame::sync::SpinIrq;

pub fn init() {
    mmio::init_mmio_window();
    let probed = mmio::probe();

    for dev in &probed {
        frame::println!(
            "[virtio] mmio @ {:#x}: device_id={} ({})",
            dev.base,
            dev.device_id,
            mmio::device_kind(dev.device_id),
        );
    }

    if let Some(rng_dev) = probed.iter().find(|d| d.device_id == mmio::DEVICE_RNG) {
        match rng::Rng::new_mmio(rng_dev.base) {
            Ok(rng) => {
                frame::println!("[virtio] rng: brought up at {:#x}", rng_dev.base);
                *RNG.lock() = Some(rng);
            }
            Err(e) => frame::println!("[virtio] rng init failed: {e:?}"),
        }
    }

    if let Some(blk_dev) = probed.iter().find(|d| d.device_id == mmio::DEVICE_BLK) {
        match blk::Blk::new_mmio(blk_dev.base) {
            Ok(blk) => {
                frame::println!(
                    "[virtio] blk: brought up via MMIO at {:#x}, capacity {} sectors",
                    blk_dev.base,
                    blk.capacity_sectors(),
                );
                *BLK.lock() = Some(blk);
            }
            Err(e) => frame::println!("[virtio] blk init failed: {e:?}"),
        }
    }

    if let Some(net_dev) = probed.iter().find(|d| d.device_id == mmio::DEVICE_NET) {
        match net::Net::new_mmio(net_dev.base) {
            Ok(net) => {
                let mac = net.mac();
                frame::println!(
                    "[virtio] net: brought up at {:#x}, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    net_dev.base,
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5],
                );
                *NET.lock() = Some(net);
            }
            Err(e) => frame::println!("[virtio] net init failed: {e:?}"),
        }
    }

    if let Some(gpu_dev) = probed.iter().find(|d| d.device_id == mmio::DEVICE_GPU) {
        match gpu::Gpu::new_mmio(gpu_dev.base) {
            Ok(mut g) => {
                let (w, h) = (g.width(), g.height());
                match g.setup_framebuffer() {
                    Ok(fb) => {
                        let len = fb.len();
                        let ptr = fb.as_mut_ptr() as u64;
                        frame::println!(
                            "[virtio] gpu: brought up at {:#x}, {}x{} fb @ {:#x} len {}",
                            gpu_dev.base,
                            w,
                            h,
                            ptr,
                            len,
                        );
                        *FB_PTR.lock() = Some((ptr, len, w, h));
                    }
                    Err(e) => frame::println!("[virtio] gpu fb setup failed: {e:?}"),
                }
                *GPU.lock() = Some(g);
            }
            Err(e) => frame::println!("[virtio] gpu init failed: {e:?}"),
        }
    }

    for inp_dev in probed.iter().filter(|d| d.device_id == mmio::DEVICE_INPUT) {
        match input::Input::new_mmio(inp_dev.base) {
            Ok(inp) => {
                frame::println!("[virtio] input: brought up at {:#x}", inp_dev.base);
                INPUTS.lock().push(inp);
            }
            Err(e) => frame::println!("[virtio] input init failed at {:#x}: {e:?}", inp_dev.base),
        }
    }

    if let Some(snd_dev) = probed.iter().find(|d| d.device_id == mmio::DEVICE_SOUND) {
        match sound::Sound::new_mmio(snd_dev.base) {
            Ok(snd) => {
                frame::println!(
                    "[virtio] sound: brought up at {:#x}, jacks={} streams={} chmaps={}",
                    snd_dev.base,
                    snd.jacks(),
                    snd.streams(),
                    snd.chmaps(),
                );
                *SND.lock() = Some(snd);
            }
            Err(e) => frame::println!("[virtio] sound init failed at {:#x}: {e:?}", snd_dev.base),
        }
    }

    pci::init_ecam_window();
    let pci_probed = pci::probe();
    for dev in &pci_probed {
        frame::println!(
            "[virtio-pci] {:?}: {:?}",
            dev.device_function,
            dev.device_type,
        );
    }
    for dev in pci_probed {
        use virtio_drivers::transport::DeviceType as Dt;
        let df = dev.device_function;
        match dev.device_type {
            Dt::Block if BLK.lock().is_none() => match blk::Blk::new_pci(dev.transport) {
                Ok(b) => {
                    frame::println!(
                        "[virtio] blk: brought up via PCI at {:?}, capacity {} sectors",
                        df,
                        b.capacity_sectors(),
                    );
                    *BLK.lock() = Some(b);
                }
                Err(e) => frame::println!("[virtio] pci blk init failed at {df:?}: {e:?}"),
            },
            Dt::Network if NET.lock().is_none() => match net::Net::new_pci(dev.transport) {
                Ok(n) => {
                    let mac = n.mac();
                    frame::println!(
                        "[virtio] net: brought up via PCI at {:?}, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        df,
                        mac[0],
                        mac[1],
                        mac[2],
                        mac[3],
                        mac[4],
                        mac[5],
                    );
                    *NET.lock() = Some(n);
                }
                Err(e) => frame::println!("[virtio] pci net init failed at {df:?}: {e:?}"),
            },
            Dt::EntropySource if RNG.lock().is_none() => match rng::Rng::new_pci(dev.transport) {
                Ok(r) => {
                    frame::println!("[virtio] rng: brought up via PCI at {:?}", df);
                    *RNG.lock() = Some(r);
                }
                Err(e) => frame::println!("[virtio] pci rng init failed at {df:?}: {e:?}"),
            },
            Dt::GPU if GPU.lock().is_none() => match gpu::Gpu::new_pci(dev.transport) {
                Ok(mut g) => {
                    let (w, h) = (g.width(), g.height());
                    match g.setup_framebuffer() {
                        Ok(fb) => {
                            let len = fb.len();
                            let ptr = fb.as_mut_ptr() as u64;
                            frame::println!(
                                "[virtio] gpu: brought up via PCI at {:?}, {}x{} fb @ {:#x} len {}",
                                df,
                                w,
                                h,
                                ptr,
                                len,
                            );
                            *FB_PTR.lock() = Some((ptr, len, w, h));
                        }
                        Err(e) => frame::println!("[virtio] pci gpu fb setup failed: {e:?}"),
                    }
                    *GPU.lock() = Some(g);
                }
                Err(e) => frame::println!("[virtio] pci gpu init failed at {df:?}: {e:?}"),
            },
            Dt::Input => match input::Input::new_pci(dev.transport) {
                Ok(i) => {
                    frame::println!("[virtio] input: brought up via PCI at {:?}", df);
                    INPUTS.lock().push(i);
                }
                Err(e) => frame::println!("[virtio] pci input init failed at {df:?}: {e:?}"),
            },
            Dt::Sound if SND.lock().is_none() => match sound::Sound::new_pci(dev.transport) {
                Ok(s) => {
                    frame::println!(
                        "[virtio] sound: brought up via PCI at {:?}, jacks={} streams={} chmaps={}",
                        df,
                        s.jacks(),
                        s.streams(),
                        s.chmaps(),
                    );
                    *SND.lock() = Some(s);
                }
                Err(e) => frame::println!("[virtio] pci sound init failed at {df:?}: {e:?}"),
            },
            other => {
                frame::println!(
                    "[virtio-pci] {:?} {:?}: no driver bound (already have MMIO instance or unsupported class)",
                    df,
                    other,
                );
            }
        }
    }

    frame::println!("[virtio] init complete: {} inputs", INPUTS.lock().len());
}

static RNG: SpinIrq<Option<rng::Rng>> = SpinIrq::new(None);
static BLK: SpinIrq<Option<blk::Blk>> = SpinIrq::new(None);
static NET: SpinIrq<Option<net::Net>> = SpinIrq::new(None);
static GPU: SpinIrq<Option<gpu::Gpu>> = SpinIrq::new(None);
static FB_PTR: SpinIrq<Option<(u64, usize, u32, u32)>> = SpinIrq::new(None);
static INPUTS: SpinIrq<alloc::vec::Vec<input::Input>> = SpinIrq::new(alloc::vec::Vec::new());
static SND: SpinIrq<Option<sound::Sound>> = SpinIrq::new(None);

pub fn framebuffer_info() -> Option<(u64, usize, u32, u32)> {
    *FB_PTR.lock()
}

pub fn fb_read(offset: usize, dst: &mut [u8]) -> usize {
    let (ptr, len, _, _) = match framebuffer_info() {
        Some(x) => x,
        None => return 0,
    };
    if offset >= len {
        return 0;
    }
    let n = dst.len().min(len - offset);
    // SAFETY: ptr/len describe the host-allocated framebuffer, which
    // lives for the kernel's lifetime; n is bounded by len.
    unsafe {
        core::ptr::copy_nonoverlapping((ptr as *const u8).add(offset), dst.as_mut_ptr(), n);
    }
    n
}

pub fn fb_write(offset: usize, src: &[u8]) -> usize {
    let (ptr, len, _, _) = match framebuffer_info() {
        Some(x) => x,
        None => return 0,
    };
    if offset >= len {
        return 0;
    }
    let n = src.len().min(len - offset);
    // SAFETY: same as fb_read; we own the framebuffer for kernel
    // lifetime and the destination range is in-bounds.
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), (ptr as *mut u8).add(offset), n);
    }
    n
}

pub fn gpu_flush() -> Result<(), Error> {
    let mut g = GPU.lock();
    let gpu = g.as_mut().ok_or(Error::NoDevice)?;
    gpu.flush().map_err(|e| match e {
        gpu::GpuError::Driver(d) => Error::Driver(d),
        gpu::GpuError::Mmio(_) => Error::Driver(virtio_drivers::Error::IoError),
    })
}

pub fn input_drain() -> alloc::vec::Vec<(usize, input::InputEvent)> {
    let mut g = INPUTS.lock();
    let mut out = alloc::vec::Vec::new();
    for (i, dev) in g.iter_mut().enumerate() {
        while let Some(ev) = dev.pop_event() {
            out.push((i, ev));
        }
    }
    out
}

pub fn input_count() -> usize {
    INPUTS.lock().len()
}

pub fn fill_random(buf: &mut [u8]) -> Result<usize, Error> {
    let mut g = RNG.lock();
    let rng = g.as_mut().ok_or(Error::NoDevice)?;
    rng.read(buf)
        .map(|n| n.min(buf.len()))
        .map_err(Error::Driver)
}

pub fn read_block_sector(lba: u64, buf: &mut [u8]) -> Result<(), Error> {
    let mut g = BLK.lock();
    let blk = g.as_mut().ok_or(Error::NoDevice)?;
    blk.read_sectors(lba, buf).map_err(Error::Driver)
}

pub fn write_block_sector(lba: u64, buf: &[u8]) -> Result<(), Error> {
    let mut g = BLK.lock();
    let blk = g.as_mut().ok_or(Error::NoDevice)?;
    blk.write_sectors(lba, buf).map_err(Error::Driver)
}

pub fn block_capacity_sectors() -> Option<u64> {
    BLK.lock().as_ref().map(|b| b.capacity_sectors())
}

pub fn net_mac() -> Option<[u8; 6]> {
    NET.lock().as_ref().map(|n| n.mac())
}

pub fn net_send(frame: &[u8]) -> Result<(), Error> {
    let mut g = NET.lock();
    let net = g.as_mut().ok_or(Error::NoDevice)?;
    net.send(frame).map_err(Error::Driver)
}

pub fn net_try_recv(buf: &mut [u8]) -> Result<usize, Error> {
    let mut g = NET.lock();
    let net = g.as_mut().ok_or(Error::NoDevice)?;
    if !net.can_recv() {
        return Err(Error::NoDevice);
    }
    let rx = net.recv().map_err(Error::Driver)?;
    let pkt = rx.packet();
    let n = pkt.len().min(buf.len());
    buf[..n].copy_from_slice(&pkt[..n]);
    net.recycle(rx).map_err(Error::Driver)?;
    Ok(n)
}

pub fn sound_topology() -> Option<(u32, u32, u32)> {
    SND.lock()
        .as_ref()
        .map(|s| (s.jacks(), s.streams(), s.chmaps()))
}

pub fn sound_output_streams() -> Result<alloc::vec::Vec<u32>, Error> {
    let mut g = SND.lock();
    let snd = g.as_mut().ok_or(Error::NoDevice)?;
    snd.output_streams().map_err(|e| match e {
        sound::SoundErr::Driver(d) => Error::Driver(d),
        sound::SoundErr::Mmio(_) => Error::Driver(virtio_drivers::Error::IoError),
    })
}

pub fn sound_play_blocking(
    stream_id: u32,
    channels: u8,
    format: sound::PcmFormat,
    rate: sound::PcmRate,
    frames: &[u8],
) -> Result<(), Error> {
    let mut g = SND.lock();
    let snd = g.as_mut().ok_or(Error::NoDevice)?;
    snd.play_blocking(stream_id, channels, format, rate, frames)
        .map_err(|e| match e {
            sound::SoundErr::Driver(d) => Error::Driver(d),
            sound::SoundErr::Mmio(_) => Error::Driver(virtio_drivers::Error::IoError),
        })
}

#[derive(Debug)]
pub enum Error {
    NoDevice,
    Driver(virtio_drivers::Error),
}
