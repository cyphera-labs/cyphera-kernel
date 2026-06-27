#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

pub mod blk;
pub mod gpu;
pub mod gpu3d;
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
        if gpu3d::mmio_offers_virgl(gpu_dev.base) {
            match gpu3d::Gpu3d::new_mmio(gpu_dev.base) {
                Ok(mut g) => {
                    let (w, h) = (g.width(), g.height());
                    match g.setup_framebuffer() {
                        Ok(fb) => {
                            let len = fb.len();
                            let ptr = fb.as_mut_ptr() as u64;
                            frame::println!(
                                "[virtio] gpu: brought up at {:#x} (virgl={}), {}x{} fb @ {:#x} len {}",
                                gpu_dev.base,
                                g.virgl_enabled(),
                                w,
                                h,
                                ptr,
                                len,
                            );
                            *FB_PTR.lock() = Some((ptr, len, w, h));
                        }
                        Err(e) => frame::println!("[virtio] gpu3d fb setup failed: {e:?}"),
                    }
                    *GPU3D.lock() = Some(g);
                }
                Err(e) => frame::println!("[virtio] gpu3d init failed: {e:?}"),
            }
        } else {
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
            Dt::GPU if GPU.lock().is_none() && GPU3D.lock().is_none() => {
                let host_visible = dev.host_visible;
                let mut transport = dev.transport;
                if gpu3d::transport_offers_virgl(&mut transport) {
                    match gpu3d::Gpu3d::new_pci(transport, host_visible) {
                        Ok(mut g) => {
                            let (w, h) = (g.width(), g.height());
                            match g.setup_framebuffer() {
                                Ok(fb) => {
                                    let len = fb.len();
                                    let ptr = fb.as_mut_ptr() as u64;
                                    frame::println!(
                                        "[virtio] gpu: brought up via PCI at {:?} (virgl={}), {}x{} fb @ {:#x} len {}",
                                        df,
                                        g.virgl_enabled(),
                                        w,
                                        h,
                                        ptr,
                                        len,
                                    );
                                    *FB_PTR.lock() = Some((ptr, len, w, h));
                                }
                                Err(e) => {
                                    frame::println!("[virtio] pci gpu3d fb setup failed: {e:?}")
                                }
                            }
                            *GPU3D.lock() = Some(g);
                        }
                        Err(e) => {
                            frame::println!("[virtio] pci gpu3d init failed at {df:?}: {e:?}")
                        }
                    }
                } else {
                    match gpu::Gpu::new_pci(transport) {
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
                                Err(e) => {
                                    frame::println!("[virtio] pci gpu fb setup failed: {e:?}")
                                }
                            }
                            *GPU.lock() = Some(g);
                        }
                        Err(e) => frame::println!("[virtio] pci gpu init failed at {df:?}: {e:?}"),
                    }
                }
            }
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
static GPU3D: SpinIrq<Option<gpu3d::Gpu3d>> = SpinIrq::new(None);
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

pub fn fb_scroll_up(rows: usize) {
    let (ptr, len, w, _) = match framebuffer_info() {
        Some(x) => x,
        None => return,
    };
    let shift = rows.saturating_mul(w as usize).saturating_mul(4);
    if shift == 0 || shift >= len {
        return;
    }
    // SAFETY: ptr/len describe the host-allocated framebuffer (kernel
    // lifetime). `copy` is overlap-safe (memmove); it moves [shift..len)
    // down to [0..len-shift), then the freed tail [len-shift..len) is
    // zeroed. shift < len, so both ranges are in-bounds.
    unsafe {
        let base = ptr as *mut u8;
        core::ptr::copy(base.add(shift), base, len - shift);
        core::ptr::write_bytes(base.add(len - shift), 0, shift);
    }
}

pub fn gpu_flush() -> Result<(), Error> {
    if let Some(g) = GPU3D.lock().as_mut() {
        return g.flush().map_err(|e| match e {
            gpu3d::Gpu3dError::Driver(d) => Error::Driver(d),
            _ => Error::Driver(virtio_drivers::Error::IoError),
        });
    }
    let mut g = GPU.lock();
    let gpu = g.as_mut().ok_or(Error::NoDevice)?;
    gpu.flush().map_err(|e| match e {
        gpu::GpuError::Driver(d) => Error::Driver(d),
        gpu::GpuError::Mmio(_) => Error::Driver(virtio_drivers::Error::IoError),
    })
}

pub fn gpu_virgl_enabled() -> bool {
    GPU3D
        .lock()
        .as_ref()
        .map(|g| g.virgl_enabled())
        .unwrap_or(false)
}

pub fn gpu_capset(cap_set_id: u32) -> Option<(u32, alloc::vec::Vec<u8>)> {
    GPU3D
        .lock()
        .as_ref()
        .and_then(|g| g.capset(cap_set_id).map(|(v, d)| (v, d.to_vec())))
}

pub fn gpu_has_capset(cap_set_id: u32) -> bool {
    GPU3D
        .lock()
        .as_ref()
        .map(|g| g.capset(cap_set_id).is_some())
        .unwrap_or(false)
}

pub fn gpu_blob_supported() -> bool {
    GPU3D
        .lock()
        .as_ref()
        .map(|g| g.blob_supported())
        .unwrap_or(false)
}

pub fn gpu_host_visible_region() -> Option<(u64, u64)> {
    GPU3D.lock().as_ref().and_then(|g| g.host_visible_region())
}

fn map_gpu3d(e: gpu3d::Gpu3dError) -> Error {
    match e {
        gpu3d::Gpu3dError::Driver(d) => Error::Driver(d),
        _ => Error::Driver(virtio_drivers::Error::IoError),
    }
}

fn with_gpu3d_ctl<R>(
    f: impl FnOnce(&mut dyn gpu3d::Gpu3dCtl) -> Result<R, gpu3d::Gpu3dError>,
) -> Result<R, Error> {
    let mut g = GPU3D.lock();
    let gpu = g.as_mut().ok_or(Error::NoDevice)?;
    f(gpu.ctl()).map_err(map_gpu3d)
}

pub fn gpu_ctx_create(ctx_id: u32) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.ctx_create(ctx_id))
}

pub fn gpu_ctx_destroy(ctx_id: u32) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.ctx_destroy(ctx_id))
}

pub fn gpu_ctx_attach_resource(ctx_id: u32, resource_id: u32) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.ctx_attach_resource(ctx_id, resource_id))
}

pub fn gpu_ctx_detach_resource(ctx_id: u32, resource_id: u32) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.ctx_detach_resource(ctx_id, resource_id))
}

pub fn gpu_create_resource_3d(args: &gpu3d::ResourceCreate3d) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.create_resource_3d(args))
}

pub fn gpu_attach_backing(resource_id: u32, entries: &[(u64, u32)]) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.attach_backing(resource_id, entries))
}

pub fn gpu_detach_backing(resource_id: u32) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.detach_backing(resource_id))
}

pub fn gpu_unref_resource(resource_id: u32) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.unref_resource(resource_id))
}

pub fn gpu_transfer_to_host_3d(ctx_id: u32, t: &gpu3d::Transfer3d) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.transfer_to_host_3d(ctx_id, t))
}

pub fn gpu_transfer_from_host_3d(ctx_id: u32, t: &gpu3d::Transfer3d) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.transfer_from_host_3d(ctx_id, t))
}

pub fn gpu_submit_3d(ctx_id: u32, blob: &[u8]) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.submit_3d(ctx_id, blob))
}

pub fn gpu_resource_create_blob(
    ctx_id: u32,
    resource_id: u32,
    blob_mem: u32,
    blob_flags: u32,
    blob_id: u64,
    size: u64,
) -> Result<(), Error> {
    with_gpu3d_ctl(|c| {
        c.resource_create_blob(ctx_id, resource_id, blob_mem, blob_flags, blob_id, size)
    })
}

pub fn gpu_resource_map_blob(resource_id: u32, offset: u64) -> Result<u32, Error> {
    with_gpu3d_ctl(|c| c.resource_map_blob(resource_id, offset))
}

pub fn gpu_resource_unmap_blob(resource_id: u32) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.resource_unmap_blob(resource_id))
}

pub fn gpu_present_resource(resource_id: u32, w: u32, h: u32) -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.present_resource(resource_id, w, h))
}

pub fn gpu_restore_console_scanout() -> Result<(), Error> {
    with_gpu3d_ctl(|c| c.restore_console())
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

pub fn input_caps(idx: usize) -> Option<input::InputCaps> {
    INPUTS.lock().get(idx).map(|d| d.caps().clone())
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
        .map_err(map_snd_err)
}

fn map_snd_err(e: sound::SoundErr) -> Error {
    match e {
        sound::SoundErr::Driver(d) => Error::Driver(d),
        sound::SoundErr::Mmio(_) => Error::Driver(virtio_drivers::Error::IoError),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn sound_pcm_set_params(
    stream_id: u32,
    buffer_bytes: u32,
    period_bytes: u32,
    channels: u8,
    format: sound::PcmFormat,
    rate: sound::PcmRate,
) -> Result<(), Error> {
    let mut g = SND.lock();
    let snd = g.as_mut().ok_or(Error::NoDevice)?;
    snd.pcm_set_params(
        stream_id,
        buffer_bytes,
        period_bytes,
        sound::PcmFeatures::empty(),
        channels,
        format,
        rate,
    )
    .map_err(map_snd_err)
}

pub fn sound_pcm_prepare(stream_id: u32) -> Result<(), Error> {
    let mut g = SND.lock();
    g.as_mut()
        .ok_or(Error::NoDevice)?
        .pcm_prepare(stream_id)
        .map_err(map_snd_err)
}

pub fn sound_pcm_start(stream_id: u32) -> Result<(), Error> {
    let mut g = SND.lock();
    g.as_mut()
        .ok_or(Error::NoDevice)?
        .pcm_start(stream_id)
        .map_err(map_snd_err)
}

pub fn sound_pcm_stop(stream_id: u32) -> Result<(), Error> {
    let mut g = SND.lock();
    g.as_mut()
        .ok_or(Error::NoDevice)?
        .pcm_stop(stream_id)
        .map_err(map_snd_err)
}

pub fn sound_pcm_write(stream_id: u32, frames: &[u8]) -> Result<usize, Error> {
    let mut g = SND.lock();
    g.as_mut()
        .ok_or(Error::NoDevice)?
        .pcm_write(stream_id, frames)
        .map_err(map_snd_err)
}

#[derive(Debug)]
pub enum Error {
    NoDevice,
    Driver(virtio_drivers::Error),
}
