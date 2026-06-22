use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use ::virtio;

use cyphera_kapi::{Errno, KResult};

use crate::vfs::{Inode, InodeKind, Stat};

pub fn null() -> Arc<dyn Inode> {
    Arc::new(Null)
}

pub fn zero() -> Arc<dyn Inode> {
    Arc::new(Zero)
}

pub fn urandom() -> Arc<dyn Inode> {
    Arc::new(Urandom)
}

pub fn random() -> Arc<dyn Inode> {
    urandom()
}

pub fn full() -> Arc<dyn Inode> {
    Arc::new(Full)
}

pub fn console() -> Arc<dyn Inode> {
    Arc::new(Console)
}

pub fn fb0() -> Arc<dyn Inode> {
    Arc::new(Fb)
}

pub fn dsp() -> Arc<dyn Inode> {
    Arc::new(Dsp)
}

pub fn input_event(idx: usize) -> Arc<dyn Inode> {
    Arc::new(InputEvent { idx })
}

pub fn tty() -> Arc<dyn Inode> {
    Arc::new(Console)
}

pub fn node_for_dev(major: u32, minor: u32) -> Option<Arc<dyn Inode>> {
    Some(match (major, minor) {
        (1, 3) => null(),
        (1, 5) => zero(),
        (1, 7) => full(),
        (1, 8) => random(),
        (1, 9) => urandom(),
        (5, 0) => tty(),
        (5, 1) => console(),
        _ => return None,
    })
}

fn char_stat() -> Stat {
    Stat::fresh(InodeKind::CharDevice, 0, 0o666)
}

pub fn vda() -> Arc<dyn Inode> {
    Arc::new(Vda)
}

struct Vda;

impl Inode for Vda {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        char_stat()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<usize> {
        if !offset.is_multiple_of(512) || !buf.len().is_multiple_of(512) {
            return Err(Errno::INVAL);
        }
        crate::io::block_read(offset / 512, buf)
            .map(|()| buf.len())
            .map_err(|_| Errno::IO)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> KResult<usize> {
        if !offset.is_multiple_of(512) || !buf.len().is_multiple_of(512) {
            return Err(Errno::INVAL);
        }
        crate::io::block_write(offset / 512, buf)
            .map(|()| buf.len())
            .map_err(|_| Errno::IO)
    }
}

struct Null;

impl Inode for Null {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        char_stat()
    }
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> KResult<usize> {
        Ok(0)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> KResult<usize> {
        Ok(buf.len())
    }
}

struct Zero;

impl Inode for Zero {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        char_stat()
    }
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> KResult<usize> {
        for b in buf.iter_mut() {
            *b = 0;
        }
        Ok(buf.len())
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> KResult<usize> {
        Ok(buf.len())
    }
}

struct Urandom;

impl Inode for Urandom {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        char_stat()
    }
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> KResult<usize> {
        crate::device::random::fill(buf);
        Ok(buf.len())
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> KResult<usize> {
        Ok(buf.len())
    }
}

struct Full;

impl Inode for Full {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        char_stat()
    }
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> KResult<usize> {
        for b in buf.iter_mut() {
            *b = 0;
        }
        Ok(buf.len())
    }
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> KResult<usize> {
        Err(Errno::NOSPC)
    }
}

struct Console;

impl Inode for Console {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        char_stat()
    }
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> KResult<usize> {
        Ok(crate::console::read_blocking(buf))
    }
    fn read_at_with_flags(
        &self,
        _offset: u64,
        buf: &mut [u8],
        flags: crate::vfs::OpenFlags,
    ) -> KResult<usize> {
        let nb = flags.contains(crate::vfs::OpenFlags::NONBLOCK);
        crate::console::read(buf, nb)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> KResult<usize> {
        frame::io::uart::write_bytes(buf);
        Ok(buf.len())
    }
    fn poll(&self) -> crate::vfs::PollMask {
        let mut m = crate::vfs::PollMask::OUT;
        if crate::console::poll_readable() {
            m |= crate::vfs::PollMask::IN;
        }
        m
    }
    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&crate::core::wait::WaitQueue)) {
        crate::console::for_each_read_wq(f);
    }
}

struct Fb;

impl Inode for Fb {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        let size = match virtio::framebuffer_info() {
            Some((_, len, _, _)) => len as u64,
            None => 0,
        };
        let mut s = Stat::fresh(InodeKind::CharDevice, 0, 0o666);
        s.size = size;
        s
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<usize> {
        if virtio::framebuffer_info().is_none() {
            return Err(Errno::NOSYS);
        }
        Ok(virtio::fb_read(offset as usize, buf))
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> KResult<usize> {
        if virtio::framebuffer_info().is_none() {
            return Err(Errno::NOSYS);
        }
        let n = virtio::fb_write(offset as usize, buf);
        let _ = virtio::gpu_flush();
        Ok(n)
    }
}

pub const DSP_INODE_BIT: u64 = 1u64 << 61;

pub static DSP_FORMAT: AtomicU32 = AtomicU32::new(AFMT_S16_LE);
pub static DSP_CHANNELS: AtomicU32 = AtomicU32::new(2);
pub static DSP_RATE: AtomicU32 = AtomicU32::new(44100);

pub const AFMT_QUERY: u32 = 0;
pub const AFMT_S8: u32 = 0x40;
pub const AFMT_U8: u32 = 0x08;
pub const AFMT_S16_LE: u32 = 0x10;
pub const AFMT_U16_LE: u32 = 0x80;

pub fn nearest_supported_rate(req_hz: u32) -> (u32, ::virtio::sound::PcmRate) {
    use ::virtio::sound::PcmRate::*;
    let table: &[(u32, ::virtio::sound::PcmRate)] = &[
        (5512, Rate5512),
        (8000, Rate8000),
        (11025, Rate11025),
        (16000, Rate16000),
        (22050, Rate22050),
        (32000, Rate32000),
        (44100, Rate44100),
        (48000, Rate48000),
    ];
    let mut best = table[6];
    let mut best_diff = u32::MAX;
    for &(hz, rate) in table {
        let diff = hz.abs_diff(req_hz);
        if diff < best_diff {
            best_diff = diff;
            best = (hz, rate);
        }
    }
    best
}

struct Dsp;

impl Inode for Dsp {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::CharDevice, 0, 0o666)
    }
    fn inode_id(&self) -> u64 {
        DSP_INODE_BIT | (self as *const Self as u64)
    }
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> KResult<usize> {
        Ok(0)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> KResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let fmt_raw = DSP_FORMAT.load(Ordering::Relaxed);
        let channels = DSP_CHANNELS.load(Ordering::Relaxed) as u8;
        let rate_hz = DSP_RATE.load(Ordering::Relaxed);
        let format = match fmt_raw {
            AFMT_S16_LE => ::virtio::sound::PcmFormat::S16,
            AFMT_U16_LE => ::virtio::sound::PcmFormat::U16,
            AFMT_S8 => ::virtio::sound::PcmFormat::S8,
            AFMT_U8 => ::virtio::sound::PcmFormat::U8,
            _ => return Err(Errno::INVAL),
        };
        let (_negotiated_hz, pcm_rate) = nearest_supported_rate(rate_hz);
        let stream_id = match ::virtio::sound_output_streams() {
            Ok(v) => *v.first().ok_or(Errno::NOSYS)?,
            Err(_) => return Err(Errno::NOSYS),
        };
        ::virtio::sound_play_blocking(stream_id, channels, format, pcm_rate, buf)
            .map(|()| buf.len())
            .map_err(|_| Errno::IO)
    }
}

struct InputEvent {
    idx: usize,
}

impl Inode for InputEvent {
    fn kind(&self) -> InodeKind {
        InodeKind::CharDevice
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::CharDevice, 0, 0o600)
    }
    fn read_at(&self, _offset: u64, buf: &mut [u8]) -> KResult<usize> {
        const EV_SIZE: usize = 24;
        if buf.len() < EV_SIZE {
            return Err(Errno::INVAL);
        }
        let drained = crate::device::input::drain_for(self.idx);
        if drained.is_empty() {
            return crate::device::input::read_blocking(self.idx, buf);
        }
        let max = buf.len() / EV_SIZE;
        let n = drained.len().min(max);
        for (i, ev) in drained.iter().take(n).enumerate() {
            let off = i * EV_SIZE;
            let now = frame::cpu::clock::nanos_since_boot();
            let sec = (now / 1_000_000_000) as i64;
            let usec = ((now / 1_000) % 1_000_000) as i64;
            buf[off..off + 8].copy_from_slice(&sec.to_le_bytes());
            buf[off + 8..off + 16].copy_from_slice(&usec.to_le_bytes());
            buf[off + 16..off + 18].copy_from_slice(&ev.event_type.to_le_bytes());
            buf[off + 18..off + 20].copy_from_slice(&ev.code.to_le_bytes());
            buf[off + 20..off + 24].copy_from_slice(&ev.value.to_le_bytes());
        }
        Ok(n * EV_SIZE)
    }
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> KResult<usize> {
        Err(Errno::NOSYS)
    }

    fn poll(&self) -> crate::vfs::PollMask {
        if crate::device::input::has_pending(self.idx) {
            crate::vfs::PollMask::IN
        } else {
            crate::vfs::PollMask::empty()
        }
    }

    fn for_each_wait_queue(&self, f: &mut dyn FnMut(&crate::core::wait::WaitQueue)) {
        crate::device::input::for_each_evdev_wq(self.idx, f);
    }
}
