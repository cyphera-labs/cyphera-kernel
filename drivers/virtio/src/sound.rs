use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::ptr::NonNull;

pub use virtio_drivers::device::sound::{PcmFeatures, PcmFormat, PcmFormats, PcmRate, PcmRates};
use virtio_drivers::{
    device::sound::VirtIOSound as InnerSound,
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        pci::PciTransport,
    },
};

use crate::hal::FrameHal;

pub struct Sound {
    inner: SoundInner,
    tx_pending: VecDeque<u16>,
    residual: Vec<u8>,
    period_bytes: usize,
}

enum SoundInner {
    Mmio(InnerSound<FrameHal, MmioTransport<'static>>),
    Pci(InnerSound<FrameHal, PciTransport>),
}

#[derive(Debug)]
pub enum SoundErr {
    Mmio(virtio_drivers::transport::mmio::MmioError),
    Driver(virtio_drivers::Error),
}

macro_rules! sound_dispatch {
    ($self:expr, $method:ident($($arg:expr),*)) => {
        match &$self.inner {
            SoundInner::Mmio(s) => s.$method($($arg),*),
            SoundInner::Pci(s) => s.$method($($arg),*),
        }
    };
}

macro_rules! sound_dispatch_mut {
    ($self:expr, $method:ident($($arg:expr),*)) => {
        match &mut $self.inner {
            SoundInner::Mmio(s) => s.$method($($arg),*),
            SoundInner::Pci(s) => s.$method($($arg),*),
        }
    };
}

impl Sound {
    pub fn new_mmio(mmio_base: u64) -> Result<Self, SoundErr> {
        let header = NonNull::new(mmio_base as *mut VirtIOHeader).expect("base non-null");
        // SAFETY: `mmio_base` is the KVA the caller mapped onto this device's
        // virtio-MMIO control-register window; `header` is non-null (the
        // `NonNull::new(...).expect()` above) and properly aligned for
        // `VirtIOHeader`. The window is exactly 0x200 bytes and is exclusively
        // owned by this transport for its `'static` lifetime, so the MMIO reads
        // and writes `new` performs touch only device registers, never
        // Rust-visible memory.
        let transport = unsafe { MmioTransport::new(header, 0x200) }.map_err(SoundErr::Mmio)?;
        let inner = InnerSound::new(transport).map_err(SoundErr::Driver)?;
        Ok(Self {
            inner: SoundInner::Mmio(inner),
            tx_pending: VecDeque::new(),
            residual: Vec::new(),
            period_bytes: 0,
        })
    }

    pub fn new_pci(transport: PciTransport) -> Result<Self, SoundErr> {
        let inner = InnerSound::new(transport).map_err(SoundErr::Driver)?;
        Ok(Self {
            inner: SoundInner::Pci(inner),
            tx_pending: VecDeque::new(),
            residual: Vec::new(),
            period_bytes: 0,
        })
    }

    pub fn jacks(&self) -> u32 {
        sound_dispatch!(self, jacks())
    }
    pub fn streams(&self) -> u32 {
        sound_dispatch!(self, streams())
    }
    pub fn chmaps(&self) -> u32 {
        sound_dispatch!(self, chmaps())
    }

    pub fn output_streams(&mut self) -> Result<Vec<u32>, SoundErr> {
        sound_dispatch_mut!(self, output_streams()).map_err(SoundErr::Driver)
    }

    pub fn input_streams(&mut self) -> Result<Vec<u32>, SoundErr> {
        sound_dispatch_mut!(self, input_streams()).map_err(SoundErr::Driver)
    }

    pub fn rates_supported(&mut self, stream_id: u32) -> Result<PcmRates, SoundErr> {
        sound_dispatch_mut!(self, rates_supported(stream_id)).map_err(SoundErr::Driver)
    }

    pub fn formats_supported(&mut self, stream_id: u32) -> Result<PcmFormats, SoundErr> {
        sound_dispatch_mut!(self, formats_supported(stream_id)).map_err(SoundErr::Driver)
    }

    pub fn ack_interrupt(&mut self) -> bool {
        match &mut self.inner {
            SoundInner::Mmio(s) => !s.ack_interrupt().is_empty(),
            SoundInner::Pci(s) => !s.ack_interrupt().is_empty(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn pcm_set_params(
        &mut self,
        stream_id: u32,
        buffer_bytes: u32,
        period_bytes: u32,
        features: PcmFeatures,
        channels: u8,
        format: PcmFormat,
        rate: PcmRate,
    ) -> Result<(), SoundErr> {
        sound_dispatch_mut!(
            self,
            pcm_set_params(
                stream_id,
                buffer_bytes,
                period_bytes,
                features,
                channels,
                format,
                rate
            )
        )
        .map_err(SoundErr::Driver)?;
        self.period_bytes = period_bytes as usize;
        self.drain_tx();
        self.residual.clear();
        Ok(())
    }

    pub fn pcm_prepare(&mut self, stream_id: u32) -> Result<(), SoundErr> {
        sound_dispatch_mut!(self, pcm_prepare(stream_id)).map_err(SoundErr::Driver)?;
        self.drain_tx();
        self.residual.clear();
        Ok(())
    }

    pub fn pcm_start(&mut self, stream_id: u32) -> Result<(), SoundErr> {
        sound_dispatch_mut!(self, pcm_start(stream_id)).map_err(SoundErr::Driver)
    }

    pub fn pcm_stop(&mut self, stream_id: u32) -> Result<(), SoundErr> {
        sound_dispatch_mut!(self, pcm_stop(stream_id)).map_err(SoundErr::Driver)?;
        self.drain_tx();
        self.residual.clear();
        Ok(())
    }

    pub fn pcm_release(&mut self, stream_id: u32) -> Result<(), SoundErr> {
        sound_dispatch_mut!(self, pcm_release(stream_id)).map_err(SoundErr::Driver)
    }

    pub fn pcm_xfer(&mut self, stream_id: u32, frames: &[u8]) -> Result<(), SoundErr> {
        sound_dispatch_mut!(self, pcm_xfer(stream_id, frames)).map_err(SoundErr::Driver)
    }

    fn pcm_xfer_nb(&mut self, stream_id: u32, frames: &[u8]) -> Result<u16, SoundErr> {
        sound_dispatch_mut!(self, pcm_xfer_nb(stream_id, frames)).map_err(SoundErr::Driver)
    }

    fn pcm_xfer_ok(&mut self, token: u16) -> Result<(), SoundErr> {
        sound_dispatch_mut!(self, pcm_xfer_ok(token)).map_err(SoundErr::Driver)
    }

    fn drain_tx(&mut self) {
        while let Some(token) = self.tx_pending.front().copied() {
            if self.pcm_xfer_ok(token).is_err() {
                break;
            }
            self.tx_pending.pop_front();
        }
        self.tx_pending.clear();
    }

    pub fn pcm_write(&mut self, stream_id: u32, frames: &[u8]) -> Result<usize, SoundErr> {
        while let Some(token) = self.tx_pending.front().copied() {
            if self.pcm_xfer_ok(token).is_err() {
                break;
            }
            self.tx_pending.pop_front();
        }
        let pb = self.period_bytes;
        if pb == 0 {
            return Ok(0);
        }
        let carried = self.residual.len();
        let mut buf = core::mem::take(&mut self.residual);
        buf.extend_from_slice(frames);

        let mut off = 0;
        while buf.len() - off >= pb {
            match self.pcm_xfer_nb(stream_id, &buf[off..off + pb]) {
                Ok(token) => {
                    self.tx_pending.push_back(token);
                    off += pb;
                }
                Err(_) => break,
            }
        }

        if buf.len() - off < pb {
            self.residual = buf.split_off(off);
            Ok(frames.len())
        } else if off == 0 {
            buf.truncate(carried);
            self.residual = buf;
            Ok(0)
        } else {
            self.residual.clear();
            Ok(off - carried)
        }
    }

    pub fn play_blocking(
        &mut self,
        stream_id: u32,
        channels: u8,
        format: PcmFormat,
        rate: PcmRate,
        frames: &[u8],
    ) -> Result<(), SoundErr> {
        let bytes_per_sample = match format {
            PcmFormat::S16 | PcmFormat::U16 => 2,
            PcmFormat::S8
            | PcmFormat::U8
            | PcmFormat::ImaAdpcm
            | PcmFormat::MuLaw
            | PcmFormat::ALaw => 1,
            _ => 4,
        };
        let rate_hz: u32 = match rate {
            PcmRate::Rate5512 => 5512,
            PcmRate::Rate8000 => 8000,
            PcmRate::Rate11025 => 11025,
            PcmRate::Rate16000 => 16000,
            PcmRate::Rate22050 => 22050,
            PcmRate::Rate32000 => 32000,
            PcmRate::Rate44100 => 44100,
            PcmRate::Rate48000 => 48000,
            PcmRate::Rate64000 => 64000,
            PcmRate::Rate88200 => 88200,
            PcmRate::Rate96000 => 96000,
            PcmRate::Rate176400 => 176400,
            PcmRate::Rate192000 => 192000,
            PcmRate::Rate384000 => 384000,
        };
        let frame_bytes = bytes_per_sample as u32 * channels as u32;
        let period_frames = rate_hz / 20;
        let period_bytes = period_frames * frame_bytes;
        let buffer_bytes = period_bytes * 4;
        self.pcm_set_params(
            stream_id,
            buffer_bytes,
            period_bytes,
            PcmFeatures::empty(),
            channels,
            format,
            rate,
        )?;
        self.pcm_prepare(stream_id)?;
        self.pcm_start(stream_id)?;
        let xfer_res = self.pcm_xfer(stream_id, frames);
        let _ = self.pcm_stop(stream_id);
        let _ = self.pcm_release(stream_id);
        xfer_res
    }
}
