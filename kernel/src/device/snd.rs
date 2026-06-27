extern crate alloc;

use frame::sync::SpinIrq;

use crate::errno::{EBUSY, EFAULT, EINVAL, EIO, ENODEV, ENOTTY, EPIPE};

pub const ALSA_CONTROL: u8 = 0;
pub const ALSA_PCM_PLAYBACK: u8 = 1;

const SNDRV_CTL_VERSION: u32 = 0x0002_0000;
const SNDRV_PCM_VERSION: u32 = 0x0002_0000;

fn decode(cmd: u32) -> (u32, u32, u8, u8) {
    let dir = (cmd >> 30) & 0x3;
    let size = (cmd >> 16) & 0x3fff;
    let typ = ((cmd >> 8) & 0xff) as u8;
    let nr = (cmd & 0xff) as u8;
    (dir, size, typ, nr)
}

pub fn ioctl(kind: u8, cmd: u32, arg: u64) -> i64 {
    match kind {
        ALSA_CONTROL => control_ioctl(cmd, arg),
        ALSA_PCM_PLAYBACK => pcm_ioctl(cmd, arg),
        _ => ENOTTY,
    }
}

fn put_cstr(buf: &mut [u8], off: usize, width: usize, s: &str) {
    let b = s.as_bytes();
    let n = b.len().min(width - 1);
    buf[off..off + n].copy_from_slice(&b[..n]);
    buf[off + n] = 0;
}

fn build_pcm_info(device: u32, subdevice: u32, stream: i32) -> [u8; 288] {
    let mut b = [0u8; 288];
    b[0..4].copy_from_slice(&device.to_le_bytes());
    b[4..8].copy_from_slice(&subdevice.to_le_bytes());
    b[8..12].copy_from_slice(&stream.to_le_bytes());
    put_cstr(&mut b, 16, 64, "Virtio");
    put_cstr(&mut b, 80, 80, "Virtio sound");
    put_cstr(&mut b, 160, 32, "subdevice #0");
    b[200..204].copy_from_slice(&1u32.to_le_bytes());
    b[204..208].copy_from_slice(&1u32.to_le_bytes());
    b
}

fn build_card_info() -> [u8; 376] {
    let mut b = [0u8; 376];
    put_cstr(&mut b, 8, 16, "Virtio");
    put_cstr(&mut b, 24, 16, "virtio_snd");
    put_cstr(&mut b, 40, 32, "Virtio sound");
    put_cstr(&mut b, 72, 80, "Virtio sound device");
    put_cstr(&mut b, 168, 80, "Virtio");
    b
}

fn control_ioctl(cmd: u32, arg: u64) -> i64 {
    let (_dir, _size, _typ, nr) = decode(cmd);
    match nr {
        0x00 => {
            if frame::user::copy_to_user(arg, &SNDRV_CTL_VERSION.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        0x01 => {
            if frame::user::copy_to_user(arg, &build_card_info()).is_err() {
                return EFAULT;
            }
            0
        }
        0x30 => {
            let mut b = [0u8; 4];
            if frame::user::copy_from_user(arg, &mut b).is_err() {
                return EFAULT;
            }
            let current = i32::from_le_bytes(b);
            let next = if current < 0 { 0 } else { current + 1 };
            let result: i32 = if next == 0 { 0 } else { -1 };
            if frame::user::copy_to_user(arg, &result.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        0x32 => 0,
        0x31 => {
            let mut b = [0u8; 288];
            if frame::user::copy_from_user(arg, &mut b).is_err() {
                return EFAULT;
            }
            let device = u32::from_le_bytes(b[0..4].try_into().unwrap());
            let stream = i32::from_le_bytes(b[8..12].try_into().unwrap());
            if device != 0 || stream != 0 {
                return ENODEV;
            }
            let info = build_pcm_info(0, 0, 0);
            if frame::user::copy_to_user(arg, &info).is_err() {
                return EFAULT;
            }
            0
        }
        _ => ENOTTY,
    }
}

const HP_MASK_ACCESS: usize = 4;
const HP_MASK_FORMAT: usize = 8;
const HP_MASK_SUBFORMAT: usize = 12;
const HP_INTERVALS: usize = 16;
const HP_CMASK: usize = 164;

const IV_SAMPLE_BITS: usize = 0;
const IV_FRAME_BITS: usize = 1;
const IV_CHANNELS: usize = 2;
const IV_RATE: usize = 3;
const IV_PERIOD_TIME: usize = 4;
const IV_PERIOD_SIZE: usize = 5;
const IV_PERIOD_BYTES: usize = 6;
const IV_PERIODS: usize = 7;
const IV_BUFFER_TIME: usize = 8;
const IV_BUFFER_SIZE: usize = 9;
const IV_BUFFER_BYTES: usize = 10;

const ACCESS_RW_INTERLEAVED: u32 = 1 << 3;
const FORMAT_S16_LE: u32 = 1 << 2;
const SUBFORMAT_STD: u32 = 1 << 0;
const INTERVAL_INTEGER: u32 = 1 << 2;

const RATE_MIN: u32 = 5512;
const RATE_MAX: u32 = 48000;

fn rd32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn wr32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn iv_off(idx: usize) -> usize {
    HP_INTERVALS + idx * 12
}
fn iv_min(b: &[u8], idx: usize) -> u32 {
    rd32(b, iv_off(idx))
}
fn iv_fix(b: &mut [u8], idx: usize, val: u32) {
    let o = iv_off(idx);
    wr32(b, o, val);
    wr32(b, o + 4, val);
    wr32(b, o + 8, INTERVAL_INTEGER);
}
fn iv_clamp(b: &mut [u8], idx: usize, lo: u32, hi: u32) {
    let o = iv_off(idx);
    let mn = rd32(b, o).max(lo);
    let mx = rd32(b, o + 4).min(hi);
    wr32(b, o, mn);
    wr32(b, o + 4, mx);
}

struct PcmState {
    rate: u32,
    channels: u32,
    period_frames: u32,
    buffer_frames: u32,
    stream_id: u32,
    configured: bool,
    started: bool,
    start_ns: u64,
    appl_frames: u64,
    opens: u32,
}

impl PcmState {
    fn frame_bytes(&self) -> u32 {
        2 * self.channels
    }
}

static PCM: SpinIrq<PcmState> = SpinIrq::new(PcmState {
    rate: 48000,
    channels: 2,
    period_frames: 0,
    buffer_frames: 0,
    stream_id: 0,
    configured: false,
    started: false,
    start_ns: 0,
    appl_frames: 0,
    opens: 0,
});

pub fn pcm_open() {
    PCM.lock().opens += 1;
}

pub fn pcm_close() {
    let mut p = PCM.lock();
    p.opens = p.opens.saturating_sub(1);
    if p.opens == 0 {
        p.configured = false;
        p.started = false;
    }
}

fn hw_refine(arg: u64) -> i64 {
    let mut b = [0u8; 256];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let access = rd32(&b, HP_MASK_ACCESS) & ACCESS_RW_INTERLEAVED;
    let format = rd32(&b, HP_MASK_FORMAT) & FORMAT_S16_LE;
    let subformat = rd32(&b, HP_MASK_SUBFORMAT) & SUBFORMAT_STD;
    let rmask = rd32(&b, 160);
    wr32(&mut b, HP_MASK_ACCESS, access);
    wr32(&mut b, HP_MASK_FORMAT, format);
    wr32(&mut b, HP_MASK_SUBFORMAT, subformat);
    iv_clamp(&mut b, IV_CHANNELS, 1, 2);
    iv_clamp(&mut b, IV_RATE, RATE_MIN, RATE_MAX);
    iv_fix(&mut b, IV_SAMPLE_BITS, 16);
    wr32(&mut b, HP_CMASK, rmask);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }
    0
}

fn hw_params(arg: u64) -> i64 {
    if PCM.lock().opens > 1 {
        return EBUSY;
    }
    let mut b = [0u8; 256];
    if frame::user::copy_from_user(arg, &mut b).is_err() {
        return EFAULT;
    }
    let channels = iv_min(&b, IV_CHANNELS).clamp(1, 2);
    let req_rate = iv_min(&b, IV_RATE).clamp(RATE_MIN, RATE_MAX);
    let (rate, _) = crate::fs::devfs::nearest_supported_rate(req_rate);

    let frame_bytes = 2 * channels;
    let max_period_frames: u32 = 1 << 20;
    let max_buffer_bytes: u32 = 4 << 20;
    let max_buffer_frames = (max_buffer_bytes / frame_bytes).max(64);

    let period_frames = {
        let ps = iv_min(&b, IV_PERIOD_SIZE);
        if ps != 0 && ps != u32::MAX {
            ps
        } else {
            let pt = iv_min(&b, IV_PERIOD_TIME);
            if pt != 0 && pt != u32::MAX {
                ((pt as u64 * rate as u64) / 1_000_000) as u32
            } else {
                rate / 50
            }
        }
    }
    .clamp(64, max_period_frames);
    let buffer_frames = {
        let bs = iv_min(&b, IV_BUFFER_SIZE);
        let from_time = {
            let bt = iv_min(&b, IV_BUFFER_TIME);
            if bt != 0 && bt != u32::MAX {
                ((bt as u64 * rate as u64) / 1_000_000) as u32
            } else {
                0
            }
        };
        let want = bs.max(from_time).max(period_frames.saturating_mul(2));
        if want == 0 || want == u32::MAX {
            period_frames.saturating_mul(2)
        } else {
            want
        }
    }
    .clamp(period_frames, max_buffer_frames);
    let periods = (buffer_frames / period_frames).max(2);
    let buffer_frames = match period_frames.checked_mul(periods) {
        Some(v) if v <= max_buffer_frames => v,
        _ => return EINVAL,
    };
    let period_bytes = match period_frames.checked_mul(frame_bytes) {
        Some(v) => v,
        None => return EINVAL,
    };
    let buffer_bytes = match buffer_frames.checked_mul(frame_bytes) {
        Some(v) => v,
        None => return EINVAL,
    };

    wr32(&mut b, HP_MASK_ACCESS, ACCESS_RW_INTERLEAVED);
    wr32(&mut b, HP_MASK_FORMAT, FORMAT_S16_LE);
    wr32(&mut b, HP_MASK_SUBFORMAT, SUBFORMAT_STD);
    iv_fix(&mut b, IV_SAMPLE_BITS, 16);
    iv_fix(&mut b, IV_FRAME_BITS, 16 * channels);
    iv_fix(&mut b, IV_CHANNELS, channels);
    iv_fix(&mut b, IV_RATE, rate);
    iv_fix(&mut b, IV_PERIOD_SIZE, period_frames);
    iv_fix(&mut b, IV_PERIOD_BYTES, period_bytes);
    iv_fix(&mut b, IV_PERIODS, periods);
    iv_fix(&mut b, IV_BUFFER_SIZE, buffer_frames);
    iv_fix(&mut b, IV_BUFFER_BYTES, buffer_bytes);
    if frame::user::copy_to_user(arg, &b).is_err() {
        return EFAULT;
    }

    let mut pcm = PCM.lock();
    pcm.rate = rate;
    pcm.channels = channels;
    pcm.period_frames = period_frames;
    pcm.buffer_frames = buffer_frames;
    pcm.configured = true;
    0
}

fn pcm_prepare_ioctl() -> i64 {
    let streams = match ::virtio::sound_output_streams() {
        Ok(s) if !s.is_empty() => s,
        _ => return ENODEV,
    };
    let stream_id = streams[0];
    let (buffer_bytes, period_bytes, channels, rate_hz) = {
        let mut pcm = PCM.lock();
        if !pcm.configured {
            return EINVAL;
        }
        pcm.stream_id = stream_id;
        pcm.started = false;
        let fb = pcm.frame_bytes();
        (
            pcm.buffer_frames * fb,
            pcm.period_frames * fb,
            pcm.channels as u8,
            pcm.rate,
        )
    };
    let pcm_rate = crate::fs::devfs::nearest_supported_rate(rate_hz).1;
    if ::virtio::sound_pcm_set_params(
        stream_id,
        buffer_bytes,
        period_bytes,
        channels,
        ::virtio::sound::PcmFormat::S16,
        pcm_rate,
    )
    .is_err()
    {
        return EIO;
    }
    if ::virtio::sound_pcm_prepare(stream_id).is_err() {
        return EIO;
    }
    0
}

fn pcm_start_ioctl() -> i64 {
    let sid = {
        let p = PCM.lock();
        if !p.configured {
            return EINVAL;
        }
        p.stream_id
    };
    if ::virtio::sound_pcm_start(sid).is_err() {
        return EIO;
    }
    let mut p = PCM.lock();
    p.started = true;
    p.start_ns = frame::cpu::clock::nanos_since_boot();
    p.appl_frames = 0;
    0
}

fn pcm_writei(arg: u64) -> i64 {
    let mut x = [0u8; 24];
    if frame::user::copy_from_user(arg, &mut x).is_err() {
        return EFAULT;
    }
    let buf = u64::from_le_bytes(x[8..16].try_into().unwrap());
    let frames = u64::from_le_bytes(x[16..24].try_into().unwrap());
    let (sid, fb, started, configured) = {
        let p = PCM.lock();
        (p.stream_id, p.frame_bytes() as u64, p.started, p.configured)
    };
    if !configured {
        return EINVAL;
    }
    if frames == 0 {
        return 0;
    }
    let max_frames = (256 * 1024) / fb;
    let xfer_frames = frames.min(max_frames);
    let nbytes = (xfer_frames * fb) as usize;
    let mut data = alloc::vec![0u8; nbytes];
    if frame::user::copy_from_user(buf, &mut data).is_err() {
        return EFAULT;
    }
    if !started {
        let _ = ::virtio::sound_pcm_start(sid);
        let mut p = PCM.lock();
        p.started = true;
        p.start_ns = frame::cpu::clock::nanos_since_boot();
        p.appl_frames = 0;
    }

    let (rate, buffer_frames, start_ns, appl) = {
        let p = PCM.lock();
        (
            p.rate as u64,
            p.buffer_frames as u64,
            p.start_ns,
            p.appl_frames,
        )
    };
    if rate > 0 && buffer_frames > 0 {
        let now = frame::cpu::clock::nanos_since_boot();
        let played = ((now.saturating_sub(start_ns)) as u128 * rate as u128 / 1_000_000_000) as u64;
        let ahead = appl.saturating_sub(played);
        if ahead + xfer_frames > buffer_frames {
            let need_played = (appl + xfer_frames).saturating_sub(buffer_frames);
            let deadline = start_ns + (need_played as u128 * 1_000_000_000 / rate as u128) as u64;
            crate::core::sleep_until(deadline);
        }
    }

    let mut consumed;
    let mut waits = 0u32;
    loop {
        consumed = match ::virtio::sound_pcm_write(sid, &data) {
            Ok(n) => n,
            Err(_) => return EPIPE,
        };
        if consumed > 0 {
            break;
        }
        let (rate2, period_frames, buffer_frames2) = {
            let p = PCM.lock();
            (
                p.rate as u64,
                p.period_frames as u64,
                p.buffer_frames as u64,
            )
        };
        if rate2 == 0 || period_frames == 0 {
            return EPIPE;
        }
        if waits >= (buffer_frames2 / period_frames).max(2) as u32 + 2 {
            return EPIPE;
        }
        waits += 1;
        let now2 = frame::cpu::clock::nanos_since_boot();
        crate::core::sleep_until(
            now2 + (period_frames as u128 * 1_000_000_000 / rate2 as u128) as u64,
        );
    }
    let frames_done = (consumed as u64) / fb;
    PCM.lock().appl_frames += frames_done;
    let _ = frame::user::copy_to_user(arg, &(frames_done as i64).to_le_bytes());
    0
}

fn pcm_ioctl(cmd: u32, arg: u64) -> i64 {
    let (_dir, _size, _typ, nr) = decode(cmd);
    match nr {
        0x00 => {
            if frame::user::copy_to_user(arg, &SNDRV_PCM_VERSION.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        0x01 => {
            if frame::user::copy_to_user(arg, &build_pcm_info(0, 0, 0)).is_err() {
                return EFAULT;
            }
            0
        }
        0x10 => hw_refine(arg),
        0x11 => hw_params(arg),
        0x13 => 0,
        0x40 => pcm_prepare_ioctl(),
        0x42 => pcm_start_ioctl(),
        0x43 => {
            let sid = PCM.lock().stream_id;
            let _ = ::virtio::sound_pcm_stop(sid);
            PCM.lock().started = false;
            0
        }
        0x50 => pcm_writei(arg),
        _ => 0,
    }
}
