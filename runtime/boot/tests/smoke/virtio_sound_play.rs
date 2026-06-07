#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use frame::{boot::parse_hvm_start_info, io::uart, println};

const SAMPLE_RATE_HZ: u32 = 44100;
const CHANNELS: u8 = 2;
const TONE_HZ: u32 = 440;
const DURATION_MS: u32 = 1000;
const AMPLITUDE: i16 = 8000;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] virtio_sound_play: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    println!("[test] virtio_sound_play: probing virtio-mmio bus");
    virtio::init();

    let (jacks, streams, chmaps) =
        virtio::sound_topology().expect("virtio-sound device not detected on the mmio bus");
    println!(
        "[test] virtio_sound_play: jacks={} streams={} chmaps={}",
        jacks, streams, chmaps
    );

    let outputs = virtio::sound_output_streams().expect("enumerate output streams");
    let stream_id = *outputs.first().expect("device has no playback streams");
    println!(
        "[test] virtio_sound_play: stream_id={} channels={} rate={}Hz tone={}Hz duration={}ms",
        stream_id, CHANNELS, SAMPLE_RATE_HZ, TONE_HZ, DURATION_MS
    );

    let pcm = sine_pcm(SAMPLE_RATE_HZ, CHANNELS, TONE_HZ, DURATION_MS, AMPLITUDE);
    println!("[test] virtio_sound_play: pcm bytes = {}", pcm.len());

    virtio::sound_play_blocking(
        stream_id,
        CHANNELS,
        virtio::sound::PcmFormat::S16,
        virtio::sound::PcmRate::Rate44100,
        &pcm,
    )
    .expect("pcm playback failed");

    println!("[test] virtio_sound_play: PASS");
    frame::io::qemu_exit::exit(frame::io::qemu_exit::ExitCode::Success)
}

fn sine_pcm(rate: u32, channels: u8, tone_hz: u32, duration_ms: u32, amp: i16) -> Vec<u8> {
    let total_frames = rate as u64 * duration_ms as u64 / 1000;
    let mut out = Vec::with_capacity(total_frames as usize * channels as usize * 2);
    let phase_step = (tone_hz as u64 * SINE_TABLE_LEN as u64 / rate as u64) as u32;
    let mut phase: u32 = 0;
    for _ in 0..total_frames {
        let idx = (phase as usize) & (SINE_TABLE_LEN - 1);
        let s = ((SINE_TABLE[idx] as i32) * (amp as i32) / 32767) as i16;
        let lo = s as u8;
        let hi = (s >> 8) as u8;
        for _ in 0..channels {
            out.push(lo);
            out.push(hi);
        }
        phase = phase.wrapping_add(phase_step);
    }
    out
}

const SINE_TABLE_LEN: usize = 1024;

include!(concat!(env!("OUT_DIR"), "/sine_table.rs"));
