#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use frame::{boot::parse_hvm_start_info, io::uart, println};

const SAMPLE_RATE_HZ: u32 = 44100;
const CHANNELS: u8 = 2;
const AMPLITUDE: i16 = 9000;
const ATTACK_MS: u32 = 10;
const RELEASE_MS: u32 = 30;

const E2: u32 = 8241;
const G2: u32 = 9800;
const A2: u32 = 11000;
const B2: u32 = 12347;

const RIFF: &[(u32, u32)] = &[
    (E2, 280),
    (E2, 280),
    (G2, 280),
    (E2, 280),
    (A2, 280),
    (E2, 280),
    (G2, 280),
    (A2, 420),
    (0, 120),
    (E2, 1400),
];
const FIFTH_MULT_NUM: u32 = 3;
const FIFTH_MULT_DEN: u32 = 2;
const ROOT_AMP_NUM: u32 = 10;
const FIFTH_AMP_NUM: u32 = 7;
const OCTAVE_AMP_NUM: u32 = 5;
const VOICE_AMP_DEN: u32 = 10 + 7 + 5;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[demo] sound_demo: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    virtio::init();

    let outputs = virtio::sound_output_streams().expect("enumerate output streams");
    let stream_id = *outputs.first().expect("device has no playback streams");
    println!(
        "[demo] sound_demo: stream_id={} — playing power-chord riff",
        stream_id
    );

    let _ = (B2,);

    let mut pcm: Vec<u8> = Vec::new();
    for (i, (root_centihz, dur_ms)) in RIFF.iter().enumerate() {
        if *root_centihz == 0 {
            append_silence(&mut pcm, SAMPLE_RATE_HZ, CHANNELS, *dur_ms);
        } else {
            append_power_chord(
                &mut pcm,
                SAMPLE_RATE_HZ,
                CHANNELS,
                *root_centihz,
                *dur_ms,
                AMPLITUDE,
            );
        }
        println!("[demo] note {}: root={}cHz × {}ms", i, root_centihz, dur_ms);
    }
    println!("[demo] sound_demo: pcm bytes = {}", pcm.len());

    virtio::sound_play_blocking(
        stream_id,
        CHANNELS,
        virtio::sound::PcmFormat::S16,
        virtio::sound::PcmRate::Rate44100,
        &pcm,
    )
    .expect("pcm playback failed");

    println!("[demo] sound_demo: PASS");
    frame::io::qemu_exit::exit(frame::io::qemu_exit::ExitCode::Success)
}

fn append_power_chord(
    out: &mut Vec<u8>,
    rate: u32,
    channels: u8,
    root_centihz: u32,
    dur_ms: u32,
    amp: i16,
) {
    let total_frames = (rate as u64 * dur_ms as u64 / 1000) as u32;
    if total_frames == 0 {
        return;
    }
    let attack_frames = (rate as u64 * ATTACK_MS as u64 / 1000) as u32;
    let release_frames = (rate as u64 * RELEASE_MS as u64 / 1000) as u32;

    let root_step = phase_step(rate, root_centihz);
    let fifth_step = phase_step(rate, root_centihz * FIFTH_MULT_NUM / FIFTH_MULT_DEN);
    let octave_step = phase_step(rate, root_centihz * 2);

    let mut root_phase: u32 = 0;
    let mut fifth_phase: u32 = 0;
    let mut octave_phase: u32 = 0;

    for n in 0..total_frames {
        let root = SINE_TABLE[(root_phase as usize) & (SINE_TABLE_LEN - 1)] as i32;
        let fifth = SINE_TABLE[(fifth_phase as usize) & (SINE_TABLE_LEN - 1)] as i32;
        let octave = SINE_TABLE[(octave_phase as usize) & (SINE_TABLE_LEN - 1)] as i32;
        let mixed = (root * ROOT_AMP_NUM as i32
            + fifth * FIFTH_AMP_NUM as i32
            + octave * OCTAVE_AMP_NUM as i32)
            / VOICE_AMP_DEN as i32;
        let scaled = mixed * amp as i32 / 32767;
        let env_num: i32 = if n < attack_frames {
            (n + 1) as i32
        } else if total_frames > release_frames && n >= total_frames - release_frames {
            (total_frames - n) as i32
        } else {
            attack_frames.max(1) as i32
        };
        let env_den: i32 = attack_frames.max(1) as i32;
        let s_clipped = (scaled * env_num.min(env_den) / env_den).clamp(-32768, 32767) as i16;
        let lo = s_clipped as u8;
        let hi = (s_clipped >> 8) as u8;
        for _ in 0..channels {
            out.push(lo);
            out.push(hi);
        }
        root_phase = root_phase.wrapping_add(root_step);
        fifth_phase = fifth_phase.wrapping_add(fifth_step);
        octave_phase = octave_phase.wrapping_add(octave_step);
    }
}

fn append_silence(out: &mut Vec<u8>, rate: u32, channels: u8, dur_ms: u32) {
    let total_frames = (rate as u64 * dur_ms as u64 / 1000) as u32;
    for _ in 0..total_frames {
        for _ in 0..channels {
            out.push(0);
            out.push(0);
        }
    }
}

fn phase_step(rate: u32, freq_centihz: u32) -> u32 {
    ((freq_centihz as u64 * SINE_TABLE_LEN as u64) / (rate as u64 * 100)) as u32
}

const SINE_TABLE_LEN: usize = 1024;
include!(concat!(env!("OUT_DIR"), "/sine_table.rs"));
