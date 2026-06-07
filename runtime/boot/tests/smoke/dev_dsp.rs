#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;

use frame::{boot::parse_hvm_start_info, io::uart, println};

const SAMPLE_RATE_HZ: u32 = 44100;
const CHANNELS: u8 = 2;
const TONE_HZ: u32 = 880;
const DURATION_MS: u32 = 500;
const AMPLITUDE: i16 = 9000;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] dev_dsp: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };
    kernel::init();

    println!("[test] dev_dsp: resolving /dev/dsp");
    let root = kernel::vfs::root_inode();
    let dev = root.lookup("dev").expect("/dev exists");
    let dsp = dev.lookup("dsp").expect("/dev/dsp exists");
    assert_eq!(dsp.kind(), kernel::vfs::InodeKind::CharDevice);
    let id = dsp.inode_id();
    assert!(
        id & kernel::fs::devfs::DSP_INODE_BIT != 0,
        "DSP_INODE_BIT not set on /dev/dsp inode_id"
    );
    println!("[test] dev_dsp: inode_id={:#x} (bit 61 set)", id);

    println!(
        "[test] dev_dsp: writing {}ms × {}Hz tone @ {}Hz/{}ch",
        DURATION_MS, TONE_HZ, SAMPLE_RATE_HZ, CHANNELS
    );
    let pcm = sine_pcm(SAMPLE_RATE_HZ, CHANNELS, TONE_HZ, DURATION_MS, AMPLITUDE);
    println!("[test] dev_dsp: pcm bytes = {}", pcm.len());

    let n = dsp.write_at(0, &pcm).expect("dsp.write_at failed");
    assert_eq!(n, pcm.len(), "short write: {} != {}", n, pcm.len());

    println!("[test] dev_dsp: PASS");
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
