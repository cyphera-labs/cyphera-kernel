#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use frame::{
    boot::parse_hvm_start_info,
    io::{
        qemu_exit::{ExitCode, exit},
        uart,
    },
    println,
};

fn build_elf(interp: Option<&[u8]>) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
    b.extend_from_slice(&[0u8; 8]);
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&62u16.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&0x1000u64.to_le_bytes());
    b.extend_from_slice(&64u64.to_le_bytes());
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&64u16.to_le_bytes());
    b.extend_from_slice(&56u16.to_le_bytes());
    b.extend_from_slice(&(if interp.is_some() { 1u16 } else { 0u16 }).to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    debug_assert_eq!(b.len(), 64);
    if let Some(path) = interp {
        let str_off = 64u64 + 56u64;
        let sz = (path.len() + 1) as u64;
        b.extend_from_slice(&3u32.to_le_bytes());
        b.extend_from_slice(&4u32.to_le_bytes());
        b.extend_from_slice(&str_off.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&sz.to_le_bytes());
        b.extend_from_slice(&sz.to_le_bytes());
        b.extend_from_slice(&1u64.to_le_bytes());
        debug_assert_eq!(b.len() as u64, str_off);
        b.extend_from_slice(path);
        b.push(0);
    }
    b
}

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] exec_interp: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };
    kernel::init();

    const MISSING: &[u8] = b"/nonexistent/ld-cyphera.so";

    let elf = build_elf(Some(MISSING));
    let got = kernel::elf::interp_path(&elf);
    assert_eq!(
        got.as_deref(),
        Some("/nonexistent/ld-cyphera.so"),
        "interp_path must extract the PT_INTERP loader path"
    );

    let ctx = kernel::vfs::path::Context::global();
    assert!(
        kernel::vfs::path::resolve(&ctx, &ctx.root, "/nonexistent/ld-cyphera.so").is_err(),
        "a missing interpreter must not resolve"
    );

    assert!(
        kernel::vfs::path::resolve(&ctx, &ctx.root, "/dev").is_ok(),
        "/dev should resolve"
    );
    assert_eq!(
        kernel::elf::interp_path(&build_elf(None)),
        None,
        "a static image has no PT_INTERP"
    );

    println!("[test] exec_interp: PASS");
    exit(ExitCode::Success)
}
