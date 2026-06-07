#![no_std]
#![no_main]

use frame::{
    boot::parse_hvm_start_info,
    io::{
        qemu_exit::{ExitCode, exit},
        uart,
    },
    println,
};

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] ex_table: bringing up frame");

    let boot_info = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&boot_info) };

    let not_copied = frame::user::ex_table_fault_probe();
    println!(
        "[test] ex_table: fault probe returned not_copied={}",
        not_copied
    );
    assert_eq!(
        not_copied, 8,
        "exception fixup should report all 8 bytes uncopied after the fault"
    );

    println!("[test] ex_table: PASS");
    exit(ExitCode::Success)
}
