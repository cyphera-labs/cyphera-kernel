#![no_std]
#![no_main]

use frame::{
    io::{
        qemu_exit::{ExitCode, exit},
        uart,
    },
    println,
};

#[no_mangle]
pub extern "C" fn kernel_main(_boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] boot_smoke: kernel reached long mode and UART");

    #[allow(clippy::eq_op)]
    {
        assert_eq!(2 + 2, 4);
    }

    println!("[test] boot_smoke: PASS");
    exit(ExitCode::Success)
}
