use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::io::qemu_exit;

static PANICKING: AtomicBool = AtomicBool::new(false);

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if PANICKING.swap(true, Ordering::SeqCst) {
        qemu_exit::exit(qemu_exit::ExitCode::Failed)
    }

    crate::println!("\nKERNEL PANIC: {info}");
    qemu_exit::exit(qemu_exit::ExitCode::Failed)
}
