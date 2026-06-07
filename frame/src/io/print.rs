use core::fmt::Write;

#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    let _ = crate::io::uart::UART.lock().write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::io::print::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
