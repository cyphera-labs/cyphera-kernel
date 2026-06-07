#![no_std]
#![no_main]

use core::arch::asm;

const SYS_WRITE: u64 = 1;
const SYS_OPEN: u64 = 2;
const SYS_IOCTL: u64 = 16;
const SYS_EXIT: u64 = 60;

const O_WRONLY: i64 = 0o1;

const SNDCTL_DSP_SETFMT_SIGN_EXTENDED: u64 = 0xFFFFFFFF_C0045005;
const AFMT_S16_LE: u32 = 0x10;

unsafe fn syscall3(nr: u64, a: u64, b: u64, c: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        in("rdi") a, in("rsi") b, in("rdx") c,
        lateout("rcx") _, lateout("r11") _,
    );
    ret
}

fn open(path: &[u8], flags: i64) -> i64 {
    let mut buf = [0u8; 64];
    buf[..path.len()].copy_from_slice(path);
    unsafe { syscall3(SYS_OPEN, buf.as_ptr() as u64, flags as u64, 0) }
}

fn write_stdout(s: &[u8]) {
    unsafe { syscall3(SYS_WRITE, 1, s.as_ptr() as u64, s.len() as u64) };
}

fn exit(code: i32) -> ! {
    unsafe { syscall3(SYS_EXIT, code as u64, 0, 0) };
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(99);
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    write_stdout(b"proc_ioctl_oss: opening /dev/dsp\n");
    let fd = open(b"/dev/dsp\0", O_WRONLY);
    if fd < 0 {
        write_stdout(b"proc_ioctl_oss: FAIL: open(/dev/dsp) returned negative\n");
        exit(1);
    }

    let mut format: u32 = AFMT_S16_LE;
    let rc = unsafe {
        syscall3(
            SYS_IOCTL,
            fd as u64,
            SNDCTL_DSP_SETFMT_SIGN_EXTENDED,
            &mut format as *mut u32 as u64,
        )
    };
    if rc < 0 {
        write_stdout(b"proc_ioctl_oss: FAIL: ioctl returned negative (sign-extension bug?)\n");
        exit(2);
    }
    if format != AFMT_S16_LE {
        write_stdout(b"proc_ioctl_oss: FAIL: format not echoed back\n");
        exit(3);
    }
    write_stdout(b"proc_ioctl_oss: PASS\n");
    exit(0);
}
