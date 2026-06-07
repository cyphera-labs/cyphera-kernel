#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(2);
}

static ARG0: &[u8] = b"/bin/proc_a\0";
static PATH: &[u8] = b"/bin/proc_a\0";

static mut VFORK_EXEC_SENTINEL: u32 = 0;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let argv: [*const u8; 2] = [ARG0.as_ptr(), core::ptr::null()];
    let envp: [*const u8; 1] = [core::ptr::null()];

    let pre0 = b"exec: vfork+execve test\n";
    sys_write(1, pre0.as_ptr(), pre0.len());
    unsafe { core::ptr::write_volatile(&raw mut VFORK_EXEC_SENTINEL, 0xABCD_1234) };
    let vf: i64;
    unsafe {
        asm!(
            "syscall",
            "test rax, rax",
            "jnz 3f",
            "mov rax, 59",
            "mov rdi, {path}",
            "mov rsi, {argv}",
            "mov rdx, {envp}",
            "syscall",
            "mov rax, 60",
            "mov rdi, 99",
            "syscall",
            "3:",
            in("rax") 58u64,
            path = in(reg) PATH.as_ptr(),
            argv = in(reg) argv.as_ptr(),
            envp = in(reg) envp.as_ptr(),
            lateout("rax") vf,
            lateout("rdi") _, lateout("rsi") _, lateout("rdx") _,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    if vf <= 0 {
        let m = b"exec: vfork failed\n";
        sys_write(1, m.as_ptr(), m.len());
        sys_exit(97);
    }
    if unsafe { core::ptr::read_volatile(&raw const VFORK_EXEC_SENTINEL) } != 0xABCD_1234 {
        let m = b"exec: parent AS corrupted by child vfork+execve\n";
        sys_write(1, m.as_ptr(), m.len());
        sys_exit(98);
    }
    let mut st: i32 = 0;
    sys_wait4(-1, &mut st as *mut i32, 0);
    let ok = b"exec: parent survived child vfork+execve OK\n";
    sys_write(1, ok.as_ptr(), ok.len());

    let pre = b"exec: pre-execve\n";
    sys_write(1, pre.as_ptr(), pre.len());

    let r = sys_execve(PATH.as_ptr(), argv.as_ptr(), envp.as_ptr());
    let m = b"exec: execve returned (failure)\n";
    sys_write(1, m.as_ptr(), m.len());
    sys_exit(if r < 0 { (-r) as i32 } else { 1 })
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 59u64,
            in("rdi") path,
            in("rsi") argv,
            in("rdx") envp,
            lateout("rax") r,
            out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_wait4(pid: i64, status: *mut i32, options: i32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 61u64, in("rdi") pid, in("rsi") status, in("rdx") options as i64,
            in("r10") 0u64,
            lateout("rax") r, out("rcx") _, out("r11") _,
            options(nostack),
        );
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
