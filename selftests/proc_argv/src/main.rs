#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

#[unsafe(naked)]
#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp+8]",
        "call {main}",
        main = sym rust_main,
    )
}

extern "C" fn rust_main(argc: u64, argv: *const *const u8) -> ! {
    let mut buf = [0u8; 32];
    let mut n = 0;
    n += put_bytes(&mut buf[n..], b"argc=");
    n += put_dec(&mut buf[n..], argc);
    n += put_bytes(&mut buf[n..], b"\n");
    sys_write(1, buf.as_ptr(), n);

    for i in 0..argc {
        let str_ptr = unsafe { *argv.add(i as usize) };
        if str_ptr.is_null() {
            break;
        }
        let mut hbuf = [0u8; 32];
        let mut hn = 0;
        hn += put_bytes(&mut hbuf[hn..], b"argv[");
        hn += put_dec(&mut hbuf[hn..], i);
        hn += put_bytes(&mut hbuf[hn..], b"]=");
        sys_write(1, hbuf.as_ptr(), hn);

        let len = strlen(str_ptr);
        sys_write(1, str_ptr, len);
        sys_write(1, b"\n".as_ptr(), 1);
    }

    sys_exit(0)
}

fn strlen(p: *const u8) -> usize {
    let mut n = 0usize;
    loop {
        let b = unsafe { *p.add(n) };
        if b == 0 {
            return n;
        }
        n += 1;
        if n > 4096 {
            return n;
        }
    }
}

fn put_bytes(out: &mut [u8], s: &[u8]) -> usize {
    let n = s.len().min(out.len());
    out[..n].copy_from_slice(&s[..n]);
    n
}

fn put_dec(out: &mut [u8], mut v: u64) -> usize {
    let mut tmp = [0u8; 20];
    let mut t = 0;
    if v == 0 {
        tmp[t] = b'0';
        t += 1;
    } else {
        while v > 0 {
            tmp[t] = b'0' + (v % 10) as u8;
            v /= 10;
            t += 1;
        }
    }
    let mut n = 0;
    while t > 0 && n < out.len() {
        t -= 1;
        out[n] = tmp[t];
        n += 1;
    }
    n
}

fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 1u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
