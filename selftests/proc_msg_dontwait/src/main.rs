#![no_std]
#![no_main]

use core::arch::asm;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    sys_exit(99);
}

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const MSG_DONTWAIT: u64 = 0x40;
const EAGAIN: i64 = -11;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("msg_dontwait test starting\n");

    let mut sp = [0i32; 2];
    if sys_socketpair(AF_UNIX, SOCK_STREAM, 0, sp.as_mut_ptr()) != 0 {
        log("socketpair STREAM failed\n");
        sys_exit(1);
    }
    let r = recvmsg_one(sp[0] as u64, MSG_DONTWAIT);
    if r != EAGAIN {
        log("recvmsg(MSG_DONTWAIT) on empty did not return EAGAIN\n");
        sys_exit(2);
    }
    if sys_write(sp[1] as u64, b"x".as_ptr(), 1) != 1 {
        log("write to peer failed\n");
        sys_exit(3);
    }
    let mut got = 0u8;
    let r = recvmsg_into(sp[0] as u64, MSG_DONTWAIT, &mut got);
    if r != 1 || got != b'x' {
        log("recvmsg(MSG_DONTWAIT) did not return buffered byte\n");
        sys_exit(4);
    }
    log("msg_dontwait: recvmsg EAGAIN-then-data ok\n");

    let udp = sys_socket(AF_INET, SOCK_DGRAM, 0);
    if udp < 0 {
        log("socket(AF_INET, SOCK_DGRAM) failed\n");
        sys_exit(5);
    }
    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    sa[2..4].copy_from_slice(&0u16.to_be_bytes());
    sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
    if sys_bind(udp as u64, sa.as_ptr(), 16) != 0 {
        log("bind UDP failed\n");
        sys_exit(6);
    }
    let mut buf = [0u8; 8];
    let r = sys_recvfrom(udp as u64, buf.as_mut_ptr(), buf.len(), MSG_DONTWAIT, 0, 0);
    if r != EAGAIN {
        log("recvfrom(MSG_DONTWAIT) on empty did not return EAGAIN\n");
        sys_exit(7);
    }
    log("msg_dontwait: recvfrom EAGAIN ok\n");

    let mut sp2 = [0i32; 2];
    if sys_socketpair(AF_UNIX, SOCK_STREAM, 0, sp2.as_mut_ptr()) != 0 {
        log("socketpair STREAM #2 failed\n");
        sys_exit(8);
    }
    let filler = [0u8; 1024];
    let mut guard = 0;
    loop {
        let r = sendmsg_msg(sp2[1] as u64, MSG_DONTWAIT, &filler, -1);
        if r == EAGAIN {
            break;
        }
        if r < 0 {
            log("fill sendmsg unexpected error\n");
            sys_exit(9);
        }
        guard += 1;
        if guard > 100000 {
            log("send buffer never filled\n");
            sys_exit(10);
        }
    }
    let r = sendmsg_msg(sp2[1] as u64, MSG_DONTWAIT, b"z", 1);
    if r != EAGAIN {
        log("sendmsg(SCM_RIGHTS, MSG_DONTWAIT) on full buffer did not EAGAIN\n");
        sys_exit(11);
    }
    log("msg_dontwait: SCM_RIGHTS sendmsg EAGAIN ok\n");

    log("MSG_DONTWAIT_OK\n");
    sys_exit(0);
}

const SCM_SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;

fn sendmsg_msg(fd: u64, flags: u64, payload: &[u8], pass_fd: i32) -> i64 {
    let mut iov = [0u8; 16];
    iov[0..8].copy_from_slice(&(payload.as_ptr() as u64).to_le_bytes());
    iov[8..16].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    let mut mh = [0u8; 56];
    mh[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_le_bytes());
    mh[24..32].copy_from_slice(&1u64.to_le_bytes());
    let mut ctrl = [0u8; 20];
    if pass_fd >= 0 {
        ctrl[0..8].copy_from_slice(&20u64.to_le_bytes());
        ctrl[8..12].copy_from_slice(&SCM_SOL_SOCKET.to_le_bytes());
        ctrl[12..16].copy_from_slice(&SCM_RIGHTS.to_le_bytes());
        ctrl[16..20].copy_from_slice(&pass_fd.to_le_bytes());
        mh[32..40].copy_from_slice(&(ctrl.as_ptr() as u64).to_le_bytes());
        mh[40..48].copy_from_slice(&20u64.to_le_bytes());
    }
    sys_sendmsg(fd, mh.as_ptr() as u64, flags)
}

#[inline(never)]
fn sys_sendmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 46u64, in("rdi") fd, in("rsi") msg, in("rdx") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

fn recvmsg_into(fd: u64, flags: u64, out: &mut u8) -> i64 {
    let buf = out as *mut u8;
    let mut iov = [0u8; 16];
    iov[0..8].copy_from_slice(&(buf as u64).to_le_bytes());
    iov[8..16].copy_from_slice(&1u64.to_le_bytes());
    let mut mh = [0u8; 56];
    mh[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_le_bytes());
    mh[24..32].copy_from_slice(&1u64.to_le_bytes());
    sys_recvmsg(fd, mh.as_ptr() as u64, flags)
}

fn recvmsg_one(fd: u64, flags: u64) -> i64 {
    let mut sink = 0u8;
    recvmsg_into(fd, flags, &mut sink)
}

#[inline(never)]
fn sys_socketpair(domain: u64, ty: u64, proto: u64, sv: *mut i32) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 53u64, in("rdi") domain, in("rsi") ty, in("rdx") proto, in("r10") sv,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_recvmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 47u64, in("rdi") fd, in("rsi") msg, in("rdx") flags,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_recvfrom(fd: u64, buf: *mut u8, len: usize, flags: u64, addr: u64, alen: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 45u64, in("rdi") fd, in("rsi") buf, in("rdx") len,
            in("r10") flags, in("r8") addr, in("r9") alen,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_socket(domain: u64, ty: u64, proto: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 41u64, in("rdi") domain, in("rsi") ty, in("rdx") proto,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_bind(fd: u64, addr: *const u8, alen: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 49u64, in("rdi") fd, in("rsi") addr, in("rdx") alen,
            lateout("rax") r, out("rcx") _, out("r11") _, options(nostack),
        );
    }
    r
}

#[inline(never)]
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

fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60u64, in("rdi") code as u64, options(noreturn, nostack));
    }
}
