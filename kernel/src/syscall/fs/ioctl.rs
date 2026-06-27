use super::*;

const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSW: u64 = 0x5403;
const TCSETSF: u64 = 0x5404;
const TIOCGPGRP: u64 = 0x540F;
const TIOCSPGRP: u64 = 0x5410;
const TIOCSCTTY: u64 = 0x540E;
const TIOCNOTTY: u64 = 0x5422;
const TIOCGSID: u64 = 0x5429;

const TCFLSH: u64 = 0x540B;
const TCXONC: u64 = 0x540A;
const TCSBRK: u64 = 0x5409;

const TIOCGPTN: u64 = 0x80045430;
const TIOCSPTLCK: u64 = 0x40045431;
const FBIOGET_VSCREENINFO: u64 = 0x4600;
const FBIOPUT_VSCREENINFO: u64 = 0x4601;
const FBIOGET_FSCREENINFO: u64 = 0x4602;
const KDGKBTYPE: u64 = 0x4B33;
const KDGKBMODE: u64 = 0x4B44;
const KDSKBMODE: u64 = 0x4B45;
const KDGETLED: u64 = 0x4B31;
const KDSETLED: u64 = 0x4B32;
const KB_101: u8 = 0x02;

const SNDCTL_DSP_RESET: u64 = 0x0000_5000;
const SNDCTL_DSP_SYNC: u64 = 0x0000_5001;
const SNDCTL_DSP_SPEED: u64 = 0xC004_5002;
const SNDCTL_DSP_STEREO: u64 = 0xC004_5003;
const SNDCTL_DSP_GETBLKSIZE: u64 = 0xC004_5004;
const SNDCTL_DSP_SETFMT: u64 = 0xC004_5005;
const SNDCTL_DSP_CHANNELS: u64 = 0xC004_5006;
const SNDCTL_DSP_GETFMTS: u64 = 0x8004_500B;
const SNDCTL_DSP_GETOSPACE: u64 = 0x8010_500C;
const SNDCTL_DSP_SETFRAGMENT: u64 = 0xC004_500A;

use crate::errno::ENOTTY;

pub(crate) const DEFAULT_TERMIOS: [u8; 36] = {
    let mut t = [0u8; 36];
    t[0] = 0x00;
    t[1] = 0x05;
    t[2] = 0x00;
    t[3] = 0x00;
    t[4] = 0x05;
    t[5] = 0x00;
    t[6] = 0x00;
    t[7] = 0x00;
    t[8] = 0xbd;
    t[9] = 0x0b;
    t[10] = 0x00;
    t[11] = 0x00;
    t[12] = 0x8b;
    t[13] = 0x00;
    t[14] = 0x00;
    t[15] = 0x00;
    t
};

fn termios_get(inode_id: u64) -> [u8; 36] {
    crate::core::tty::termios_get(inode_id)
}

fn termios_set(inode_id: u64, t: [u8; 36]) {
    crate::core::tty::termios_set(inode_id, t);
}

pub fn termios_get_pub(inode_id: u64) -> [u8; 36] {
    termios_get(inode_id)
}

fn winsize_get(inode_id: u64) -> [u8; 8] {
    crate::core::tty::winsize_get(inode_id)
}

fn winsize_set(inode_id: u64, w: [u8; 8]) {
    crate::core::tty::winsize_set(inode_id, w);
}

pub(crate) fn sys_ioctl(fd: u64, cmd: u64, arg: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let is_tty = file.inode.kind() == InodeKind::CharDevice;
    let cmd = cmd & 0xFFFF_FFFF;
    if file.inode.is_drm_card() && (cmd >> 8) & 0xff == 0x64 {
        return crate::device::drm::ioctl(cmd as u32, arg);
    }
    if file.inode.is_drm_render() && (cmd >> 8) & 0xff == 0x64 {
        return crate::device::virtgpu::ioctl(cmd as u32, arg);
    }
    if let Some(kind) = file.inode.alsa_kind() {
        return crate::device::snd::ioctl(kind, cmd as u32, arg);
    }
    if let Some(idx) = file.inode.evdev_idx() {
        return crate::device::input::evdev_ioctl(idx, cmd as u32, arg);
    }
    match cmd {
        TIOCGWINSZ => {
            if !is_tty {
                return ENOTTY;
            }
            let buf = winsize_get(file.inode.inode_id());
            if frame::user::copy_to_user(arg, &buf).is_err() {
                return EFAULT;
            }
            0
        }
        TIOCSWINSZ => {
            if !is_tty {
                return ENOTTY;
            }
            let mut buf = [0u8; 8];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            winsize_set(file.inode.inode_id(), buf);
            0
        }
        TCGETS => {
            if !is_tty {
                return ENOTTY;
            }
            let t = termios_get(file.inode.inode_id());
            if frame::user::copy_to_user(arg, &t).is_err() {
                return EFAULT;
            }
            0
        }
        TCSETS | TCSETSW | TCSETSF => {
            if !is_tty {
                return ENOTTY;
            }
            let mut buf = [0u8; 36];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            if let Err(e) = crate::core::tty::background_write_guard(file.inode.inode_id()) {
                return e.as_neg_i64();
            }
            if cmd == TCSETSF {
                flush_tty_input(file.inode.inode_id());
            }
            termios_set(file.inode.inode_id(), buf);
            0
        }
        TIOCGPGRP => {
            if !is_tty {
                return ENOTTY;
            }
            let tty = crate::core::tty::tty_id_for_inode(file.inode.inode_id());
            let fg = crate::core::tty::foreground_pgrp(tty);
            let host_pgid = if fg.0 != 0 { fg } else { sched::current_pgid() };
            let pgid = sched::host_to_caller_local(host_pgid);
            if frame::user::copy_to_user(arg, &pgid.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        TIOCSPGRP => {
            if !is_tty {
                return ENOTTY;
            }
            let mut buf = [0u8; 4];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            if let Err(e) = crate::core::tty::background_write_guard(file.inode.inode_id()) {
                return e.as_neg_i64();
            }
            let pgrp_local = u32::from_le_bytes(buf);
            let pgrp_host = sched::caller_local_to_host(pgrp_local)
                .map(|p| p.0)
                .unwrap_or(pgrp_local);
            let tty = crate::core::tty::tty_id_for_inode(file.inode.inode_id());
            let my_sid = sched::current_sid();
            match crate::core::tty::set_foreground(
                tty,
                my_sid,
                crate::process_model::Pid(pgrp_host),
            ) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        TIOCSCTTY => {
            if !is_tty {
                return ENOTTY;
            }
            let pid = sched::current_pid();
            let my_sid = sched::current_sid();
            if my_sid != pid {
                return EPERM;
            }
            let tty = crate::core::tty::tty_id_for_inode(file.inode.inode_id());
            match crate::core::tty::acquire(tty, my_sid, sched::current_pgid()) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        TIOCNOTTY => {
            if !is_tty {
                return ENOTTY;
            }
            let tty = crate::core::tty::tty_id_for_inode(file.inode.inode_id());
            if crate::core::tty::session(tty) == sched::current_sid() {
                crate::core::tty::drop_session(tty);
            }
            0
        }
        TIOCGSID => {
            if !is_tty {
                return ENOTTY;
            }
            let tty = crate::core::tty::tty_id_for_inode(file.inode.inode_id());
            let sid = crate::core::tty::session(tty);
            if sid.0 == 0 {
                return ENOTTY;
            }
            let local = sched::host_to_caller_local(sid);
            if frame::user::copy_to_user(arg, &local.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        TIOCGPTN => {
            if !is_tty {
                return ENOTTY;
            }
            let id = file.inode.inode_id();
            const MASTER_BIT: u64 = 1u64 << 62;
            if id & MASTER_BIT == 0 {
                return ENOTTY;
            }
            let n = (id & !(MASTER_BIT)) as u32;
            if frame::user::copy_to_user(arg, &n.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        TIOCSPTLCK => {
            if !is_tty {
                return ENOTTY;
            }
            0
        }
        TCFLSH => {
            if !is_tty {
                return ENOTTY;
            }
            const TCIFLUSH: u64 = 0;
            const TCOFLUSH: u64 = 1;
            const TCIOFLUSH: u64 = 2;
            if arg == TCIFLUSH || arg == TCIOFLUSH {
                flush_tty_input(file.inode.inode_id());
            }
            if arg == TCOFLUSH || arg == TCIOFLUSH {
                flush_tty_output(file.inode.inode_id());
            }
            0
        }
        TCXONC => {
            if !is_tty {
                return ENOTTY;
            }
            0
        }
        TCSBRK => {
            if !is_tty {
                return ENOTTY;
            }
            0
        }
        FBIOGET_VSCREENINFO => {
            let (_ptr, _len, w, h) = match virtio::framebuffer_info() {
                Some(i) => i,
                None => return ENOTTY,
            };
            let buf = fb_var_screeninfo(w, h);
            if frame::user::copy_to_user(arg, &buf).is_err() {
                return EFAULT;
            }
            0
        }
        FBIOPUT_VSCREENINFO => {
            if virtio::framebuffer_info().is_none() {
                return ENOTTY;
            }
            0
        }
        FBIOGET_FSCREENINFO => {
            let (ptr, len, w, _h) = match virtio::framebuffer_info() {
                Some(i) => i,
                None => return ENOTTY,
            };
            let buf = fb_fix_screeninfo(ptr, len, w);
            if frame::user::copy_to_user(arg, &buf).is_err() {
                return EFAULT;
            }
            0
        }
        KDGKBTYPE => {
            if !is_tty {
                return ENOTTY;
            }
            if frame::user::copy_to_user(arg, &[KB_101]).is_err() {
                return EFAULT;
            }
            0
        }
        KDGKBMODE => {
            if !is_tty {
                return ENOTTY;
            }
            let mode = crate::console::kbd_mode_get();
            if frame::user::copy_to_user(arg, &mode.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        KDSKBMODE => {
            if !is_tty {
                return ENOTTY;
            }
            crate::console::kbd_mode_set(arg as u32);
            0
        }
        KDGETLED => {
            if !is_tty {
                return ENOTTY;
            }
            if frame::user::copy_to_user(arg, &[0u8]).is_err() {
                return EFAULT;
            }
            0
        }
        KDSETLED => {
            if !is_tty {
                return ENOTTY;
            }
            0
        }
        SNDCTL_DSP_SETFMT
        | SNDCTL_DSP_CHANNELS
        | SNDCTL_DSP_SPEED
        | SNDCTL_DSP_GETOSPACE
        | SNDCTL_DSP_GETFMTS
        | SNDCTL_DSP_GETBLKSIZE
        | SNDCTL_DSP_SETFRAGMENT
        | SNDCTL_DSP_STEREO
        | SNDCTL_DSP_SYNC
        | SNDCTL_DSP_RESET => {
            if file.inode.inode_id() & crate::fs::devfs::DSP_INODE_BIT == 0 {
                return ENOTTY;
            }
            do_dsp_ioctl(cmd, arg)
        }
        _ => ENOTTY,
    }
}

fn flush_tty_input(inode_id: u64) {
    match crate::core::tty::tty_id_for_inode(inode_id) {
        crate::core::tty::TtyId::Pty(n) => crate::device::pty::flush_input(n),
        crate::core::tty::TtyId::Console => crate::console::flush_input(),
    }
}

fn flush_tty_output(inode_id: u64) {
    match crate::core::tty::tty_id_for_inode(inode_id) {
        crate::core::tty::TtyId::Pty(n) => crate::device::pty::flush_output(n),
        crate::core::tty::TtyId::Console => crate::console::flush_output(),
    }
}

fn do_dsp_ioctl(cmd: u64, arg: u64) -> i64 {
    use crate::fs::devfs::{
        AFMT_QUERY, AFMT_S8, AFMT_S16_LE, AFMT_U8, AFMT_U16_LE, DSP_CHANNELS, DSP_FORMAT, DSP_RATE,
        nearest_supported_rate,
    };
    use core::sync::atomic::Ordering;
    match cmd {
        SNDCTL_DSP_SETFMT => {
            let mut buf = [0u8; 4];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            let req = u32::from_le_bytes(buf);
            let chosen = match req {
                AFMT_QUERY => DSP_FORMAT.load(Ordering::Relaxed),
                AFMT_S16_LE | AFMT_U16_LE | AFMT_S8 | AFMT_U8 => req,
                _ => AFMT_S16_LE,
            };
            DSP_FORMAT.store(chosen, Ordering::Relaxed);
            if frame::user::copy_to_user(arg, &chosen.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_CHANNELS => {
            let mut buf = [0u8; 4];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            let req = u32::from_le_bytes(buf);
            let chosen = if req == 1 || req == 2 { req } else { 2 };
            DSP_CHANNELS.store(chosen, Ordering::Relaxed);
            if frame::user::copy_to_user(arg, &chosen.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_STEREO => {
            let mut buf = [0u8; 4];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            let req = u32::from_le_bytes(buf);
            let channels = if req == 0 { 1 } else { 2 };
            DSP_CHANNELS.store(channels, Ordering::Relaxed);
            let echo = if channels == 1 { 0u32 } else { 1u32 };
            if frame::user::copy_to_user(arg, &echo.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_SPEED => {
            let mut buf = [0u8; 4];
            if frame::user::copy_from_user(arg, &mut buf).is_err() {
                return EFAULT;
            }
            let req = u32::from_le_bytes(buf);
            let (negotiated_hz, _) = nearest_supported_rate(req);
            DSP_RATE.store(negotiated_hz, Ordering::Relaxed);
            if frame::user::copy_to_user(arg, &negotiated_hz.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_GETOSPACE => {
            let fragments: i32 = 8;
            let fragstotal: i32 = 8;
            let fragsize: i32 = 4096;
            let bytes: i32 = fragments * fragsize;
            let mut out = [0u8; 16];
            out[0..4].copy_from_slice(&fragments.to_le_bytes());
            out[4..8].copy_from_slice(&fragstotal.to_le_bytes());
            out[8..12].copy_from_slice(&fragsize.to_le_bytes());
            out[12..16].copy_from_slice(&bytes.to_le_bytes());
            if frame::user::copy_to_user(arg, &out).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_GETFMTS => {
            let mask: u32 = AFMT_S16_LE | AFMT_U16_LE | AFMT_S8 | AFMT_U8;
            if frame::user::copy_to_user(arg, &mask.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_GETBLKSIZE => {
            let blk: u32 = 4096;
            if frame::user::copy_to_user(arg, &blk.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        SNDCTL_DSP_SETFRAGMENT => 0,
        SNDCTL_DSP_SYNC | SNDCTL_DSP_RESET => 0,
        _ => ENOTTY,
    }
}

fn fb_var_screeninfo(width: u32, height: u32) -> [u8; 160] {
    let mut out = [0u8; 160];
    let put_u32 = |out: &mut [u8; 160], off: usize, v: u32| {
        out[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    put_u32(&mut out, 0, width);
    put_u32(&mut out, 4, height);
    put_u32(&mut out, 8, width);
    put_u32(&mut out, 12, height);
    put_u32(&mut out, 16, 0);
    put_u32(&mut out, 20, 0);
    put_u32(&mut out, 24, 32);
    put_u32(&mut out, 28, 0);
    put_u32(&mut out, 32, 16);
    put_u32(&mut out, 36, 8);
    put_u32(&mut out, 40, 0);
    put_u32(&mut out, 44, 8);
    put_u32(&mut out, 48, 8);
    put_u32(&mut out, 52, 0);
    put_u32(&mut out, 56, 0);
    put_u32(&mut out, 60, 8);
    put_u32(&mut out, 64, 0);
    put_u32(&mut out, 68, 24);
    put_u32(&mut out, 72, 8);
    put_u32(&mut out, 76, 0);
    out
}

fn fb_fix_screeninfo(smem_start: u64, smem_len: usize, width: u32) -> [u8; 80] {
    let mut out = [0u8; 80];
    let id = b"cyphera-virtgpu";
    let n = id.len().min(15);
    out[..n].copy_from_slice(&id[..n]);
    out[16..24].copy_from_slice(&smem_start.to_le_bytes());
    out[24..28].copy_from_slice(&(smem_len as u32).to_le_bytes());
    out[36..40].copy_from_slice(&2u32.to_le_bytes());
    out[48..52].copy_from_slice(&(width * 4).to_le_bytes());
    out
}
