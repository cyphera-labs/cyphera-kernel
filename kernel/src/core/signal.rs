use crate::process_model::{SigAction, sa};
use frame::user::TrapFrame;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DefaultAction {
    Term,
    Core,
    Stop,
    Cont,
    Ignore,
}

pub fn default_action(signum: u32) -> DefaultAction {
    use DefaultAction::*;
    match signum {
        1 => Term,
        2 => Term,
        3 => Core,
        4 => Core,
        5 => Core,
        6 => Core,
        7 => Core,
        8 => Core,
        9 => Term,
        10 => Term,
        11 => Core,
        12 => Term,
        13 => Term,
        14 => Term,
        15 => Term,
        16 => Term,
        17 => Ignore,
        18 => Cont,
        19 => Stop,
        20 => Stop,
        21 => Stop,
        22 => Stop,
        23 => Ignore,
        24 => Core,
        25 => Core,
        26 => Term,
        27 => Term,
        28 => Ignore,
        29 => Term,
        30 => Term,
        31 => Core,
        _ => Term,
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SigInfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub _pad0: u32,
    pub sifields: [u8; 112],
}

pub const SI_KERNEL: i32 = 0x80;
pub const SI_TIMER: i32 = -2;
pub const SEGV_MAPERR: i32 = 1;
pub const SEGV_ACCERR: i32 = 2;
pub const FPE_INTDIV: i32 = 1;
pub const ILL_ILLOPN: i32 = 2;
pub const BUS_ADRALN: i32 = 1;

#[derive(Copy, Clone, Default)]
pub struct PendingSigInfo {
    pub si_code: i32,
    pub _pad: u32,
    pub aux: u64,
    pub sival: u64,
}

impl PendingSigInfo {
    pub fn expand(&self, signal: u32) -> SigInfo {
        let mut info = SigInfo::zero();
        info.si_signo = signal as i32;
        info.si_code = self.si_code;
        if signal == crate::process_model::SIGCHLD {
            let pid = (self.aux >> 32) as u32;
            let status = (self.aux & 0xffff_ffff) as i32;
            info.sifields[0..4].copy_from_slice(&(pid as i32).to_le_bytes());
            info.sifields[8..12].copy_from_slice(&status.to_le_bytes());
        } else if matches!(signal, crate::process_model::SIGSEGV | 7 | 8 | 4) {
            info.sifields[0..8].copy_from_slice(&self.aux.to_le_bytes());
        } else if signal == 31 && self.si_code == 1 {
            info.si_errno = self._pad as i32;
            info.sifields[0..8].copy_from_slice(&self.aux.to_le_bytes());
            info.sifields[8..12].copy_from_slice(&(self.sival as u32).to_le_bytes());
            info.sifields[12..16]
                .copy_from_slice(&crate::security::seccomp::AUDIT_ARCH_X86_64.to_le_bytes());
        } else if self.si_code == SI_TIMER {
            info.sifields[0..4].copy_from_slice(&(self.aux as u32).to_le_bytes());
            info.sifields[4..8].copy_from_slice(&self._pad.to_le_bytes());
            info.sifields[8..16].copy_from_slice(&self.sival.to_le_bytes());
        } else {
            let pid = self.aux as u32;
            info.sifields[0..4].copy_from_slice(&(pid as i32).to_le_bytes());
            info.sifields[8..16].copy_from_slice(&self.sival.to_le_bytes());
        }
        info
    }
}

impl SigInfo {
    pub const SIZE: usize = 128;

    pub const fn zero() -> Self {
        Self {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad0: 0,
            sifields: [0; 112],
        }
    }

    pub fn for_kill(_signo: u32, sender_pid: u32) -> PendingSigInfo {
        PendingSigInfo {
            si_code: 0,
            _pad: 0,
            aux: sender_pid as u64,
            sival: 0,
        }
    }

    pub fn for_kernel(_signo: u32) -> PendingSigInfo {
        PendingSigInfo {
            si_code: 0x80,
            _pad: 0,
            aux: 0,
            sival: 0,
        }
    }

    pub fn for_tkill(_signo: u32, sender_pid: u32) -> PendingSigInfo {
        PendingSigInfo {
            si_code: -6,
            _pad: 0,
            aux: sender_pid as u64,
            sival: 0,
        }
    }

    pub fn for_timer(timer_id: i32, overrun: i32, sival: u64) -> PendingSigInfo {
        PendingSigInfo {
            si_code: SI_TIMER,
            _pad: overrun as u32,
            aux: timer_id as u32 as u64,
            sival,
        }
    }

    pub fn for_queue(_signo: u32, si_code: i32, sender_pid: u32, sival: u64) -> PendingSigInfo {
        PendingSigInfo {
            si_code,
            _pad: 0,
            aux: sender_pid as u64,
            sival,
        }
    }

    pub fn for_fault(_signo: u32, fault_addr: u64) -> PendingSigInfo {
        PendingSigInfo {
            si_code: 0x80,
            _pad: 0,
            aux: fault_addr,
            sival: 0,
        }
    }

    pub fn for_fault_code(fault_addr: u64, si_code: i32) -> PendingSigInfo {
        PendingSigInfo {
            si_code,
            _pad: 0,
            aux: fault_addr,
            sival: 0,
        }
    }

    pub fn for_seccomp(call_addr: u64, syscall_nr: u32, data: u16) -> PendingSigInfo {
        PendingSigInfo {
            si_code: 1,
            _pad: data as u32,
            aux: call_addr,
            sival: syscall_nr as u64,
        }
    }

    pub fn for_child(child_pid: u32, status: i32, code: i32) -> PendingSigInfo {
        PendingSigInfo {
            si_code: code,
            _pad: 0,
            aux: ((child_pid as u64) << 32) | (status as u32 as u64),
            sival: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.si_signo.to_le_bytes());
        buf[4..8].copy_from_slice(&self.si_errno.to_le_bytes());
        buf[8..12].copy_from_slice(&self.si_code.to_le_bytes());
        buf[12..16].copy_from_slice(&self._pad0.to_le_bytes());
        buf[16..128].copy_from_slice(&self.sifields);
        buf
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SigContext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub _ss: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    pub fpstate: u64,
    pub _reserved: [u64; 8],
}

impl SigContext {
    pub const SIZE: usize = 256;

    pub fn from_trap_frame(tf: &TrapFrame, oldmask: u64) -> Self {
        Self {
            r8: tf.r8,
            r9: tf.r9,
            r10: tf.r10,
            r11: tf.r11,
            r12: tf.r12,
            r13: tf.r13,
            r14: tf.r14,
            r15: tf.r15,
            rdi: tf.rdi,
            rsi: tf.rsi,
            rbp: tf.rbp,
            rbx: tf.rbx,
            rdx: tf.rdx,
            rax: tf.rax,
            rcx: tf.rcx,
            rsp: tf.rsp_user,
            rip: tf.rip_user,
            eflags: tf.rflags_user,
            cs: 0x23,
            gs: 0,
            fs: 0,
            _ss: 0x1B,
            err: 0,
            trapno: 0,
            oldmask,
            cr2: 0,
            fpstate: 0,
            _reserved: [0; 8],
        }
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        let words: [(usize, u64); 19] = [
            (0, self.r8),
            (8, self.r9),
            (16, self.r10),
            (24, self.r11),
            (32, self.r12),
            (40, self.r13),
            (48, self.r14),
            (56, self.r15),
            (64, self.rdi),
            (72, self.rsi),
            (80, self.rbp),
            (88, self.rbx),
            (96, self.rdx),
            (104, self.rax),
            (112, self.rcx),
            (120, self.rsp),
            (128, self.rip),
            (136, self.eflags),
            (152, self.err),
        ];
        for (off, v) in words {
            buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        let words2: [(usize, u64); 4] = [
            (160, self.trapno),
            (168, self.oldmask),
            (176, self.cr2),
            (184, self.fpstate),
        ];
        for (off, v) in words2 {
            buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
        }
        buf[144..146].copy_from_slice(&self.cs.to_le_bytes());
        buf[146..148].copy_from_slice(&self.gs.to_le_bytes());
        buf[148..150].copy_from_slice(&self.fs.to_le_bytes());
        buf[150..152].copy_from_slice(&self._ss.to_le_bytes());
        for (i, w) in self._reserved.iter().enumerate() {
            buf[192 + i * 8..192 + i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        buf
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Self {
        let rd = |off: usize| u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
        let rdu16 = |off: usize| u16::from_le_bytes(buf[off..off + 2].try_into().unwrap());
        Self {
            r8: rd(0),
            r9: rd(8),
            r10: rd(16),
            r11: rd(24),
            r12: rd(32),
            r13: rd(40),
            r14: rd(48),
            r15: rd(56),
            rdi: rd(64),
            rsi: rd(72),
            rbp: rd(80),
            rbx: rd(88),
            rdx: rd(96),
            rax: rd(104),
            rcx: rd(112),
            rsp: rd(120),
            rip: rd(128),
            eflags: rd(136),
            cs: rdu16(144),
            gs: rdu16(146),
            fs: rdu16(148),
            _ss: rdu16(150),
            err: rd(152),
            trapno: rd(160),
            oldmask: rd(168),
            cr2: rd(176),
            fpstate: rd(184),
            _reserved: {
                let mut r = [0u64; 8];
                for (i, slot) in r.iter_mut().enumerate() {
                    *slot = rd(192 + i * 8);
                }
                r
            },
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct AltStack {
    pub sp: u64,
    pub flags: i32,
    pub size: u64,
}

impl AltStack {
    pub const SS_DISABLE: i32 = 0x2;
    pub const SS_ONSTACK: i32 = 0x1;
    pub const SS_AUTODISARM: i32 = 0x80000000u32 as i32;

    pub const MIN_SIZE: u64 = 2048;

    pub const fn disabled() -> Self {
        Self {
            sp: 0,
            flags: Self::SS_DISABLE,
            size: 0,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.flags & Self::SS_DISABLE == 0 && self.size >= Self::MIN_SIZE
    }
}

pub const UC_SIZE: usize = 424 + 512;
const UC_OFF_FLAGS: usize = 0;
const UC_OFF_LINK: usize = 8;
const UC_OFF_STACK_SP: usize = 16;
const UC_OFF_STACK_FLAGS: usize = 24;
const UC_OFF_STACK_SIZE: usize = 32;
const UC_OFF_MCONTEXT: usize = 40;
const UC_OFF_SIGMASK: usize = 296;
const _UC_OFF_FPREGS: usize = 424;

fn write_ucontext(buf: &mut [u8; UC_SIZE], sigmask: u64, altstack: AltStack, ctx: &SigContext) {
    buf[UC_OFF_FLAGS..UC_OFF_FLAGS + 8].fill(0);
    buf[UC_OFF_LINK..UC_OFF_LINK + 8].fill(0);
    buf[UC_OFF_STACK_SP..UC_OFF_STACK_SP + 8].copy_from_slice(&altstack.sp.to_le_bytes());
    buf[UC_OFF_STACK_FLAGS..UC_OFF_STACK_FLAGS + 4].copy_from_slice(&altstack.flags.to_le_bytes());
    buf[UC_OFF_STACK_FLAGS + 4..UC_OFF_STACK_FLAGS + 8].fill(0);
    buf[UC_OFF_STACK_SIZE..UC_OFF_STACK_SIZE + 8].copy_from_slice(&altstack.size.to_le_bytes());
    let mctx = ctx.to_bytes();
    buf[UC_OFF_MCONTEXT..UC_OFF_MCONTEXT + SigContext::SIZE].copy_from_slice(&mctx);
    buf[UC_OFF_SIGMASK..UC_OFF_SIGMASK + 8].copy_from_slice(&sigmask.to_le_bytes());
    buf[UC_OFF_SIGMASK + 8..UC_OFF_SIGMASK + 128].fill(0);
}

fn read_sigcontext_from_ucontext(buf: &[u8; UC_SIZE]) -> SigContext {
    let mut mctx = [0u8; SigContext::SIZE];
    mctx.copy_from_slice(&buf[UC_OFF_MCONTEXT..UC_OFF_MCONTEXT + SigContext::SIZE]);
    SigContext::from_bytes(&mctx)
}

fn read_sigmask_from_ucontext(buf: &[u8; UC_SIZE]) -> u64 {
    u64::from_le_bytes(buf[UC_OFF_SIGMASK..UC_OFF_SIGMASK + 8].try_into().unwrap())
}

const FRAME_TOTAL: u64 = 8 + UC_SIZE as u64 + SigInfo::SIZE as u64;

pub fn deliver_to_handler(
    tf: &mut TrapFrame,
    signal: u32,
    action: &SigAction,
    pre_blocked: u64,
    info: &SigInfo,
    altstack: AltStack,
) -> Result<u64, frame::user::UserAccessFault> {
    let never_restart = matches!(
        tf.orig_rax,
        7 | 23 | 34 | 128 | 130 | 232 | 270 | 271 | 281 | 441
    );
    if (tf.rax as i64) == -4 && action.flags & sa::SA_RESTART != 0 && !never_restart {
        tf.rip_user = tf.rip_user.wrapping_sub(2);
        tf.rax = tf.orig_rax;
    }

    let on_alt = action.flags & sa::SA_ONSTACK != 0
        && altstack.is_enabled()
        && !is_on_altstack(tf.rsp_user, altstack);
    let base_rsp = if on_alt {
        altstack.sp + altstack.size
    } else {
        tf.rsp_user
    };

    let aligned = base_rsp & !15;
    let frame_base = aligned.wrapping_sub(FRAME_TOTAL) & !15;
    let frame_base = frame_base.wrapping_sub(8);

    let pretcode_addr = frame_base;
    let uc_addr = frame_base + 8;
    let info_addr = uc_addr + UC_SIZE as u64;

    frame::user::copy_to_user(pretcode_addr, &action.restorer.to_le_bytes())?;

    let ctx = SigContext::from_trap_frame(tf, pre_blocked);
    let mut uc_buf = [0u8; UC_SIZE];
    write_ucontext(&mut uc_buf, pre_blocked, altstack, &ctx);
    frame::user::copy_to_user(uc_addr, &uc_buf)?;

    let info_bytes = info.to_bytes();
    frame::user::copy_to_user(info_addr, &info_bytes)?;

    tf.rip_user = action.handler;
    tf.rsp_user = frame_base;
    tf.rdi = signal as u64;
    tf.rsi = info_addr;
    tf.rdx = uc_addr;
    tf.rax = 0;
    tf.r8 = 0;
    tf.r9 = 0;
    tf.r10 = 0;
    tf.rflags_user |= 0x202;

    let mut new_blocked = pre_blocked | action.mask;
    if action.flags & sa::SA_NODEFER == 0 {
        new_blocked |= 1u64 << signal;
    }
    Ok(new_blocked)
}

fn is_on_altstack(rsp: u64, alt: AltStack) -> bool {
    alt.is_enabled() && rsp >= alt.sp && rsp < alt.sp + alt.size
}

const USER_RFLAGS_MASK: u64 = 0x0020_0CD5;

pub fn restore_from_frame(tf: &mut TrapFrame) -> Result<u64, frame::user::UserAccessFault> {
    let mut buf = [0u8; UC_SIZE];
    frame::user::copy_from_user(tf.rsp_user, &mut buf)?;
    let ctx = read_sigcontext_from_ucontext(&buf);
    let saved_mask = read_sigmask_from_ucontext(&buf);
    tf.r8 = ctx.r8;
    tf.r9 = ctx.r9;
    tf.r10 = ctx.r10;
    tf.r11 = ctx.r11;
    tf.rcx = ctx.rcx;
    tf.r12 = ctx.r12;
    tf.r13 = ctx.r13;
    tf.r14 = ctx.r14;
    tf.r15 = ctx.r15;
    tf.rdi = ctx.rdi;
    tf.rsi = ctx.rsi;
    tf.rbp = ctx.rbp;
    tf.rbx = ctx.rbx;
    tf.rdx = ctx.rdx;
    tf.rax = ctx.rax;
    tf.rsp_user = ctx.rsp;
    tf.rip_user = ctx.rip;
    tf.rflags_user = (ctx.eflags & USER_RFLAGS_MASK) | 0x202;
    Ok(saved_mask)
}
