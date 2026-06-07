extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::bpf::BpfProgram;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
pub const SECCOMP_RET_KILL_THREAD: u32 = 0x00000000;
pub const SECCOMP_RET_TRAP: u32 = 0x00030000;
pub const SECCOMP_RET_ERRNO: u32 = 0x00050000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc00000;
pub const SECCOMP_RET_TRACE: u32 = 0x7ff00000;
pub const SECCOMP_RET_LOG: u32 = 0x7ffc0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

pub const SECCOMP_RET_ACTION: u32 = 0xffff0000;
pub const SECCOMP_RET_DATA: u32 = 0x0000ffff;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

impl SeccompData {
    pub const SIZE: u32 = 64;

    pub fn to_bytes(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..4].copy_from_slice(&self.nr.to_le_bytes());
        out[4..8].copy_from_slice(&self.arch.to_le_bytes());
        out[8..16].copy_from_slice(&self.instruction_pointer.to_le_bytes());
        for i in 0..6 {
            out[16 + i * 8..16 + (i + 1) * 8].copy_from_slice(&self.args[i].to_le_bytes());
        }
        out
    }
}

pub const AUDIT_ARCH_X86_64: u32 = 0xC000003E;

pub fn evaluate_chain(chain: &[Arc<BpfProgram>], data: SeccompData) -> u32 {
    if chain.is_empty() {
        return SECCOMP_RET_ALLOW;
    }
    let bytes = data.to_bytes();
    let mut best = SECCOMP_RET_ALLOW;
    for prog in chain {
        let r = prog.run(&bytes);
        if (r & SECCOMP_RET_ACTION) < (best & SECCOMP_RET_ACTION) {
            best = r;
        }
    }
    best
}

pub fn install_filter(prog: Arc<BpfProgram>) {
    crate::sched::seccomp_append_filter(prog);
}

pub fn install_filter_all_threads(prog: Arc<BpfProgram>) {
    crate::sched::seccomp_append_filter_tgid(prog);
}

pub fn evaluate_for_syscall(tf: &frame::user::TrapFrame) -> u32 {
    let chain = match crate::sched::current_seccomp_chain() {
        Some(c) => c,
        None => return SECCOMP_RET_ALLOW,
    };
    if chain.is_empty() {
        return SECCOMP_RET_ALLOW;
    }
    let data = SeccompData {
        nr: tf.rax as i32,
        arch: AUDIT_ARCH_X86_64,
        instruction_pointer: tf.rip_user,
        args: [tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9],
    };
    let _ = chain;
    let chain = crate::sched::current_seccomp_chain().unwrap_or_default();
    evaluate_chain(&chain, data)
}

pub type Chain = Vec<Arc<BpfProgram>>;
