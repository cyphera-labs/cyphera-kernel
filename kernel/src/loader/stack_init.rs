use alloc::vec::Vec;

use frame::mm::vm::VmSpace;

use cyphera_kapi::{Errno, KResult};

const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_FLAGS: u64 = 8;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_PLATFORM: u64 = 15;
const AT_HWCAP: u64 = 16;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;
const AT_EXECFN: u64 = 31;

#[derive(Clone, Copy)]
pub struct AuxvInfo {
    pub phdr: u64,
    pub phent: u16,
    pub phnum: u16,
    pub entry: u64,
    pub interp_base: u64,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub secure: bool,
}

impl AuxvInfo {
    pub const NONE: Self = Self {
        phdr: 0,
        phent: 0,
        phnum: 0,
        entry: 0,
        interp_base: 0,
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
        secure: false,
    };

    pub fn for_exec(
        loaded: &crate::loader::elf::Loaded,
        uid: u32,
        euid: u32,
        gid: u32,
        egid: u32,
        secure: bool,
    ) -> Self {
        Self {
            phdr: loaded.phdr_va,
            phent: loaded.phent,
            phnum: loaded.phnum,
            entry: loaded.entry,
            interp_base: loaded.interp_base.unwrap_or(0),
            uid,
            euid,
            gid,
            egid,
            secure,
        }
    }
}

pub fn build_user_stack(
    vmspace: &VmSpace,
    stack_top: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    aux: &AuxvInfo,
) -> KResult<u64> {
    vmspace.with_active(|| build_user_stack_active(stack_top, argv, envp, aux))
}

fn build_user_stack_active(
    stack_top: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    aux: &AuxvInfo,
) -> KResult<u64> {
    let argc = argv.len();
    let envc = envp.len();

    let argv_str_bytes: usize = argv.iter().map(|s| s.len() + 1).sum();
    let envp_str_bytes: usize = envp.iter().map(|s| s.len() + 1).sum();
    const AT_RANDOM_BYTES: usize = 16;

    let strings_end = stack_top;
    let mut p = strings_end - AT_RANDOM_BYTES as u64;
    let at_random_addr = p;
    write_user(p, &random_bytes_16())?;

    let mut envp_ptrs: Vec<u64> = Vec::with_capacity(envc);
    for s in envp.iter().rev() {
        p = p.checked_sub(s.len() as u64 + 1).ok_or(Errno::NOMEM)?;
        write_user(p, s)?;
        write_user(p + s.len() as u64, &[0u8])?;
        envp_ptrs.push(p);
    }
    envp_ptrs.reverse();

    let mut argv_ptrs: Vec<u64> = Vec::with_capacity(argc);
    for s in argv.iter().rev() {
        p = p.checked_sub(s.len() as u64 + 1).ok_or(Errno::NOMEM)?;
        write_user(p, s)?;
        write_user(p + s.len() as u64, &[0u8])?;
        argv_ptrs.push(p);
    }
    argv_ptrs.reverse();

    let _ = (argv_str_bytes, envp_str_bytes);

    let auxv_entries = 15;
    let structure_words = 1 + (argc + 1) + (envc + 1) + (auxv_entries * 2) + 2;
    let structure_bytes = (structure_words * 8) as u64;

    let strings_bottom = p;
    let rsp = (strings_bottom - structure_bytes) & !15;
    if rsp >= strings_end || rsp < (stack_top - 16 * 4096) {
        return Err(Errno::NOMEM);
    }

    let mut q = rsp;
    write_user(q, &(argc as u64).to_le_bytes())?;
    q += 8;

    for ptr in &argv_ptrs {
        write_user(q, &ptr.to_le_bytes())?;
        q += 8;
    }
    write_user(q, &0u64.to_le_bytes())?;
    q += 8;

    for ptr in &envp_ptrs {
        write_user(q, &ptr.to_le_bytes())?;
        q += 8;
    }
    write_user(q, &0u64.to_le_bytes())?;
    q += 8;

    write_user(q, &AT_PHDR.to_le_bytes())?;
    q += 8;
    write_user(q, &aux.phdr.to_le_bytes())?;
    q += 8;

    write_user(q, &AT_PHENT.to_le_bytes())?;
    q += 8;
    write_user(q, &(aux.phent as u64).to_le_bytes())?;
    q += 8;

    write_user(q, &AT_PHNUM.to_le_bytes())?;
    q += 8;
    write_user(q, &(aux.phnum as u64).to_le_bytes())?;
    q += 8;

    write_user(q, &AT_PAGESZ.to_le_bytes())?;
    q += 8;
    write_user(q, &4096u64.to_le_bytes())?;
    q += 8;

    write_user(q, &AT_ENTRY.to_le_bytes())?;
    q += 8;
    write_user(q, &aux.entry.to_le_bytes())?;
    q += 8;

    write_user(q, &AT_RANDOM.to_le_bytes())?;
    q += 8;
    write_user(q, &at_random_addr.to_le_bytes())?;
    q += 8;

    if aux.interp_base != 0 {
        write_user(q, &AT_BASE.to_le_bytes())?;
        q += 8;
        write_user(q, &aux.interp_base.to_le_bytes())?;
        q += 8;
    }

    write_user(q, &AT_FLAGS.to_le_bytes())?;
    q += 8;
    write_user(q, &0u64.to_le_bytes())?;
    q += 8;

    write_user(q, &AT_UID.to_le_bytes())?;
    q += 8;
    write_user(q, &(aux.uid as u64).to_le_bytes())?;
    q += 8;
    write_user(q, &AT_EUID.to_le_bytes())?;
    q += 8;
    write_user(q, &(aux.euid as u64).to_le_bytes())?;
    q += 8;
    write_user(q, &AT_GID.to_le_bytes())?;
    q += 8;
    write_user(q, &(aux.gid as u64).to_le_bytes())?;
    q += 8;
    write_user(q, &AT_EGID.to_le_bytes())?;
    q += 8;
    write_user(q, &(aux.egid as u64).to_le_bytes())?;
    q += 8;

    let secure: u64 = if aux.secure { 1 } else { 0 };
    write_user(q, &AT_SECURE.to_le_bytes())?;
    q += 8;
    write_user(q, &secure.to_le_bytes())?;
    q += 8;

    write_user(q, &AT_HWCAP.to_le_bytes())?;
    q += 8;
    write_user(q, &0u64.to_le_bytes())?;
    q += 8;

    write_user(q, &AT_CLKTCK.to_le_bytes())?;
    q += 8;
    write_user(q, &100u64.to_le_bytes())?;
    q += 8;

    let _ = (AT_PLATFORM, AT_EXECFN);

    write_user(q, &AT_NULL.to_le_bytes())?;
    q += 8;
    write_user(q, &0u64.to_le_bytes())?;

    Ok(rsp)
}

fn write_user(addr: u64, bytes: &[u8]) -> KResult<()> {
    frame::user::copy_to_user(addr, bytes).map_err(|_| Errno::FAULT)
}

fn random_bytes_16() -> [u8; 16] {
    let mut buf = [0u8; 16];
    crate::device::random::fill(&mut buf);
    buf
}
