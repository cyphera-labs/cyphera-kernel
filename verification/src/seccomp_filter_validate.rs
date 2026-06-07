pub const MAX_INSNS: usize = 4;

pub const SCRATCH_LEN: usize = 16;

pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;

pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BpfError {
    Empty,
    InvalidJump,
    InvalidScratch,
    InvalidOpcode,
    NoTrailingRet,
}

#[derive(Copy, Clone, Debug)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

pub fn verify(insns: &[SockFilter]) -> Result<(), BpfError> {
    if insns.is_empty() {
        return Err(BpfError::Empty);
    }
    let mut pc = 0;
    while pc < insns.len() {
        let ins = insns[pc];
        let class = ins.code & 0x07;
        match class {
            c if c == BPF_LD || c == BPF_LDX => {
                let mode = ins.code & 0xe0;
                if mode == 0x60 && (ins.k as usize) >= SCRATCH_LEN {
                    return Err(BpfError::InvalidScratch);
                }
            }
            c if c == BPF_ST || c == BPF_STX => {
                if (ins.k as usize) >= SCRATCH_LEN {
                    return Err(BpfError::InvalidScratch);
                }
            }
            c if c == BPF_JMP => {
                let op = ins.code & 0xf0;
                let max = (insns.len() - pc - 1) as u32;
                if op == BPF_JA {
                    if ins.k > max {
                        return Err(BpfError::InvalidJump);
                    }
                } else if op == BPF_JEQ || op == BPF_JGT || op == BPF_JGE || op == BPF_JSET {
                    if (ins.jt as u32) > max || (ins.jf as u32) > max {
                        return Err(BpfError::InvalidJump);
                    }
                } else {
                    return Err(BpfError::InvalidOpcode);
                }
            }
            c if c == BPF_ALU => {}
            c if c == BPF_RET => {}
            c if c == BPF_MISC => {}
            _ => return Err(BpfError::InvalidOpcode),
        }
        pc += 1;
    }
    if (insns[insns.len() - 1].code & 0x07) != BPF_RET {
        return Err(BpfError::NoTrailingRet);
    }
    Ok(())
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn empty_rejected() {
        let r = verify(&[]);
        assert_eq!(r, Err(BpfError::Empty));
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn single_ret_accepted() {
        let k: u32 = kani::any();
        let insns = [SockFilter {
            code: BPF_RET,
            jt: 0,
            jf: 0,
            k,
        }];
        assert!(verify(&insns).is_ok());
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn no_trailing_ret_rejected() {
        let insns = [SockFilter {
            code: BPF_ALU,
            jt: 0,
            jf: 0,
            k: 0,
        }];
        let r = verify(&insns);
        assert_eq!(r, Err(BpfError::NoTrailingRet));
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn out_of_range_scratch_rejected() {
        let k: u32 = kani::any();
        kani::assume(k as usize >= SCRATCH_LEN);
        let insns = [
            SockFilter {
                code: BPF_ST,
                jt: 0,
                jf: 0,
                k,
            },
            SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ];
        let r = verify(&insns);
        assert_eq!(r, Err(BpfError::InvalidScratch));
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn in_range_scratch_accepted() {
        let k: u32 = kani::any();
        kani::assume((k as usize) < SCRATCH_LEN);
        let insns = [
            SockFilter {
                code: BPF_ST,
                jt: 0,
                jf: 0,
                k,
            },
            SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ];
        assert!(verify(&insns).is_ok());
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn out_of_range_ja_rejected() {
        let k: u32 = kani::any();
        kani::assume(k > 1);
        let insns = [
            SockFilter {
                code: BPF_JMP | BPF_JA,
                jt: 0,
                jf: 0,
                k,
            },
            SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ];
        let r = verify(&insns);
        assert_eq!(r, Err(BpfError::InvalidJump));
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn in_range_jeq_accepted() {
        let jt: u8 = kani::any();
        let jf: u8 = kani::any();
        kani::assume((jt as u32) <= 2);
        kani::assume((jf as u32) <= 2);
        let insns = [
            SockFilter {
                code: BPF_JMP | BPF_JEQ,
                jt,
                jf,
                k: 0,
            },
            SockFilter {
                code: BPF_ALU,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ];
        assert!(verify(&insns).is_ok());
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn unknown_jump_op_rejected() {
        let insns = [
            SockFilter {
                code: BPF_JMP | 0x50,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_RET,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ];
        let r = verify(&insns);
        assert_eq!(r, Err(BpfError::InvalidOpcode));
    }
}
