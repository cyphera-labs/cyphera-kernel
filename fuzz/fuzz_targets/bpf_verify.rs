#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let packet_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let mut insns = alloc::vec::Vec::new();
    let mut i = 4;
    while i + 8 <= data.len() {
        insns.push(SockFilter {
            code: u16::from_le_bytes([data[i], data[i + 1]]),
            jt: data[i + 2],
            jf: data[i + 3],
            k: u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]),
        });
        i += 8;
    }
    if let Ok(prog) = verify(insns, packet_len) {
        assert!(!prog.insns.is_empty());
        assert!(prog.insns.len() <= BPF_MAXINSNS);
        let last = prog.insns.last().unwrap();
        assert_eq!(
            last.code & 0x07,
            BPF_RET,
            "verifier accepted program whose last instruction is not RET",
        );
    }
});

extern crate alloc;

#[derive(Copy, Clone, Debug)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;
const BPF_MSH: u16 = 0xa0;

const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_MUL: u16 = 0x20;
const BPF_DIV: u16 = 0x30;
const BPF_OR: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;
const BPF_NEG: u16 = 0x80;
const BPF_MOD: u16 = 0x90;
const BPF_XOR: u16 = 0xa0;

const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

const SCRATCH_LEN: usize = 16;
const BPF_MAXINSNS: usize = 4096;

#[derive(Debug)]
#[allow(dead_code)]
enum BpfError {
    Empty,
    TooLong,
    InvalidJump,
    InvalidLoad,
    InvalidScratch,
    InvalidOpcode,
    NoTrailingRet,
}

struct BpfProgram {
    insns: alloc::vec::Vec<SockFilter>,
}

fn verify(insns: alloc::vec::Vec<SockFilter>, packet_len: u32) -> Result<BpfProgram, BpfError> {
    if insns.is_empty() {
        return Err(BpfError::Empty);
    }
    if insns.len() > BPF_MAXINSNS {
        return Err(BpfError::TooLong);
    }
    for (pc, ins) in insns.iter().enumerate() {
        let class = ins.code & 0x07;
        match class {
            c if c == BPF_LD || c == BPF_LDX => {
                let mode = ins.code & 0xe0;
                match mode {
                    m if m == BPF_IMM => {}
                    m if m == BPF_ABS => {
                        let size = match ins.code & 0x18 {
                            BPF_W => 4,
                            BPF_H => 2,
                            BPF_B => 1,
                            _ => return Err(BpfError::InvalidOpcode),
                        };
                        if ins.k.saturating_add(size) > packet_len {
                            return Err(BpfError::InvalidLoad);
                        }
                    }
                    m if m == BPF_IND => {}
                    m if m == BPF_MEM => {
                        if ins.k as usize >= SCRATCH_LEN {
                            return Err(BpfError::InvalidScratch);
                        }
                    }
                    m if m == BPF_LEN => {}
                    m if m == BPF_MSH => {}
                    _ => return Err(BpfError::InvalidOpcode),
                }
            }
            c if c == BPF_ST || c == BPF_STX => {
                if ins.k as usize >= SCRATCH_LEN {
                    return Err(BpfError::InvalidScratch);
                }
            }
            c if c == BPF_JMP => {
                let op = ins.code & 0xf0;
                let max = (insns.len() - pc - 1) as u32;
                match op {
                    o if o == BPF_JA => {
                        if ins.k > max {
                            return Err(BpfError::InvalidJump);
                        }
                    }
                    o if o == BPF_JEQ || o == BPF_JGT || o == BPF_JGE || o == BPF_JSET => {
                        if (ins.jt as u32) > max || (ins.jf as u32) > max {
                            return Err(BpfError::InvalidJump);
                        }
                    }
                    _ => return Err(BpfError::InvalidOpcode),
                }
            }
            c if c == BPF_ALU => {
                let op = ins.code & 0xf0;
                if !matches!(
                    op,
                    x if x == BPF_ADD || x == BPF_SUB || x == BPF_MUL || x == BPF_DIV
                        || x == BPF_OR || x == BPF_AND || x == BPF_LSH || x == BPF_RSH
                        || x == BPF_NEG || x == BPF_MOD || x == BPF_XOR
                ) {
                    return Err(BpfError::InvalidOpcode);
                }
            }
            c if c == BPF_RET => {}
            c if c == BPF_MISC => {
                let op = ins.code & 0xf8;
                if op != BPF_TAX && op != BPF_TXA {
                    return Err(BpfError::InvalidOpcode);
                }
            }
            _ => return Err(BpfError::InvalidOpcode),
        }
    }
    let last = insns.last().unwrap();
    if (last.code & 0x07) != BPF_RET {
        return Err(BpfError::NoTrailingRet);
    }
    Ok(BpfProgram { insns })
}
