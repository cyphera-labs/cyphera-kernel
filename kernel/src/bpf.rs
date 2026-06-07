extern crate alloc;

#[cfg(host_test)]
#[allow(unused_imports)]
use frame_host as frame;

use alloc::vec::Vec;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
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

const BPF_K: u16 = 0x00;
const BPF_A: u16 = 0x10;

const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

const SCRATCH_LEN: usize = 16;

#[derive(Debug)]
pub enum BpfError {
    Empty,
    TooLong,
    InvalidJump,
    InvalidLoad,
    InvalidScratch,
    InvalidOpcode,
    NoTrailingRet,
}

pub struct BpfProgram {
    pub insns: Vec<SockFilter>,
}

const BPF_MAXINSNS: usize = 4096;

impl BpfProgram {
    pub fn verify(insns: Vec<SockFilter>, packet_len: u32) -> Result<Self, BpfError> {
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
                        m if m == BPF_IND => {
                        }
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

    pub fn run(&self, packet: &[u8]) -> u32 {
        let mut a: u32 = 0;
        let mut x: u32 = 0;
        let mut m: [u32; SCRATCH_LEN] = [0; SCRATCH_LEN];
        let mut pc: usize = 0;
        while pc < self.insns.len() {
            let ins = self.insns[pc];
            pc += 1;
            let class = ins.code & 0x07;
            match class {
                c if c == BPF_LD => {
                    let mode = ins.code & 0xe0;
                    match mode {
                        m_ if m_ == BPF_IMM => a = ins.k,
                        m_ if m_ == BPF_ABS => {
                            a = read_packet(packet, ins.k as usize, ins.code & 0x18);
                        }
                        m_ if m_ == BPF_IND => {
                            a = read_packet(
                                packet,
                                (ins.k.wrapping_add(x)) as usize,
                                ins.code & 0x18,
                            );
                        }
                        m_ if m_ == BPF_MEM => a = m[ins.k as usize],
                        m_ if m_ == BPF_LEN => a = packet.len() as u32,
                        _ => return 0,
                    }
                }
                c if c == BPF_LDX => {
                    let mode = ins.code & 0xe0;
                    match mode {
                        m_ if m_ == BPF_IMM => x = ins.k,
                        m_ if m_ == BPF_MEM => x = m[ins.k as usize],
                        m_ if m_ == BPF_LEN => x = packet.len() as u32,
                        m_ if m_ == BPF_MSH => {
                            let v = read_packet(packet, ins.k as usize, BPF_B);
                            x = (v & 0x0f) << 2;
                        }
                        _ => return 0,
                    }
                }
                c if c == BPF_ST => m[ins.k as usize] = a,
                c if c == BPF_STX => m[ins.k as usize] = x,
                c if c == BPF_ALU => {
                    let op = ins.code & 0xf0;
                    let src = ins.code & 0x08;
                    let v = if src == BPF_K { ins.k } else { x };
                    a = match op {
                        o if o == BPF_ADD => a.wrapping_add(v),
                        o if o == BPF_SUB => a.wrapping_sub(v),
                        o if o == BPF_MUL => a.wrapping_mul(v),
                        o if o == BPF_DIV => {
                            if v == 0 {
                                return 0;
                            }
                            a / v
                        }
                        o if o == BPF_OR => a | v,
                        o if o == BPF_AND => a & v,
                        o if o == BPF_LSH => a.wrapping_shl(v & 31),
                        o if o == BPF_RSH => a.wrapping_shr(v & 31),
                        o if o == BPF_NEG => 0u32.wrapping_sub(a),
                        o if o == BPF_MOD => {
                            if v == 0 {
                                return 0;
                            }
                            a % v
                        }
                        o if o == BPF_XOR => a ^ v,
                        _ => return 0,
                    };
                }
                c if c == BPF_JMP => {
                    let op = ins.code & 0xf0;
                    let src = ins.code & 0x08;
                    let v = if src == BPF_K { ins.k } else { x };
                    let take = match op {
                        o if o == BPF_JA => {
                            pc += ins.k as usize;
                            continue;
                        }
                        o if o == BPF_JEQ => a == v,
                        o if o == BPF_JGT => a > v,
                        o if o == BPF_JGE => a >= v,
                        o if o == BPF_JSET => (a & v) != 0,
                        _ => return 0,
                    };
                    if take {
                        pc += ins.jt as usize;
                    } else {
                        pc += ins.jf as usize;
                    }
                }
                c if c == BPF_RET => {
                    let src = ins.code & 0x18;
                    return if src == BPF_A { a } else { ins.k };
                }
                c if c == BPF_MISC => {
                    let op = ins.code & 0xf8;
                    if op == BPF_TAX {
                        x = a;
                    } else if op == BPF_TXA {
                        a = x;
                    }
                }
                _ => return 0,
            }
        }
        0
    }
}

#[cfg(host_test)]
#[cfg(test)]
mod host_tests {
    use super::*;
    use alloc::vec;

    fn ret_k(k: u32) -> SockFilter {
        SockFilter {
            code: BPF_RET | BPF_K,
            jt: 0,
            jf: 0,
            k,
        }
    }

    #[test]
    fn verify_rejects_empty() {
        let r = BpfProgram::verify(vec![], 64);
        assert!(matches!(r, Err(BpfError::Empty)));
    }

    #[test]
    fn verify_rejects_no_trailing_ret() {
        let prog = vec![SockFilter {
            code: BPF_ALU | BPF_ADD | BPF_K,
            jt: 0,
            jf: 0,
            k: 1,
        }];
        let r = BpfProgram::verify(prog, 64);
        assert!(matches!(r, Err(BpfError::NoTrailingRet)));
    }

    #[test]
    fn verify_rejects_oob_jump() {
        let prog = vec![
            SockFilter {
                code: BPF_JMP | BPF_JA,
                jt: 0,
                jf: 0,
                k: 99,
            },
            ret_k(0),
        ];
        let r = BpfProgram::verify(prog, 64);
        assert!(matches!(r, Err(BpfError::InvalidJump)));
    }

    #[test]
    fn verify_rejects_oob_packet_load() {
        let prog = vec![
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 62,
            },
            ret_k(0),
        ];
        let r = BpfProgram::verify(prog, 64);
        assert!(matches!(r, Err(BpfError::InvalidLoad)));
    }

    #[test]
    fn verify_rejects_oob_scratch() {
        let prog = vec![
            SockFilter {
                code: BPF_ST,
                jt: 0,
                jf: 0,
                k: 16,
            },
            ret_k(0),
        ];
        let r = BpfProgram::verify(prog, 64);
        assert!(matches!(r, Err(BpfError::InvalidScratch)));
    }

    #[test]
    fn run_minimal_ret_k() {
        let prog = BpfProgram::verify(vec![ret_k(0xdead_beef)], 64).unwrap();
        let packet = [0u8; 64];
        assert_eq!(prog.run(&packet), 0xdead_beef);
    }

    #[test]
    fn run_load_compare_branch() {
        let prog = vec![
            SockFilter {
                code: BPF_LD | BPF_W | BPF_ABS,
                jt: 0,
                jf: 0,
                k: 0,
            },
            SockFilter {
                code: BPF_JMP | BPF_JEQ | BPF_K,
                jt: 0,
                jf: 1,
                k: 1,
            },
            ret_k(0x7fff_0000),
            ret_k(0),
        ];
        let prog = BpfProgram::verify(prog, 64).unwrap();

        let mut packet = [0u8; 64];
        packet[0..4].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(prog.run(&packet), 0x7fff_0000);

        packet[0..4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(prog.run(&packet), 0);
    }

    #[test]
    fn run_alu_arithmetic_wraps_cleanly() {
        let prog = vec![
            SockFilter {
                code: BPF_LD | BPF_IMM,
                jt: 0,
                jf: 0,
                k: 0xffff_ffff,
            },
            SockFilter {
                code: BPF_ALU | BPF_ADD | BPF_K,
                jt: 0,
                jf: 0,
                k: 2,
            },
            SockFilter {
                code: BPF_RET | BPF_A,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ];
        let prog = BpfProgram::verify(prog, 0).unwrap();
        assert_eq!(prog.run(&[]), 1);
    }

    #[test]
    fn run_lsh_mask_high_bits() {
        let prog = vec![
            SockFilter {
                code: BPF_LD | BPF_IMM,
                jt: 0,
                jf: 0,
                k: 1,
            },
            SockFilter {
                code: BPF_ALU | BPF_LSH | BPF_K,
                jt: 0,
                jf: 0,
                k: 33,
            },
            SockFilter {
                code: BPF_RET | BPF_A,
                jt: 0,
                jf: 0,
                k: 0,
            },
        ];
        let prog = BpfProgram::verify(prog, 0).unwrap();
        assert_eq!(prog.run(&[]), 2);
    }

    #[test]
    fn run_div_by_zero_returns_zero() {
        let prog = vec![
            SockFilter {
                code: BPF_LD | BPF_IMM,
                jt: 0,
                jf: 0,
                k: 100,
            },
            SockFilter {
                code: BPF_ALU | BPF_DIV | BPF_K,
                jt: 0,
                jf: 0,
                k: 0,
            },
            ret_k(0xbad),
        ];
        let prog = BpfProgram::verify(prog, 0).unwrap();
        assert_eq!(prog.run(&[]), 0);
    }
}

fn read_packet(packet: &[u8], offset: usize, size: u16) -> u32 {
    match size {
        BPF_W => {
            if offset + 4 > packet.len() {
                return 0;
            }
            u32::from_le_bytes([
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ])
        }
        BPF_H => {
            if offset + 2 > packet.len() {
                return 0;
            }
            u16::from_le_bytes([packet[offset], packet[offset + 1]]) as u32
        }
        BPF_B => {
            if offset >= packet.len() {
                return 0;
            }
            packet[offset] as u32
        }
        _ => 0,
    }
}
