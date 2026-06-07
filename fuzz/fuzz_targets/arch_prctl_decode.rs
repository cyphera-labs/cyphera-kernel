#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    code: u64,
    addr: u64,
    code_pick: u8,
}

fuzz_target!(|input: Input| {
    let code = match input.code_pick % 5 {
        0 => ARCH_SET_FS,
        1 => ARCH_GET_FS,
        2 => ARCH_SET_GS,
        3 => ARCH_GET_GS,
        _ => input.code,
    };
    let result = decode_arch_prctl(code, input.addr);

    match result {
        Outcome::Ok => {
            assert!(
                code == ARCH_SET_FS || (code == ARCH_GET_FS && input.addr != 0),
                "Ok for unexpected code={:#x} addr={:#x}",
                code,
                input.addr
            );
        }
        Outcome::Fault => {
            assert_eq!(code, ARCH_GET_FS);
            assert_eq!(input.addr, 0);
        }
        Outcome::Inval => {
            let known_ok = code == ARCH_SET_FS
                || (code == ARCH_GET_FS && input.addr != 0);
            let known_fault = code == ARCH_GET_FS && input.addr == 0;
            assert!(!known_ok && !known_fault, "Inval for known-ok case");
        }
    }
});

const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_SET_GS: u64 = 0x1001;
const ARCH_GET_GS: u64 = 0x1004;

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Ok,
    Fault,
    Inval,
}

fn decode_arch_prctl(code: u64, addr: u64) -> Outcome {
    match code {
        ARCH_SET_FS => Outcome::Ok,
        ARCH_GET_FS => {
            if addr == 0 {
                Outcome::Fault
            } else {
                Outcome::Ok
            }
        }
        ARCH_SET_GS | ARCH_GET_GS => Outcome::Inval,
        _ => Outcome::Inval,
    }
}
