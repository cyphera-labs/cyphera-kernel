#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    size: u8,
    bytes: [u8; 88],
}

fuzz_target!(|input: Input| {
    let size = (input.size as u64) % 97;
    let result = decode_clone3_args(size, &input.bytes);

    if let Ok(decoded) = result {
        let expected_low = decoded.exit_signal & 0xff;
        let expected_high = decoded.flags & !0xff;
        assert_eq!(
            decoded.merged_flags & 0xff,
            expected_low,
            "merged_flags low byte mismatch: got {:#x} expected {:#x}",
            decoded.merged_flags & 0xff,
            expected_low
        );
        assert_eq!(
            decoded.merged_flags & !0xff,
            expected_high,
            "merged_flags high bits mismatch"
        );
    }
});

const SIZE_V0: u64 = 64;
const SIZE_V1: u64 = 88;
const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

#[derive(Debug)]
#[allow(dead_code)]
struct DecodedCloneArgs {
    flags: u64,
    exit_signal: u64,
    merged_flags: u64,
    child_stack: u64,
    ptid: u64,
    ctid: u64,
    tls: u64,
}

#[derive(Debug)]
#[allow(dead_code)]
enum CloneError {
    Inval,
}

fn decode_clone3_args(size: u64, user_buf: &[u8]) -> Result<DecodedCloneArgs, CloneError> {
    if size < SIZE_V0 {
        return Err(CloneError::Inval);
    }

    let mut buf = [0u8; SIZE_V1 as usize];
    let read_len = core::cmp::min(size, SIZE_V1) as usize;
    let copy_len = core::cmp::min(read_len, user_buf.len());
    buf[..copy_len].copy_from_slice(&user_buf[..copy_len]);

    let read_u64 =
        |off: usize| -> u64 { u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) };
    let flags = read_u64(0);
    let _pidfd = read_u64(8);
    let ctid = read_u64(16);
    let ptid = read_u64(24);
    let exit_signal = read_u64(32);
    let stack = read_u64(40);
    let stack_size = read_u64(48);
    let tls = read_u64(56);
    let set_tid = if size as usize >= 72 { read_u64(64) } else { 0 };
    let set_tid_size = if size as usize >= 80 { read_u64(72) } else { 0 };
    let _cgroup = if size as usize >= 88 { read_u64(80) } else { 0 };

    if set_tid != 0 || set_tid_size != 0 {
        return Err(CloneError::Inval);
    }
    if flags & (CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP) != 0 {
        return Err(CloneError::Inval);
    }

    let child_stack = if stack == 0 {
        0
    } else {
        stack.wrapping_add(stack_size)
    };

    let merged_flags = (flags & !0xff) | (exit_signal & 0xff);

    Ok(DecodedCloneArgs {
        flags,
        exit_signal,
        merged_flags,
        child_stack,
        ptid,
        ctid,
        tls,
    })
}
