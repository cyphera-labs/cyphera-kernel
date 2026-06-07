#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    signum: u8,
    sigsetsize: u8,
    has_new_act: bool,
    bytes: [u8; 32],
}

fuzz_target!(|input: Input| {
    let signum = input.signum as u64;
    let sigsetsize = input.sigsetsize as u64;
    let new_act_ptr = if input.has_new_act { 1u64 } else { 0u64 };

    let result = decode_rt_sigaction(signum, new_act_ptr, sigsetsize, &input.bytes);

    match result {
        Ok(Some(action)) => {
            assert!(signum > 0 && signum < 64);
            assert!(signum != 9 && signum != 19);
            assert!(sigsetsize == 8);
            let mut roundtrip = [0u8; 32];
            roundtrip[0..8].copy_from_slice(&action.handler.to_le_bytes());
            roundtrip[8..16].copy_from_slice(&action.flags.to_le_bytes());
            roundtrip[16..24].copy_from_slice(&action.restorer.to_le_bytes());
            roundtrip[24..32].copy_from_slice(&action.mask.to_le_bytes());
            assert_eq!(roundtrip, input.bytes);
        }
        Ok(None) => {
            assert!(!input.has_new_act);
        }
        Err(_) => {
        }
    }
});

#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
struct SigAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[derive(Debug)]
#[allow(dead_code)]
enum SigActError {
    Inval,
}

fn decode_rt_sigaction(
    signum: u64,
    new_act: u64,
    sigsetsize: u64,
    buf: &[u8; 32],
) -> Result<Option<SigAction>, SigActError> {
    if signum == 0 || signum >= 64 {
        return Err(SigActError::Inval);
    }
    if new_act != 0 && (signum == 9 || signum == 19) {
        return Err(SigActError::Inval);
    }
    if sigsetsize != 8 {
        return Err(SigActError::Inval);
    }

    if new_act == 0 {
        return Ok(None);
    }

    let action = SigAction {
        handler: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        flags: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        restorer: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        mask: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
    };

    if signum == 0 || signum as usize >= 64 || signum == 9 || signum == 19 {
        return Err(SigActError::Inval);
    }

    Ok(Some(action))
}
