#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let result = parse_octal(data);

    if let Ok(v) = result {
        if v != 0 {
            let mut saw_nonzero_octal = false;
            let mut saw_digit = false;
            for &b in data {
                match b {
                    b'1'..=b'7' => {
                        saw_nonzero_octal = true;
                        saw_digit = true;
                    }
                    b'0' => {
                        saw_digit = true;
                    }
                    b' ' | 0 if saw_digit => break,
                    b' ' | 0 => continue,
                    _ => break,
                }
            }
            assert!(
                saw_nonzero_octal,
                "parse_octal returned non-zero ({v}) with no non-zero octal digit in {data:?}"
            );
        }
    }
});

#[derive(Debug)]
#[allow(dead_code)]
enum TarError {
    BadField(&'static str),
}

fn parse_octal(bytes: &[u8]) -> Result<u64, TarError> {
    let mut v: u64 = 0;
    let mut any = false;
    for &b in bytes {
        match b {
            b'0'..=b'7' => {
                v = v
                    .checked_mul(8)
                    .and_then(|x| x.checked_add((b - b'0') as u64))
                    .ok_or(TarError::BadField("octal overflow"))?;
                any = true;
            }
            b' ' | 0 if any => break,
            b' ' | 0 => continue,
            _ => return Err(TarError::BadField("non-octal digit")),
        }
    }
    Ok(v)
}
