#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= BLOCK_SIZE {
        let _ = parse_header(&data[..BLOCK_SIZE]);
    }

    let _ = parse_octal(data);

    let _ = cstring_to_string(data);

    let _ = parse_pax(data);
});

const BLOCK_SIZE: usize = 512;

#[derive(Debug)]
#[allow(dead_code)]
struct Header {
    name: String,
    linkname: String,
    size: u64,
    typeflag: u8,
    mode: u16,
    uid: u32,
    gid: u32,
}

#[derive(Debug)]
#[allow(dead_code)]
enum TarError {
    BadChecksum,
    BadField(&'static str),
}

fn parse_header(block: &[u8]) -> Result<Header, TarError> {
    debug_assert_eq!(block.len(), BLOCK_SIZE);

    let stored_chksum = parse_octal(&block[148..156])?;
    let mut computed: u32 = 0;
    for (i, &b) in block.iter().enumerate() {
        if (148..156).contains(&i) {
            computed += b' ' as u32;
        } else {
            computed += b as u32;
        }
    }
    if computed != stored_chksum as u32 {
        return Err(TarError::BadChecksum);
    }

    let name_short = cstring_to_string(&block[0..100]);
    let prefix = cstring_to_string(&block[345..500]);
    let name = if prefix.is_empty() {
        name_short
    } else {
        let mut combined = String::with_capacity(prefix.len() + 1 + name_short.len());
        combined.push_str(&prefix);
        combined.push('/');
        combined.push_str(&name_short);
        combined
    };

    let mode = (parse_octal(&block[100..108])? & 0o7777) as u16;
    let uid = parse_octal(&block[108..116])? as u32;
    let gid = parse_octal(&block[116..124])? as u32;
    let size = parse_octal(&block[124..136])?;
    let typeflag = block[156];
    let linkname = cstring_to_string(&block[157..257]);

    Ok(Header {
        name,
        linkname,
        size,
        typeflag,
        mode,
        uid,
        gid,
    })
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

fn cstring_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end])
        .unwrap_or("")
        .to_string()
}

fn parse_pax(data: &[u8]) -> (Option<String>, Option<String>) {
    let mut path: Option<String> = None;
    let mut linkpath: Option<String> = None;
    let mut cursor = 0usize;

    while cursor < data.len() {
        let space = match data[cursor..].iter().position(|&b| b == b' ') {
            Some(s) => s,
            None => break,
        };
        let len: usize = core::str::from_utf8(&data[cursor..cursor + space])
            .unwrap_or("0")
            .parse()
            .unwrap_or(0);
        let line_end = match cursor.checked_add(len) {
            Some(e) if len > 0 && e <= data.len() => e,
            _ => break,
        };
        if len < space + 3 {
            break;
        }
        let line = &data[cursor..line_end];
        let key_value = &line[space + 1..line.len().saturating_sub(1)];
        if let Some(eq) = key_value.iter().position(|&b| b == b'=') {
            let key = &key_value[..eq];
            let val = &key_value[eq + 1..];
            let val_str = core::str::from_utf8(val).unwrap_or("").to_string();
            match key {
                b"path" => path = Some(val_str),
                b"linkpath" => linkpath = Some(val_str),
                _ => {}
            }
        }
        cursor += len;
    }

    (path, linkpath)
}
