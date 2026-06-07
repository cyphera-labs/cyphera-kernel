#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input<'a> {
    text: &'a str,
}

fuzz_target!(|input: Input| {
    let text = input.text;

    let _ = parse_max(text);

    let _ = parse_cpu_max(text);

    let _ = parse_io_max(text);

    let _ = parse_io_weight(text);
});

#[derive(Debug)]
#[allow(dead_code)]
enum FsError {
    InvalidArgument,
}

fn parse_max(text: &str) -> Result<Option<u64>, FsError> {
    if text == "max" {
        return Ok(None);
    }
    text.parse::<u64>()
        .map(Some)
        .map_err(|_| FsError::InvalidArgument)
}

fn parse_cpu_max(text: &str) -> Result<(Option<u64>, u64), FsError> {
    let mut parts = text.split_ascii_whitespace();
    let q_str = parts.next().ok_or(FsError::InvalidArgument)?;
    let p_str = parts.next().unwrap_or("100000");
    let period: u64 = p_str.parse().map_err(|_| FsError::InvalidArgument)?;
    let quota = if q_str == "max" {
        None
    } else {
        Some(q_str.parse::<u64>().map_err(|_| FsError::InvalidArgument)?)
    };
    Ok((quota, period))
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct IoLimits {
    rbps: Option<Option<u64>>,
    wbps: Option<Option<u64>>,
    riops: Option<Option<u64>>,
    wiops: Option<Option<u64>>,
}

fn parse_io_max(text: &str) -> Result<IoLimits, FsError> {
    let mut parts = text.split_ascii_whitespace();
    let _device = parts.next().ok_or(FsError::InvalidArgument)?;
    let mut out = IoLimits::default();
    for kv in parts {
        let (k, v) = kv.split_once('=').ok_or(FsError::InvalidArgument)?;
        let parsed: Option<u64> = if v == "max" {
            None
        } else {
            Some(v.parse().map_err(|_| FsError::InvalidArgument)?)
        };
        match k {
            "rbps" => out.rbps = Some(parsed),
            "wbps" => out.wbps = Some(parsed),
            "riops" => out.riops = Some(parsed),
            "wiops" => out.wiops = Some(parsed),
            _ => return Err(FsError::InvalidArgument),
        }
    }
    Ok(out)
}

fn parse_io_weight(text: &str) -> Result<u64, FsError> {
    let trimmed = text.trim();
    let val_str = trimmed
        .strip_prefix("default ")
        .map(|s| s.trim())
        .unwrap_or(trimmed);
    let w: u64 = val_str.parse().map_err(|_| FsError::InvalidArgument)?;
    if !(1..=10_000).contains(&w) {
        return Err(FsError::InvalidArgument);
    }
    Ok(w)
}
