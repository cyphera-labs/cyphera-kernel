pub const MAX_PATH: usize = 4;

pub const MAX_SEGS: usize = MAX_PATH * 2;

pub const MAX_OUT: usize = MAX_PATH * 4;

#[derive(Copy, Clone)]
struct Seg {
    start: u8,
    len: u8,
    src: u8,
}

fn is_dot(bytes: &[u8], start: usize, len: usize) -> bool {
    len == 1 && bytes[start] == b'.'
}

fn is_dotdot(bytes: &[u8], start: usize, len: usize) -> bool {
    len == 2 && bytes[start] == b'.' && bytes[start + 1] == b'.'
}

fn push_segments(
    bytes: &[u8],
    bytes_len: usize,
    src: u8,
    parts: &mut [Seg; MAX_SEGS],
    count: &mut usize,
) {
    let mut i = 0;
    while i < bytes_len {
        if bytes[i] == b'/' {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes_len && bytes[i] != b'/' {
            i += 1;
        }
        let len = i - start;
        if is_dot(bytes, start, len) {
        } else if is_dotdot(bytes, start, len) {
            if *count > 0 {
                *count -= 1;
            }
        } else if *count < MAX_SEGS {
            parts[*count] = Seg {
                start: start as u8,
                len: len as u8,
                src,
            };
            *count += 1;
        }
    }
}

pub fn normalize(
    cwd: &[u8],
    cwd_len: usize,
    target: &[u8],
    target_len: usize,
    out: &mut [u8; MAX_OUT],
) -> usize {
    let mut parts = [Seg {
        start: 0,
        len: 0,
        src: 0,
    }; MAX_SEGS];
    let mut count: usize = 0;

    let target_is_abs = target_len > 0 && target[0] == b'/';

    if !target_is_abs {
        push_segments(cwd, cwd_len, 0, &mut parts, &mut count);
    }
    push_segments(target, target_len, 1, &mut parts, &mut count);

    if count == 0 {
        out[0] = b'/';
        return 1;
    }

    let mut out_len = 0;
    let mut p = 0;
    while p < count {
        out[out_len] = b'/';
        out_len += 1;
        let seg = parts[p];
        let bytes: &[u8] = if seg.src == 0 { cwd } else { target };
        let mut k = 0;
        while k < seg.len as usize {
            out[out_len] = bytes[seg.start as usize + k];
            out_len += 1;
            k += 1;
        }
        p += 1;
    }
    out_len
}

#[allow(dead_code)]
fn output_has_dot_segment(out: &[u8], out_len: usize) -> bool {
    let mut i = 0;
    while i < out_len {
        if out[i] == b'/' {
            i += 1;
            let start = i;
            while i < out_len && out[i] != b'/' {
                i += 1;
            }
            let len = i - start;
            if len == 1 && out[start] == b'.' {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

#[allow(dead_code)]
fn output_has_dotdot_segment(out: &[u8], out_len: usize) -> bool {
    let mut i = 0;
    while i < out_len {
        if out[i] == b'/' {
            i += 1;
            let start = i;
            while i < out_len && out[i] != b'/' {
                i += 1;
            }
            let len = i - start;
            if len == 2 && out[start] == b'.' && out[start + 1] == b'.' {
                return true;
            }
        } else {
            i += 1;
        }
    }
    false
}

#[allow(dead_code)]
fn output_has_double_slash(out: &[u8], out_len: usize) -> bool {
    let mut i = 1;
    while i < out_len {
        if out[i - 1] == b'/' && out[i] == b'/' {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn run_normalize() -> ([u8; MAX_OUT], usize) {
        let cwd: [u8; MAX_PATH] = kani::any();
        let cwd_len: usize = kani::any();
        kani::assume(cwd_len <= MAX_PATH);

        let target: [u8; MAX_PATH] = kani::any();
        let target_len: usize = kani::any();
        kani::assume(target_len <= MAX_PATH);

        let mut out = [0u8; MAX_OUT];
        let n = normalize(&cwd, cwd_len, &target, target_len, &mut out);
        (out, n)
    }

    #[kani::proof]
    #[kani::unwind(20)]
    fn result_never_empty() {
        let (_out, n) = run_normalize();
        assert!(n >= 1);
    }

    #[kani::proof]
    #[kani::unwind(20)]
    fn result_starts_with_slash() {
        let (out, n) = run_normalize();
        assert!(n >= 1);
        assert!(out[0] == b'/');
    }

    #[kani::proof]
    #[kani::unwind(20)]
    fn result_has_no_dotdot() {
        let (out, n) = run_normalize();
        assert!(!output_has_dotdot_segment(&out, n));
    }

    #[kani::proof]
    #[kani::unwind(20)]
    fn result_has_no_dot() {
        let (out, n) = run_normalize();
        assert!(!output_has_dot_segment(&out, n));
    }

    #[kani::proof]
    #[kani::unwind(20)]
    fn result_has_no_empty_segment() {
        let (out, n) = run_normalize();
        assert!(!output_has_double_slash(&out, n));
    }
}
