#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input<'a> {
    cwd: &'a str,
    target: &'a str,
}

fuzz_target!(|input: Input| {
    let out = normalize(input.cwd, input.target);

    assert!(!out.is_empty(), "normalize returned empty string");

    assert!(out.starts_with('/'), "normalize result not absolute: {out:?}");

    if out != "/" {
        for (i, seg) in out.split('/').enumerate() {
            if i == 0 {
                continue;
            }
            assert!(!seg.is_empty(), "normalize left empty segment: {out:?}");
            assert!(seg != "..", "normalize left `..` in result: {out:?}");
            assert!(seg != ".", "normalize left `.` in result: {out:?}");
        }
    }
});

fn normalize(cwd: &str, target: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if !target.starts_with('/') {
        for c in cwd.split('/').filter(|s| !s.is_empty()) {
            match c {
                "." => {}
                ".." => {
                    parts.pop();
                }
                _ => parts.push(c),
            }
        }
    }
    for c in target.split('/').filter(|s| !s.is_empty()) {
        match c {
            "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(c),
        }
    }
    if parts.is_empty() {
        return String::from("/");
    }
    let mut s = String::new();
    for p in parts {
        s.push('/');
        s.push_str(p);
    }
    s
}
