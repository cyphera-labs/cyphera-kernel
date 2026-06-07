extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[cfg(not(host_test))]
use alloc::sync::Arc;

#[cfg(not(host_test))]
use crate::vfs::{FsError, Inode, InodeKind, path::normalize};

#[derive(Debug)]
pub enum TarError {
    BadChecksum,
    BadField(&'static str),
    Truncated,
    #[cfg(not(host_test))]
    Vfs(FsError),
    BadPath,
}

#[cfg(not(host_test))]
impl From<FsError> for TarError {
    fn from(e: FsError) -> Self {
        TarError::Vfs(e)
    }
}

#[cfg(not(host_test))]
pub fn extract_into(root: &Arc<dyn Inode>, archive: &[u8]) -> Result<usize, TarError> {
    let mut planted = 0usize;
    let mut cursor = 0usize;

    let mut pending_path: Option<String> = None;
    let mut pending_linkpath: Option<String> = None;

    while cursor + BLOCK_SIZE <= archive.len() {
        let block = &archive[cursor..cursor + BLOCK_SIZE];

        if block.iter().all(|&b| b == 0) {
            let next_off = cursor + BLOCK_SIZE;
            if next_off + BLOCK_SIZE <= archive.len()
                && archive[next_off..next_off + BLOCK_SIZE]
                    .iter()
                    .all(|&b| b == 0)
            {
                break;
            }
            cursor += BLOCK_SIZE;
            continue;
        }

        let hdr = parse_header(block)?;
        cursor += BLOCK_SIZE;

        let name = pending_path.take().unwrap_or_else(|| hdr.name.clone());
        let linkname = pending_linkpath
            .take()
            .unwrap_or_else(|| hdr.linkname.clone());

        let data_blocks = hdr.size.div_ceil(BLOCK_SIZE as u64);
        let data_end = cursor + (data_blocks as usize) * BLOCK_SIZE;
        if data_end > archive.len() {
            return Err(TarError::Truncated);
        }
        let data = &archive[cursor..cursor + hdr.size as usize];

        match hdr.typeflag {
            b'x' | b'g' => {
                let (path, linkpath) = parse_pax(data);
                if let Some(p) = path {
                    pending_path = Some(p);
                }
                if let Some(p) = linkpath {
                    pending_linkpath = Some(p);
                }
            }
            b'L' => {
                pending_path = Some(cstring_to_string(data));
            }
            b'K' => {
                pending_linkpath = Some(cstring_to_string(data));
            }
            b'5' => {
                let (parent, leaf) = match resolve_parent(root, &name)? {
                    Some(t) => t,
                    None => {
                        cursor = data_end;
                        continue;
                    }
                };
                let inode = match parent.lookup(&leaf) {
                    Ok(i) => i,
                    Err(_) => parent.create(&leaf, InodeKind::Directory)?,
                };
                apply_meta(&inode, &hdr);
                planted += 1;
            }
            b'2' => {
                let (parent, leaf) = match resolve_parent(root, &name)? {
                    Some(t) => t,
                    None => {
                        cursor = data_end;
                        continue;
                    }
                };
                let inode = parent.symlink(&leaf, &linkname)?;
                let _ = inode.set_owner(Some(hdr.uid), Some(hdr.gid));
                planted += 1;
            }
            b'1' => {
                let target = resolve_path(root, &linkname)?;
                let (parent, leaf) = match resolve_parent(root, &name)? {
                    Some(t) => t,
                    None => {
                        cursor = data_end;
                        continue;
                    }
                };
                parent.attach(&leaf, target)?;
                planted += 1;
            }
            0 | b'0' | b'7' => {
                let (parent, leaf) = match resolve_parent(root, &name)? {
                    Some(t) => t,
                    None => {
                        cursor = data_end;
                        continue;
                    }
                };
                let inode = match parent.lookup(&leaf) {
                    Ok(i) => i,
                    Err(_) => parent.create(&leaf, InodeKind::Regular)?,
                };
                if !data.is_empty() {
                    inode.write_at(0, data)?;
                }
                apply_meta(&inode, &hdr);
                planted += 1;
            }
            b'3' | b'4' | b'6' => {}
            _ => {}
        }

        cursor = data_end;
    }

    Ok(planted)
}

#[cfg(not(host_test))]
fn apply_meta(inode: &Arc<dyn Inode>, hdr: &Header) {
    if hdr.mode != 0 {
        let _ = inode.set_mode(hdr.mode);
    }
    let _ = inode.set_owner(Some(hdr.uid), Some(hdr.gid));
}

const BLOCK_SIZE: usize = 512;

#[derive(Debug)]
struct Header {
    name: String,
    linkname: String,
    size: u64,
    typeflag: u8,
    mode: u16,
    uid: u32,
    gid: u32,
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

#[cfg(not(host_test))]
type ParentLeaf = (Arc<dyn Inode>, String);

#[cfg(not(host_test))]
fn resolve_parent(root: &Arc<dyn Inode>, path: &str) -> Result<Option<ParentLeaf>, TarError> {
    let normalized = normalize("/", path);
    let mut parts: Vec<&str> = normalized.split('/').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return Ok(None);
    }
    let leaf = parts.pop().ok_or(TarError::BadPath)?.to_string();
    let mut cur = root.clone();
    for p in parts {
        cur = match cur.lookup(p) {
            Ok(i) => i,
            Err(_) => cur.create(p, InodeKind::Directory)?,
        };
    }
    Ok(Some((cur, leaf)))
}

#[cfg(not(host_test))]
fn resolve_path(root: &Arc<dyn Inode>, path: &str) -> Result<Arc<dyn Inode>, TarError> {
    let normalized = normalize("/", path);
    let mut cur = root.clone();
    for p in normalized.split('/').filter(|p| !p.is_empty()) {
        cur = cur.lookup(p)?;
    }
    Ok(cur)
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

#[cfg(host_test)]
#[cfg(test)]
mod host_tests {
    use super::*;
    use alloc::vec;

    fn make_header(name: &[u8], size: u64, typeflag: u8) -> Vec<u8> {
        let mut block = vec![0u8; BLOCK_SIZE];
        block[..name.len().min(100)].copy_from_slice(&name[..name.len().min(100)]);
        block[100..108].copy_from_slice(b"0000644\0");
        block[108..116].copy_from_slice(b"0000000\0");
        block[116..124].copy_from_slice(b"0000000\0");
        let sz = alloc::format!("{:011o}\0", size);
        block[124..124 + sz.len()].copy_from_slice(sz.as_bytes());
        block[156] = typeflag;
        block[148..156].copy_from_slice(b"        ");
        let sum: u32 = block.iter().map(|&b| b as u32).sum();
        let cs = alloc::format!("{:06o}\0 ", sum);
        block[148..148 + cs.len()].copy_from_slice(cs.as_bytes());
        block
    }

    #[test]
    fn parse_octal_zero_and_padding() {
        assert_eq!(parse_octal(b"0000000\0").unwrap(), 0);
        assert_eq!(parse_octal(b"      0").unwrap(), 0);
    }

    #[test]
    fn parse_octal_valid_digits() {
        assert_eq!(parse_octal(b"0000644 ").unwrap(), 0o644);
        assert_eq!(parse_octal(b"00012345").unwrap(), 0o12345);
    }

    #[test]
    fn parse_octal_rejects_non_octal() {
        assert!(parse_octal(b"0000128 ").is_err());
        assert!(parse_octal(b"0000129\0").is_err());
        assert!(parse_octal(b"0000abc\0").is_err());
    }

    #[test]
    fn parse_octal_overflow_caught() {
        assert!(parse_octal(b"777777777777777777777777").is_err());
    }

    #[test]
    fn cstring_to_string_terminates_at_nul() {
        assert_eq!(cstring_to_string(b"abc\0xyz"), "abc");
        assert_eq!(cstring_to_string(b"abc"), "abc");
        assert_eq!(cstring_to_string(b""), "");
        assert_eq!(cstring_to_string(&[0xffu8, 0xfe, 0x00]), "");
    }

    #[test]
    fn parse_header_valid_minimal() {
        let block = make_header(b"hello.txt", 42, b'0');
        let hdr = parse_header(&block).unwrap();
        assert_eq!(hdr.name, "hello.txt");
        assert_eq!(hdr.size, 42);
        assert_eq!(hdr.typeflag, b'0');
        assert_eq!(hdr.mode, 0o644);
    }

    #[test]
    fn parse_header_rejects_bad_checksum() {
        let mut block = make_header(b"bad.txt", 0, b'0');
        block[0] = b'X';
        let r = parse_header(&block);
        assert!(matches!(r, Err(TarError::BadChecksum)));
    }

    #[test]
    fn parse_header_handles_prefix_join() {
        let mut block = make_header(b"name", 0, b'0');
        block[345..345 + 6].copy_from_slice(b"prefix");
        block[148..156].copy_from_slice(b"        ");
        let sum: u32 = block.iter().map(|&b| b as u32).sum();
        let cs = alloc::format!("{:06o}\0 ", sum);
        block[148..148 + cs.len()].copy_from_slice(cs.as_bytes());
        let hdr = parse_header(&block).unwrap();
        assert_eq!(hdr.name, "prefix/name");
    }

    #[test]
    fn parse_pax_empty_input() {
        let (path, link) = parse_pax(b"");
        assert!(path.is_none());
        assert!(link.is_none());
    }

    #[test]
    fn parse_pax_valid_path_record() {
        let blob = b"18 path=hello.txt\n";
        assert_eq!(blob.len(), 18);
        let (path, link) = parse_pax(blob);
        assert_eq!(path.as_deref(), Some("hello.txt"));
        assert!(link.is_none());
    }

    #[test]
    fn parse_pax_truncated_no_space() {
        let (p, l) = parse_pax(b"12345");
        assert!(p.is_none() && l.is_none());
    }

    #[test]
    fn parse_pax_len_zero_caught() {
        let (p, l) = parse_pax(b"0 path=foo\n");
        assert!(p.is_none() && l.is_none());
    }

    #[test]
    fn parse_pax_len_larger_than_buffer() {
        let (p, l) = parse_pax(b"99 path=oops\n");
        assert!(p.is_none() && l.is_none());
    }

    #[test]
    fn parse_pax_len_max_does_not_overflow() {
        let huge = alloc::format!("{} path=evil\n", usize::MAX);
        let (p, l) = parse_pax(huge.as_bytes());
        assert!(p.is_none() && l.is_none());
    }

    #[test]
    fn parse_pax_short_record_does_not_underflow() {
        let (p, l) = parse_pax(b"3 a");
        assert!(p.is_none() && l.is_none());
    }

    #[test]
    fn parse_pax_linkpath_recognized() {
        let blob = b"24 linkpath=/tmp/foo\n";
        assert_eq!(blob.len(), 21);
        let blob = b"21 linkpath=/tmp/foo\n";
        assert_eq!(blob.len(), 21);
        let (path, link) = parse_pax(blob);
        assert!(path.is_none());
        assert_eq!(link.as_deref(), Some("/tmp/foo"));
    }

    #[test]
    fn parse_pax_multiple_records() {
        let blob = b"21 linkpath=/tmp/foo\n18 path=hello.txt\n";
        assert_eq!(blob.len(), 39);
        let (path, link) = parse_pax(blob);
        assert_eq!(path.as_deref(), Some("hello.txt"));
        assert_eq!(link.as_deref(), Some("/tmp/foo"));
    }
}
