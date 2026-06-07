#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let entries = parse_dir_block(data);

    let max_entries = data.len() / 8 + 1;
    assert!(
        entries.len() <= max_entries,
        "produced {} entries from {}-byte buffer (max {})",
        entries.len(),
        data.len(),
        max_entries,
    );

    for e in &entries {
        assert!(
            e.rec_len >= 8,
            "entry rec_len {} below 8-byte header minimum",
            e.rec_len
        );
        assert!(
            e.offset
                .checked_add(e.rec_len as usize)
                .is_some_and(|end| end <= data.len()),
            "entry at offset {} + rec_len {} overflows {}-byte buffer",
            e.offset,
            e.rec_len,
            data.len(),
        );
        assert_eq!(
            e.name.len(),
            e.name_len as usize,
            "entry name length {} disagrees with name_len {}",
            e.name.len(),
            e.name_len,
        );
    }
});

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ParsedEntry {
    offset: usize,
    inode: u32,
    rec_len: u16,
    name_len: u8,
    file_type: u8,
    name: alloc::vec::Vec<u8>,
}

extern crate alloc;

fn parse_dir_block(data: &[u8]) -> alloc::vec::Vec<ParsedEntry> {
    let mut entries = alloc::vec::Vec::new();
    let mut p = 0usize;
    while p + 8 <= data.len() {
        let inode = u32::from_le_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
        let rec_len = u16::from_le_bytes([data[p + 4], data[p + 5]]) as usize;
        let name_len = data[p + 6] as usize;
        let file_type = data[p + 7];
        if rec_len == 0 || rec_len < 8 || p + rec_len > data.len() {
            break;
        }
        if name_len + 8 > rec_len {
            break;
        }
        if inode != 0 {
            let name = data[p + 8..p + 8 + name_len].to_vec();
            entries.push(ParsedEntry {
                offset: p,
                inode,
                rec_len: rec_len as u16,
                name_len: name_len as u8,
                file_type,
                name,
            });
        }
        p += rec_len;
    }
    entries
}
