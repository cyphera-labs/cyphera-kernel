#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }

    if let Ok(h) = parse_extent_header(&data[..12]) {
        assert_eq!(h.magic, EXT4_EXT_MAGIC);
    }

    let leaf = parse_extent(&data[..12]);
    let real = leaf.real_len();
    assert!(
        real <= 0x7FFF,
        "extent real_len {} exceeds 15-bit on-disk field",
        real
    );
    let phys = leaf.start_phys();
    assert_eq!(phys & 0xFFFF_FFFF, leaf.start_lo as u64);
    assert_eq!(phys >> 32, leaf.start_hi as u64);

    let idx = parse_extent_idx(&data[..12]);
    let leaf_phys = idx.leaf_phys();
    assert_eq!(leaf_phys & 0xFFFF_FFFF, idx.leaf_lo as u64);
    assert_eq!(leaf_phys >> 32, idx.leaf_hi as u64);

    if data.len() >= 60 {
        let _ = walk_inode_block(&data[..60]);
    }
});

const EXT4_EXT_MAGIC: u16 = 0xF30A;

#[derive(Debug)]
#[allow(dead_code)]
enum Ext4Error {
    BadInode,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct ExtentHeader {
    magic: u16,
    entries: u16,
    max: u16,
    depth: u16,
    generation: u32,
}

fn parse_extent_header(buf: &[u8]) -> Result<ExtentHeader, Ext4Error> {
    if buf.len() < 12 {
        return Err(Ext4Error::BadInode);
    }
    let magic = u16::from_le_bytes([buf[0], buf[1]]);
    if magic != EXT4_EXT_MAGIC {
        return Err(Ext4Error::BadInode);
    }
    Ok(ExtentHeader {
        magic,
        entries: u16::from_le_bytes([buf[2], buf[3]]),
        max: u16::from_le_bytes([buf[4], buf[5]]),
        depth: u16::from_le_bytes([buf[6], buf[7]]),
        generation: read_u32(buf, 8),
    })
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct Extent {
    block: u32,
    len: u16,
    start_hi: u16,
    start_lo: u32,
}

fn parse_extent(buf: &[u8]) -> Extent {
    Extent {
        block: read_u32(buf, 0),
        len: u16::from_le_bytes([buf[4], buf[5]]),
        start_hi: u16::from_le_bytes([buf[6], buf[7]]),
        start_lo: read_u32(buf, 8),
    }
}

impl Extent {
    fn start_phys(&self) -> u64 {
        ((self.start_hi as u64) << 32) | self.start_lo as u64
    }

    fn real_len(&self) -> u32 {
        if self.len & 0x8000 != 0 {
            (self.len & 0x7FFF) as u32
        } else {
            self.len as u32
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct ExtentIdx {
    block: u32,
    leaf_lo: u32,
    leaf_hi: u16,
    _unused: u16,
}

fn parse_extent_idx(buf: &[u8]) -> ExtentIdx {
    ExtentIdx {
        block: read_u32(buf, 0),
        leaf_lo: read_u32(buf, 4),
        leaf_hi: u16::from_le_bytes([buf[8], buf[9]]),
        _unused: u16::from_le_bytes([buf[10], buf[11]]),
    }
}

impl ExtentIdx {
    fn leaf_phys(&self) -> u64 {
        ((self.leaf_hi as u64) << 32) | self.leaf_lo as u64
    }
}

fn walk_inode_block(buf: &[u8]) -> Result<(), Ext4Error> {
    let h = parse_extent_header(&buf[..12])?;
    let stride = 12;
    let mut off = stride;
    let mut count = 0usize;
    while off + stride <= buf.len() && count < h.entries as usize {
        if h.depth == 0 {
            let _ = parse_extent(&buf[off..off + stride]);
        } else {
            let _ = parse_extent_idx(&buf[off..off + stride]);
        }
        off += stride;
        count += 1;
    }
    Ok(())
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
