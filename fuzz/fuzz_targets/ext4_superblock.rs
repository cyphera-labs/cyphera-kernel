#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 1024 {
        return;
    }
    if let Ok(sb) = parse_superblock(&data[..1024]) {
        assert!(
            sb.block_size.is_power_of_two(),
            "ext4 block_size not power of two: {}",
            sb.block_size
        );
        assert_ne!(sb.inode_size, 0, "ext4 inode_size zero after parse");
        assert_ne!(sb.desc_size, 0, "ext4 desc_size zero after parse");
    }
});

const EXT4_MAGIC: u16 = 0xEF53;
const FEATURE_INCOMPAT_64BIT: u32 = 0x0080;

#[derive(Debug)]
#[allow(dead_code)]
enum Ext4Error {
    BadMagic,
    BadSuperblock,
}

#[derive(Debug)]
#[allow(dead_code)]
struct Superblock {
    inodes_count: u32,
    blocks_count: u64,
    log_block_size: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    state: u16,
    inode_size: u32,
    feature_compat: u32,
    feature_incompat: u32,
    feature_ro_compat: u32,
    desc_size: u16,
    first_data_block: u32,
    block_size: u32,
}

fn parse_superblock(buf: &[u8]) -> Result<Superblock, Ext4Error> {
    if buf.len() < 1024 {
        return Err(Ext4Error::BadMagic);
    }
    let magic = u16::from_le_bytes([buf[56], buf[57]]);
    if magic != EXT4_MAGIC {
        return Err(Ext4Error::BadMagic);
    }
    let inodes_count = read_u32(buf, 0);
    let blocks_count_lo = read_u32(buf, 4);
    let log_block_size = read_u32(buf, 24);
    let blocks_per_group = read_u32(buf, 32);
    let inodes_per_group = read_u32(buf, 40);
    let state = u16::from_le_bytes([buf[58], buf[59]]);
    let feature_compat = read_u32(buf, 92);
    let feature_incompat = read_u32(buf, 96);
    let feature_ro_compat = read_u32(buf, 100);
    let inode_size = if feature_compat & 0x4 != 0 {
        u16::from_le_bytes([buf[88], buf[89]]) as u32
    } else {
        u16::from_le_bytes([buf[88], buf[89]]) as u32
    };
    let inode_size = if inode_size == 0 { 128 } else { inode_size };
    let desc_size = if feature_incompat & FEATURE_INCOMPAT_64BIT != 0 {
        u16::from_le_bytes([buf[254], buf[255]])
    } else {
        32
    };
    let desc_size = if desc_size == 0 { 32 } else { desc_size };
    let first_data_block = read_u32(buf, 20);

    let blocks_count_hi = if feature_incompat & FEATURE_INCOMPAT_64BIT != 0 {
        read_u32(buf, 336)
    } else {
        0
    };
    let blocks_count = ((blocks_count_hi as u64) << 32) | blocks_count_lo as u64;
    if log_block_size > 6 {
        return Err(Ext4Error::BadSuperblock);
    }
    let block_size: u32 = 1024u32 << log_block_size;

    Ok(Superblock {
        inodes_count,
        blocks_count,
        log_block_size,
        blocks_per_group,
        inodes_per_group,
        state,
        inode_size,
        feature_compat,
        feature_incompat,
        feature_ro_compat,
        desc_size,
        first_data_block,
        block_size,
    })
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
