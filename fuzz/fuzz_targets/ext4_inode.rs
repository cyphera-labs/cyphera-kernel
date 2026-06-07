#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 128 {
        return;
    }
    let raw = parse_raw_inode(data);

    let s = raw.size();
    assert_eq!(s & 0xFFFF_FFFF, raw.i_size_lo as u64);
    assert_eq!(s >> 32, raw.i_size_hi as u64);

    let _ = raw.kind();

    let uid = raw.uid();
    assert_eq!(uid & 0xFFFF, raw.i_uid_lo as u32);
    assert_eq!(uid >> 16, raw.i_uid_hi as u32);
    let gid = raw.gid();
    assert_eq!(gid & 0xFFFF, raw.i_gid_lo as u32);
    assert_eq!(gid >> 16, raw.i_gid_hi as u32);

    let _ = raw.perm_bits();
    let _ = raw.has_extents();
});

const I_MODE_FIFO: u16 = 0x1000;
const I_MODE_CHR: u16 = 0x2000;
const I_MODE_DIR: u16 = 0x4000;
const I_MODE_FILE: u16 = 0x8000;
const I_MODE_LNK: u16 = 0xA000;

const I_FLAG_EXTENTS: u32 = 0x80000;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum InodeKind {
    Regular,
    Directory,
    CharDevice,
    Symlink,
    Pipe,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RawInode {
    i_mode: u16,
    i_uid_lo: u16,
    i_size_lo: u32,
    i_atime: u32,
    i_ctime: u32,
    i_mtime: u32,
    i_dtime: u32,
    i_gid_lo: u16,
    i_links_count: u16,
    i_blocks_lo: u32,
    i_flags: u32,
    i_block: [u8; 60],
    i_generation: u32,
    i_size_hi: u32,
    i_blocks_hi: u16,
    i_uid_hi: u16,
    i_gid_hi: u16,
    i_extra_isize: u16,
}

fn parse_raw_inode(buf: &[u8]) -> RawInode {
    let i_mode = u16::from_le_bytes([buf[0], buf[1]]);
    let i_uid_lo = u16::from_le_bytes([buf[2], buf[3]]);
    let i_size_lo = read_u32(buf, 4);
    let i_atime = read_u32(buf, 8);
    let i_ctime = read_u32(buf, 12);
    let i_mtime = read_u32(buf, 16);
    let i_dtime = read_u32(buf, 20);
    let i_gid_lo = u16::from_le_bytes([buf[24], buf[25]]);
    let i_links_count = u16::from_le_bytes([buf[26], buf[27]]);
    let i_blocks_lo = read_u32(buf, 28);
    let i_flags = read_u32(buf, 32);
    let mut i_block = [0u8; 60];
    i_block.copy_from_slice(&buf[40..100]);
    let i_generation = read_u32(buf, 100);
    let i_size_hi = if buf.len() >= 112 {
        read_u32(buf, 108)
    } else {
        0
    };
    let i_blocks_hi = if buf.len() >= 118 {
        u16::from_le_bytes([buf[116], buf[117]])
    } else {
        0
    };
    let i_uid_hi = if buf.len() >= 122 {
        u16::from_le_bytes([buf[120], buf[121]])
    } else {
        0
    };
    let i_gid_hi = if buf.len() >= 124 {
        u16::from_le_bytes([buf[122], buf[123]])
    } else {
        0
    };
    let i_extra_isize = if buf.len() >= 130 {
        u16::from_le_bytes([buf[128], buf[129]])
    } else {
        0
    };
    RawInode {
        i_mode,
        i_uid_lo,
        i_size_lo,
        i_atime,
        i_ctime,
        i_mtime,
        i_dtime,
        i_gid_lo,
        i_links_count,
        i_blocks_lo,
        i_flags,
        i_block,
        i_generation,
        i_size_hi,
        i_blocks_hi,
        i_uid_hi,
        i_gid_hi,
        i_extra_isize,
    }
}

impl RawInode {
    fn size(&self) -> u64 {
        ((self.i_size_hi as u64) << 32) | self.i_size_lo as u64
    }

    fn uid(&self) -> u32 {
        ((self.i_uid_hi as u32) << 16) | self.i_uid_lo as u32
    }

    fn gid(&self) -> u32 {
        ((self.i_gid_hi as u32) << 16) | self.i_gid_lo as u32
    }

    fn kind(&self) -> InodeKind {
        match self.i_mode & 0xF000 {
            I_MODE_DIR => InodeKind::Directory,
            I_MODE_FILE => InodeKind::Regular,
            I_MODE_CHR => InodeKind::CharDevice,
            I_MODE_LNK => InodeKind::Symlink,
            I_MODE_FIFO => InodeKind::Pipe,
            _ => InodeKind::Regular,
        }
    }

    fn perm_bits(&self) -> u16 {
        self.i_mode & 0o7777
    }

    fn has_extents(&self) -> bool {
        self.i_flags & I_FLAG_EXTENTS != 0
    }
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
