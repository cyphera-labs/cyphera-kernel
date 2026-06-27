extern crate alloc;

use alloc::vec::Vec;

#[cfg(not(host_test))]
use alloc::string::{String, ToString};
#[cfg(not(host_test))]
use alloc::sync::Arc;
#[cfg(not(host_test))]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(host_test))]
use frame::sync::SpinIrq;

use cyphera_kapi::{Errno, KResult};

#[cfg(not(host_test))]
use crate::vfs::{DirEntry, Inode, InodeKind, OpenFlags, Stat, TimeSpec};

#[cfg(not(host_test))]
pub trait BlockDevice: Send + Sync {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<()>;
    fn write_at(&self, offset: u64, buf: &[u8]) -> KResult<()>;
    fn capacity_bytes(&self) -> u64;
}

#[cfg(not(host_test))]
pub struct InMemoryDevice {
    bytes: SpinIrq<Vec<u8>>,
    cap: u64,
}

#[cfg(not(host_test))]
impl InMemoryDevice {
    pub fn new(initial: Vec<u8>) -> Arc<Self> {
        let cap = initial.len() as u64;
        Arc::new(Self {
            bytes: SpinIrq::new(initial),
            cap,
        })
    }
}

#[cfg(not(host_test))]
impl BlockDevice for InMemoryDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<()> {
        let g = self.bytes.lock();
        let start = offset as usize;
        let end = start.checked_add(buf.len()).ok_or(Errno::IO)?;
        if end > g.len() {
            return Err(Errno::IO);
        }
        buf.copy_from_slice(&g[start..end]);
        Ok(())
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> KResult<()> {
        let mut g = self.bytes.lock();
        let start = offset as usize;
        let end = start.checked_add(buf.len()).ok_or(Errno::IO)?;
        if end > g.len() {
            return Err(Errno::IO);
        }
        g[start..end].copy_from_slice(buf);
        Ok(())
    }
    fn capacity_bytes(&self) -> u64 {
        self.cap
    }
}

#[cfg(not(host_test))]
pub struct VirtioBlockDevice {
    cap: u64,
}

#[cfg(not(host_test))]
impl VirtioBlockDevice {
    pub fn new() -> Option<Arc<Self>> {
        let sectors = ::virtio::block_capacity_sectors()?;
        Some(Arc::new(Self {
            cap: sectors.saturating_mul(512),
        }))
    }
}

#[cfg(not(host_test))]
impl BlockDevice for VirtioBlockDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        offset
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= self.cap)
            .ok_or(Errno::IO)?;
        let first = offset / 512;
        let last = (offset + buf.len() as u64 - 1) / 512;
        let nsec = (last - first + 1) as usize;
        let mut tmp = alloc::vec![0u8; nsec * 512];
        crate::io::block_read(first, &mut tmp).map_err(|_| Errno::IO)?;
        let start = (offset - first * 512) as usize;
        buf.copy_from_slice(&tmp[start..start + buf.len()]);
        Ok(())
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> KResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        offset
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= self.cap)
            .ok_or(Errno::IO)?;
        let first = offset / 512;
        let last = (offset + buf.len() as u64 - 1) / 512;
        let nsec = (last - first + 1) as usize;
        let mut tmp = alloc::vec![0u8; nsec * 512];
        crate::io::block_read(first, &mut tmp).map_err(|_| Errno::IO)?;
        let start = (offset - first * 512) as usize;
        tmp[start..start + buf.len()].copy_from_slice(buf);
        crate::io::block_write(first, &tmp).map_err(|_| Errno::IO)
    }
    fn capacity_bytes(&self) -> u64 {
        self.cap
    }
}

const EXT4_MAGIC: u16 = 0xEF53;
const EXT4_ROOT_INO: u32 = 2;

const FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
const FEATURE_INCOMPAT_RECOVER: u32 = 0x0004;
const FEATURE_INCOMPAT_JOURNAL_DEV: u32 = 0x0008;
const FEATURE_INCOMPAT_META_BG: u32 = 0x0010;
const FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
const FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
const FEATURE_INCOMPAT_MMP: u32 = 0x0100;
const FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
const FEATURE_INCOMPAT_INLINE_DATA: u32 = 0x8000;
const FEATURE_INCOMPAT_ENCRYPT: u32 = 0x10000;
const FEATURE_INCOMPAT_CASEFOLD: u32 = 0x20000;

const FEATURE_INCOMPAT_SUPPORTED: u32 = FEATURE_INCOMPAT_FILETYPE
    | FEATURE_INCOMPAT_EXTENTS
    | FEATURE_INCOMPAT_64BIT
    | FEATURE_INCOMPAT_FLEX_BG
    | FEATURE_INCOMPAT_META_BG;

const FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
const FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x0002;
const FEATURE_RO_COMPAT_HUGE_FILE: u32 = 0x0008;
const FEATURE_RO_COMPAT_DIR_NLINK: u32 = 0x0020;
const FEATURE_RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;

const FEATURE_RO_COMPAT_SUPPORTED: u32 = FEATURE_RO_COMPAT_SPARSE_SUPER
    | FEATURE_RO_COMPAT_LARGE_FILE
    | FEATURE_RO_COMPAT_HUGE_FILE
    | FEATURE_RO_COMPAT_DIR_NLINK
    | FEATURE_RO_COMPAT_EXTRA_ISIZE;

const I_MODE_FIFO: u16 = 0x1000;
const I_MODE_CHR: u16 = 0x2000;
const I_MODE_DIR: u16 = 0x4000;
#[allow(dead_code)]
const I_MODE_BLK: u16 = 0x6000;
const I_MODE_FILE: u16 = 0x8000;
const I_MODE_LNK: u16 = 0xA000;

const I_FLAG_EXTENTS: u32 = 0x80000;
#[allow(dead_code)]
const I_FLAG_INDEX: u32 = 0x1000;

const FT_UNKNOWN: u8 = 0;
const FT_REG: u8 = 1;
const FT_DIR: u8 = 2;
const FT_CHR: u8 = 3;
const FT_BLK: u8 = 4;
const FT_FIFO: u8 = 5;
const FT_SOCK: u8 = 6;
const FT_LNK: u8 = 7;

const EXT4_EXT_MAGIC: u16 = 0xF30A;

#[derive(Debug, Clone)]
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

impl Superblock {
    fn parse(buf: &[u8]) -> KResult<Self> {
        if buf.len() < 1024 {
            return Err(Errno::INVAL);
        }
        let magic = u16::from_le_bytes([buf[56], buf[57]]);
        if magic != EXT4_MAGIC {
            return Err(Errno::INVAL);
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
        let inode_size = u16::from_le_bytes([buf[88], buf[89]]) as u32;
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
            return Err(Errno::INVAL);
        }
        if blocks_per_group == 0 || inodes_per_group == 0 {
            return Err(Errno::INVAL);
        }
        let block_size: u32 = 1024u32 << log_block_size;

        Ok(Self {
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
}

#[derive(Debug, Clone, Copy)]
struct Bgd {
    block_bitmap: u64,
    inode_bitmap: u64,
    inode_table: u64,
    free_blocks_count: u32,
    free_inodes_count: u32,
    used_dirs_count: u32,
    flags: u16,
}

impl Bgd {
    fn parse(buf: &[u8], desc_size: u16) -> Self {
        let block_bitmap_lo = read_u32(buf, 0) as u64;
        let inode_bitmap_lo = read_u32(buf, 4) as u64;
        let inode_table_lo = read_u32(buf, 8) as u64;
        let free_blocks_lo = u16::from_le_bytes([buf[12], buf[13]]) as u32;
        let free_inodes_lo = u16::from_le_bytes([buf[14], buf[15]]) as u32;
        let used_dirs_lo = u16::from_le_bytes([buf[16], buf[17]]) as u32;
        let flags = u16::from_le_bytes([buf[18], buf[19]]);
        let (
            block_bitmap_hi,
            inode_bitmap_hi,
            inode_table_hi,
            free_blocks_hi,
            free_inodes_hi,
            used_dirs_hi,
        ) = if desc_size >= 64 {
            (
                read_u32(buf, 32) as u64,
                read_u32(buf, 36) as u64,
                read_u32(buf, 40) as u64,
                u16::from_le_bytes([buf[44], buf[45]]) as u32,
                u16::from_le_bytes([buf[46], buf[47]]) as u32,
                u16::from_le_bytes([buf[48], buf[49]]) as u32,
            )
        } else {
            (0, 0, 0, 0, 0, 0)
        };
        Bgd {
            block_bitmap: (block_bitmap_hi << 32) | block_bitmap_lo,
            inode_bitmap: (inode_bitmap_hi << 32) | inode_bitmap_lo,
            inode_table: (inode_table_hi << 32) | inode_table_lo,
            free_blocks_count: (free_blocks_hi << 16) | free_blocks_lo,
            free_inodes_count: (free_inodes_hi << 16) | free_inodes_lo,
            used_dirs_count: (used_dirs_hi << 16) | used_dirs_lo,
            flags,
        }
    }

    fn serialize(&self, buf: &mut [u8], desc_size: u16) {
        write_u32(buf, 0, self.block_bitmap as u32);
        write_u32(buf, 4, self.inode_bitmap as u32);
        write_u32(buf, 8, self.inode_table as u32);
        buf[12..14].copy_from_slice(&(self.free_blocks_count as u16).to_le_bytes());
        buf[14..16].copy_from_slice(&(self.free_inodes_count as u16).to_le_bytes());
        buf[16..18].copy_from_slice(&(self.used_dirs_count as u16).to_le_bytes());
        buf[18..20].copy_from_slice(&self.flags.to_le_bytes());
        if desc_size >= 64 {
            write_u32(buf, 32, (self.block_bitmap >> 32) as u32);
            write_u32(buf, 36, (self.inode_bitmap >> 32) as u32);
            write_u32(buf, 40, (self.inode_table >> 32) as u32);
            buf[44..46].copy_from_slice(&((self.free_blocks_count >> 16) as u16).to_le_bytes());
            buf[46..48].copy_from_slice(&((self.free_inodes_count >> 16) as u16).to_le_bytes());
            buf[48..50].copy_from_slice(&((self.used_dirs_count >> 16) as u16).to_le_bytes());
        }
    }
}

#[derive(Debug, Clone)]
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

impl RawInode {
    fn parse(buf: &[u8]) -> Self {
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

    fn serialize(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.i_mode.to_le_bytes());
        buf[2..4].copy_from_slice(&self.i_uid_lo.to_le_bytes());
        write_u32(buf, 4, self.i_size_lo);
        write_u32(buf, 8, self.i_atime);
        write_u32(buf, 12, self.i_ctime);
        write_u32(buf, 16, self.i_mtime);
        write_u32(buf, 20, self.i_dtime);
        buf[24..26].copy_from_slice(&self.i_gid_lo.to_le_bytes());
        buf[26..28].copy_from_slice(&self.i_links_count.to_le_bytes());
        write_u32(buf, 28, self.i_blocks_lo);
        write_u32(buf, 32, self.i_flags);
        buf[40..100].copy_from_slice(&self.i_block);
        write_u32(buf, 100, self.i_generation);
        if buf.len() >= 112 {
            write_u32(buf, 108, self.i_size_hi);
        }
        if buf.len() >= 118 {
            buf[116..118].copy_from_slice(&self.i_blocks_hi.to_le_bytes());
        }
        if buf.len() >= 122 {
            buf[120..122].copy_from_slice(&self.i_uid_hi.to_le_bytes());
        }
        if buf.len() >= 124 {
            buf[122..124].copy_from_slice(&self.i_gid_hi.to_le_bytes());
        }
        if buf.len() >= 130 {
            buf[128..130].copy_from_slice(&self.i_extra_isize.to_le_bytes());
        }
    }

    fn size(&self) -> u64 {
        ((self.i_size_hi as u64) << 32) | self.i_size_lo as u64
    }

    fn set_size(&mut self, size: u64) {
        self.i_size_lo = size as u32;
        self.i_size_hi = (size >> 32) as u32;
    }

    fn uid(&self) -> u32 {
        ((self.i_uid_hi as u32) << 16) | self.i_uid_lo as u32
    }

    fn gid(&self) -> u32 {
        ((self.i_gid_hi as u32) << 16) | self.i_gid_lo as u32
    }

    #[cfg(not(host_test))]
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

#[derive(Debug, Clone, Copy)]
struct ExtentHeader {
    magic: u16,
    entries: u16,
    max: u16,
    depth: u16,
    generation: u32,
}

impl ExtentHeader {
    fn parse(buf: &[u8]) -> KResult<Self> {
        if buf.len() < 12 {
            return Err(Errno::INVAL);
        }
        let magic = u16::from_le_bytes([buf[0], buf[1]]);
        if magic != EXT4_EXT_MAGIC {
            return Err(Errno::INVAL);
        }
        Ok(ExtentHeader {
            magic,
            entries: u16::from_le_bytes([buf[2], buf[3]]),
            max: u16::from_le_bytes([buf[4], buf[5]]),
            depth: u16::from_le_bytes([buf[6], buf[7]]),
            generation: read_u32(buf, 8),
        })
    }

    fn write(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.magic.to_le_bytes());
        buf[2..4].copy_from_slice(&self.entries.to_le_bytes());
        buf[4..6].copy_from_slice(&self.max.to_le_bytes());
        buf[6..8].copy_from_slice(&self.depth.to_le_bytes());
        write_u32(buf, 8, self.generation);
    }
}

#[derive(Debug, Clone, Copy)]
struct Extent {
    block: u32,
    len: u16,
    start_hi: u16,
    start_lo: u32,
}

impl Extent {
    fn parse(buf: &[u8]) -> Self {
        Extent {
            block: read_u32(buf, 0),
            len: u16::from_le_bytes([buf[4], buf[5]]),
            start_hi: u16::from_le_bytes([buf[6], buf[7]]),
            start_lo: read_u32(buf, 8),
        }
    }

    fn write(&self, buf: &mut [u8]) {
        write_u32(buf, 0, self.block);
        buf[4..6].copy_from_slice(&self.len.to_le_bytes());
        buf[6..8].copy_from_slice(&self.start_hi.to_le_bytes());
        write_u32(buf, 8, self.start_lo);
    }

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
struct ExtentIdx {
    block: u32,
    leaf_lo: u32,
    leaf_hi: u16,
    _unused: u16,
}

impl ExtentIdx {
    fn parse(buf: &[u8]) -> Self {
        ExtentIdx {
            block: read_u32(buf, 0),
            leaf_lo: read_u32(buf, 4),
            leaf_hi: u16::from_le_bytes([buf[8], buf[9]]),
            _unused: u16::from_le_bytes([buf[10], buf[11]]),
        }
    }

    fn write(&self, buf: &mut [u8]) {
        write_u32(buf, 0, self.block);
        write_u32(buf, 4, self.leaf_lo);
        buf[8..10].copy_from_slice(&self.leaf_hi.to_le_bytes());
        buf[10..12].copy_from_slice(&self._unused.to_le_bytes());
    }

    fn leaf_phys(&self) -> u64 {
        ((self.leaf_hi as u64) << 32) | self.leaf_lo as u64
    }
}

fn parse_extents(buf: &[u8], entries: u16) -> Vec<Extent> {
    (0..entries as usize)
        .map(|i| Extent::parse(&buf[12 + i * 12..12 + i * 12 + 12]))
        .collect()
}

fn parse_idxs(buf: &[u8], entries: u16) -> Vec<ExtentIdx> {
    (0..entries as usize)
        .map(|i| ExtentIdx::parse(&buf[12 + i * 12..12 + i * 12 + 12]))
        .collect()
}

fn write_extents(buf: &mut [u8], exts: &[Extent], max: u16, generation: u32) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    ExtentHeader {
        magic: EXT4_EXT_MAGIC,
        entries: exts.len() as u16,
        max,
        depth: 0,
        generation,
    }
    .write(&mut buf[..12]);
    for (i, e) in exts.iter().enumerate() {
        e.write(&mut buf[12 + i * 12..12 + i * 12 + 12]);
    }
}

fn write_idxs(buf: &mut [u8], idxs: &[ExtentIdx], generation: u32) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    ExtentHeader {
        magic: EXT4_EXT_MAGIC,
        entries: idxs.len() as u16,
        max: 4,
        depth: 1,
        generation,
    }
    .write(&mut buf[..12]);
    for (i, e) in idxs.iter().enumerate() {
        e.write(&mut buf[12 + i * 12..12 + i * 12 + 12]);
    }
}

fn sorted_insert_extent(exts: &mut Vec<Extent>, ext: Extent) {
    let pos = exts.partition_point(|e| e.block < ext.block);
    exts.insert(pos, ext);
}

fn sorted_insert_idx(idxs: &mut Vec<ExtentIdx>, idx: ExtentIdx) {
    let pos = idxs.partition_point(|e| e.block < idx.block);
    idxs.insert(pos, idx);
}

#[cfg(not(host_test))]
static NEXT_EXT4_DEV_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(not(host_test))]
pub struct Ext4Fs {
    device: Arc<dyn BlockDevice>,
    sb: SpinIrq<Superblock>,
    bgds: SpinIrq<Vec<Bgd>>,
    pub block_size: u32,
    inode_size: u32,
    inodes_per_group: u32,
    blocks_per_group: u32,
    first_data_block: u64,
    #[allow(dead_code)]
    desc_size: u16,
    has_filetype: bool,
    dev_id: u64,
}

#[cfg(not(host_test))]
impl Ext4Fs {
    pub fn mount(device: Arc<dyn BlockDevice>) -> KResult<Arc<Self>> {
        let mut sb_buf = [0u8; 1024];
        device.read_at(1024, &mut sb_buf)?;
        let sb = Superblock::parse(&sb_buf)?;

        let unsupported = sb.feature_incompat & !FEATURE_INCOMPAT_SUPPORTED;
        if unsupported & FEATURE_INCOMPAT_RECOVER != 0 {
            return Err(Errno::INVAL);
        }
        if unsupported
            & (FEATURE_INCOMPAT_ENCRYPT
                | FEATURE_INCOMPAT_CASEFOLD
                | FEATURE_INCOMPAT_MMP
                | FEATURE_INCOMPAT_INLINE_DATA
                | FEATURE_INCOMPAT_JOURNAL_DEV)
            != 0
        {
            return Err(Errno::INVAL);
        }

        if sb.feature_ro_compat & !FEATURE_RO_COMPAT_SUPPORTED != 0 {
            return Err(Errno::INVAL);
        }

        let block_size = sb.block_size;
        let blocks_per_group = sb.blocks_per_group;
        let inodes_per_group = sb.inodes_per_group;
        let inode_size = sb.inode_size;
        let first_data_block = sb.first_data_block as u64;
        let desc_size = sb.desc_size;
        let has_filetype = sb.feature_incompat & FEATURE_INCOMPAT_FILETYPE != 0;
        let blocks_count = sb.blocks_count;
        let group_count = blocks_count.div_ceil(blocks_per_group as u64);

        let gdt_start_block = if block_size == 1024 { 2 } else { 1 };
        let gdt_byte_offset = (gdt_start_block as u64) * (block_size as u64);
        let gdt_total_bytes = group_count * desc_size as u64;
        let gdt_blocks = gdt_total_bytes.div_ceil(block_size as u64);
        let mut gdt_buf = alloc::vec![0u8; (gdt_blocks * block_size as u64) as usize];
        device.read_at(gdt_byte_offset, &mut gdt_buf)?;
        let mut bgds = Vec::with_capacity(group_count as usize);
        for i in 0..group_count {
            let off = (i as usize) * (desc_size as usize);
            bgds.push(Bgd::parse(
                &gdt_buf[off..off + desc_size as usize],
                desc_size,
            ));
        }

        let dev_id = 0xe400_0000_0000_0000 | NEXT_EXT4_DEV_ID.fetch_add(1, Ordering::Relaxed);

        Ok(Arc::new(Self {
            device,
            sb: SpinIrq::new(sb),
            bgds: SpinIrq::new(bgds),
            block_size,
            inode_size,
            inodes_per_group,
            blocks_per_group,
            first_data_block,
            desc_size,
            has_filetype,
            dev_id,
        }))
    }

    pub fn root_inode(self: &Arc<Self>) -> Arc<dyn Inode> {
        Arc::new(Ext4Inode::new(self.clone(), EXT4_ROOT_INO))
    }

    fn read_block(&self, phys: u64) -> KResult<Vec<u8>> {
        let mut buf = alloc::vec![0u8; self.block_size as usize];
        self.device
            .read_at(phys * self.block_size as u64, &mut buf)?;
        Ok(buf)
    }

    fn write_block(&self, phys: u64, data: &[u8]) -> KResult<()> {
        if data.len() != self.block_size as usize {
            return Err(Errno::IO);
        }
        self.device.write_at(phys * self.block_size as u64, data)
    }

    fn read_inode(&self, ino: u32) -> KResult<RawInode> {
        if ino == 0 {
            return Err(Errno::INVAL);
        }
        let group = (ino - 1) / self.inodes_per_group;
        let index_in_group = (ino - 1) % self.inodes_per_group;
        let bgds = self.bgds.lock();
        let bgd = bgds.get(group as usize).copied().ok_or(Errno::INVAL)?;
        drop(bgds);
        let table_start_byte = bgd.inode_table * self.block_size as u64;
        let inode_byte = table_start_byte + (index_in_group as u64) * (self.inode_size as u64);
        let mut buf = alloc::vec![0u8; self.inode_size as usize];
        self.device.read_at(inode_byte, &mut buf)?;
        Ok(RawInode::parse(&buf))
    }

    fn write_inode(&self, ino: u32, raw: &RawInode) -> KResult<()> {
        if ino == 0 {
            return Err(Errno::INVAL);
        }
        let group = (ino - 1) / self.inodes_per_group;
        let index_in_group = (ino - 1) % self.inodes_per_group;
        let bgds = self.bgds.lock();
        let bgd = bgds.get(group as usize).copied().ok_or(Errno::INVAL)?;
        drop(bgds);
        let table_start_byte = bgd.inode_table * self.block_size as u64;
        let inode_byte = table_start_byte + (index_in_group as u64) * (self.inode_size as u64);
        let mut buf = alloc::vec![0u8; self.inode_size as usize];
        self.device.read_at(inode_byte, &mut buf)?;
        raw.serialize(&mut buf);
        self.device.write_at(inode_byte, &buf)
    }

    fn resolve_block(&self, raw: &RawInode, logical: u64) -> KResult<Option<u64>> {
        if !raw.has_extents() {
            return Err(Errno::INVAL);
        }
        let header = ExtentHeader::parse(&raw.i_block[..])?;
        self.walk_extents(&raw.i_block[..], header, logical)
    }

    fn walk_extents(
        &self,
        node_buf: &[u8],
        header: ExtentHeader,
        logical: u64,
    ) -> KResult<Option<u64>> {
        let entries = header.entries as usize;
        if header.depth == 0 {
            for i in 0..entries {
                let off = 12 + i * 12;
                let ext = Extent::parse(&node_buf[off..off + 12]);
                let lo = ext.block as u64;
                let hi = lo + ext.real_len() as u64;
                if logical >= lo && logical < hi {
                    return Ok(Some(ext.start_phys() + (logical - lo)));
                }
            }
            Ok(None)
        } else {
            let mut chosen: Option<ExtentIdx> = None;
            for i in 0..entries {
                let off = 12 + i * 12;
                let idx = ExtentIdx::parse(&node_buf[off..off + 12]);
                if (idx.block as u64) <= logical && chosen.is_none_or(|c| idx.block >= c.block) {
                    chosen = Some(idx);
                }
            }
            let idx = chosen.ok_or(Errno::IO)?;
            let leaf = self.read_block(idx.leaf_phys())?;
            let leaf_header = ExtentHeader::parse(&leaf)?;
            self.walk_extents(&leaf, leaf_header, logical)
        }
    }

    fn alloc_block(&self) -> KResult<u64> {
        let mut bgds = self.bgds.lock();
        for (group_idx, bgd) in bgds.iter_mut().enumerate() {
            if bgd.free_blocks_count == 0 {
                continue;
            }
            let mut bitmap = alloc::vec![0u8; self.block_size as usize];
            self.device
                .read_at(bgd.block_bitmap * self.block_size as u64, &mut bitmap)?;
            for byte_idx in 0..bitmap.len() {
                if bitmap[byte_idx] == 0xff {
                    continue;
                }
                let bit = (!bitmap[byte_idx]).trailing_zeros() as usize;
                let block_idx_in_group = (byte_idx * 8 + bit) as u64;
                if block_idx_in_group >= self.blocks_per_group as u64 {
                    break;
                }
                bitmap[byte_idx] |= 1 << bit;
                self.device
                    .write_at(bgd.block_bitmap * self.block_size as u64, &bitmap)?;
                bgd.free_blocks_count -= 1;
                self.persist_bgd(group_idx, bgd)?;
                let block_no = self.first_data_block
                    + (group_idx as u64) * self.blocks_per_group as u64
                    + block_idx_in_group;
                let zeros = alloc::vec![0u8; self.block_size as usize];
                self.write_block(block_no, &zeros)?;
                return Ok(block_no);
            }
        }
        Err(Errno::NOSPC)
    }

    fn persist_bgd(&self, group_idx: usize, bgd: &Bgd) -> KResult<()> {
        let sb = self.sb.lock();
        let block_size = sb.block_size;
        let desc_size = sb.desc_size;
        drop(sb);
        let gdt_start_block = if block_size == 1024 { 2 } else { 1 };
        let gdt_byte_offset = (gdt_start_block as u64) * (block_size as u64);
        let off = gdt_byte_offset + (group_idx as u64) * (desc_size as u64);
        let mut buf = alloc::vec![0u8; desc_size as usize];
        self.device.read_at(off, &mut buf)?;
        bgd.serialize(&mut buf, desc_size);
        self.device.write_at(off, &buf)
    }

    fn free_block(&self, phys: u64) -> KResult<()> {
        let rel = phys.saturating_sub(self.first_data_block);
        let group_idx = (rel / self.blocks_per_group as u64) as usize;
        let bit_in_group = (rel % self.blocks_per_group as u64) as usize;
        let mut bgds = self.bgds.lock();
        let bgd = bgds.get_mut(group_idx).ok_or(Errno::IO)?;
        let mut bitmap = alloc::vec![0u8; self.block_size as usize];
        self.device
            .read_at(bgd.block_bitmap * self.block_size as u64, &mut bitmap)?;
        bitmap[bit_in_group / 8] &= !(1 << (bit_in_group % 8));
        self.device
            .write_at(bgd.block_bitmap * self.block_size as u64, &bitmap)?;
        bgd.free_blocks_count += 1;
        let bgd_copy = *bgd;
        drop(bgds);
        self.persist_bgd(group_idx, &bgd_copy)
    }

    fn alloc_inode(&self, kind: InodeKind) -> KResult<u32> {
        let mut bgds = self.bgds.lock();
        for (group_idx, bgd) in bgds.iter_mut().enumerate() {
            if bgd.free_inodes_count == 0 {
                continue;
            }
            let mut bitmap = alloc::vec![0u8; self.block_size as usize];
            self.device
                .read_at(bgd.inode_bitmap * self.block_size as u64, &mut bitmap)?;
            for byte_idx in 0..bitmap.len() {
                if bitmap[byte_idx] == 0xff {
                    continue;
                }
                let bit = (!bitmap[byte_idx]).trailing_zeros() as usize;
                let inode_idx_in_group = (byte_idx * 8 + bit) as u32;
                if inode_idx_in_group >= self.inodes_per_group {
                    break;
                }
                bitmap[byte_idx] |= 1 << bit;
                self.device
                    .write_at(bgd.inode_bitmap * self.block_size as u64, &bitmap)?;
                bgd.free_inodes_count -= 1;
                if kind == InodeKind::Directory {
                    bgd.used_dirs_count += 1;
                }
                let bgd_copy = *bgd;
                self.persist_bgd(group_idx, &bgd_copy)?;
                let ino = (group_idx as u32) * self.inodes_per_group + inode_idx_in_group + 1;
                return Ok(ino);
            }
        }
        Err(Errno::NOSPC)
    }
}

#[cfg(not(host_test))]
pub struct Ext4Inode {
    fs: Arc<Ext4Fs>,
    ino: u32,
}

#[cfg(not(host_test))]
impl Ext4Inode {
    fn new(fs: Arc<Ext4Fs>, ino: u32) -> Self {
        Self { fs, ino }
    }

    fn raw(&self) -> KResult<RawInode> {
        self.fs.read_inode(self.ino)
    }

    fn write_raw(&self, raw: &RawInode) -> KResult<()> {
        self.fs.write_inode(self.ino, raw)
    }

    fn read_data(&self, offset: u64, buf: &mut [u8]) -> KResult<usize> {
        let raw = self.raw()?;
        let size = raw.size();
        if offset >= size {
            return Ok(0);
        }
        let bs = self.fs.block_size as u64;
        let to_read = (size - offset).min(buf.len() as u64) as usize;
        let mut written = 0usize;
        let mut cur = offset;
        let end = offset + to_read as u64;
        let mut block_buf = alloc::vec![0u8; bs as usize];
        while cur < end {
            let logical = cur / bs;
            let in_block = (cur % bs) as usize;
            let chunk = ((bs - cur % bs) as usize).min((end - cur) as usize);
            match self.fs.resolve_block(&raw, logical)? {
                Some(phys) => {
                    self.fs.device.read_at(phys * bs, &mut block_buf)?;
                    buf[written..written + chunk]
                        .copy_from_slice(&block_buf[in_block..in_block + chunk]);
                }
                None => {
                    for b in &mut buf[written..written + chunk] {
                        *b = 0;
                    }
                }
            }
            written += chunk;
            cur += chunk as u64;
        }
        Ok(written)
    }

    fn append_extent(&self, raw: &mut RawInode, logical: u32, phys: u64, len: u16) -> KResult<()> {
        let header = ExtentHeader::parse(&raw.i_block[..])?;
        let new_ext = Extent {
            block: logical,
            len,
            start_hi: (phys >> 32) as u16,
            start_lo: phys as u32,
        };
        let bs = self.fs.block_size as usize;
        let max_leaf = ((bs - 12) / 12) as u16;

        if header.depth == 0 {
            let mut exts = parse_extents(&raw.i_block[..], header.entries);
            sorted_insert_extent(&mut exts, new_ext);
            if exts.len() <= 4 {
                write_extents(&mut raw.i_block[..], &exts, 4, header.generation);
                return Ok(());
            }
            let leaf_phys = self.fs.alloc_block()?;
            let mut leaf = alloc::vec![0u8; bs];
            write_extents(&mut leaf, &exts, max_leaf, header.generation);
            self.fs.write_block(leaf_phys, &leaf)?;
            let idx = ExtentIdx {
                block: exts[0].block,
                leaf_lo: leaf_phys as u32,
                leaf_hi: (leaf_phys >> 32) as u16,
                _unused: 0,
            };
            write_idxs(&mut raw.i_block[..], &[idx], header.generation);
            return Ok(());
        }

        let mut idxs = parse_idxs(&raw.i_block[..], header.entries);
        let mut target = 0usize;
        for (i, ix) in idxs.iter().enumerate() {
            if (ix.block as u64) <= (logical as u64) {
                target = i;
            }
        }
        let leaf_phys = idxs[target].leaf_phys();
        let mut leaf = self.fs.read_block(leaf_phys)?;
        let leaf_header = ExtentHeader::parse(&leaf)?;
        debug_assert_eq!(
            leaf_header.depth, 0,
            "depth-2 extent trees are not supported"
        );
        let mut leaf_exts = parse_extents(&leaf, leaf_header.entries);

        if (leaf_exts.len() as u16) < max_leaf {
            sorted_insert_extent(&mut leaf_exts, new_ext);
            idxs[target].block = leaf_exts[0].block;
            write_extents(&mut leaf, &leaf_exts, max_leaf, leaf_header.generation);
            self.fs.write_block(leaf_phys, &leaf)?;
            write_idxs(&mut raw.i_block[..], &idxs, header.generation);
            return Ok(());
        }

        let last = leaf_exts.last().unwrap();
        let leaf_end = last.block as u64 + last.real_len() as u64;
        if idxs.len() >= 4 {
            return Err(Errno::NOSPC);
        }
        if (logical as u64) >= leaf_end {
            let new_leaf_phys = self.fs.alloc_block()?;
            let mut new_leaf = alloc::vec![0u8; bs];
            write_extents(&mut new_leaf, &[new_ext], max_leaf, leaf_header.generation);
            self.fs.write_block(new_leaf_phys, &new_leaf)?;
            let new_idx = ExtentIdx {
                block: logical,
                leaf_lo: new_leaf_phys as u32,
                leaf_hi: (new_leaf_phys >> 32) as u16,
                _unused: 0,
            };
            sorted_insert_idx(&mut idxs, new_idx);
            write_idxs(&mut raw.i_block[..], &idxs, header.generation);
            return Ok(());
        }

        let new_leaf_phys = self.fs.alloc_block()?;
        sorted_insert_extent(&mut leaf_exts, new_ext);
        let mid = leaf_exts.len() / 2;
        let upper = leaf_exts.split_off(mid);
        let mut new_leaf = alloc::vec![0u8; bs];
        write_extents(&mut new_leaf, &upper, max_leaf, leaf_header.generation);
        self.fs.write_block(new_leaf_phys, &new_leaf)?;
        write_extents(&mut leaf, &leaf_exts, max_leaf, leaf_header.generation);
        self.fs.write_block(leaf_phys, &leaf)?;
        idxs[target].block = leaf_exts[0].block;
        let new_idx = ExtentIdx {
            block: upper[0].block,
            leaf_lo: new_leaf_phys as u32,
            leaf_hi: (new_leaf_phys >> 32) as u16,
            _unused: 0,
        };
        sorted_insert_idx(&mut idxs, new_idx);
        write_idxs(&mut raw.i_block[..], &idxs, header.generation);
        Ok(())
    }

    fn write_data(&self, offset: u64, buf: &[u8]) -> KResult<usize> {
        let mut raw = self.raw()?;
        let bs = self.fs.block_size as u64;
        let mut written = 0usize;
        let mut cur = offset;
        let end = offset + buf.len() as u64;
        let mut block_buf = alloc::vec![0u8; bs as usize];
        while cur < end {
            let logical = cur / bs;
            let in_block = (cur % bs) as usize;
            let chunk = ((bs - cur % bs) as usize).min((end - cur) as usize);
            let phys = match self.fs.resolve_block(&raw, logical)? {
                Some(p) => p,
                None => {
                    let p = self.fs.alloc_block()?;
                    self.append_extent(&mut raw, logical as u32, p, 1)?;
                    p
                }
            };
            self.fs.device.read_at(phys * bs, &mut block_buf)?;
            block_buf[in_block..in_block + chunk].copy_from_slice(&buf[written..written + chunk]);
            self.fs.device.write_at(phys * bs, &block_buf)?;
            written += chunk;
            cur += chunk as u64;
        }
        if cur > raw.size() {
            raw.set_size(cur);
        }
        let now = (frame::cpu::clock::wall_clock_nanos() / 1_000_000_000) as u32;
        raw.i_mtime = now;
        raw.i_ctime = now;
        self.write_raw(&raw)?;
        Ok(written)
    }

    fn shrink_leaf_extents(&self, exts: &[Extent], cutoff: u64) -> Vec<Extent> {
        let mut kept = Vec::new();
        for ext in exts {
            let lo = ext.block as u64;
            let real = ext.real_len() as u64;
            let hi = lo + real;
            if lo >= cutoff {
                for b in 0..real {
                    let _ = self.fs.free_block(ext.start_phys() + b);
                }
            } else if hi <= cutoff {
                kept.push(*ext);
            } else {
                let keep = cutoff - lo;
                for b in keep..real {
                    let _ = self.fs.free_block(ext.start_phys() + b);
                }
                let mut trimmed = *ext;
                trimmed.len = (keep as u16) & 0x7FFF;
                kept.push(trimmed);
            }
        }
        kept
    }

    fn truncate_to(&self, len: u64) -> KResult<()> {
        let mut raw = self.raw()?;
        let bs = self.fs.block_size as u64;
        let max_leaf = ((self.fs.block_size as usize - 12) / 12) as u16;
        if raw.has_extents() && (len == 0 || len < raw.size()) {
            let header = ExtentHeader::parse(&raw.i_block[..])?;
            let cutoff = if len == 0 { 0 } else { len.div_ceil(bs) };
            if header.depth == 0 {
                let exts = parse_extents(&raw.i_block[..], header.entries);
                let kept = self.shrink_leaf_extents(&exts, cutoff);
                write_extents(&mut raw.i_block[..], &kept, 4, header.generation);
            } else {
                let idxs = parse_idxs(&raw.i_block[..], header.entries);
                let mut kept_idxs: Vec<ExtentIdx> = Vec::new();
                for mut idx in idxs {
                    let leaf = self.fs.read_block(idx.leaf_phys())?;
                    let lh = ExtentHeader::parse(&leaf)?;
                    debug_assert_eq!(lh.depth, 0, "depth-2 extent trees are not supported");
                    let exts = parse_extents(&leaf, lh.entries);
                    let kept = self.shrink_leaf_extents(&exts, cutoff);
                    if kept.is_empty() {
                        let _ = self.fs.free_block(idx.leaf_phys());
                    } else {
                        idx.block = kept[0].block;
                        let mut leaf_buf = alloc::vec![0u8; self.fs.block_size as usize];
                        write_extents(&mut leaf_buf, &kept, max_leaf, lh.generation);
                        self.fs.write_block(idx.leaf_phys(), &leaf_buf)?;
                        kept_idxs.push(idx);
                    }
                }
                if kept_idxs.is_empty() {
                    write_extents(&mut raw.i_block[..], &[], 4, header.generation);
                } else {
                    write_idxs(&mut raw.i_block[..], &kept_idxs, header.generation);
                }
            }
        }
        raw.set_size(len);
        let now = (frame::cpu::clock::wall_clock_nanos() / 1_000_000_000) as u32;
        raw.i_mtime = now;
        raw.i_ctime = now;
        self.write_raw(&raw)
    }

    fn read_dir_entries(&self) -> KResult<Vec<RawDirent>> {
        let raw = self.raw()?;
        if raw.kind() != InodeKind::Directory {
            return Err(Errno::NOTDIR);
        }
        let size = raw.size();
        let mut data = alloc::vec![0u8; size as usize];
        self.read_data(0, &mut data)?;
        Ok(parse_dir_entries(&data))
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RawDirent {
    inode: u32,
    rec_len: u16,
    name_len: u8,
    file_type: u8,
    name: Vec<u8>,
}

fn parse_dir_entries(data: &[u8]) -> Vec<RawDirent> {
    let mut entries = Vec::new();
    let mut p = 0usize;
    while p + 8 <= data.len() {
        let inode = read_u32(data, p);
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
            entries.push(RawDirent {
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

#[cfg(not(host_test))]
fn ft_for_kind(kind: InodeKind) -> u8 {
    match kind {
        InodeKind::Regular => FT_REG,
        InodeKind::Directory => FT_DIR,
        InodeKind::CharDevice => FT_CHR,
        InodeKind::Symlink => FT_LNK,
        InodeKind::Pipe => FT_FIFO,
        InodeKind::Socket => FT_SOCK,
    }
}

#[cfg(not(host_test))]
fn kind_from_ft(ft: u8) -> Option<InodeKind> {
    match ft {
        FT_REG => Some(InodeKind::Regular),
        FT_DIR => Some(InodeKind::Directory),
        FT_CHR => Some(InodeKind::CharDevice),
        FT_BLK => Some(InodeKind::CharDevice),
        FT_FIFO => Some(InodeKind::Pipe),
        FT_SOCK => Some(InodeKind::Pipe),
        FT_LNK => Some(InodeKind::Symlink),
        FT_UNKNOWN => None,
        _ => None,
    }
}

#[cfg(not(host_test))]
impl Inode for Ext4Inode {
    fn kind(&self) -> InodeKind {
        self.raw().map(|r| r.kind()).unwrap_or(InodeKind::Regular)
    }

    fn inode_id(&self) -> u64 {
        self.fs.dev_id ^ (self.ino as u64)
    }

    fn fs_id(&self) -> usize {
        Arc::as_ptr(&self.fs) as usize
    }

    fn stat(&self) -> Stat {
        let raw = self.raw().unwrap_or(RawInode {
            i_mode: 0,
            i_uid_lo: 0,
            i_size_lo: 0,
            i_atime: 0,
            i_ctime: 0,
            i_mtime: 0,
            i_dtime: 0,
            i_gid_lo: 0,
            i_links_count: 0,
            i_blocks_lo: 0,
            i_flags: 0,
            i_block: [0; 60],
            i_generation: 0,
            i_size_hi: 0,
            i_blocks_hi: 0,
            i_uid_hi: 0,
            i_gid_hi: 0,
            i_extra_isize: 0,
        });
        let size = raw.size();
        Stat {
            size,
            kind: raw.kind(),
            mode: raw.perm_bits(),
            nlink: raw.i_links_count as u32,
            uid: raw.uid(),
            gid: raw.gid(),
            inode_id: self.inode_id(),
            dev_id: self.fs.dev_id,
            rdev: 0,
            blksize: self.fs.block_size,
            blocks: size.div_ceil(512),
            atime: TimeSpec {
                sec: raw.i_atime as i64,
                nsec: 0,
            },
            mtime: TimeSpec {
                sec: raw.i_mtime as i64,
                nsec: 0,
            },
            ctime: TimeSpec {
                sec: raw.i_ctime as i64,
                nsec: 0,
            },
        }
    }

    fn set_mode(&self, mode: u16) -> KResult<()> {
        let mut raw = self.raw()?;
        raw.i_mode = (raw.i_mode & 0xF000) | (mode & 0o7777);
        let now = (frame::cpu::clock::wall_clock_nanos() / 1_000_000_000) as u32;
        raw.i_ctime = now;
        self.write_raw(&raw)
    }

    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> KResult<()> {
        let mut raw = self.raw()?;
        if let Some(u) = uid {
            raw.i_uid_lo = u as u16;
            raw.i_uid_hi = (u >> 16) as u16;
        }
        if let Some(g) = gid {
            raw.i_gid_lo = g as u16;
            raw.i_gid_hi = (g >> 16) as u16;
        }
        let now = (frame::cpu::clock::wall_clock_nanos() / 1_000_000_000) as u32;
        raw.i_ctime = now;
        self.write_raw(&raw)
    }

    fn set_times(&self, atime: Option<TimeSpec>, mtime: Option<TimeSpec>) -> KResult<()> {
        let mut raw = self.raw()?;
        if let Some(a) = atime {
            raw.i_atime = a.sec as u32;
        }
        if let Some(m) = mtime {
            raw.i_mtime = m.sec as u32;
        }
        let now = (frame::cpu::clock::wall_clock_nanos() / 1_000_000_000) as u32;
        raw.i_ctime = now;
        self.write_raw(&raw)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<usize> {
        let raw = self.raw()?;
        if raw.kind() != InodeKind::Regular {
            return Err(Errno::ISDIR);
        }
        let id = self.inode_id();
        let mut total = 0usize;
        while total < buf.len() {
            let cur_off = offset + total as u64;
            let page_off = cur_off & !0xfff;
            let in_page = (cur_off - page_off) as usize;
            let want = (buf.len() - total).min(4096 - in_page);
            if let Some(cached) = crate::fs::pagecache::lookup(id, page_off) {
                let avail = cached.len().saturating_sub(in_page);
                if avail == 0 {
                    break;
                }
                let n = avail.min(want);
                buf[total..total + n].copy_from_slice(&cached[in_page..in_page + n]);
                total += n;
                if n < want {
                    break;
                }
                continue;
            }
            let mut page = alloc::vec![0u8; 4096];
            let got = self.read_data(page_off, &mut page)?;
            if got == 0 {
                break;
            }
            crate::fs::pagecache::insert(id, page_off, &page[..got]);
            let avail_in_page = got.saturating_sub(in_page);
            if avail_in_page == 0 {
                break;
            }
            let n = avail_in_page.min(want);
            buf[total..total + n].copy_from_slice(&page[in_page..in_page + n]);
            total += n;
            if n < want {
                break;
            }
        }
        Ok(total)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> KResult<usize> {
        let raw = self.raw()?;
        if raw.kind() != InodeKind::Regular {
            return Err(Errno::ISDIR);
        }
        let n = self.write_data(offset, buf)?;
        crate::fs::pagecache::write_through(self.inode_id(), offset, &buf[..n]);
        Ok(n)
    }

    fn truncate(&self, len: u64) -> KResult<()> {
        let raw = self.raw()?;
        if raw.kind() != InodeKind::Regular {
            return Err(Errno::ISDIR);
        }
        crate::fs::pagecache::invalidate_range(self.inode_id(), len, u64::MAX);
        self.truncate_to(len)
    }

    fn lookup(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        let entries = self.read_dir_entries()?;
        for e in &entries {
            if e.name == name.as_bytes() {
                return Ok(Arc::new(Ext4Inode::new(self.fs.clone(), e.inode)));
            }
        }
        Err(Errno::NOENT)
    }

    fn create(&self, name: &str, kind: InodeKind) -> KResult<Arc<dyn Inode>> {
        let new_ino = self.fs.alloc_inode(kind)?;
        let mode_bits = match kind {
            InodeKind::Regular => I_MODE_FILE | 0o644,
            InodeKind::Directory => I_MODE_DIR | 0o755,
            InodeKind::Symlink => I_MODE_LNK | 0o777,
            InodeKind::CharDevice => I_MODE_CHR | 0o666,
            InodeKind::Pipe => I_MODE_FIFO | 0o600,
            InodeKind::Socket => 0xC000 | 0o600,
        };
        let now = (frame::cpu::clock::wall_clock_nanos() / 1_000_000_000) as u32;
        let mut new_raw = RawInode {
            i_mode: mode_bits,
            i_uid_lo: 0,
            i_size_lo: 0,
            i_atime: now,
            i_ctime: now,
            i_mtime: now,
            i_dtime: 0,
            i_gid_lo: 0,
            i_links_count: if kind == InodeKind::Directory { 2 } else { 1 },
            i_blocks_lo: 0,
            i_flags: I_FLAG_EXTENTS,
            i_block: [0; 60],
            i_generation: 0,
            i_size_hi: 0,
            i_blocks_hi: 0,
            i_uid_hi: 0,
            i_gid_hi: 0,
            i_extra_isize: 32,
        };
        let header = ExtentHeader {
            magic: EXT4_EXT_MAGIC,
            entries: 0,
            max: 4,
            depth: 0,
            generation: 0,
        };
        header.write(&mut new_raw.i_block[..12]);

        if kind == InodeKind::Directory {
            let block = self.fs.alloc_block()?;
            let mut blk = alloc::vec![0u8; self.fs.block_size as usize];
            write_u32(&mut blk, 0, new_ino);
            blk[4..6].copy_from_slice(&12u16.to_le_bytes());
            blk[6] = 1;
            blk[7] = FT_DIR;
            blk[8] = b'.';
            write_u32(&mut blk, 12, self.ino);
            let rest = (self.fs.block_size - 12) as u16;
            blk[16..18].copy_from_slice(&rest.to_le_bytes());
            blk[18] = 2;
            blk[19] = FT_DIR;
            blk[20] = b'.';
            blk[21] = b'.';
            self.fs.write_block(block, &blk)?;

            self.append_extent(&mut new_raw, 0, block, 1)?;
            new_raw.set_size(self.fs.block_size as u64);
        }
        self.fs.write_inode(new_ino, &new_raw)?;

        self.dir_add_entry(name, new_ino, ft_for_kind(kind))?;

        if kind == InodeKind::Directory {
            let mut self_raw = self.raw()?;
            self_raw.i_links_count += 1;
            self.write_raw(&self_raw)?;
        }

        Ok(Arc::new(Ext4Inode::new(self.fs.clone(), new_ino)))
    }

    fn list(&self) -> KResult<Vec<DirEntry>> {
        let entries = self.read_dir_entries()?;
        let mut out = Vec::new();
        for e in &entries {
            if e.name == b"." || e.name == b".." {
                continue;
            }
            let name = match String::from_utf8(e.name.clone()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let kind = if self.fs.has_filetype {
                kind_from_ft(e.file_type).unwrap_or(InodeKind::Regular)
            } else {
                Ext4Inode::new(self.fs.clone(), e.inode).kind()
            };
            out.push(DirEntry {
                name,
                kind,
                inode_id: self.fs.dev_id ^ (e.inode as u64),
            });
        }
        Ok(out)
    }

    fn unlink(&self, name: &str) -> KResult<()> {
        let entries = self.read_dir_entries()?;
        let mut found_ino: Option<u32> = None;
        for e in &entries {
            if e.name == name.as_bytes() {
                found_ino = Some(e.inode);
                break;
            }
        }
        let ino = found_ino.ok_or(Errno::NOENT)?;
        self.dir_remove_entry(name)?;
        let target = Ext4Inode::new(self.fs.clone(), ino);
        let mut traw = target.raw()?;
        traw.i_links_count = traw.i_links_count.saturating_sub(1);
        if traw.i_links_count == 0 {
            let _ = target.truncate_to(0);
            traw.i_dtime = (frame::cpu::clock::wall_clock_nanos() / 1_000_000_000) as u32;
        }
        target.write_raw(&traw)?;
        Ok(())
    }

    fn link(&self, name: &str, target: Arc<dyn Inode>) -> KResult<()> {
        if target.kind() == InodeKind::Directory {
            return Err(Errno::ACCES);
        }
        let target_id = target.inode_id();
        let target_ino = (target_id ^ self.fs.dev_id) as u32;
        let _ = self.fs.read_inode(target_ino)?;
        let kind = target.kind();
        self.dir_add_entry(name, target_ino, ft_for_kind(kind))?;
        target.bump_nlink();
        Ok(())
    }

    fn symlink(&self, name: &str, target: &str) -> KResult<Arc<dyn Inode>> {
        let new_ino = self.fs.alloc_inode(InodeKind::Symlink)?;
        let now = (frame::cpu::clock::wall_clock_nanos() / 1_000_000_000) as u32;
        let mut raw = RawInode {
            i_mode: I_MODE_LNK | 0o777,
            i_uid_lo: 0,
            i_size_lo: target.len() as u32,
            i_atime: now,
            i_ctime: now,
            i_mtime: now,
            i_dtime: 0,
            i_gid_lo: 0,
            i_links_count: 1,
            i_blocks_lo: 0,
            i_flags: 0,
            i_block: [0; 60],
            i_generation: 0,
            i_size_hi: 0,
            i_blocks_hi: 0,
            i_uid_hi: 0,
            i_gid_hi: 0,
            i_extra_isize: 32,
        };
        if target.len() <= 60 {
            raw.i_block[..target.len()].copy_from_slice(target.as_bytes());
        } else {
            raw.i_flags = I_FLAG_EXTENTS;
            let header = ExtentHeader {
                magic: EXT4_EXT_MAGIC,
                entries: 0,
                max: 4,
                depth: 0,
                generation: 0,
            };
            header.write(&mut raw.i_block[..12]);
            let block = self.fs.alloc_block()?;
            let mut data = alloc::vec![0u8; self.fs.block_size as usize];
            data[..target.len()].copy_from_slice(target.as_bytes());
            self.fs.write_block(block, &data)?;
            let new_inode = Ext4Inode::new(self.fs.clone(), new_ino);
            new_inode.append_extent(&mut raw, 0, block, 1)?;
        }
        self.fs.write_inode(new_ino, &raw)?;
        self.dir_add_entry(name, new_ino, FT_LNK)?;
        Ok(Arc::new(Ext4Inode::new(self.fs.clone(), new_ino)))
    }

    fn read_link(&self) -> KResult<String> {
        let raw = self.raw()?;
        if raw.kind() != InodeKind::Symlink {
            return Err(Errno::INVAL);
        }
        let size = raw.size() as usize;
        if size <= 60 && !raw.has_extents() {
            let s = core::str::from_utf8(&raw.i_block[..size]).map_err(|_| Errno::INVAL)?;
            return Ok(s.to_string());
        }
        let mut buf = alloc::vec![0u8; size];
        self.read_data(0, &mut buf)?;
        core::str::from_utf8(&buf)
            .map(|s| s.to_string())
            .map_err(|_| Errno::INVAL)
    }

    fn rmdir(&self, name: &str) -> KResult<()> {
        let target = self.lookup(name)?;
        if target.kind() != InodeKind::Directory {
            return Err(Errno::NOTDIR);
        }
        let entries = target.list()?;
        if !entries.is_empty() {
            return Err(Errno::NOTEMPTY);
        }
        self.dir_remove_entry(name)?;
        let target_id = target.inode_id();
        let target_ino = (target_id ^ self.fs.dev_id) as u32;
        let mut traw = self.fs.read_inode(target_ino)?;
        traw.i_links_count = 0;
        traw.i_dtime = (frame::cpu::clock::wall_clock_nanos() / 1_000_000_000) as u32;
        let _ = Ext4Inode::new(self.fs.clone(), target_ino).truncate_to(0);
        self.fs.write_inode(target_ino, &traw)?;
        let mut self_raw = self.raw()?;
        self_raw.i_links_count = self_raw.i_links_count.saturating_sub(1);
        self.write_raw(&self_raw)?;
        Ok(())
    }

    fn mknod(&self, name: &str, kind: InodeKind, _dev: u64) -> KResult<Arc<dyn Inode>> {
        match kind {
            InodeKind::Regular | InodeKind::CharDevice | InodeKind::Pipe => self.create(name, kind),
            _ => Err(Errno::INVAL),
        }
    }

    fn rename(&self, old_name: &str, new_parent: &Arc<dyn Inode>, new_name: &str) -> KResult<()> {
        let entries = self.read_dir_entries()?;
        let mut found: Option<(u32, u8)> = None;
        for e in &entries {
            if e.name == old_name.as_bytes() {
                found = Some((e.inode, e.file_type));
                break;
            }
        }
        let (ino, ft) = found.ok_or(Errno::NOENT)?;
        if let Ok(existing) = new_parent.lookup(new_name) {
            let existing_ino = (existing.inode_id() ^ self.fs.dev_id) as u32;
            if existing_ino == ino {
                return Ok(());
            }
            let src_dir = ft == FT_DIR;
            let dst_dir = existing.kind() == InodeKind::Directory;
            match (src_dir, dst_dir) {
                (false, true) => return Err(Errno::ISDIR),
                (true, false) => return Err(Errno::NOTDIR),
                (true, true) => new_parent.rmdir(new_name)?,
                (false, false) => new_parent.unlink(new_name)?,
            }
        }
        let new_target = Ext4Inode::new(self.fs.clone(), ino);
        let new_target_arc: Arc<dyn Inode> = Arc::new(new_target);
        new_parent
            .link(new_name, new_target_arc.clone())
            .or_else(|_| {
                if Arc::as_ptr(new_parent) as *const () == self as *const _ as *const () {
                    self.dir_add_entry(new_name, ino, ft)
                } else {
                    Err(Errno::ACCES)
                }
            })?;
        if let Ok(mut tr) = self.fs.read_inode(ino) {
            if ft != FT_DIR {
                tr.i_links_count = tr.i_links_count.saturating_sub(1);
                let _ = self.fs.write_inode(ino, &tr);
            }
        }
        self.dir_remove_entry(old_name)?;
        Ok(())
    }

    fn bump_nlink(&self) {
        if let Ok(mut raw) = self.raw() {
            raw.i_links_count = raw.i_links_count.saturating_add(1);
            let _ = self.write_raw(&raw);
        }
    }

    fn drop_nlink(&self) {
        if let Ok(mut raw) = self.raw() {
            raw.i_links_count = raw.i_links_count.saturating_sub(1);
            let _ = self.write_raw(&raw);
        }
    }

    fn on_open(&self, _flags: OpenFlags) {}
    fn on_close(&self, _flags: OpenFlags) {}
}

#[cfg(not(host_test))]
impl Ext4Inode {
    fn dir_add_entry(&self, name: &str, ino: u32, ft: u8) -> KResult<()> {
        let raw = self.raw()?;
        let bs = self.fs.block_size as u64;
        let dir_blocks = raw.size() / bs;
        let name_bytes = name.as_bytes();
        let needed = align_up(8 + name_bytes.len(), 4);
        for dblk in 0..dir_blocks {
            let phys = match self.fs.resolve_block(&raw, dblk)? {
                Some(p) => p,
                None => continue,
            };
            let mut block = self.fs.read_block(phys)?;
            let mut p = 0usize;
            while p + 8 <= block.len() {
                let rec_len = u16::from_le_bytes([block[p + 4], block[p + 5]]) as usize;
                let inode = read_u32(&block, p);
                let name_len = block[p + 6] as usize;
                let actual = align_up(8 + name_len, 4);
                if rec_len == 0 || rec_len < actual {
                    break;
                }
                let slack = rec_len - actual;
                let last = p + rec_len >= block.len();
                if slack >= needed && (last || inode != 0 || rec_len > needed) {
                    let new_cur_len = if inode == 0 && last {
                        block[p..p + 4].copy_from_slice(&ino.to_le_bytes());
                        block[p + 4..p + 6].copy_from_slice(&(rec_len as u16).to_le_bytes());
                        block[p + 6] = name_bytes.len() as u8;
                        block[p + 7] = ft;
                        block[p + 8..p + 8 + name_bytes.len()].copy_from_slice(name_bytes);
                        block[p + 8 + name_bytes.len()..p + rec_len].fill(0);
                        self.fs.write_block(phys, &block)?;
                        return Ok(());
                    } else {
                        actual
                    };
                    block[p + 4..p + 6].copy_from_slice(&(new_cur_len as u16).to_le_bytes());
                    let new_p = p + new_cur_len;
                    let new_rec_len = rec_len - new_cur_len;
                    block[new_p..new_p + 4].copy_from_slice(&ino.to_le_bytes());
                    block[new_p + 4..new_p + 6]
                        .copy_from_slice(&(new_rec_len as u16).to_le_bytes());
                    block[new_p + 6] = name_bytes.len() as u8;
                    block[new_p + 7] = ft;
                    block[new_p + 8..new_p + 8 + name_bytes.len()].copy_from_slice(name_bytes);
                    block[new_p + 8 + name_bytes.len()..new_p + new_rec_len].fill(0);
                    self.fs.write_block(phys, &block)?;
                    return Ok(());
                }
                p += rec_len;
            }
        }
        let new_block = self.fs.alloc_block()?;
        let mut block = alloc::vec![0u8; self.fs.block_size as usize];
        let total = self.fs.block_size as u16;
        block[0..4].copy_from_slice(&ino.to_le_bytes());
        block[4..6].copy_from_slice(&total.to_le_bytes());
        block[6] = name_bytes.len() as u8;
        block[7] = ft;
        block[8..8 + name_bytes.len()].copy_from_slice(name_bytes);
        self.fs.write_block(new_block, &block)?;
        let mut raw_mut = self.raw()?;
        self.append_extent(&mut raw_mut, dir_blocks as u32, new_block, 1)?;
        raw_mut.set_size(raw_mut.size() + bs);
        self.write_raw(&raw_mut)
    }

    fn dir_remove_entry(&self, name: &str) -> KResult<()> {
        let raw = self.raw()?;
        let bs = self.fs.block_size as u64;
        let dir_blocks = raw.size() / bs;
        let name_bytes = name.as_bytes();
        for dblk in 0..dir_blocks {
            let phys = match self.fs.resolve_block(&raw, dblk)? {
                Some(p) => p,
                None => continue,
            };
            let mut block = self.fs.read_block(phys)?;
            let mut prev: Option<usize> = None;
            let mut p = 0usize;
            while p + 8 <= block.len() {
                let rec_len = u16::from_le_bytes([block[p + 4], block[p + 5]]) as usize;
                let inode = read_u32(&block, p);
                let name_len = block[p + 6] as usize;
                if rec_len == 0 {
                    break;
                }
                if inode != 0
                    && name_len == name_bytes.len()
                    && &block[p + 8..p + 8 + name_len] == name_bytes
                {
                    if let Some(prev_off) = prev {
                        let prev_rec_len =
                            u16::from_le_bytes([block[prev_off + 4], block[prev_off + 5]]) as usize;
                        let new_prev = prev_rec_len + rec_len;
                        block[prev_off + 4..prev_off + 6]
                            .copy_from_slice(&(new_prev as u16).to_le_bytes());
                    } else {
                        block[p..p + 4].copy_from_slice(&0u32.to_le_bytes());
                    }
                    self.fs.write_block(phys, &block)?;
                    return Ok(());
                }
                prev = Some(p);
                p += rec_len;
            }
        }
        Err(Errno::NOENT)
    }
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn align_up(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

#[cfg(host_test)]
#[cfg(test)]
mod host_tests {
    use super::*;

    fn make_sb(log_block_size: u32) -> Vec<u8> {
        let mut buf = alloc::vec![0u8; 1024];
        buf[56] = 0x53;
        buf[57] = 0xEF;
        buf[24..28].copy_from_slice(&log_block_size.to_le_bytes());
        buf[40..44].copy_from_slice(&8192u32.to_le_bytes());
        buf[32..36].copy_from_slice(&8192u32.to_le_bytes());
        buf
    }

    #[test]
    fn superblock_rejects_short_buffer() {
        let short = alloc::vec![0u8; 100];
        assert!(matches!(Superblock::parse(&short), Err(Errno::INVAL)));
    }

    #[test]
    fn superblock_rejects_bad_magic() {
        let mut buf = make_sb(2);
        buf[56] = 0;
        buf[57] = 0;
        assert!(matches!(Superblock::parse(&buf), Err(Errno::INVAL)));
    }

    #[test]
    fn superblock_accepts_4k_block_size() {
        let buf = make_sb(2);
        let sb = Superblock::parse(&buf).unwrap();
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.log_block_size, 2);
    }

    #[test]
    fn superblock_accepts_1k_block_size() {
        let buf = make_sb(0);
        let sb = Superblock::parse(&buf).unwrap();
        assert_eq!(sb.block_size, 1024);
    }

    #[test]
    fn superblock_accepts_64k_block_size_boundary() {
        let buf = make_sb(6);
        let sb = Superblock::parse(&buf).unwrap();
        assert_eq!(sb.block_size, 1024 << 6);
    }

    #[test]
    fn superblock_rejects_oversized_block_size() {
        let buf = make_sb(7);
        assert!(matches!(Superblock::parse(&buf), Err(Errno::INVAL)));
    }

    #[test]
    fn superblock_rejects_shift_overflow_log_block_size() {
        for lbs in [7u32, 16, 31, 32, 33, 64, 100, u32::MAX] {
            let buf = make_sb(lbs);
            assert!(matches!(Superblock::parse(&buf), Err(Errno::INVAL)));
        }
    }

    #[test]
    fn parse_dir_entries_handles_empty_data() {
        let entries = parse_dir_entries(&[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_dir_entries_walks_one_entry() {
        let mut buf = alloc::vec![0u8; 16];
        buf[0..4].copy_from_slice(&11u32.to_le_bytes());
        buf[4..6].copy_from_slice(&16u16.to_le_bytes());
        buf[6] = 4;
        buf[7] = 2;
        buf[8..12].copy_from_slice(b"abcd");
        let entries = parse_dir_entries(&buf);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].inode, 11);
        assert_eq!(entries[0].name_len, 4);
        assert_eq!(&entries[0].name, b"abcd");
    }

    #[test]
    fn parse_dir_entries_skips_zero_inode() {
        let mut buf = alloc::vec![0u8; 16];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        buf[4..6].copy_from_slice(&16u16.to_le_bytes());
        buf[6] = 4;
        buf[7] = 1;
        let entries = parse_dir_entries(&buf);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_dir_entries_rejects_rec_len_zero() {
        let mut buf = alloc::vec![0u8; 16];
        buf[0..4].copy_from_slice(&5u32.to_le_bytes());
        buf[4..6].copy_from_slice(&0u16.to_le_bytes());
        buf[6] = 4;
        buf[7] = 1;
        let entries = parse_dir_entries(&buf);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_dir_entries_rejects_rec_len_too_short() {
        let mut buf = alloc::vec![0u8; 16];
        buf[0..4].copy_from_slice(&5u32.to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        buf[6] = 0;
        buf[7] = 0;
        let entries = parse_dir_entries(&buf);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_dir_entries_rejects_rec_len_past_buffer() {
        let mut buf = alloc::vec![0u8; 16];
        buf[0..4].copy_from_slice(&5u32.to_le_bytes());
        buf[4..6].copy_from_slice(&999u16.to_le_bytes());
        buf[6] = 4;
        buf[7] = 1;
        let entries = parse_dir_entries(&buf);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_dir_entries_rejects_name_len_past_rec_len() {
        let mut buf = alloc::vec![0u8; 32];
        buf[0..4].copy_from_slice(&5u32.to_le_bytes());
        buf[4..6].copy_from_slice(&16u16.to_le_bytes());
        buf[6] = 100;
        buf[7] = 1;
        let entries = parse_dir_entries(&buf);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_dir_entries_walks_two_entries() {
        let mut buf = alloc::vec![0u8; 32];
        buf[0..4].copy_from_slice(&11u32.to_le_bytes());
        buf[4..6].copy_from_slice(&16u16.to_le_bytes());
        buf[6] = 4;
        buf[7] = 2;
        buf[8..12].copy_from_slice(b"abcd");
        buf[16..20].copy_from_slice(&12u32.to_le_bytes());
        buf[20..22].copy_from_slice(&16u16.to_le_bytes());
        buf[22] = 2;
        buf[23] = 1;
        buf[24..26].copy_from_slice(b"xy");
        let entries = parse_dir_entries(&buf);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].inode, 11);
        assert_eq!(entries[1].inode, 12);
        assert_eq!(&entries[1].name, b"xy");
    }

    #[test]
    fn parse_dir_entries_handles_name_len_zero() {
        let mut buf = alloc::vec![0u8; 16];
        buf[0..4].copy_from_slice(&3u32.to_le_bytes());
        buf[4..6].copy_from_slice(&16u16.to_le_bytes());
        buf[6] = 0;
        buf[7] = 0;
        let entries = parse_dir_entries(&buf);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].name.is_empty());
    }

    #[test]
    fn extent_header_rejects_short_buffer() {
        let short = [0u8; 11];
        assert!(matches!(ExtentHeader::parse(&short), Err(Errno::INVAL)));
    }

    #[test]
    fn extent_header_rejects_bad_magic() {
        let mut buf = [0u8; 12];
        buf[0] = 0xFF;
        buf[1] = 0xFF;
        assert!(matches!(ExtentHeader::parse(&buf), Err(Errno::INVAL)));
    }

    #[test]
    fn extent_header_accepts_valid_magic() {
        let mut buf = [0u8; 12];
        buf[0..2].copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&3u16.to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        let hdr = ExtentHeader::parse(&buf).unwrap();
        assert_eq!(hdr.entries, 3);
        assert_eq!(hdr.max, 4);
        assert_eq!(hdr.depth, 0);
    }

    #[test]
    fn extent_real_len_strips_uninitialized_bit() {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        buf[4..6].copy_from_slice(&0x8005u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        buf[8..12].copy_from_slice(&100u32.to_le_bytes());
        let ext = Extent::parse(&buf);
        assert_eq!(ext.real_len(), 5);
        assert_eq!(ext.start_phys(), 100);
    }
}
