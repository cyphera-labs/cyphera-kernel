#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    i_mode: u16,
    file_type: u8,
}

fuzz_target!(|input: Input| {
    let kind = decode_kind(input.i_mode);
    let perm = decode_perm(input.i_mode);

    assert!(perm <= 0o7777, "perm_bits leaked: {:#o}", perm);

    assert!(matches!(
        kind,
        InodeKind::Regular
            | InodeKind::Directory
            | InodeKind::Symlink
            | InodeKind::CharDevice
            | InodeKind::Pipe
    ));

    let marker = mode_marker(kind);
    let rebuilt = marker | perm;
    let kind2 = decode_kind(rebuilt);
    assert_eq!(
        kind, kind2,
        "kind round-trip failed: {:?} -> {:#x} -> {:?}",
        kind, rebuilt, kind2
    );
    assert_eq!(
        decode_perm(rebuilt),
        perm,
        "perm round-trip failed for {:#x}",
        rebuilt
    );

    let ft_kind = kind_from_ft(input.file_type);
    match input.file_type {
        FT_REG | FT_DIR | FT_CHR | FT_BLK | FT_FIFO | FT_SOCK | FT_LNK => {
            assert!(
                ft_kind.is_some(),
                "kind_from_ft({}) rejected a documented code",
                input.file_type
            );
        }
        _ => {
            assert!(
                ft_kind.is_none(),
                "kind_from_ft({}) accepted an undocumented code",
                input.file_type
            );
        }
    }
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InodeKind {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    Pipe,
}

const I_MODE_FIFO: u16 = 0x1000;
const I_MODE_CHR: u16 = 0x2000;
const I_MODE_DIR: u16 = 0x4000;
const I_MODE_FILE: u16 = 0x8000;
const I_MODE_LNK: u16 = 0xA000;

fn decode_kind(i_mode: u16) -> InodeKind {
    match i_mode & 0xF000 {
        m if m == I_MODE_DIR => InodeKind::Directory,
        m if m == I_MODE_FILE => InodeKind::Regular,
        m if m == I_MODE_CHR => InodeKind::CharDevice,
        m if m == I_MODE_LNK => InodeKind::Symlink,
        m if m == I_MODE_FIFO => InodeKind::Pipe,
        _ => InodeKind::Regular,
    }
}

fn decode_perm(i_mode: u16) -> u16 {
    i_mode & 0o7777
}

fn mode_marker(kind: InodeKind) -> u16 {
    match kind {
        InodeKind::Regular => I_MODE_FILE,
        InodeKind::Directory => I_MODE_DIR,
        InodeKind::Symlink => I_MODE_LNK,
        InodeKind::CharDevice => I_MODE_CHR,
        InodeKind::Pipe => I_MODE_FIFO,
    }
}

const FT_REG: u8 = 1;
const FT_DIR: u8 = 2;
const FT_CHR: u8 = 3;
const FT_BLK: u8 = 4;
const FT_FIFO: u8 = 5;
const FT_SOCK: u8 = 6;
const FT_LNK: u8 = 7;

fn kind_from_ft(ft: u8) -> Option<InodeKind> {
    match ft {
        FT_REG => Some(InodeKind::Regular),
        FT_DIR => Some(InodeKind::Directory),
        FT_CHR => Some(InodeKind::CharDevice),
        FT_BLK => Some(InodeKind::CharDevice),
        FT_FIFO => Some(InodeKind::Pipe),
        FT_SOCK => Some(InodeKind::Pipe),
        FT_LNK => Some(InodeKind::Symlink),
        _ => None,
    }
}
