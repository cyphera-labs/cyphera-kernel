#![no_main]

use libfuzzer_sys::fuzz_target;
use object::elf::{FileHeader64, SHT_GNU_HASH, SHT_HASH, SHT_REL, SHT_RELA};
use object::read::elf::{
    ElfFile, FileHeader, GnuHashTable, HashTable, Rel, Rela, SectionHeader,
};
use object::Endianness;

fuzz_target!(|data: &[u8]| {
    let elf: ElfFile<FileHeader64<Endianness>> = match ElfFile::parse(data) {
        Ok(e) => e,
        Err(_) => return,
    };
    let header = elf.elf_header();
    let endian = match header.endian() {
        Ok(e) => e,
        Err(_) => return,
    };

    for (_sect_idx, sh) in elf.elf_section_table().enumerate() {
        match sh.sh_type(endian) {
            SHT_RELA => {
                if let Ok(Some((relas, _link))) = sh.rela(endian, data) {
                    for r in relas {
                        let _ = r.r_offset(endian);
                        let _ = r.r_addend(endian);
                        let _ = r.r_sym(endian, false);
                        let _ = r.r_type(endian, false);
                    }
                }
            }
            SHT_REL => {
                if let Ok(Some((rels, _link))) = sh.rel(endian, data) {
                    for r in rels {
                        let _ = r.r_offset(endian);
                        let _ = r.r_sym(endian);
                        let _ = r.r_type(endian);
                    }
                }
            }
            SHT_HASH => {
                if let Ok(bytes) = sh.data(endian, data) {
                    let _ = HashTable::<FileHeader64<Endianness>>::parse(endian, bytes);
                }
            }
            SHT_GNU_HASH => {
                if let Ok(bytes) = sh.data(endian, data) {
                    let _ = GnuHashTable::<FileHeader64<Endianness>>::parse(endian, bytes);
                }
            }
            _ => {}
        }
    }
});
