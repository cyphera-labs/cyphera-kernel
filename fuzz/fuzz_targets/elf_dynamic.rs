#![no_main]

use libfuzzer_sys::fuzz_target;
use object::elf::{
    FileHeader64, SHT_DYNAMIC, SHT_DYNSYM, SHT_NOTE, SHT_STRTAB, SHT_SYMTAB,
};
use object::read::elf::{Dyn, ElfFile, FileHeader, SectionHeader, Sym};
use object::{Endianness, StringTable};

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
    let section_table = elf.elf_section_table();

    for sh_type in [SHT_SYMTAB, SHT_DYNSYM] {
        if let Ok(symtab) = section_table.symbols(endian, data, sh_type) {
            let strings: StringTable<_> = symtab.strings();
            for sym in symtab.iter() {
                let _ = sym.st_name(endian);
                let _ = sym.st_info();
                let _ = sym.st_value(endian);
                let _ = sym.st_size(endian);
                let _ = sym.name(endian, strings);
            }
        }
    }

    for (_sect_idx, sh) in section_table.enumerate() {
        let ty = sh.sh_type(endian);
        let _ = sh.data(endian, data);

        match ty {
            SHT_DYNAMIC => {
                if let Ok(Some((entries, _str_idx))) = sh.dynamic(endian, data) {
                    for e in entries {
                        let _ = e.d_tag(endian);
                        let _ = e.d_val(endian);
                    }
                }
            }
            SHT_NOTE => {
                if let Ok(Some(mut notes)) = sh.notes(endian, data) {
                    while let Ok(Some(note)) = notes.next() {
                        let _ = note.n_type(endian);
                        let _ = note.name();
                        let _ = note.desc();
                    }
                }
            }
            SHT_STRTAB => {
                let _ = sh.strings(endian, data);
            }
            _ => {}
        }
    }
});
