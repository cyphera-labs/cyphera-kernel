#![no_main]

use libfuzzer_sys::fuzz_target;
use object::Endianness;
use object::elf::FileHeader64;
use object::read::elf::{ElfFile, FileHeader, ProgramHeader, SectionHeader};

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

    let _ = header.e_ident();
    let _ = header.e_machine(endian);
    let _ = header.e_entry(endian);
    let _ = header.e_phoff(endian);
    let _ = header.e_phentsize(endian);
    let _ = header.e_phnum(endian);

    for ph in elf.elf_program_headers() {
        let _ = ph.p_type(endian);
        let _ = ph.p_vaddr(endian);
        let _ = ph.p_filesz(endian);
        let _ = ph.p_memsz(endian);
        let _ = ph.p_flags(endian);
        let _ = ph.p_offset(endian);
        let _ = ph.data(endian, data);
    }

    for (_idx, sh) in elf.elf_section_table().enumerate() {
        let _ = sh.sh_type(endian);
        let _ = sh.sh_addr(endian);
        let _ = sh.sh_size(endian);
        let _ = sh.sh_offset(endian);
        let _ = sh.sh_flags(endian);
        let _ = sh.data(endian, data);
    }
});
