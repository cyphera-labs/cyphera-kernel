extern crate alloc;

use cyphera_kapi::{Errno, KResult};
use frame::mm::{
    VirtAddr, frame_alloc, vm::Perms, vm::USER_VA_END, vm::VmSpace, write_to_frame, zero_frame,
};
use object::Endianness;
use object::elf::{FileHeader64, PF_R, PF_W, PF_X, PT_INTERP, PT_LOAD};
use object::read::elf::{ElfFile, FileHeader, ProgramHeader};
use object::{Object, ObjectSection};

type Elf64<'a> = ElfFile<'a, FileHeader64<Endianness>>;

type SegmentRanges = alloc::vec::Vec<(u64, u64, Perms)>;

fn map_err(e: frame::mm::vm::MapError) -> Errno {
    use frame::mm::vm::MapError as M;
    match e {
        M::OutOfFrames => Errno::NOMEM,
        M::Misaligned => Errno::NOEXEC,
        M::AlreadyMapped | M::ParentTableHugePage => Errno::INVAL,
        M::OutOfUserRange => Errno::NOEXEC,
    }
}

pub struct Loaded {
    pub entry: u64,
    pub image_end: u64,
    pub phdr_va: u64,
    pub phent: u16,
    pub phnum: u16,
    pub interp_base: Option<u64>,
    pub interp_entry: Option<u64>,
    pub segments: alloc::vec::Vec<(u64, u64, Perms)>,
    pub interp_segments: alloc::vec::Vec<(u64, u64, Perms)>,
}

pub fn interp_path(elf_bytes: &[u8]) -> Option<alloc::string::String> {
    let elf: Elf64 = ElfFile::parse(elf_bytes).ok()?;
    let endian = elf.elf_header().endian().ok()?;
    for ph in elf.elf_program_headers() {
        if ph.p_type(endian) == PT_INTERP {
            let bytes = ph.data(endian, elf_bytes).ok()?;
            let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            let s = core::str::from_utf8(&bytes[..nul]).ok()?;
            return Some(alloc::string::String::from(s));
        }
    }
    None
}

pub fn load_static(elf_bytes: &[u8], vmspace: &mut VmSpace) -> KResult<Loaded> {
    let elf: Elf64 = ElfFile::parse(elf_bytes).map_err(|_| Errno::NOEXEC)?;
    let header = elf.elf_header();
    let endian = header.endian().map_err(|_| Errno::NOEXEC)?;

    let relocs = collect_relative_relocs(&elf, 0)?;

    let mut image_end: u64 = 0;
    let mut interp_path: Option<alloc::string::String> = None;
    let mut segments: alloc::vec::Vec<(u64, u64, Perms)> = alloc::vec::Vec::new();
    let mut interp_segments: alloc::vec::Vec<(u64, u64, Perms)> = alloc::vec::Vec::new();
    for ph in elf.elf_program_headers() {
        match ph.p_type(endian) {
            PT_INTERP => {
                let bytes = ph.data(endian, elf_bytes).map_err(|_| Errno::NOEXEC)?;
                let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                let s = core::str::from_utf8(&bytes[..nul]).map_err(|_| Errno::NOEXEC)?;
                interp_path = Some(alloc::string::String::from(s));
            }
            PT_LOAD => {
                let (seg_start, seg_end, seg_perms) =
                    load_segment(elf_bytes, ph, endian, vmspace, 0, &relocs)?;
                if seg_end > image_end {
                    image_end = seg_end;
                }
                segments.push((seg_start, seg_end, seg_perms));
            }
            _ => {}
        }
    }

    let e_phoff = header.e_phoff(endian);
    let phent = header.e_phentsize(endian);
    let phnum = header.e_phnum(endian);
    let mut phdr_va: u64 = 0;
    for ph in elf.elf_program_headers() {
        if ph.p_type(endian) == PT_LOAD
            && ph.p_offset(endian) <= e_phoff
            && e_phoff < ph.p_offset(endian) + ph.p_filesz(endian)
        {
            phdr_va = ph.p_vaddr(endian) + (e_phoff - ph.p_offset(endian));
            break;
        }
    }

    let (interp_base, interp_entry) = if let Some(path) = interp_path {
        match load_interpreter(&path, vmspace) {
            Ok((base, entry, segs)) => {
                interp_segments = segs;
                (Some(base), Some(entry))
            }
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    Ok(Loaded {
        entry: header.e_entry(endian),
        image_end,
        phdr_va,
        phent,
        phnum,
        interp_base,
        interp_entry,
        segments,
        interp_segments,
    })
}

const INTERP_LOAD_BASE: u64 = 0x4000_0000_0000;

fn load_interpreter(path: &str, vmspace: &mut VmSpace) -> KResult<(u64, u64, SegmentRanges)> {
    use alloc::vec;
    let ctx = crate::vfs::path::Context::global();
    let inode = crate::vfs::path::resolve(&ctx, &ctx.root, path).map_err(|_| Errno::NOEXEC)?;
    let stat = inode.stat();
    let size = stat.size as usize;
    if size == 0 {
        return Err(Errno::NOEXEC);
    }
    let mut buf = vec![0u8; size];
    let mut total = 0usize;
    while total < size {
        let n = inode
            .read_at(total as u64, &mut buf[total..])
            .map_err(|_| Errno::NOEXEC)?;
        if n == 0 {
            break;
        }
        total += n;
    }
    if total != size {
        return Err(Errno::NOEXEC);
    }
    let interp: Elf64 = ElfFile::parse(&buf[..]).map_err(|_| Errno::NOEXEC)?;
    let interp_header = interp.elf_header();
    let endian = interp_header.endian().map_err(|_| Errno::NOEXEC)?;
    let base = INTERP_LOAD_BASE;
    let mut interp_segments: alloc::vec::Vec<(u64, u64, Perms)> = alloc::vec::Vec::new();
    for ph in interp.elf_program_headers() {
        if ph.p_type(endian) == PT_LOAD {
            let (seg_start, seg_end, seg_perms) =
                load_segment(&buf, ph, endian, vmspace, base, &[])?;
            interp_segments.push((seg_start, seg_end, seg_perms));
        }
    }
    let entry = interp_header.e_entry(endian) + base;
    Ok((base, entry, interp_segments))
}

fn load_segment(
    elf_bytes: &[u8],
    ph: &<FileHeader64<Endianness> as FileHeader>::ProgramHeader,
    endian: Endianness,
    vmspace: &mut VmSpace,
    base: u64,
    relocs: &[(u64, u64)],
) -> KResult<(u64, u64, Perms)> {
    let vaddr = ph.p_vaddr(endian).checked_add(base).ok_or(Errno::NOEXEC)?;
    let mem_size = ph.p_memsz(endian);
    let file_size = ph.p_filesz(endian);
    let file_offset = ph.p_offset(endian);
    let flags = ph.p_flags(endian);

    let perms = elf_perms(flags & PF_R != 0, flags & PF_W != 0, flags & PF_X != 0);

    let segment_data = if file_size == 0 {
        &[][..]
    } else {
        let file_end = file_offset.checked_add(file_size).ok_or(Errno::NOEXEC)?;
        if file_end > elf_bytes.len() as u64 {
            return Err(Errno::NOEXEC);
        }
        &elf_bytes[file_offset as usize..file_end as usize]
    };

    let seg_top = vaddr
        .checked_add(mem_size)
        .and_then(|t| t.checked_add(0xfff))
        .ok_or(Errno::NOEXEC)?;
    let file_top = vaddr.checked_add(file_size).ok_or(Errno::NOEXEC)?;
    let page_start = vaddr & !0xfff;
    let page_end = seg_top & !0xfff;
    if page_end > USER_VA_END {
        return Err(Errno::NOEXEC);
    }
    let num_pages = ((page_end - page_start) / 4096) as usize;

    for i in 0..num_pages {
        let page_va = page_start + (i as u64) * 4096;

        let frame = frame_alloc::alloc_frame().ok_or(Errno::NOMEM)?;
        zero_frame(frame);

        let copy_start_va = page_va.max(vaddr);
        let copy_end_va = (page_va + 4096).min(file_top);

        if copy_end_va > copy_start_va {
            let data_start_in_segment = (copy_start_va - vaddr) as usize;
            let copy_len = (copy_end_va - copy_start_va) as usize;
            let offset_in_page = (copy_start_va - page_va) as usize;
            write_to_frame(
                frame,
                offset_in_page,
                &segment_data[data_start_in_segment..data_start_in_segment + copy_len],
            );
        }

        for &(target_va, value) in relocs {
            if target_va >= page_va && target_va + 8 <= page_va + 4096 {
                write_to_frame(frame, (target_va - page_va) as usize, &value.to_le_bytes());
            }
        }

        let region = vmspace
            .map(VirtAddr::new(page_va), frame, perms)
            .map_err(map_err)?;
        core::mem::forget(region);
    }

    Ok((page_start, page_end, perms))
}

fn elf_perms(r: bool, w: bool, x: bool) -> Perms {
    let mut p = Perms::USER;
    if r {
        p |= Perms::READ;
    }
    if w {
        p |= Perms::WRITE;
    }
    if x {
        p |= Perms::EXECUTE;
    }
    p
}

const R_X86_64_RELATIVE: u32 = 8;

fn collect_relative_relocs(elf: &Elf64<'_>, base: u64) -> KResult<alloc::vec::Vec<(u64, u64)>> {
    let mut out = alloc::vec::Vec::new();
    let section = match elf.section_by_name(".rela.dyn") {
        Some(s) => s,
        None => return Ok(out),
    };
    let data = section.data().map_err(|_| Errno::NOEXEC)?;
    for entry in data.chunks_exact(24) {
        let r_offset = u64::from_le_bytes(entry[0..8].try_into().unwrap());
        let r_info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        let r_addend = u64::from_le_bytes(entry[16..24].try_into().unwrap());
        if (r_info & 0xffff_ffff) as u32 == R_X86_64_RELATIVE {
            out.push((base.wrapping_add(r_offset), base.wrapping_add(r_addend)));
        }
    }
    Ok(out)
}
