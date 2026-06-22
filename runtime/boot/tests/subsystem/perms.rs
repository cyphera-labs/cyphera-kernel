#![no_std]
#![no_main]

use frame::{
    boot::parse_hvm_start_info,
    io::uart,
    mm::{
        VirtAddr,
        vm::{Perms, VmSpace},
    },
    println,
};

const ELF_LEN: usize = include_bytes!(env!("PROC_PERMS_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedElf([u8; ELF_LEN]);

static ELF_ALIGNED: AlignedElf = AlignedElf(*include_bytes!(env!("PROC_PERMS_ELF_PATH")));
const ELF: &[u8] = &ELF_ALIGNED.0;

const PROBE_LEN: usize = include_bytes!(env!("PROC_AUXV_PROBE_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedProbe([u8; PROBE_LEN]);

static PROBE_ALIGNED: AlignedProbe =
    AlignedProbe(*include_bytes!(env!("PROC_AUXV_PROBE_ELF_PATH")));
const PROBE_ELF: &[u8] = &PROBE_ALIGNED.0;

const STACK_VADDR: u64 = 0x7008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] perms: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let root = kernel::vfs::root_inode();
    let bin = root
        .create("bin", kernel::vfs::InodeKind::Directory)
        .expect("create /bin");
    let probe_inode = bin
        .create("proc_auxv_probe", kernel::vfs::InodeKind::Regular)
        .expect("create /bin/proc_auxv_probe");
    let written = probe_inode
        .write_at(0, PROBE_ELF)
        .expect("write /bin/proc_auxv_probe");
    assert_eq!(
        written,
        PROBE_ELF.len(),
        "short write planting /bin/proc_auxv_probe"
    );
    println!(
        "[test] perms: planted /bin/proc_auxv_probe ({} bytes)",
        written
    );

    let mut vmspace = VmSpace::new_user().expect("alloc proc_perms vmspace");

    let loaded = kernel::loader::elf::load_static(ELF, &mut vmspace).expect("load proc_perms");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map stack");

    let _pid = kernel::process_model::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x7010_0000,
    );

    println!("[test] perms: dropping to ring 3");
    println!("------ user output ------");
    kernel::core::start_first()
}
