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

const PROC_LEN: usize = include_bytes!(env!("PROC_PTRACE_TRACEEXEC_ELF_PATH")).len();
const PROC_A_LEN: usize = include_bytes!(env!("PROC_A_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedProc([u8; PROC_LEN]);
#[repr(C, align(8))]
struct AlignedA([u8; PROC_A_LEN]);

static PROC_ALIGNED: AlignedProc =
    AlignedProc(*include_bytes!(env!("PROC_PTRACE_TRACEEXEC_ELF_PATH")));
static PROC_A_ALIGNED: AlignedA = AlignedA(*include_bytes!(env!("PROC_A_ELF_PATH")));

const PROC_ELF: &[u8] = &PROC_ALIGNED.0;
const PROC_A_ELF: &[u8] = &PROC_A_ALIGNED.0;

const STACK_VADDR: u64 = 0x7048_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] ptrace_traceexec: bringing up frame; proc={} bytes; proc_a={} bytes",
        PROC_ELF.len(),
        PROC_A_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let root = kernel::vfs::root_inode();
    let bin = root
        .create("bin", kernel::vfs::InodeKind::Directory)
        .expect("create /bin");
    let proc_a_inode = bin
        .create("proc_a", kernel::vfs::InodeKind::Regular)
        .expect("create /bin/proc_a");
    let written = proc_a_inode
        .write_at(0, PROC_A_ELF)
        .expect("write /bin/proc_a");
    assert_eq!(
        written,
        PROC_A_ELF.len(),
        "short write planting /bin/proc_a"
    );
    println!(
        "[test] ptrace_traceexec: planted /bin/proc_a ({} bytes)",
        written
    );

    let mut vmspace = VmSpace::new_user().expect("alloc vmspace");
    let loaded = kernel::loader::elf::load_static(PROC_ELF, &mut vmspace)
        .expect("load proc_ptrace_traceexec");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map stack");
    let pid = kernel::process_model::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x7050_0000,
    );

    println!(
        "[test] ptrace_traceexec: registered pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::core::start_first()
}
