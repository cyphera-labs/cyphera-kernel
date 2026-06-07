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

const PROC_EXEC_THREADED_LEN: usize = include_bytes!(env!("PROC_EXEC_THREADED_ELF_PATH")).len();
const PROC_A_LEN: usize = include_bytes!(env!("PROC_A_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedExec([u8; PROC_EXEC_THREADED_LEN]);
#[repr(C, align(8))]
struct AlignedA([u8; PROC_A_LEN]);

static PROC_EXEC_THREADED_ALIGNED: AlignedExec =
    AlignedExec(*include_bytes!(env!("PROC_EXEC_THREADED_ELF_PATH")));
static PROC_A_ALIGNED: AlignedA = AlignedA(*include_bytes!(env!("PROC_A_ELF_PATH")));

const PROC_EXEC_THREADED_ELF: &[u8] = &PROC_EXEC_THREADED_ALIGNED.0;
const PROC_A_ELF: &[u8] = &PROC_A_ALIGNED.0;

const STACK_VADDR: u64 = 0x5008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] exec_threaded: bringing up frame; proc_exec_threaded={} bytes; proc_a={} bytes",
        PROC_EXEC_THREADED_ELF.len(),
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
        "[test] exec_threaded: planted /bin/proc_a ({} bytes)",
        written
    );

    let mut vmspace = VmSpace::new_user().expect("alloc proc_exec_threaded vmspace");
    let loaded = kernel::elf::load_static(PROC_EXEC_THREADED_ELF, &mut vmspace)
        .expect("load proc_exec_threaded");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_exec_threaded stack");
    let pid = kernel::sched::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x5010_0000,
    );

    println!(
        "[test] exec_threaded: registered proc_exec_threaded as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::sched::start_first()
}
