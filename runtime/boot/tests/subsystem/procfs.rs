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

const PROCFS_LEN: usize = include_bytes!(env!("PROC_PROCFS_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedElf([u8; PROCFS_LEN]);

static PROCFS_ALIGNED: AlignedElf = AlignedElf(*include_bytes!(env!("PROC_PROCFS_ELF_PATH")));
const PROCFS_ELF: &[u8] = &PROCFS_ALIGNED.0;

const STACK_VADDR: u64 = 0x7008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] procfs: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_procfs vmspace");

    let loaded =
        kernel::loader::elf::load_static(PROCFS_ELF, &mut vmspace).expect("load proc_procfs");
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
        0x7010_0000,
    );

    let mut comm = [0u8; 16];
    let name = b"proc_procfs";
    comm[..name.len()].copy_from_slice(name);
    kernel::core::set_name(pid, comm);

    println!("[test] procfs: dropping to ring 3");
    println!("------ user output ------");
    kernel::core::start_first()
}
