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

const PROC_ARGV_LEN: usize = include_bytes!(env!("PROC_ARGV_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedArgv([u8; PROC_ARGV_LEN]);

static PROC_ARGV_ALIGNED: AlignedArgv = AlignedArgv(*include_bytes!(env!("PROC_ARGV_ELF_PATH")));

const PROC_ARGV_ELF: &[u8] = &PROC_ARGV_ALIGNED.0;

const STACK_VADDR: u64 = 0x7008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] argv: bringing up frame; proc_argv={} bytes",
        PROC_ARGV_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_argv vmspace");
    let loaded =
        kernel::loader::elf::load_static(PROC_ARGV_ELF, &mut vmspace).expect("load proc_argv");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_argv stack");

    let argv: [&[u8]; 3] = [b"/bin/proc_argv", b"hello", b"world"];
    let envp: [&[u8]; 1] = [b"FOO=bar"];

    let aux = kernel::loader::stack_init::AuxvInfo::for_exec(&loaded, 0, 0, 0, 0, false);
    let pid = kernel::process_model::register_with_argv(
        vmspace,
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x7010_0000,
        b"/bin/proc_argv",
        &argv,
        &envp,
        &aux,
    )
    .expect("register_with_argv");

    println!(
        "[test] argv: registered proc_argv as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::core::start_first()
}
