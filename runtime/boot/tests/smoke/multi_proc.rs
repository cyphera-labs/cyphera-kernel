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

const PROC_A_LEN: usize = include_bytes!(env!("PROC_A_ELF_PATH")).len();
const PROC_B_LEN: usize = include_bytes!(env!("PROC_B_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedProcA([u8; PROC_A_LEN]);
#[repr(C, align(8))]
struct AlignedProcB([u8; PROC_B_LEN]);

static PROC_A_ALIGNED: AlignedProcA = AlignedProcA(*include_bytes!(env!("PROC_A_ELF_PATH")));
static PROC_B_ALIGNED: AlignedProcB = AlignedProcB(*include_bytes!(env!("PROC_B_ELF_PATH")));

const PROC_A_ELF: &[u8] = &PROC_A_ALIGNED.0;
const PROC_B_ELF: &[u8] = &PROC_B_ALIGNED.0;

const PROC_A_STACK_VADDR: u64 = 0x4008_0000;
const PROC_B_STACK_VADDR: u64 = 0x5008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] multi_proc: bringing up frame; proc_a={} bytes, proc_b={} bytes",
        PROC_A_ELF.len(),
        PROC_B_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut a_vm = VmSpace::new_user().expect("alloc proc_a vmspace");
    let a = kernel::loader::elf::load_static(PROC_A_ELF, &mut a_vm).expect("load proc_a");
    let _ = a_vm
        .map_anon(
            VirtAddr::new(PROC_A_STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_a stack");
    let pid_a = kernel::process_model::register_with_vmspace(
        Some(a_vm),
        a.entry,
        PROC_A_STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x4010_0000,
    );

    let mut b_vm = VmSpace::new_user().expect("alloc proc_b vmspace");
    let b = kernel::loader::elf::load_static(PROC_B_ELF, &mut b_vm).expect("load proc_b");
    let _ = b_vm
        .map_anon(
            VirtAddr::new(PROC_B_STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_b stack");
    let pid_b = kernel::process_model::register_with_vmspace(
        Some(b_vm),
        b.entry,
        PROC_B_STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x5010_0000,
    );

    println!(
        "[test] multi_proc: registered pid {} (A @ {:#x}) and pid {} (B @ {:#x})",
        pid_a.raw(),
        a.entry,
        pid_b.raw(),
        b.entry,
    );
    println!("------ user output ------");

    kernel::core::start_first()
}
