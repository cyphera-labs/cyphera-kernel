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
const PROC_SEGV_LEN: usize = include_bytes!(env!("PROC_SEGV_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedA([u8; PROC_A_LEN]);
#[repr(C, align(8))]
struct AlignedS([u8; PROC_SEGV_LEN]);

static A_ALIGNED: AlignedA = AlignedA(*include_bytes!(env!("PROC_A_ELF_PATH")));
static S_ALIGNED: AlignedS = AlignedS(*include_bytes!(env!("PROC_SEGV_ELF_PATH")));

const PROC_A_ELF: &[u8] = &A_ALIGNED.0;
const PROC_SEGV_ELF: &[u8] = &S_ALIGNED.0;

const A_STACK: u64 = 0x4008_0000;
const S_STACK: u64 = 0x6008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] page_fault: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut a_vm = VmSpace::new_user().expect("alloc proc_a vmspace");
    let a = kernel::loader::elf::load_static(PROC_A_ELF, &mut a_vm).expect("load proc_a");
    let _ = a_vm
        .map_anon(
            VirtAddr::new(A_STACK),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map A stack");
    let pid_a = kernel::process_model::register_with_vmspace(
        Some(a_vm),
        a.entry,
        A_STACK + (STACK_PAGES * 4096) as u64,
        0x4010_0000,
    );

    let mut s_vm = VmSpace::new_user().expect("alloc proc_segv vmspace");
    let s = kernel::loader::elf::load_static(PROC_SEGV_ELF, &mut s_vm).expect("load proc_segv");
    let _ = s_vm
        .map_anon(
            VirtAddr::new(S_STACK),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map segv stack");
    let pid_s = kernel::process_model::register_with_vmspace(
        Some(s_vm),
        s.entry,
        S_STACK + (STACK_PAGES * 4096) as u64,
        0x6010_0000,
    );

    println!(
        "[test] page_fault: pid {} (A) and pid {} (segv) registered",
        pid_a.raw(),
        pid_s.raw()
    );
    println!("------ user output ------");

    kernel::core::start_first()
}
