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

const PROC_SPIN_KILL_LEN: usize = include_bytes!(env!("PROC_SPIN_KILL_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedSpinKill([u8; PROC_SPIN_KILL_LEN]);

static PROC_SPIN_KILL_ALIGNED: AlignedSpinKill =
    AlignedSpinKill(*include_bytes!(env!("PROC_SPIN_KILL_ELF_PATH")));

const PROC_SPIN_KILL_ELF: &[u8] = &PROC_SPIN_KILL_ALIGNED.0;

const STACK_VADDR: u64 = 0x6008_0000;
const STACK_PAGES: usize = 8;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!(
        "[test] spin_kill: bringing up frame; proc_spin_kill={} bytes",
        PROC_SPIN_KILL_ELF.len()
    );

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_spin_kill vmspace");
    let loaded =
        kernel::elf::load_static(PROC_SPIN_KILL_ELF, &mut vmspace).expect("load proc_spin_kill");
    let _ = vmspace
        .map_anon(
            VirtAddr::new(STACK_VADDR),
            STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("map proc_spin_kill stack");
    let pid = kernel::sched::register_with_vmspace(
        Some(vmspace),
        loaded.entry,
        STACK_VADDR + (STACK_PAGES * 4096) as u64,
        0x6010_0000,
    );

    println!(
        "[test] spin_kill: registered proc_spin_kill as pid {} (entry {:#x})",
        pid.raw(),
        loaded.entry
    );
    println!("------ user output ------");
    kernel::sched::start_first()
}
