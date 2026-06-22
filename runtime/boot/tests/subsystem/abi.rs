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

const ABI_LEN: usize = include_bytes!(env!("PROC_ABI_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedElf([u8; ABI_LEN]);

static ABI_ALIGNED: AlignedElf = AlignedElf(*include_bytes!(env!("PROC_ABI_ELF_PATH")));
const ABI_ELF: &[u8] = &ABI_ALIGNED.0;

const STACK_VADDR: u64 = 0x7008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] abi: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let mut vmspace = VmSpace::new_user().expect("alloc proc_abi vmspace");
    let loaded = kernel::loader::elf::load_static(ABI_ELF, &mut vmspace).expect("load proc_abi");
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
    kernel::core::set_cmdline(pid, b"abi-test\0".to_vec());

    {
        let mut layout = kernel::process_model::MapsLayout::default();
        for (lo, hi, prot) in &loaded.segments {
            layout.segments.push(kernel::process_model::MapSegment {
                start: *lo,
                end: *hi,
                prot: *prot,
                label: kernel::process_model::MapSegLabel::Image,
            });
        }
        layout.segments.push(kernel::process_model::MapSegment {
            start: STACK_VADDR,
            end: STACK_VADDR + (STACK_PAGES * 4096) as u64,
            prot: Perms::READ | Perms::WRITE | Perms::USER,
            label: kernel::process_model::MapSegLabel::Stack,
        });
        kernel::core::set_maps_layout(pid, layout);
    }

    println!("[test] abi: dropping to ring 3");
    println!("------ user output ------");
    kernel::core::start_first()
}
