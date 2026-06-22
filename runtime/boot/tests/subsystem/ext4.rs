#![no_std]
#![no_main]

extern crate alloc;

use frame::{
    boot::parse_hvm_start_info,
    io::uart,
    mm::{
        VirtAddr,
        vm::{Perms, VmSpace},
    },
    println,
};

use kernel::fs::ext4::{Ext4Fs, InMemoryDevice};
use kernel::vfs;

const EXT4_LEN: usize = include_bytes!(env!("EXT4_FIXTURE_PATH")).len();

#[repr(C, align(8))]
struct AlignedImg([u8; EXT4_LEN]);

static EXT4_IMG_ALIGNED: AlignedImg = AlignedImg(*include_bytes!(env!("EXT4_FIXTURE_PATH")));
const EXT4_IMG: &[u8] = &EXT4_IMG_ALIGNED.0;

const PROC_EXT4_LEN: usize = include_bytes!(env!("PROC_EXT4_ELF_PATH")).len();

#[repr(C, align(8))]
struct AlignedElf([u8; PROC_EXT4_LEN]);

static PROC_EXT4_ALIGNED: AlignedElf = AlignedElf(*include_bytes!(env!("PROC_EXT4_ELF_PATH")));
const PROC_EXT4_ELF: &[u8] = &PROC_EXT4_ALIGNED.0;

const STACK_VADDR: u64 = 0x7008_0000;
const STACK_PAGES: usize = 4;

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] ext4: bringing up frame");

    let bi = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&bi) };

    kernel::init();

    let dev = InMemoryDevice::new(EXT4_IMG.to_vec());
    let fs = Ext4Fs::mount(dev).expect("mount ext4");
    vfs::root_inode()
        .attach("mnt", fs.root_inode())
        .expect("attach /mnt");
    println!(
        "[test] ext4: mounted fixture image at /mnt ({} bytes)",
        EXT4_LEN
    );

    let mut vmspace = VmSpace::new_user().expect("alloc proc_ext4 vmspace");

    let loaded =
        kernel::loader::elf::load_static(PROC_EXT4_ELF, &mut vmspace).expect("load proc_ext4");
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

    println!("[test] ext4: dropping to ring 3");
    println!("------ user output ------");
    kernel::core::start_first()
}
