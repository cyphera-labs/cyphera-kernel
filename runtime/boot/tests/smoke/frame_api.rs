#![no_std]
#![no_main]

extern crate alloc;

use alloc::{boxed::Box, vec, vec::Vec};

use frame::{
    boot::parse_hvm_start_info,
    cpu::{per_cpu::PerCpu, task::Task},
    intr,
    io::{
        qemu_exit::{ExitCode, exit},
        uart,
    },
    mm::{
        VirtAddr, frame_alloc,
        vm::{MapError, Perms, VmSpace},
    },
    println,
    sync::SpinIrq,
};

static COUNTER: SpinIrq<u32> = SpinIrq::new(0);
static THREAD_LOCAL: PerCpu<u32> = PerCpu::new(42);

extern "C" fn worker_entry() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) }
    }
}

#[no_mangle]
pub extern "C" fn kernel_main(boot_info_ptr: u32) -> ! {
    uart::init();
    println!("[test] frame_api: bringing up frame");

    let boot_info = unsafe { parse_hvm_start_info(boot_info_ptr) };
    unsafe { frame::init(&boot_info) };

    let b: Box<u64> = Box::new(0x00C0_FFEE_DEAD_BEEF_u64);
    assert_eq!(*b, 0x00C0_FFEE_DEAD_BEEF_u64);
    let mut v: Vec<u8> = vec![0xAA; 8 * 1024];
    v[42] = 0x55;
    assert_eq!(v[42], 0x55);
    assert_eq!(v.iter().filter(|&&b| b == 0xAA).count(), v.len() - 1);
    println!("[test] frame_api: heap OK ({} byte vec)", v.len());

    for _ in 0..1000 {
        *COUNTER.lock() += 1;
    }
    assert_eq!(*COUNTER.lock(), 1000);
    println!("[test] frame_api: spinlock OK (counter = 1000)");

    THREAD_LOCAL.with(|x| {
        assert_eq!(*x, 42);
        *x = 100;
    });
    THREAD_LOCAL.with_ref(|x| assert_eq!(*x, 100));
    println!("[test] frame_api: per-CPU OK");

    let f1 = frame_alloc::alloc_frame().expect("alloc_frame");
    let f2 = frame_alloc::alloc_frame().expect("alloc_frame");
    assert_ne!(f1.start_address(), f2.start_address());
    frame_alloc::free_frame(f1);
    frame_alloc::free_frame(f2);
    println!("[test] frame_api: frame_alloc OK");

    let mut vmspace = VmSpace::current();
    let some_kernel_addr = VirtAddr::new(0x10_0000);
    let phys = vmspace.translate(some_kernel_addr);
    assert!(phys.is_some(), "kernel image must be mapped");
    println!(
        "[test] frame_api: vm translate OK ({:#x} -> {:#x})",
        some_kernel_addr.as_u64(),
        phys.unwrap().as_u64()
    );

    let region = vmspace
        .map_anon(VirtAddr::new(0x4000_0000), 4, Perms::KERNEL_RW)
        .expect("map_anon");
    assert_eq!(region.pages(), 4);
    assert_eq!(region.size_bytes(), 4 * 4096);
    let pagebuf = unsafe { core::slice::from_raw_parts_mut(region.start().as_mut_ptr(), 4096) };
    pagebuf[0] = 0xAB;
    assert_eq!(pagebuf[0], 0xAB);
    vmspace.unmap(region);
    println!("[test] frame_api: vm map/unmap OK (4 pages)");

    let bound_frame = frame_alloc::alloc_frame().expect("alloc_frame");
    let kernel_half = VirtAddr::new(0xFFFF_8000_0000_0000);
    assert!(
        matches!(
            vmspace.map(kernel_half, bound_frame, Perms::USER_RW),
            Err(MapError::OutOfUserRange)
        ),
        "USER map into kernel half must be refused"
    );
    assert!(
        matches!(
            vmspace.map_anon(kernel_half, 1, Perms::USER_RW),
            Err(MapError::OutOfUserRange)
        ),
        "USER map_anon into kernel half must be refused"
    );
    frame_alloc::free_frame(bound_frame);
    println!("[test] frame_api: user-half mapping bound OK (kernel-half USER refused)");

    fn dummy_handler(_ctx: &mut intr::IrqContext) {}
    intr::register_irq(40, dummy_handler).expect("register");
    intr::unregister_irq(40);
    intr::register_irq(40, dummy_handler).expect("re-register after unregister");
    intr::unregister_irq(40);
    println!("[test] frame_api: intr register/unregister OK");

    let _t = Task::spawn(worker_entry);
    println!("[test] frame_api: Task::spawn OK (no switch yet)");

    assert!(
        frame::cpu::cpu_registry::selftest_sparse_mapping(),
        "sparse APIC ids must map to dense cpu indices"
    );
    println!("[test] frame_api: cpu_registry sparse->dense mapping OK");

    println!("[test] frame_api: PASS");
    exit(ExitCode::Success)
}
