use alloc::alloc::{Layout, alloc_zeroed};
use core::arch::global_asm;
use core::ptr::{copy_nonoverlapping, write_volatile};
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

global_asm!(include_str!("ap_trampoline.s"), options(att_syntax));

extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end: u8;
}

pub const AP_TRAMPOLINE_PA: u64 = 0x8000;

const AP_SIPI_VECTOR: u8 = (AP_TRAMPOLINE_PA >> 12) as u8;

#[repr(C)]
struct ApParams {
    rsp: u64,
    entry: u64,
    cr3: u64,
    cpu_id: u64,
}

pub type ApMain = extern "C" fn(cpu_id: u64) -> !;

static AP_MAIN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

static CPU_ONLINE_MASK: AtomicU64 = AtomicU64::new(1);

static AP_BOOT_STACK: AtomicU64 = AtomicU64::new(0);

pub fn set_ap_main(f: ApMain) {
    AP_MAIN.store(f as *mut (), Ordering::SeqCst);
}

pub fn ap_online_count() -> u32 {
    CPU_ONLINE_MASK.load(Ordering::Acquire).count_ones()
}

pub fn online_mask() -> u64 {
    CPU_ONLINE_MASK.load(Ordering::Acquire)
}

pub fn bring_up(apic_ids: &[u8]) {
    if apic_ids.is_empty() {
        return;
    }

    // SAFETY: `ap_trampoline_start`/`_end` are linker-defined symbols bounding
    // the trampoline bytes in the kernel image; we read between them and
    // copy_nonoverlapping into VA 0x8000 (== phys AP_TRAMPOLINE_PA), which the
    // active boot PML4's low identity map (PML4[0], boot.s; dropped post-init)
    // maps WRITABLE. The frame_alloc low-1 MiB carve-out only reserves that
    // page from allocation — it does NOT establish the mapping. Source and
    // destination are valid, distinct, non-overlapping byte regions.
    let len = unsafe {
        let start = &ap_trampoline_start as *const u8;
        let end = &ap_trampoline_end as *const u8;
        let len = (end as usize).saturating_sub(start as usize);
        if len == 0 {
            crate::println!("smp: zero-length trampoline; aborting bringup");
            return;
        }
        copy_nonoverlapping(start, AP_TRAMPOLINE_PA as *mut u8, len);
        len
    };

    let params_pa = AP_TRAMPOLINE_PA as usize + len - core::mem::size_of::<ApParams>();
    let cr3 = x86_64::registers::control::Cr3::read()
        .0
        .start_address()
        .as_u64();

    for &apic_id in apic_ids {
        let layout = Layout::from_size_align(64 * 1024, 16).unwrap();
        // SAFETY: `layout` is non-zero-size (64 KiB) and 16-aligned,
        // built via `from_size_align(...).unwrap()`, so it satisfies
        // `alloc_zeroed`'s contract. The null return is checked below
        // before the pointer is used.
        let stack = unsafe { alloc_zeroed(layout) };
        if !stack.is_null() {
            let guard_layout = Layout::from_size_align(4 * 1024, 16).unwrap();
            // SAFETY: `guard_layout` is a non-zero-size (4 KiB),
            // 16-aligned layout, satisfying `alloc_zeroed`'s contract.
            // The returned pointer is intentionally never dereferenced
            // (deliberately leaked spacer), so a null return is benign.
            let _guard = unsafe { alloc_zeroed(guard_layout) };
        }
        if stack.is_null() {
            crate::println!("smp: ap{apic_id} stack alloc failed");
            continue;
        }
        // SAFETY: `stack` is the non-null base of the 64 KiB block
        // allocated just above (null was rejected by the `is_null`
        // check), so `stack + 64 KiB` is the one-past-the-end address
        // of that same allocation — in bounds for `add`, and never
        // dereferenced (it's only the stack-grows-down top pointer).
        let stack_top = unsafe { stack.add(64 * 1024) } as u64;
        AP_BOOT_STACK.store(stack_top, Ordering::SeqCst);

        // SAFETY: `params_pa` is in the page we just zeroed and copied into;
        // it's exclusive to us until SIPI fires, and `ApParams` is a plain
        // POD struct, so this `write_volatile` initializes a valid value with
        // no aliasing.
        unsafe {
            let params = params_pa as *mut ApParams;
            write_volatile(
                params,
                ApParams {
                    rsp: stack_top,
                    entry: ap_low_entry as *const () as u64,
                    cr3,
                    cpu_id: apic_id as u64,
                },
            );
        }

        crate::intr::lapic::send_ipi(apic_id, 0, IpiKind::Init);
        crate::cpu::busy_wait_nanos(10_000_000);

        crate::intr::lapic::send_ipi(apic_id, AP_SIPI_VECTOR, IpiKind::Startup);
        crate::cpu::busy_wait_nanos(200_000);

        crate::intr::lapic::send_ipi(apic_id, AP_SIPI_VECTOR, IpiKind::Startup);

        let ap_bit = 1u64 << apic_id;
        let deadline_ns = 100_000_000;
        let start_ns = crate::cpu::nanos_since_boot();
        while CPU_ONLINE_MASK.load(Ordering::Acquire) & ap_bit == 0 {
            if crate::cpu::nanos_since_boot().wrapping_sub(start_ns) > deadline_ns {
                crate::println!("smp: ap{apic_id} timed out coming online");
                break;
            }
            core::hint::spin_loop();
        }
    }
}

pub use crate::intr::lapic::IpiKind;

extern "C" fn ap_low_entry(cpu_id: u64) -> ! {
    super::gdt::init_for(cpu_id as u32);
    super::idt::init();

    super::enable_cpu_features_ap();

    crate::cpu::per_cpu::init_ap(cpu_id as u32);

    crate::cpu::clock::init_ap(cpu_id as u32);

    // SAFETY: runs exactly once per AP, on the AP itself, after the
    // GDT/IDT and per-CPU GS base are established above — so the
    // timer vector this arms resolves to valid handlers on this CPU,
    // satisfying `init_ap`'s once-per-CPU-after-IDT contract.
    unsafe { crate::intr::lapic::init_ap() };

    crate::user::init();

    debug_assert!(
        cpu_id < 64,
        "cpu_id {} exceeds CPU_ONLINE_MASK width",
        cpu_id
    );
    CPU_ONLINE_MASK.fetch_or(1u64 << cpu_id, Ordering::Release);

    let ptr = AP_MAIN.load(Ordering::SeqCst);
    if !ptr.is_null() {
        // SAFETY: `AP_MAIN` is private; its sole writer is
        // `set_ap_main`, which stores a value typed `ApMain`. The
        // `is_null` check above guarantees `ptr` is a real fn pointer,
        // so transmuting it back to `ApMain` is valid.
        let f: ApMain = unsafe { core::mem::transmute(ptr) };
        f(cpu_id);
    }

    crate::cpu::halt()
}
