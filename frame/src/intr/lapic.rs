use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use x86_64::registers::model_specific::Msr;

use crate::boot::KERNEL_VMA_OFFSET;

const IA32_APIC_BASE: u32 = 0x1B;
const APIC_BASE_ENABLE: u64 = 1 << 11;

const REG_APIC_ID: usize = 0x020;
const REG_TPR: usize = 0x080;
const REG_EOI: usize = 0x0B0;
const REG_SVR: usize = 0x0F0;
const REG_ICR_LOW: usize = 0x300;
const REG_ICR_HIGH: usize = 0x310;
const REG_LVT_TIMER: usize = 0x320;
const REG_TIMER_INIT: usize = 0x380;
const REG_TIMER_CURRENT: usize = 0x390;
const REG_TIMER_DIVIDE: usize = 0x3E0;

pub const TIMER_VECTOR: u8 = 0x20;
pub const RESCHED_IPI_VECTOR: u8 = 0x21;
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0x22;
pub const SPURIOUS_VECTOR: u8 = 0xFF;

const LVT_TIMER_PERIODIC: u32 = 1 << 17;
const SVR_ENABLE: u32 = 1 << 8;
const TIMER_DIVIDE_BY_16: u32 = 0x3;

static TICKS_PER_PERIOD: AtomicU64 = AtomicU64::new(0);
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);
static LAPIC_BASE: AtomicPtr<u32> = AtomicPtr::new(core::ptr::null_mut());
static TICK_HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

pub type TickHandler = fn(bool);

/// # Safety
///
/// Must be called exactly once on the BSP, with IRQs disabled, before
/// any other LAPIC API; the LAPIC MMIO page must already be mapped.
pub unsafe fn init() {
    let mut msr = Msr::new(IA32_APIC_BASE);
    let value = msr.read();
    let phys_base = value & 0xFFFF_F000;

    let high_va = phys_base | KERNEL_VMA_OFFSET;
    msr.write(value | APIC_BASE_ENABLE);
    LAPIC_BASE.store(high_va as *mut u32, Ordering::SeqCst);

    write_reg(REG_SVR, SVR_ENABLE | SPURIOUS_VECTOR as u32);
    write_reg(REG_TPR, 0);
    write_reg(REG_TIMER_DIVIDE, TIMER_DIVIDE_BY_16);

    write_reg(REG_LVT_TIMER, (TIMER_VECTOR as u32) | (1 << 16));
    write_reg(REG_TIMER_INIT, 0xFFFF_FFFF);
    crate::cpu::busy_wait_nanos(10_000_000);
    let remaining = read_reg(REG_TIMER_CURRENT);
    let elapsed = 0xFFFF_FFFFu32.wrapping_sub(remaining);
    TICKS_PER_PERIOD.store(elapsed as u64, Ordering::SeqCst);

    write_reg(REG_LVT_TIMER, (TIMER_VECTOR as u32) | LVT_TIMER_PERIODIC);
    write_reg(REG_TIMER_INIT, elapsed);

    crate::println!(
        "lapic: enabled @ {:#x}; timer 100 Hz ({} bus-ticks per 10 ms)",
        phys_base,
        elapsed,
    );
}

fn write_reg(off: usize, val: u32) {
    let base = LAPIC_BASE.load(Ordering::Relaxed) as usize;
    if base == 0 {
        return;
    }
    // SAFETY: `base` is the LAPIC MMIO VA published by `init` (consumed by
    // `init_ap` on APs): `phys_base | KERNEL_VMA_OFFSET`, inside the boot
    // stub's PDPT_high[511] device window (phys 0xc000_0000..0x1_0000_0000,
    // mapped uncacheable), so it aliases LAPIC phys 0xfee0_0000. The
    // `base==0` guard above proves it's the initialized non-null value.
    // `off` is one of the page-relative LAPIC register constants (<= 0x3E0),
    // so `base+off` stays inside that mapped, naturally u32-aligned register
    // page and touches device MMIO only — no Rust-visible memory.
    unsafe { write_volatile((base + off) as *mut u32, val) }
}

fn read_reg(off: usize) -> u32 {
    let base = LAPIC_BASE.load(Ordering::Relaxed) as usize;
    if base == 0 {
        return 0;
    }
    // SAFETY: `base` is the LAPIC MMIO VA published by `init` (consumed by
    // `init_ap` on APs): `phys_base | KERNEL_VMA_OFFSET`, inside the boot
    // stub's PDPT_high[511] device window (phys 0xc000_0000..0x1_0000_0000,
    // mapped uncacheable), so it aliases LAPIC phys 0xfee0_0000. The
    // `base==0` guard above proves it's the initialized non-null value.
    // `off` is one of the page-relative LAPIC register constants (<= 0x3E0),
    // so `base+off` stays inside that mapped, naturally u32-aligned register
    // page and reads device MMIO only — no Rust-visible memory.
    unsafe { read_volatile((base + off) as *const u32) }
}

pub fn eoi() {
    write_reg(REG_EOI, 0);
}

#[inline]
pub fn local_apic_id() -> u8 {
    (read_reg(REG_APIC_ID) >> 24) as u8
}

pub fn register_tick_handler(f: TickHandler) {
    TICK_HANDLER.store(f as *mut (), Ordering::SeqCst);
}

pub fn arm_oneshot_ns(delta_ns: u64) {
    let per_period = TICKS_PER_PERIOD.load(Ordering::Relaxed);
    if per_period == 0 {
        return;
    }
    let count = (delta_ns.saturating_mul(per_period)) / 10_000_000;
    let count = count.clamp(1, 0xFFFF_FFFF) as u32;
    write_reg(REG_LVT_TIMER, (TIMER_VECTOR as u32) | (1 << 16));
    write_reg(REG_TIMER_INIT, count);
    write_reg(REG_LVT_TIMER, TIMER_VECTOR as u32);
}

pub fn arm_periodic() {
    let per_period = TICKS_PER_PERIOD.load(Ordering::Relaxed);
    if per_period == 0 {
        return;
    }
    write_reg(REG_LVT_TIMER, (TIMER_VECTOR as u32) | LVT_TIMER_PERIODIC);
    write_reg(REG_TIMER_INIT, per_period as u32);
}

pub fn ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}

#[derive(Copy, Clone, Debug)]
pub enum IpiKind {
    Fixed,
    Init,
    Startup,
}

impl IpiKind {
    fn delivery_bits(self) -> u32 {
        match self {
            IpiKind::Fixed => 0,
            IpiKind::Init => 5 << 8,
            IpiKind::Startup => 6 << 8,
        }
    }
}

pub fn send_ipi(target_apic_id: u8, vector: u8, kind: IpiKind) {
    let saved_if = {
        let flags: u64;
        // SAFETY: `pushfq; pop` snapshots RFLAGS into `flags` to capture
        // the current IF state; it reads no Rust-visible memory (`nomem`)
        // and clobbers no flags (`preserves_flags`), only writing the
        // declared `out` register.
        unsafe {
            core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags))
        };
        (flags & 0x200) != 0
    };
    // SAFETY: `cli` only clears IF to open the indivisible ICR_HIGH +
    // ICR_LOW + delivery-spin critical section documented above; it
    // touches no memory and uses no stack (`nostack`). The prior
    // `saved_if` snapshot lets the matching `sti` restore the caller's
    // interrupt state.
    unsafe { core::arch::asm!("cli", options(nostack)) };

    write_reg(REG_ICR_HIGH, (target_apic_id as u32) << 24);
    let low = (vector as u32) | kind.delivery_bits() | (1 << 14);
    write_reg(REG_ICR_LOW, low);

    while read_reg(REG_ICR_LOW) & (1 << 12) != 0 {
        core::hint::spin_loop();
    }

    if saved_if {
        // SAFETY: `sti` only re-enables IF, and is reached solely when
        // `saved_if` recorded that interrupts were enabled on entry, so
        // this restores the caller's prior interrupt state after the ICR
        // write pair completed. It touches no memory and no stack.
        unsafe { core::arch::asm!("sti", options(nostack)) };
    }
}

/// # Safety
///
/// Caller must be running on the target AP, with IRQs disabled. The
/// LAPIC MMIO page must already be mapped (the BSP does this during
/// its own `init()`).
pub unsafe fn init_ap() {
    let mut msr = Msr::new(IA32_APIC_BASE);
    let value = msr.read();
    msr.write(value | APIC_BASE_ENABLE);

    write_reg(REG_SVR, SVR_ENABLE | SPURIOUS_VECTOR as u32);
    write_reg(REG_TPR, 0);
    write_reg(REG_TIMER_DIVIDE, TIMER_DIVIDE_BY_16);

    let ticks = TICKS_PER_PERIOD.load(Ordering::Acquire);
    write_reg(REG_LVT_TIMER, (TIMER_VECTOR as u32) | LVT_TIMER_PERIODIC);
    write_reg(REG_TIMER_INIT, ticks as u32);

    crate::println!("lapic[ap]: enabled; timer @ 100 Hz");
}

pub(crate) fn handle_tick() {
    dispatch_tick(true);
}

pub(crate) fn handle_resched() {
    dispatch_tick(false);
}

fn dispatch_tick(is_timer: bool) {
    eoi();
    if is_timer {
        TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
    }
    let ptr = TICK_HANDLER.load(Ordering::Relaxed);
    if !ptr.is_null() {
        // SAFETY: we only ever store fn pointers via
        // `register_tick_handler`, and that function takes a typed
        // `fn(bool)` parameter so the cast back is sound.
        let f: TickHandler = unsafe { core::mem::transmute(ptr) };
        f(is_timer);
    }
}
