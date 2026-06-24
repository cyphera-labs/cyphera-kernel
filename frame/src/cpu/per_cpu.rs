use core::cell::UnsafeCell;

use x86_64::VirtAddr;
use x86_64::registers::model_specific::{GsBase, KernelGsBase};

use crate::sync::IrqGuard;

pub const MAX_CPUS: usize = 4;
const _: () = assert!(MAX_CPUS <= 64);

#[repr(C)]
pub struct CpuArea {
    pub kernel_rsp: u64,
    pub user_rsp: u64,
    pub cpu_id: u32,
    pub _pad: u32,
    pub current_pid: u32,
    pub _pad2: u32,
    pub fault_gpr: [u64; 15],
}

impl CpuArea {
    const fn empty() -> Self {
        Self {
            kernel_rsp: 0,
            user_rsp: 0,
            cpu_id: 0,
            _pad: 0,
            current_pid: 0,
            _pad2: 0,
            fault_gpr: [0; 15],
        }
    }
}

pub const FAULT_GPR_OFFSET: usize = 0x20;

const _: () = assert!(core::mem::offset_of!(CpuArea, fault_gpr) == FAULT_GPR_OFFSET);

pub fn fault_gprs() -> [u64; 15] {
    let id = current_cpu_id();
    let ptr = area_ptr(id);
    // SAFETY: `current_cpu_id` selects this CPU's own area (the one GS_BASE
    // points at), so this reads only local storage with no cross-CPU
    // aliasing. The exception trampoline wrote the snapshot into these slots
    // immediately before the handler that calls this ran, with interrupts
    // masked, so no peer write can be in flight.
    unsafe { (*ptr).fault_gpr }
}

#[repr(C, align(64))]
struct AreaCell(UnsafeCell<CpuArea>);

// SAFETY: no `CpuArea` field is ever accessed cross-CPU. Each CPU
// reaches only `AREAS[this_cpu]` through its own `IA32_GS_BASE` (set
// in `init_for`); `current_cpu_id`/`kernel_rsp`/`set_kernel_rsp` and
// the syscall trampoline all use `gs:[offset]`, so they touch only the
// local CPU's cell. The one-time `init_for` write runs on that CPU
// before its GS_BASE is in use. So `&AreaCell` is shared between CPUs
// but the interior `UnsafeCell` is only ever touched by its owning CPU
// — no aliasing, no data race.
unsafe impl Sync for AreaCell {}

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY_CELL: AreaCell = AreaCell(UnsafeCell::new(CpuArea::empty()));
static AREAS: [AreaCell; MAX_CPUS] = [EMPTY_CELL; MAX_CPUS];

#[inline]
pub fn current_cpu_id() -> u32 {
    let id: u32;
    // SAFETY: reads the 32-bit cpu_id at gs:[0x10] in this CPU's own
    // CpuArea (CpuArea is repr(C); cpu_id sits at offset 0x10). After
    // init GS_BASE points at AREAS[this_cpu]. The pre-init GS_BASE=0
    // case is only reached after the early boot page tables map the low
    // range, so gs:[0x10] resolves to a mapped low VA that reads 0 — it
    // is not independently bounds-checked here. Touches only GS-relative
    // kernel memory, no Rust-visible object; readonly + nostack assert
    // it writes no memory.
    unsafe {
        core::arch::asm!(
            "mov {0:e}, gs:[0x10]",
            out(reg) id,
            options(nostack, preserves_flags, readonly),
        );
    }
    id
}

#[inline]
pub fn set_kernel_rsp(rsp: u64) {
    // SAFETY: writes the kernel_rsp field at gs:[0x0] (offset 0x00 of
    // the repr(C) CpuArea) in this CPU's own area. GS_BASE points at
    // AREAS[this_cpu] post-init; each CPU writes only its own slot, so
    // there's no cross-CPU aliasing. The write lands in GS-relative
    // kernel memory only, touching no Rust-visible object.
    unsafe {
        core::arch::asm!(
            "mov gs:[0x0], {0}",
            in(reg) rsp,
            options(nostack, preserves_flags),
        );
    }
}

#[inline]
pub fn kernel_rsp() -> u64 {
    let v: u64;
    // SAFETY: reads the kernel_rsp field at gs:[0x0] (offset 0x00 of the
    // repr(C) CpuArea) in this CPU's own area, the value last written by
    // set_kernel_rsp. GS_BASE points at AREAS[this_cpu] post-init.
    // Reads GS-relative kernel memory only; readonly + nostack assert it
    // writes no memory.
    unsafe {
        core::arch::asm!(
            "mov {0}, gs:[0x0]",
            out(reg) v,
            options(nostack, preserves_flags, readonly),
        );
    }
    v
}

fn area_ptr(cpu_id: u32) -> *mut CpuArea {
    AREAS[cpu_id as usize].0.get()
}

pub fn init_bsp() {
    init_for(0);
    crate::println!("per_cpu: BSP storage initialized (cpu 0)");
}

pub fn init_ap(cpu_id: u32) {
    init_for(cpu_id);
}

fn init_for(cpu_id: u32) {
    assert!((cpu_id as usize) < MAX_CPUS, "cpu_id out of range");
    let ptr = area_ptr(cpu_id);
    // SAFETY: each CPU only initializes its own area; no concurrent
    // writes. The pointer comes from a static array, so it's
    // valid for the program's lifetime.
    unsafe {
        (*ptr).cpu_id = cpu_id;
        (*ptr).kernel_rsp = 0;
        (*ptr).user_rsp = 0;
        (*ptr).current_pid = 0;
    }
    GsBase::write(VirtAddr::new(ptr as u64));
    KernelGsBase::write(VirtAddr::new(ptr as u64));
}

pub struct PerCpu<T> {
    inner: UnsafeCell<T>,
}

// SAFETY: `with`/`with_ref` take an `IrqGuard` before touching the inner
// `UnsafeCell`, which masks interrupts on the LOCAL CPU only, so it
// prevents a second re-entrant borrow on the same CPU. It does NOT give
// cross-CPU exclusion: `IrqGuard` is just `cli`/`sti` and `inner` is a
// single shared `UnsafeCell<T>`, not per-CPU storage. This impl is
// therefore only sound under the caller-enforced precondition that any
// given `PerCpu<T>` instance is touched from one CPU only; nothing here
// enforces that. `T: Send` covers handing the value across that one-CPU
// boundary.
//
// CAUTION: if a `static PerCpu<T>` is reached from more than one CPU,
// two concurrent `with()` calls each produce `&mut *inner.get()` to the
// same cell — aliasing `&mut` / a data race (UB). See the flagged note
// in the per_cpu module: this needs real per-CPU slots (indexed by
// `current_cpu_id`) or a cross-CPU lock to be unconditionally sound.
unsafe impl<T: Send> Sync for PerCpu<T> {}

impl<T> PerCpu<T> {
    pub const fn new(val: T) -> Self {
        Self {
            inner: UnsafeCell::new(val),
        }
    }
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let _irq = IrqGuard::new();
        // SAFETY: IrqGuard holds interrupts disabled for the whole closure,
        // so on this CPU nothing can re-enter with()/with_ref() while this
        // &mut is live. Single-CPU-owner exclusivity (no peer CPU touches
        // this instance concurrently) is the caller's responsibility — see
        // the `Sync` impl note above. get() yields a valid, non-null pointer
        // into the live UnsafeCell.
        unsafe { f(&mut *self.inner.get()) }
    }
    pub fn with_ref<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let _irq = IrqGuard::new();
        // SAFETY: IrqGuard keeps interrupts off for the closure, so no
        // re-entrant with() on this CPU can create an aliasing &mut while
        // this shared borrow is live. Cross-CPU exclusivity is the caller's
        // responsibility (see the `Sync` impl note above). get() yields a
        // valid, non-null pointer into the live UnsafeCell.
        unsafe { f(&*self.inner.get()) }
    }
}
