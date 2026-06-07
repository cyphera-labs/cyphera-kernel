use core::cell::UnsafeCell;
use core::mem::MaybeUninit;

use x86_64::VirtAddr;
use x86_64::structures::tss::TaskStateSegment;

use crate::cpu::per_cpu::{MAX_CPUS, current_cpu_id};

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

const STACK_SIZE: usize = 16 * 1024;

#[repr(C, align(16))]
struct IstStack([MaybeUninit<u8>; STACK_SIZE]);

#[repr(transparent)]
struct IstStackCell(UnsafeCell<IstStack>);
// SAFETY: `DF_STACKS` is partitioned by CPU index. `populate_for` only
// reads each slot's address to compute its IST top — it never writes the
// cell's bytes. At runtime a cell's contents are written solely by
// hardware #DF exception-frame delivery, which occurs only on the owning
// CPU, so no two CPUs ever write the same cell and the interior
// mutability is never shared concurrently.
unsafe impl Sync for IstStackCell {}

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY_IST_STACK: IstStackCell = IstStackCell(UnsafeCell::new(IstStack(
    [MaybeUninit::uninit(); STACK_SIZE],
)));
static DF_STACKS: [IstStackCell; MAX_CPUS] = [EMPTY_IST_STACK; MAX_CPUS];

#[repr(transparent)]
struct TssCell(UnsafeCell<TaskStateSegment>);
// SAFETY: all IST setup runs in the one-time `GDT::call_once` init,
// where the BSP calls `populate_for` for every CPU index single-
// threaded, before any AP is started — so those cross-slot writes have
// no concurrent writer. After init each CPU mutates only its own slot's
// `rsp0` via `set_rsp0` keyed on `current_cpu_id`; the only other access
// is that CPU's own hardware rsp0/IST reads as aligned loads, which don't
// race that same CPU's aligned stores. No cell is ever written by two CPUs.
unsafe impl Sync for TssCell {}

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY_TSS: TssCell = TssCell(UnsafeCell::new(TaskStateSegment::new()));
static TSSES: [TssCell; MAX_CPUS] = [EMPTY_TSS; MAX_CPUS];

pub(super) fn tss_static(i: u32) -> &'static TaskStateSegment {
    assert!((i as usize) < MAX_CPUS);
    // SAFETY: TSSES is in static memory; we hand out a shared
    // reference into it. Concurrent mutations (per-CPU `rsp0`
    // writes) are 8-byte-aligned stores that don't race against
    // CPU reads from the same field.
    unsafe { &*TSSES[i as usize].0.get() }
}

pub(super) fn populate_for(cpu_id: u32) {
    assert!((cpu_id as usize) < MAX_CPUS);
    let tss_ptr = TSSES[cpu_id as usize].0.get();
    // SAFETY: `cpu_id` is bounds-checked above, so `DF_STACKS[cpu_id]`
    // is a live static `IstStack` of exactly `STACK_SIZE` bytes; `.get()`
    // yields its base and `add(STACK_SIZE)` lands one-past-the-end within
    // the same allocation (the legal stack top, since stacks grow down).
    // The pointer is only recorded as the IST value, never dereferenced.
    let stack_top = unsafe {
        let p = DF_STACKS[cpu_id as usize].0.get() as *mut u8;
        p.add(STACK_SIZE)
    };
    // SAFETY: `populate_for` runs only inside the one-time
    // `GDT::call_once` init (on the BSP, single-threaded, before any AP
    // starts), so this write to `TSSES[cpu_id]` has no concurrent writer;
    // it is also idempotent (same value) on any later re-run.
    unsafe {
        (*tss_ptr).interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
            VirtAddr::from_ptr(stack_top);
    }
}

pub fn set_rsp0(rsp: u64) {
    let cpu = current_cpu_id();
    let tss_ptr = TSSES[cpu as usize].0.get();
    // SAFETY: only this CPU writes its own `rsp0`; the CPU's read
    // of rsp0 is a single 64-bit aligned load, not racy against a
    // 64-bit aligned store from the same CPU.
    unsafe {
        (*tss_ptr).privilege_stack_table[0] = VirtAddr::new(rsp);
    }
}
