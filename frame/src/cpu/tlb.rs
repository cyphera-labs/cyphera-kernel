use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::registers::control::Cr3;

const MAX_CPUS: usize = 64;

#[repr(C, align(64))]
struct Slot {
    request_seqno: AtomicU64,
    ack_seqno: AtomicU64,
}

#[allow(clippy::declare_interior_mutable_const)]
const SLOT_INIT: Slot = Slot {
    request_seqno: AtomicU64::new(0),
    ack_seqno: AtomicU64::new(0),
};
static PER_CPU: [Slot; MAX_CPUS] = [SLOT_INIT; MAX_CPUS];

#[inline]
pub fn flush_local() {
    let (frame, flags) = Cr3::read();
    // SAFETY: rewriting CR3 with its own value preserves the address
    // space; the only effect is the implied TLB flush.
    unsafe { Cr3::write(frame, flags) };
}

pub fn shootdown_all() {
    flush_local();

    let mask = crate::arch::x86_64::smp::online_mask();
    if mask.count_ones() <= 1 {
        return;
    }
    let me = crate::intr::lapic::local_apic_id() as u32;

    let mut expected = [0u64; MAX_CPUS];
    for cpu in 0..MAX_CPUS as u32 {
        if mask & (1u64 << cpu) == 0 || cpu == me {
            continue;
        }
        let prev = PER_CPU[cpu as usize]
            .request_seqno
            .fetch_add(1, Ordering::AcqRel);
        expected[cpu as usize] = prev + 1;
        crate::intr::lapic::send_ipi(
            cpu as u8,
            crate::intr::lapic::TLB_SHOOTDOWN_VECTOR,
            crate::intr::lapic::IpiKind::Fixed,
        );
    }

    let saved_if = saved_irq_flag();
    enable_irqs();
    for cpu in 0..MAX_CPUS as u32 {
        if mask & (1u64 << cpu) == 0 || cpu == me {
            continue;
        }
        let want = expected[cpu as usize];
        while PER_CPU[cpu as usize].ack_seqno.load(Ordering::Acquire) < want {
            core::hint::spin_loop();
        }
    }
    if !saved_if {
        disable_irqs();
    }
}

#[inline]
fn saved_irq_flag() -> bool {
    let flags: u64;
    // SAFETY: pushfq/pop only reads RFLAGS into a register; it touches
    // no Rust-visible memory (nomem) and does not alter the CPU's flag
    // state (preserves_flags), so it cannot violate any aliasing or
    // control-flow assumption the compiler relies on.
    unsafe { core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags)) };
    (flags & 0x200) != 0
}

#[inline]
fn enable_irqs() {
    // SAFETY: sti only sets RFLAGS.IF to permit interrupt delivery; it
    // accesses no memory and the IDT/per-CPU state needed to service an
    // incoming IRQ is already installed. The caller (shootdown_all)
    // snapshots the entry IF via saved_irq_flag and, if it was clear,
    // calls disable_irqs() to re-mask afterward, so the prior
    // interrupt-masking contract is restored.
    unsafe { core::arch::asm!("sti", options(nostack)) };
}

#[inline]
fn disable_irqs() {
    // SAFETY: cli only clears RFLAGS.IF to mask maskable interrupts; it
    // accesses no memory. Masking interrupts is always sound, and here
    // it merely restores the IRQ-disabled state the caller held before
    // shootdown_all temporarily enabled IRQs to spin for ACKs.
    unsafe { core::arch::asm!("cli", options(nostack)) };
}

pub fn handle_shootdown_ipi() {
    flush_local();
    crate::intr::lapic::eoi();
    let me = crate::intr::lapic::local_apic_id() as usize;
    if me >= MAX_CPUS {
        return;
    }
    let cur = PER_CPU[me].request_seqno.load(Ordering::Acquire);
    PER_CPU[me].ack_seqno.store(cur, Ordering::Release);
}
