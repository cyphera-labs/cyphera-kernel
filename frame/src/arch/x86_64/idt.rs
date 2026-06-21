use spin::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use super::tss::DOUBLE_FAULT_IST_INDEX;

static IDT: Once<InterruptDescriptorTable> = Once::new();

pub fn init() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();

        idt.divide_error.set_handler_fn(handle_divide_error);
        idt.debug.set_handler_fn(handle_debug);
        idt.non_maskable_interrupt.set_handler_fn(handle_nmi);
        idt.breakpoint
            .set_handler_fn(handle_breakpoint)
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        idt.overflow.set_handler_fn(handle_overflow);
        idt.bound_range_exceeded.set_handler_fn(handle_bound);
        idt.invalid_opcode.set_handler_fn(handle_invalid_opcode);
        idt.device_not_available.set_handler_fn(handle_device_na);

        // SAFETY: set_stack_index requires the IST index to name a
        // valid, dedicated stack so the CPU switches to it on #DF.
        // DOUBLE_FAULT_IST_INDEX (0) is the slot `tss::populate_for`
        // fills with this CPU's 16 KiB IST stack before the IDT is
        // used, and that slot is reserved for #DF alone — so the
        // double-fault handler always lands on a known-good rsp even
        // when the interrupted stack is corrupt.
        unsafe {
            idt.double_fault
                .set_handler_fn(handle_double_fault)
                .set_stack_index(DOUBLE_FAULT_IST_INDEX);
        }

        idt.invalid_tss.set_handler_fn(handle_invalid_tss);
        idt.segment_not_present.set_handler_fn(handle_segment_np);
        idt.stack_segment_fault.set_handler_fn(handle_stack_seg);
        idt.general_protection_fault.set_handler_fn(handle_gpf);
        idt.page_fault.set_handler_fn(handle_page_fault);
        idt.x87_floating_point.set_handler_fn(handle_x87);
        idt.alignment_check.set_handler_fn(handle_alignment);
        idt.machine_check.set_handler_fn(handle_machine_check);
        idt.simd_floating_point.set_handler_fn(handle_simd);
        idt.virtualization.set_handler_fn(handle_virt);

        idt[crate::intr::lapic::TIMER_VECTOR].set_handler_fn(handle_timer);
        idt[crate::intr::lapic::RESCHED_IPI_VECTOR].set_handler_fn(handle_resched_ipi);
        idt[crate::intr::lapic::TLB_SHOOTDOWN_VECTOR].set_handler_fn(handle_tlb_shootdown);
        idt[crate::intr::lapic::SPURIOUS_VECTOR].set_handler_fn(handle_spurious);

        idt
    });
    idt.load();
}

extern "x86-interrupt" fn handle_divide_error(frame: InterruptStackFrame) {
    panic_with_frame("#DE divide-by-zero", &frame, None);
}

extern "x86-interrupt" fn handle_debug(mut frame: InterruptStackFrame) {
    if from_user(&frame) {
        if let Some(h) = crate::user::trace_trap_hook() {
            // SAFETY: `as_mut()` exposes the iretq frame's slots for
            // in-place mutation — the supported use (rewriting
            // rip/rflags before iretq resumes user mode). The fault came
            // from ring 3 (from_user above), so the frame sits on the
            // current kernel stack and is the only live reference to it.
            unsafe {
                let mut volatile = frame.as_mut();
                let mut snap = volatile.read();
                let mut rip = snap.instruction_pointer.as_u64();
                let mut rflags = snap.cpu_flags.bits();
                if h(&mut rip, &mut rflags, 1) {
                    snap.instruction_pointer = crate::mm::VirtAddr::new(rip);
                    snap.cpu_flags = x86_64::registers::rflags::RFlags::from_bits_truncate(rflags);
                    volatile.write(snap);
                    return;
                }
            }
        }
    }
    panic_with_frame("#DB debug exception", &frame, None);
}

extern "x86-interrupt" fn handle_nmi(frame: InterruptStackFrame) {
    panic_with_frame("NMI non-maskable interrupt", &frame, None);
}

extern "x86-interrupt" fn handle_breakpoint(mut frame: InterruptStackFrame) {
    if from_user(&frame) {
        if let Some(h) = crate::user::trace_trap_hook() {
            // SAFETY: `as_mut()` exposes the iretq frame's slots for
            // in-place mutation — exactly the supported use (rewriting
            // rip/rflags before iretq resumes user mode). The fault came
            // from ring 3 (from_user above), so the frame sits on the
            // current kernel stack and is the only live reference to it.
            unsafe {
                let mut volatile = frame.as_mut();
                let mut snap = volatile.read();
                let mut rip = snap.instruction_pointer.as_u64();
                let mut rflags = snap.cpu_flags.bits();
                if h(&mut rip, &mut rflags, 3) {
                    snap.instruction_pointer = crate::mm::VirtAddr::new(rip);
                    snap.cpu_flags = x86_64::registers::rflags::RFlags::from_bits_truncate(rflags);
                    volatile.write(snap);
                    return;
                }
            }
        }
    }
    crate::println!("#BP breakpoint @ {:#x}", frame.instruction_pointer.as_u64());
}

extern "x86-interrupt" fn handle_overflow(frame: InterruptStackFrame) {
    panic_with_frame("#OF overflow", &frame, None);
}

extern "x86-interrupt" fn handle_bound(frame: InterruptStackFrame) {
    panic_with_frame("#BR bound range exceeded", &frame, None);
}

extern "x86-interrupt" fn handle_invalid_opcode(frame: InterruptStackFrame) {
    if from_user(&frame) {
        if let Some(h) = crate::user::user_fault_handler() {
            crate::println!(
                "#UD from user @ rip={:#x}; killing process",
                frame.instruction_pointer.as_u64()
            );
            h(0, 6, 0);
        }
    }
    panic_with_frame("#UD invalid opcode", &frame, None);
}

extern "x86-interrupt" fn handle_device_na(frame: InterruptStackFrame) {
    panic_with_frame("#NM device not available", &frame, None);
}

extern "x86-interrupt" fn handle_double_fault(frame: InterruptStackFrame, _err: u64) -> ! {
    panic_with_frame("#DF double fault", &frame, None);
}

extern "x86-interrupt" fn handle_invalid_tss(frame: InterruptStackFrame, err: u64) {
    panic_with_frame("#TS invalid TSS", &frame, Some(err));
}

extern "x86-interrupt" fn handle_segment_np(frame: InterruptStackFrame, err: u64) {
    panic_with_frame("#NP segment not present", &frame, Some(err));
}

extern "x86-interrupt" fn handle_stack_seg(frame: InterruptStackFrame, err: u64) {
    panic_with_frame("#SS stack-segment fault", &frame, Some(err));
}

extern "x86-interrupt" fn handle_gpf(frame: InterruptStackFrame, err: u64) {
    if from_user(&frame) {
        if let Some(h) = crate::user::user_fault_handler() {
            crate::println!(
                "#GP from user @ rip={:#x} err={err:#x}; killing process",
                frame.instruction_pointer.as_u64()
            );
            h(0, 13, err);
        }
    }
    panic_with_frame("#GP general protection fault", &frame, Some(err));
}

extern "x86-interrupt" fn handle_page_fault(
    mut frame: InterruptStackFrame,
    err: PageFaultErrorCode,
) {
    let cr2 = x86_64::registers::control::Cr2::read_raw();
    if !from_user(&frame) {
        let rip = frame.instruction_pointer.as_u64();
        if let Some(fixup) = crate::user::fixup_exception(rip) {
            // SAFETY: the InterruptStackFrame's iretq slots are
            // mutable (same `as_mut()` path the #DB handler uses);
            // resuming at the fixup VA runs the copy routine's
            // fault-return path, which yields the un-copied count.
            unsafe {
                let mut volatile = frame.as_mut();
                let mut snap = volatile.read();
                snap.instruction_pointer = crate::mm::VirtAddr::new(fixup);
                volatile.write(snap);
            }
            return;
        }
    }
    if from_user(&frame) {
        if let Some(hook) = crate::user::user_pf_hook() {
            if hook(cr2, err.bits()) {
                return;
            }
        }
        if let Some(h) = crate::user::user_fault_handler() {
            crate::println!(
                "#PF from user @ rip={:#x} cr2={:#x} err={:?}; killing process",
                frame.instruction_pointer.as_u64(),
                cr2,
                err
            );
            h(cr2, 14, err.bits());
        }
    }
    crate::println!(
        "#PF page fault @ rip={:#x} cr2={:#x} err={:?}",
        frame.instruction_pointer.as_u64(),
        cr2,
        err
    );
    panic_with_frame("#PF page fault", &frame, Some(err.bits()));
}

fn from_user(frame: &InterruptStackFrame) -> bool {
    (frame.code_segment.0 & 3) == 3
}

extern "x86-interrupt" fn handle_x87(frame: InterruptStackFrame) {
    panic_with_frame("#MF x87 FPU error", &frame, None);
}

extern "x86-interrupt" fn handle_alignment(frame: InterruptStackFrame, err: u64) {
    panic_with_frame("#AC alignment check", &frame, Some(err));
}

extern "x86-interrupt" fn handle_machine_check(frame: InterruptStackFrame) -> ! {
    panic_with_frame("#MC machine check", &frame, None);
}

extern "x86-interrupt" fn handle_simd(frame: InterruptStackFrame) {
    panic_with_frame("#XM SIMD floating-point", &frame, None);
}

extern "x86-interrupt" fn handle_virt(frame: InterruptStackFrame) {
    panic_with_frame("#VE virtualization", &frame, None);
}

extern "x86-interrupt" fn handle_timer(frame: InterruptStackFrame) {
    crate::intr::lapic::handle_tick();
    notify_resume_on_user_return(&frame);
}

extern "x86-interrupt" fn handle_resched_ipi(frame: InterruptStackFrame) {
    crate::intr::lapic::handle_resched();
    notify_resume_on_user_return(&frame);
}

fn notify_resume_on_user_return(frame: &InterruptStackFrame) {
    if from_user(frame) {
        if let Some(h) = crate::user::irq_notify_resume() {
            h();
        }
    }
}

extern "x86-interrupt" fn handle_tlb_shootdown(_frame: InterruptStackFrame) {
    crate::cpu::tlb::handle_shootdown_ipi();
}

extern "x86-interrupt" fn handle_spurious(_frame: InterruptStackFrame) {}

#[track_caller]
fn panic_with_frame(name: &str, frame: &InterruptStackFrame, err: Option<u64>) -> ! {
    crate::println!("--- KERNEL EXCEPTION ---");
    crate::println!("vector  : {name}");
    if let Some(e) = err {
        crate::println!("error   : {e:#x}");
    }
    crate::println!("rip     : {:#x}", frame.instruction_pointer.as_u64());
    crate::println!("cs      : {:#x}", frame.code_segment.0);
    crate::println!("rflags  : {:#x}", frame.cpu_flags);
    crate::println!("rsp     : {:#x}", frame.stack_pointer.as_u64());
    crate::println!("ss      : {:#x}", frame.stack_segment.0);
    let rsp = frame.stack_pointer.as_u64() as *const u64;
    crate::println!("--- stack at rsp (16 qwords) ---");
    for i in 0..16 {
        // SAFETY: best-effort postmortem dump on the path to an
        // unconditional `panic!`. `rsp` is the stack pointer the CPU
        // captured into the trap frame; it is NOT guaranteed aligned or
        // mapped — a corrupt/misaligned/unmapped rsp is exactly the kind
        // of fault we are dumping, so a read here may itself fault. That
        // is acceptable: we are already aborting. Volatile keeps each
        // read from being elided or coalesced so the dump reflects actual
        // memory; we walk a fixed 16-qword window forward from `rsp`.
        let val = unsafe { core::ptr::read_volatile(rsp.add(i)) };
        crate::println!("  [{:#x}] = {:#x}", rsp as u64 + (i as u64) * 8, val);
    }
    panic!("{name}");
}
