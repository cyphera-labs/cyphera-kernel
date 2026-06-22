use spin::Once;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use super::tss::DOUBLE_FAULT_IST_INDEX;

core::arch::global_asm!(include_str!("fault.s"), options(att_syntax));

extern "C" {
    fn de_trampoline();
    fn of_trampoline();
    fn br_trampoline();
    fn ud_trampoline();
    fn gp_trampoline();
    fn pf_trampoline();
    fn mf_trampoline();
    fn ac_trampoline();
    fn xm_trampoline();
}

static IDT: Once<InterruptDescriptorTable> = Once::new();

pub fn init() {
    let idt = IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();

        idt.debug.set_handler_fn(handle_debug);
        idt.non_maskable_interrupt.set_handler_fn(handle_nmi);
        idt.breakpoint
            .set_handler_fn(handle_breakpoint)
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
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
        idt.machine_check.set_handler_fn(handle_machine_check);
        idt.virtualization.set_handler_fn(handle_virt);

        // SAFETY: each synchronous user-fault vector is installed by address to
        // a register-snapshot trampoline (gs-relative stores + jmp to the typed
        // handler, leaving the CPU exception frame intact, so the handler runs
        // as a direct gate would). The symbols are crate-local `.text`, valid
        // for the program's lifetime; set_handler_addr only stores the gate's
        // target.
        unsafe {
            idt.divide_error
                .set_handler_addr(x86_64::VirtAddr::new(de_trampoline as *const () as u64));
            idt.overflow
                .set_handler_addr(x86_64::VirtAddr::new(of_trampoline as *const () as u64));
            idt.bound_range_exceeded
                .set_handler_addr(x86_64::VirtAddr::new(br_trampoline as *const () as u64));
            idt.invalid_opcode
                .set_handler_addr(x86_64::VirtAddr::new(ud_trampoline as *const () as u64));
            idt.general_protection_fault
                .set_handler_addr(x86_64::VirtAddr::new(gp_trampoline as *const () as u64));
            idt.page_fault
                .set_handler_addr(x86_64::VirtAddr::new(pf_trampoline as *const () as u64));
            idt.x87_floating_point
                .set_handler_addr(x86_64::VirtAddr::new(mf_trampoline as *const () as u64));
            idt.alignment_check
                .set_handler_addr(x86_64::VirtAddr::new(ac_trampoline as *const () as u64));
            idt.simd_floating_point
                .set_handler_addr(x86_64::VirtAddr::new(xm_trampoline as *const () as u64));
        }

        idt[crate::intr::lapic::TIMER_VECTOR].set_handler_fn(handle_timer);
        idt[crate::intr::lapic::RESCHED_IPI_VECTOR].set_handler_fn(handle_resched_ipi);
        idt[crate::intr::lapic::TLB_SHOOTDOWN_VECTOR].set_handler_fn(handle_tlb_shootdown);
        idt[crate::intr::lapic::SPURIOUS_VECTOR].set_handler_fn(handle_spurious);

        idt
    });
    idt.load();
}

#[no_mangle]
extern "x86-interrupt" fn handle_divide_error(frame: InterruptStackFrame) {
    if from_user(&frame) {
        try_deliver_user_fault(&frame, 0, 0, 0);
    }
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

#[no_mangle]
extern "x86-interrupt" fn handle_overflow(frame: InterruptStackFrame) {
    if from_user(&frame) {
        try_deliver_user_fault(&frame, 4, 0, 0);
    }
    panic_with_frame("#OF overflow", &frame, None);
}

#[no_mangle]
extern "x86-interrupt" fn handle_bound(frame: InterruptStackFrame) {
    if from_user(&frame) {
        try_deliver_user_fault(&frame, 5, 0, 0);
    }
    panic_with_frame("#BR bound range exceeded", &frame, None);
}

#[no_mangle]
extern "x86-interrupt" fn handle_invalid_opcode(frame: InterruptStackFrame) {
    if from_user(&frame) {
        try_deliver_user_fault(&frame, 6, 0, 0);
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

#[no_mangle]
extern "x86-interrupt" fn handle_gpf(frame: InterruptStackFrame, err: u64) {
    if from_user(&frame) {
        try_deliver_user_fault(&frame, 13, err, 0);
    }
    panic_with_frame("#GP general protection fault", &frame, Some(err));
}

#[no_mangle]
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
        try_deliver_user_fault(&frame, 14, err.bits(), cr2);
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

fn try_deliver_user_fault(frame: &InterruptStackFrame, vector: u8, error: u64, addr: u64) {
    if let Some(h) = crate::user::user_fault_signal() {
        let mut tf = crate::user::fault_trapframe(
            frame.instruction_pointer.as_u64(),
            frame.cpu_flags.bits(),
            frame.stack_pointer.as_u64(),
        );
        h(&mut tf, vector, error, addr);
    }
}

#[no_mangle]
extern "x86-interrupt" fn handle_x87(frame: InterruptStackFrame) {
    if from_user(&frame) {
        try_deliver_user_fault(&frame, 16, 0, 0);
    }
    panic_with_frame("#MF x87 FPU error", &frame, None);
}

#[no_mangle]
extern "x86-interrupt" fn handle_alignment(frame: InterruptStackFrame, err: u64) {
    if from_user(&frame) {
        try_deliver_user_fault(&frame, 17, err, 0);
    }
    panic_with_frame("#AC alignment check", &frame, Some(err));
}

extern "x86-interrupt" fn handle_machine_check(frame: InterruptStackFrame) -> ! {
    panic_with_frame("#MC machine check", &frame, None);
}

#[no_mangle]
extern "x86-interrupt" fn handle_simd(frame: InterruptStackFrame) {
    if from_user(&frame) {
        try_deliver_user_fault(&frame, 19, 0, 0);
    }
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
