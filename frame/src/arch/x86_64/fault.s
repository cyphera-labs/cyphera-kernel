# Per-vector fault trampolines: snapshot the 15 GP registers gs-relative (order
# mirrored by per_cpu::fault_gprs), then jmp — never call (a return address would
# shift the CPU exception frame) — to the typed handler. GS is the per-CPU base in
# both rings (no swapgs), so the stores are valid for kernel faults too.

.section .text

.macro SNAPSHOT_FAULT_GPRS
    mov %rax, %gs:0x20
    mov %rbx, %gs:0x28
    mov %rcx, %gs:0x30
    mov %rdx, %gs:0x38
    mov %rsi, %gs:0x40
    mov %rdi, %gs:0x48
    mov %rbp, %gs:0x50
    mov %r8,  %gs:0x58
    mov %r9,  %gs:0x60
    mov %r10, %gs:0x68
    mov %r11, %gs:0x70
    mov %r12, %gs:0x78
    mov %r13, %gs:0x80
    mov %r14, %gs:0x88
    mov %r15, %gs:0x90
.endm

.global de_trampoline
de_trampoline:
    SNAPSHOT_FAULT_GPRS
    jmp handle_divide_error

.global of_trampoline
of_trampoline:
    SNAPSHOT_FAULT_GPRS
    jmp handle_overflow

.global br_trampoline
br_trampoline:
    SNAPSHOT_FAULT_GPRS
    jmp handle_bound

.global ud_trampoline
ud_trampoline:
    SNAPSHOT_FAULT_GPRS
    jmp handle_invalid_opcode

.global gp_trampoline
gp_trampoline:
    SNAPSHOT_FAULT_GPRS
    jmp handle_gpf

.global pf_trampoline
pf_trampoline:
    SNAPSHOT_FAULT_GPRS
    jmp handle_page_fault

.global mf_trampoline
mf_trampoline:
    SNAPSHOT_FAULT_GPRS
    jmp handle_x87

.global ac_trampoline
ac_trampoline:
    SNAPSHOT_FAULT_GPRS
    jmp handle_alignment

.global xm_trampoline
xm_trampoline:
    SNAPSHOT_FAULT_GPRS
    jmp handle_simd
