.section .text.ap_trampoline, "ax"
.code16
.global ap_trampoline_start
.global ap_trampoline_end
.global ap_trampoline_params
.global ap_trampoline_size

.equ AP_BASE, 0x8000

ap_trampoline_start:
    cli
    cld

    mov %cs, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    movw $0x0FFF, %sp

    lgdtl ap_gdt_ptr - ap_trampoline_start

    mov %cr0, %eax
    or  $0x1, %eax
    mov %eax, %cr0

    ljmpl $0x08, $(AP_BASE + (ap_protected_mode - ap_trampoline_start))

.code32
ap_protected_mode:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    movl (AP_BASE + ap_param_cr3 - ap_trampoline_start), %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl  $(1 << 5), %eax
    movl %eax, %cr4

    movl $0xC0000080, %ecx
    rdmsr
    orl  $((1 << 8) | (1 << 11)), %eax
    wrmsr

    movl %cr0, %eax
    orl  $(1 << 31), %eax
    movl %eax, %cr0

    lgdt (AP_BASE + ap_gdt64_ptr - ap_trampoline_start)
    ljmpl $0x08, $(AP_BASE + (ap_long_mode - ap_trampoline_start))

.code64
ap_long_mode:
    xorw %ax, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs
    movw %ax, %ss

    movq (AP_BASE + ap_param_rsp - ap_trampoline_start), %rsp

    movq (AP_BASE + ap_param_cpu_id - ap_trampoline_start), %rdi

    movq (AP_BASE + ap_param_entry - ap_trampoline_start), %rax
    jmpq *%rax

.align 8
ap_gdt:
    .quad 0
    .word 0xFFFF
    .word 0x0000
    .byte 0x00
    .byte 0x9A
    .byte 0xCF
    .byte 0x00
    .word 0xFFFF
    .word 0x0000
    .byte 0x00
    .byte 0x92
    .byte 0xCF
    .byte 0x00
ap_gdt_end:
ap_gdt_ptr:
    .word ap_gdt_end - ap_gdt - 1
    .long AP_BASE + (ap_gdt - ap_trampoline_start)

.align 8
ap_gdt64:
    .quad 0
    .quad (1 << 43) | (1 << 44) | (1 << 47) | (1 << 53)
ap_gdt64_end:
ap_gdt64_ptr:
    .word ap_gdt64_end - ap_gdt64 - 1
    .quad AP_BASE + (ap_gdt64 - ap_trampoline_start)

.align 8
ap_trampoline_params:
ap_param_rsp:
    .quad 0
ap_param_entry:
    .quad 0
ap_param_cr3:
    .quad 0
ap_param_cpu_id:
    .quad 0

ap_trampoline_end:
ap_trampoline_size:
    .long ap_trampoline_end - ap_trampoline_start
