.section .note.Xen, "a", @note
.align 4
    .long 4
    .long 4
    .long 18
    .asciz "Xen"
    .align 4
    .long _start
.align 4

.section .multiboot2, "a"
.align 8
.global __multiboot2_header_start
__multiboot2_header_start:
    .long 0xE85250D6
    .long 0
    .long __multiboot2_header_end - __multiboot2_header_start
    .long -(0xE85250D6 + 0 + (__multiboot2_header_end - __multiboot2_header_start))
    .short 0
    .short 0
    .long 8
.global __multiboot2_header_end
__multiboot2_header_end:
.align 8

.section .bss.boot, "aw", @nobits
.align 4096
.global __bootstrap_pml4
__bootstrap_pml4:
    .skip 4096
__bootstrap_pdpt_low:
    .skip 4096
__bootstrap_pdpt_high:
    .skip 4096
__bootstrap_pd_low:
    .skip 4096
.align 16
.global __bootstrap_stack_bottom
__bootstrap_stack_bottom:
    .skip 65536
.global __bootstrap_stack_top
__bootstrap_stack_top:

.section .data.boot, "aw", @progbits
.align 8
__pvh_boot_info_ptr:
    .long 0
.align 8
.global __boot_protocol
__boot_protocol:
    .quad 0

.section .data.boot, "aw", @progbits
.align 8
__bootstrap_gdt:
    .quad 0
    .quad (1 << 43) | (1 << 44) | (1 << 47) | (1 << 53)
__bootstrap_gdt_end:
__bootstrap_gdt_ptr:
    .short __bootstrap_gdt_end - __bootstrap_gdt - 1
    .quad __bootstrap_gdt

.section .text.boot, "ax"
.code32
.global _start
_start:
    movl $__bootstrap_stack_top, %esp

    movl %ebx, __pvh_boot_info_ptr
    movl $0, __boot_protocol
    cmpl $0x36D76289, %eax
    jne .Lprotocol_done
    movl $1, __boot_protocol
.Lprotocol_done:

    movl $__boot_bss_phys_start, %edi
    movl $__boot_bss_phys_end, %ecx
    subl %edi, %ecx
    shrl $2, %ecx
    xorl %eax, %eax
    rep stosl

    movl %ebx, __pvh_boot_info_ptr

    movl $__bootstrap_pdpt_low, %eax
    orl $0x3, %eax
    movl %eax, __bootstrap_pml4

    movl $__bootstrap_pdpt_high, %eax
    orl $0x3, %eax
    movl %eax, __bootstrap_pml4 + 511 * 8

    movl $__bootstrap_pd_low, %eax
    orl $0x3, %eax
    movl %eax, __bootstrap_pdpt_low

    xorl %ecx, %ecx
.Lfill_pd_low:
    movl %ecx, %eax
    shll $21, %eax
    orl $0x83, %eax
    movl %eax, __bootstrap_pd_low(,%ecx,8)
    incl %ecx
    cmpl $512, %ecx
    jne .Lfill_pd_low

    movl $0x8000009b, %eax
    movl %eax, __bootstrap_pdpt_high + 509 * 8
    movl $0x00000083, %eax
    movl %eax, __bootstrap_pdpt_high + 510 * 8
    movl $0xc000009b, %eax
    movl %eax, __bootstrap_pdpt_high + 511 * 8

    movl $__bootstrap_pml4, %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl $(1 << 5), %eax
    movl %eax, %cr4

    movl $0xC0000080, %ecx
    rdmsr
    orl $(1 << 8), %eax
    wrmsr

    movl %cr0, %eax
    orl $(1 << 31), %eax
    movl %eax, %cr0

    lgdt __bootstrap_gdt_ptr
    ljmp $0x08, $long_mode_start

.code64
long_mode_start:
    xorw %ax, %ax
    movw %ax, %ss
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %fs
    movw %ax, %gs

    movabsq $__bss_start, %rdi
    movabsq $__bss_end, %rcx
    subq %rdi, %rcx
    shrq $3, %rcx
    xorq %rax, %rax
    rep stosq

    movabsq $0xffffffff80000000, %rax
    movl    $__bootstrap_stack_top, %ebx
    addq    %rax, %rbx
    movq    %rbx, %rsp

    movl __pvh_boot_info_ptr, %edi
    movl __boot_protocol, %esi

    movabsq $kernel_main, %rax
    callq *%rax

.Lhalt:
    cli
    hlt
    jmp .Lhalt
