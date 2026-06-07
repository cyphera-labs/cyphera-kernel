.section .text
.global syscall_entry
syscall_entry:
    mov %rsp, %gs:0x8
    mov %gs:0x0, %rsp

    push %rax
    push %r15
    push %r14
    push %r13
    push %r12
    push %rbp
    push %rbx
    pushq %gs:0x8
    push %r11
    push %rcx
    push %r9
    push %r8
    push %r10
    push %rdx
    push %rsi
    push %rdi
    push %rax

    sti

    mov %rsp, %rdi
    call syscall_dispatch_entry

    cli

    pop %rax
    pop %rdi
    pop %rsi
    pop %rdx
    pop %r10
    pop %r8
    pop %r9
    pop %rcx
    pop %r11
    popq %gs:0x8
    pop %rbx
    pop %rbp
    pop %r12
    pop %r13
    pop %r14
    pop %r15
    add $8, %rsp

    mov %gs:0x8, %rsp
    sysretq
