ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
}

SECTIONS {
    /* proc_exec loads at 1.25 GiB — distinct from proc_a (1 GiB) so
     * a debugger sees them at separate VAs even though execve will
     * tear down proc_exec's image before proc_a is loaded. */
    . = 0x50000000;

    .text : ALIGN(4K) { *(.text.boot) *(.text .text.*) } :text
    . = ALIGN(4K);
    .rodata : { *(.rodata .rodata.*) } :rodata
    . = ALIGN(4K);
    .data : { *(.data .data.*) } :data
    .bss  : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ : { *(.eh_frame) *(.note.*) *(.comment) }
}
