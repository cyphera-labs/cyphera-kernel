ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
}

SECTIONS {
    /* proc_misc loads at 768 MiB. (Lower-than-usual address because
     * the small code model needs the image to fit inside the signed
     * 32-bit range — 2 GiB+ overflows R_X86_64_32S relocations.) */
    . = 0x30000000;

    .text : ALIGN(4K) { *(.text.boot) *(.text .text.*) } :text
    . = ALIGN(4K);
    .rodata : { *(.rodata .rodata.*) } :rodata
    . = ALIGN(4K);
    .data : { *(.data .data.*) } :data
    .bss  : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ : { *(.eh_frame) *(.note.*) *(.comment) }
}
