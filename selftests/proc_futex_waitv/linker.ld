ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
}

SECTIONS {
    . = 0x70300000;

    .text : ALIGN(4K) { *(.text.boot) *(.text .text.*) } :text
    . = ALIGN(4K);
    .rodata : { *(.rodata .rodata.*) } :rodata
    . = ALIGN(4K);
    .data : { *(.data .data.*) } :data
    .bss  : { *(.bss .bss.*) *(COMMON) } :data

    /DISCARD/ : { *(.eh_frame) *(.note.*) *(.comment) }
}
