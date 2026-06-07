ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5);  /* R + X */
    rodata PT_LOAD FLAGS(4);  /* R     */
    data   PT_LOAD FLAGS(6);  /* R + W */
}

SECTIONS {
    /*
     * 0x4000_0000 (1 GiB) — above the bootstrap PML4's identity-map
     * region which is paved with 2 MiB huge pages and therefore not
     * subdividable into 4 KiB pages. Lower load addresses such as the
     * conventional 0x400000 fall inside that huge-page region.
     */
    . = 0x40000000;

    .text : ALIGN(4K) {
        *(.text.boot)
        *(.text .text.*)
    } :text

    . = ALIGN(4K);
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(4K);
    .data : {
        *(.data .data.*)
    } :data

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame)
        *(.note.*)
        *(.comment)
    }
}
