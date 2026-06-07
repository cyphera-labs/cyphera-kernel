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
     * subdividable into 4 KiB pages. A bootstrap map made of 4 KiB
     * pages everywhere would allow the lower 0x400000 conventional
     * load address instead.
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
