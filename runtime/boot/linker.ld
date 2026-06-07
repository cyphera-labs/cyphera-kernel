/*
 * Boot stub at low VMA (runs in 32-bit mode before paging is on),
 * main kernel image at canonical high half.
 *
 * Memory layout:
 *   - PVH bootloader places the entire ELF starting at 1 MiB physical.
 *   - .boot.* (note.Xen, text.boot, data.boot, bss.boot) live at LMA == VMA
 *     == 1 MiB+. The 32-bit boot stub runs at and accesses these via
 *     physical addresses (paging off, then identity-mapped).
 *   - .text / .rodata / .data / .bss have VMA in the canonical kernel high
 *     half (0xffff_ffff_8000_0000 + offset) but LMA continues directly
 *     after .boot.* in physical memory, so the bootloader still loads
 *     the whole ELF into one contiguous low region.
 *   - The boot stub builds two PML4 mappings — low identity (for itself)
 *     and high half (so kernel_main can run from high VAs) — then ljmps
 *     to long mode and movabs-jumps to kernel_main at its high VA.
 *
 * Linker symbols:
 *   __kernel_image_phys_start / _end  — physical extent the bootloader
 *     consumes; the frame allocator carves this out of usable RAM.
 *   __boot_bss_phys_start / _end      — boot stub zeroes this in 32-bit.
 *   __bss_phys_start / _end           — boot stub zeroes this in 64-bit
 *     (after long mode, via high VAs courtesy of the high mapping).
 */

ENTRY(_start)

KERNEL_LMA_BASE   = 1M;
KERNEL_VMA_OFFSET = 0xffffffff80000000;

SECTIONS {
    . = KERNEL_LMA_BASE;
    __kernel_image_phys_start = .;

    /* PVH note must be its own section so QEMU's PVH loader finds it
     * by name. Place it first; it's small. */
    .note.Xen : ALIGN(4) {
        KEEP(*(.note.Xen))
    }

    /* Multiboot2 header. GRUB scans the first 32 KiB of
     * the image for the 0xE85250D6 magic. Pin this section right
     * after .note.Xen so it lands well within the scan window.
     * KEEP prevents --gc-sections from dropping it (nothing in the
     * kernel source references it). 8-byte aligned per the
     * multiboot2 spec. */
    .multiboot2 : ALIGN(8) {
        KEEP(*(.multiboot2))
    }

    /* Boot stub — runs in 32-bit mode before paging. VMA == LMA. */
    .boot.text : ALIGN(4K) {
        *(.text.boot)
    }

    .boot.data : ALIGN(4K) {
        *(.data.boot)
    }

    .boot.bss : ALIGN(4K) {
        __boot_bss_phys_start = .;
        *(.bss.boot)
        . = ALIGN(4K);
        __boot_bss_phys_end = .;
    }

    __boot_phys_end = .;

    /* Main kernel sections — HIGH VMA, LOW LMA. LMA is set to
     * VMA - KERNEL_VMA_OFFSET on every section so the boot stub's
     * single-offset mapping (high = low + KERNEL_VMA_OFFSET) is
     * correct for *all* sections, not just .text. A per-section LMA
     * (rather than a contiguous LMA chain) keeps the VMA-LMA delta a
     * constant KERNEL_VMA_OFFSET across 4K-aligned sections, so every
     * section reached through the high mapping resolves to its own
     * initialized load image. */
    . = . + KERNEL_VMA_OFFSET;

    .text : AT(ADDR(.text) - KERNEL_VMA_OFFSET) ALIGN(4K) {
        *(.text .text.*)
    }

    .rodata : AT(ADDR(.rodata) - KERNEL_VMA_OFFSET) ALIGN(4K) {
        *(.rodata .rodata.*)
        *(.gcc_except_table*)
    }

    /* Exception-fixup table for fault-tolerant user-memory copies.
     * Each entry is a (faulting-instruction VA, fixup VA) pair; the
     * page-fault handler consults it on a kernel-mode fault so a
     * copy_to/from_user racing a concurrent unmap returns -EFAULT
     * instead of panicking. KEEP because nothing in Rust source
     * references the input section directly — only the lld-generated
     * `__start___ex_table` / `__stop___ex_table` boundary symbols,
     * which are tied to this OUTPUT section name. Pinned to the high
     * VMA like the other read-only sections so the handler can read
     * it after the bootstrap identity map is torn down. */
    __ex_table : AT(ADDR(__ex_table) - KERNEL_VMA_OFFSET) ALIGN(8) {
        KEEP(*(__ex_table))
    }

    /* Even with `panic = "abort"` the toolchain can emit an
     * .eh_frame_hdr (and `--eh-frame-hdr` is on by default). */
    .eh_frame_hdr : AT(ADDR(.eh_frame_hdr) - KERNEL_VMA_OFFSET) ALIGN(8) {
        *(.eh_frame_hdr) *(.eh_frame_hdr.*)
    }

    /* LLVM source-based coverage sections. The instrumentation pass
     * emits `__llvm_prf_*` (counters, data records, function-name
     * table, branch/MC-DC bitmap) plus `__llvm_cov{fun,map}`
     * (coverage map metadata). Default orphan placement scatters
     * `__llvm_prf_cnts` into the low LMA region near `.boot.data`,
     * which is unreachable once the bootstrap identity map is torn
     * down. Pin every prf section to the high VMA so
     * `frame::coverage::dump` can always read it.
     *
     * Each section keeps its own output-section name so lld
     * auto-generates the matching `__start_<name>` / `__stop_<name>`
     * boundary symbols. Folding them into one umbrella section would
     * break those bounds — the boundary symbols are tied to OUTPUT
     * section names, not input.
     *
     * `__llvm_prf_cnts` is the only writable one (counters get bumped
     * at every basic-block entry); the rest are read-only metadata.
     * Keep them adjacent so the kernel image stays one contiguous
     * load. */
    __llvm_prf_cnts : AT(ADDR(__llvm_prf_cnts) - KERNEL_VMA_OFFSET) ALIGN(8) {
        *(__llvm_prf_cnts)
    }
    __llvm_prf_data : AT(ADDR(__llvm_prf_data) - KERNEL_VMA_OFFSET) ALIGN(8) {
        *(__llvm_prf_data)
    }
    __llvm_prf_bits : AT(ADDR(__llvm_prf_bits) - KERNEL_VMA_OFFSET) ALIGN(8) {
        *(__llvm_prf_bits)
    }
    __llvm_prf_names : AT(ADDR(__llvm_prf_names) - KERNEL_VMA_OFFSET) ALIGN(8) {
        *(__llvm_prf_names)
    }
    __llvm_prf_vnds : AT(ADDR(__llvm_prf_vnds) - KERNEL_VMA_OFFSET) ALIGN(8) {
        *(__llvm_prf_vnds)
    }
    __llvm_covfun : AT(ADDR(__llvm_covfun) - KERNEL_VMA_OFFSET) ALIGN(8) {
        *(__llvm_covfun)
    }
    __llvm_covmap : AT(ADDR(__llvm_covmap) - KERNEL_VMA_OFFSET) ALIGN(8) {
        *(__llvm_covmap)
    }

    .data : AT(ADDR(.data) - KERNEL_VMA_OFFSET) ALIGN(4K) {
        *(.data .data.*)
        *(.got .got.plt)
    }

    .bss : AT(ADDR(.bss) - KERNEL_VMA_OFFSET) ALIGN(4K) {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Phys-address shadows of __bss_start / __bss_end so the 64-bit boot
     * stub can zero .bss before Rust statics see uninitialized memory.
     * Using the high VAs would require building the high mapping first,
     * which we do — but accessing bss via the LMA is also fine because
     * the low identity map covers the same physical pages. We use the
     * high VAs in practice (so this pair is informational).
     */
    __bss_phys_start = LOADADDR(.bss);
    __bss_phys_end   = LOADADDR(.bss) + SIZEOF(.bss);

    __kernel_image_phys_end = LOADADDR(.bss) + SIZEOF(.bss);

    /DISCARD/ : {
        *(.eh_frame)
        *(.note.gnu.build-id)
        *(.note.GNU-stack)
        *(.note.gnu.property)
        *(.comment)
    }
}
