use core::fmt::Write;

use crate::io::uart::UART;

// SAFETY: each declared type is `u8`, matching the byte granularity at
// which the linker-synthesized `__start`/`__stop` boundary anchors are
// addressed; we only ever take their addresses (never read the marker
// bytes themselves), so the declared type imposes no value-validity
// obligation. The anchors below guarantee every symbol resolves.
unsafe extern "C" {
    static __start___llvm_prf_cnts: u8;
    static __stop___llvm_prf_cnts: u8;
    static __start___llvm_prf_bits: u8;
    static __stop___llvm_prf_bits: u8;
    static __start___llvm_prf_data: u8;
    static __stop___llvm_prf_data: u8;
    static __start___llvm_prf_names: u8;
    static __stop___llvm_prf_names: u8;
}

#[used]
#[link_section = "__llvm_prf_cnts"]
static _COV_CNTS_ANCHOR: [u8; 0] = [];
#[used]
#[link_section = "__llvm_prf_bits"]
static _COV_BITS_ANCHOR: [u8; 0] = [];
#[used]
#[link_section = "__llvm_prf_data"]
static _COV_DATA_ANCHOR: [u8; 0] = [];
#[used]
#[link_section = "__llvm_prf_names"]
static _COV_NAMES_ANCHOR: [u8; 0] = [];

fn hex_dump_bytes(bytes: &[u8]) {
    const PER_LINE: usize = 64;
    for chunk in bytes.chunks(PER_LINE) {
        let mut uart = UART.lock();
        for b in chunk {
            let _ = write!(&mut *uart, "{b:02x}");
        }
        let _ = writeln!(&mut *uart);
    }
}

/// # Safety
///
/// `start` and `end` must be a matched `_start`/`_end` pair from the
/// same linker-defined section.
unsafe fn section_slice(start: *const u8, end: *const u8) -> &'static [u8] {
    let len = (end as usize).saturating_sub(start as usize);
    if len == 0 {
        &[]
    } else {
        // SAFETY: caller asserts matched section bounds, so `[start,
        // end)` lies within one linker-emitted `__llvm_prf_*` section
        // (a single allocated object). Those sections are part of the
        // linked kernel image, mapped + readable for the kernel's
        // lifetime; `u8` makes alignment trivial, and we only read.
        // (`__llvm_prf_cnts` is live, writable counter data — a torn
        // read against a concurrent counter bump is harmless for a
        // best-effort coverage dump.)
        unsafe { core::slice::from_raw_parts(start, len) }
    }
}

pub fn dump() {
    // SAFETY: each pair below is a matched lld-auto-generated
    // section-boundary pair (see the `extern "C"` block above).
    let cnts = unsafe {
        section_slice(
            &__start___llvm_prf_cnts as *const u8,
            &__stop___llvm_prf_cnts as *const u8,
        )
    };
    // SAFETY: `__start`/`__stop___llvm_prf_bits` is a matched
    // lld-auto-generated boundary pair for the same input section,
    // discharging `section_slice`'s contract.
    let bits = unsafe {
        section_slice(
            &__start___llvm_prf_bits as *const u8,
            &__stop___llvm_prf_bits as *const u8,
        )
    };
    // SAFETY: `__start`/`__stop___llvm_prf_data` is a matched
    // lld-auto-generated boundary pair for the same input section,
    // discharging `section_slice`'s contract.
    let data = unsafe {
        section_slice(
            &__start___llvm_prf_data as *const u8,
            &__stop___llvm_prf_data as *const u8,
        )
    };
    // SAFETY: `__start`/`__stop___llvm_prf_names` is a matched
    // lld-auto-generated boundary pair for the same input section,
    // discharging `section_slice`'s contract.
    let names = unsafe {
        section_slice(
            &__start___llvm_prf_names as *const u8,
            &__stop___llvm_prf_names as *const u8,
        )
    };

    crate::println!("<<<COV-BEGIN>>>");
    crate::println!("LEN_CNTS={}", cnts.len());
    hex_dump_bytes(cnts);
    crate::println!("LEN_BITS={}", bits.len());
    hex_dump_bytes(bits);
    crate::println!("LEN_DATA={}", data.len());
    hex_dump_bytes(data);
    crate::println!("LEN_NAMES={}", names.len());
    hex_dump_bytes(names);
    crate::println!("<<<COV-END>>>");
}
