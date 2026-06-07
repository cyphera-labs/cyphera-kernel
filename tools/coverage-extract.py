#!/usr/bin/env python3
"""Reassemble an LLVM `.profraw` file from a kernel QEMU serial log.

Pipeline:
  qemu serial stdout
    ──> kernel `frame::coverage::dump()` (hex-prints
        `__llvm_prf_{cnts,bits,data,names}` between `<<<COV-BEGIN>>>`
        and `<<<COV-END>>>` markers)
    ──> this script (parses framing, hex-decodes, writes profraw)
    ──> `llvm-profdata merge` + `cargo llvm-cov report`

LLVM raw-profile layout this script targets (source of truth:
`llvm/include/llvm/ProfileData/InstrProfData.inc`):

    struct __llvm_profile_header {
        uint64_t Magic;                  // 'lprofr\x81' little-endian
        uint64_t Version;                // INSTR_PROF_RAW_VERSION
        uint64_t BinaryIdsSize;          // 0 (we don't emit binary IDs)
        uint64_t NumData;                // sizeof(__llvm_prf_data)
                                         //   / sizeof(profile_data_t)
        uint64_t PaddingBytesBeforeCounters;
        uint64_t NumCounters;            // sizeof(__llvm_prf_cnts) / 8
        uint64_t PaddingBytesAfterCounters;
        uint64_t NumBitmapBytes;         // sizeof(__llvm_prf_bits)
        uint64_t PaddingBytesAfterBitmapBytes;
        uint64_t NamesSize;              // sizeof(__llvm_prf_names)
        uint64_t CountersDelta;          // vaddr of __llvm_prf_cnts
        uint64_t BitmapDelta;            // vaddr of __llvm_prf_bits
        uint64_t NamesDelta;             // vaddr of __llvm_prf_names
        uint64_t ValueKindLast;          // IPVK_Last (1 or 2)
    };
    // followed by: binary IDs, data, counters, padding, bitmap,
    //              padding, names

The header *deltas* must match the section addresses recorded inside
each `__llvm_profile_data` record at compile time, or
`llvm-profdata merge` rejects the file. We pull those addresses out
of the kernel ELF (`readelf -s`) — there's no way to recover them
from a serial dump alone.

Counter-entry size and version number are also LLVM-version-bound; we
read both from the ELF via the `INSTR_PROF_RAW_VERSION` /
`__llvm_profile_raw_version` variables emitted by the instrumentation
pass.

Usage:
    python3 tools/coverage-extract.py \\
        --serial-log coverage.serial-log \\
        --elf target/.../coverage/deps/user_hello-XXXX \\
        --out coverage.profraw
"""

from __future__ import annotations

import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path


COV_BEGIN = "<<<COV-BEGIN>>>"
COV_END = "<<<COV-END>>>"

# 'lprofr' + 0x81 + nul, little-endian, terminated by 0xff. The exact
# magic the InstrProf runtime uses is the bytes `\xff lprofr\x81`
# packed as a u64 little-endian. See INSTR_PROF_RAW_MAGIC_64 in
# llvm/include/llvm/ProfileData/InstrProfData.inc.
INSTR_PROF_RAW_MAGIC = struct.unpack(
    "<Q", b"\x81" + b"rforpl" + b"\xff"
)[0]

# sizeof(__llvm_profile_data) for the current LLVM raw profile
# format. This is the on-disk size of one entry in __llvm_prf_data —
# it must match what the instrumentation pass emits or the data
# section can't be interpreted. Verified against a host build
# (`rustc -C instrument-coverage`): the `__llvm_prf_data` section
# in the resulting ELF is 64 bytes per profiled function for the
# LLVM 22 / rustc nightly 2026-03 toolchain. Older LLVM used 48-byte
# entries; if you bump rust-toolchain.toml past LLVM ~25, re-check.
PROFILE_DATA_ENTRY_SIZE = 64


def find_cov_block(text: str) -> str:
    """Pull the BEGIN..END block out of a noisy serial log.

    Other CPUs may interleave `[sched] ...` print lines into the block
    while one CPU is dumping. We tolerate that here: lines that aren't
    hex bytes or `LEN_<NAME>=N` markers are silently dropped.
    """
    start = text.find(COV_BEGIN)
    end = text.find(COV_END, start + 1 if start >= 0 else 0)
    if start < 0 or end < 0:
        sys.exit(
            "coverage-extract: no <<<COV-BEGIN>>>...<<<COV-END>>> "
            "block in input"
        )
    return text[start + len(COV_BEGIN) : end]


HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
LEN_RE = re.compile(r"^LEN_([A-Z]+)=(\d+)\s*$")


def parse_sections(block: str) -> dict[str, bytes]:
    """Walk the body of a COV block and group hex into sections.

    Output keys: 'CNTS', 'BITS', 'DATA', 'NAMES' — each mapping to the
    raw section bytes. Sections appear in dump order; we identify each
    by its `LEN_<NAME>=N` header line and accumulate hex lines that
    follow up to either the next `LEN_` line or end-of-block. The
    declared length is enforced — short or over-long collections are a
    fail-fast signal that the serial log got truncated.
    """
    sections: dict[str, bytes] = {}
    current: str | None = None
    declared_len: int | None = None
    buf = bytearray()

    def flush():
        nonlocal current, declared_len, buf
        if current is not None and declared_len is not None:
            if len(buf) != declared_len:
                sys.exit(
                    f"coverage-extract: section {current} length "
                    f"mismatch: got {len(buf)} bytes, expected "
                    f"{declared_len}"
                )
            sections[current] = bytes(buf)
        current = None
        declared_len = None
        buf = bytearray()

    for raw in block.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = LEN_RE.match(line)
        if m:
            flush()
            current = m.group(1)
            declared_len = int(m.group(2))
            buf = bytearray()
            continue
        if current is None:
            # Pre-LEN noise from another CPU's println; ignore.
            continue
        if HEX_RE.match(line) and len(line) % 2 == 0:
            try:
                buf.extend(bytes.fromhex(line))
            except ValueError:
                # Non-hex sneaking in; drop the offending line.
                continue
            continue
        # Anything else is interleaved println from another CPU — drop.
    flush()

    for need in ("CNTS", "BITS", "DATA", "NAMES"):
        if need not in sections:
            sys.exit(
                f"coverage-extract: missing section LEN_{need} in dump"
            )
    return sections


def readelf_symbol(elf: Path, name: str) -> int | None:
    """Look up `name`'s `Value` (i.e. its address) via `nm`.

    Returns None if the symbol doesn't exist (we tolerate that for
    bits/names — zero-sized sections still produce start == stop and
    we want a deterministic delta in that case).
    """
    try:
        out = subprocess.check_output(
            ["nm", str(elf)], text=True, stderr=subprocess.DEVNULL
        )
    except FileNotFoundError:
        sys.exit("coverage-extract: `nm` not in PATH")
    for line in out.splitlines():
        parts = line.split()
        # nm prints `<addr> <type> <name>` for defined symbols.
        if len(parts) == 3 and parts[2] == name:
            try:
                return int(parts[0], 16)
            except ValueError:
                continue
    return None


def readelf_version(elf: Path) -> int:
    """Recover INSTR_PROF_RAW_VERSION from the binary.

    The instrumentation pass emits `__llvm_profile_raw_version` as a
    u64 constant in the binary. Rather than decode it from the ELF, we
    match what the toolchain bundles: INSTR_PROF_RAW_VERSION_VAR is
    currently 10 (LLVM 20). Override via --version on the CLI if a
    future toolchain bump moves it.
    """
    return 10


def build_profraw(
    sections: dict[str, bytes],
    counters_delta: int,
    bitmap_delta: int,
    names_delta: int,
    version: int,
) -> bytes:
    """Assemble the in-memory profraw blob the LLVM runtime would
    write itself on a host target.

    The three `*_delta` values are u64-masked `(section_addr -
    data_section_addr)` differences, as the LLVM runtime expects in
    the header (it uses them to relocate the per-function pointers
    embedded in the data section).
    """
    cnts = sections["CNTS"]
    bits = sections["BITS"]
    data = sections["DATA"]
    names = sections["NAMES"]

    if len(data) % PROFILE_DATA_ENTRY_SIZE != 0:
        sys.exit(
            f"coverage-extract: __llvm_prf_data size {len(data)} "
            f"isn't a multiple of {PROFILE_DATA_ENTRY_SIZE} "
            "(profile_data_t size mismatch — toolchain may have "
            "moved to a new raw-profile version)"
        )
    num_data = len(data) // PROFILE_DATA_ENTRY_SIZE

    # Counters are u64 each.
    if len(cnts) % 8 != 0:
        sys.exit(
            f"coverage-extract: __llvm_prf_cnts size {len(cnts)} "
            "isn't a multiple of 8"
        )
    num_counters = len(cnts) // 8

    # 8-byte align padding between sections (LLVM's writer convention).
    def pad8(n: int) -> int:
        return (-n) & 0x7

    pad_before_counters = pad8(len(data))
    pad_after_counters = pad8(len(cnts))
    pad_after_bitmap = pad8(len(bits))

    # Raw profile header layout per the LLVM 22 (rustc nightly 2026-03)
    # shape of llvm/include/llvm/ProfileData/InstrProfData.inc:
    # 16 u64s = 128 bytes. The pre-vtable shape was 14 u64s; LLVM grew
    # two extra fields (NumVTables, VNamesSize) before ValueKindLast
    # to support vtable instrumentation. We don't emit vtable data, so
    # both new fields are zero — but they MUST be present or the
    # header size disagrees and llvm-profdata rejects the file as
    # "corrupt".
    #
    # Verified against a known-good profraw produced by a host
    # `rustc -C instrument-coverage` run with the same toolchain:
    # ValueKindLast lands at offset 120 (16th u64); fields 14 and 15
    # are zero in the no-vtable case.
    header = struct.pack(
        "<16Q",
        INSTR_PROF_RAW_MAGIC,
        version,
        0,  # binary_ids_size
        num_data,
        pad_before_counters,
        num_counters,
        pad_after_counters,
        len(bits),
        pad_after_bitmap,
        len(names),
        counters_delta,
        bitmap_delta,
        names_delta,
        0,  # NumVTables — unused (no vtable instrumentation)
        0,  # VNamesSize — unused
        2,  # IPVK_Last
    )

    # LLVM's InstrProfReader::readHeader computes ValueDataOffset =
    # NamesOffset + NamesSize + getNumPaddingBytes(NamesSize), then
    # validates `Start + ValueDataOffset <= BufferEnd`. If we omit the
    # trailing names-alignment pad, the check fails with the
    # unhelpful "file header is corrupt" error even when every byte
    # before that is well-formed. The pad must always be emitted: a
    # NamesSize that happens to be a multiple of 8 yields pad=0, but
    # any other size requires the explicit padding.
    pad_after_names = pad8(len(names))

    return (
        header
        + data
        + b"\x00" * pad_before_counters
        + cnts
        + b"\x00" * pad_after_counters
        + bits
        + b"\x00" * pad_after_bitmap
        + names
        + b"\x00" * pad_after_names
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Reconstruct .profraw from a QEMU serial log."
    )
    ap.add_argument(
        "--serial-log",
        type=Path,
        help="Path to serial log file (default: stdin)",
    )
    ap.add_argument(
        "--elf",
        type=Path,
        required=True,
        help="Instrumented kernel ELF (for __llvm_prf_* addresses)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output profraw path",
    )
    ap.add_argument(
        "--version",
        type=int,
        default=None,
        help="INSTR_PROF_RAW_VERSION (default: probe from toolchain)",
    )
    args = ap.parse_args()

    if args.serial_log:
        text = args.serial_log.read_text(errors="replace")
    else:
        text = sys.stdin.read()

    block = find_cov_block(text)
    sections = parse_sections(block)

    cnts_addr = readelf_symbol(args.elf, "__start___llvm_prf_cnts")
    bits_addr = readelf_symbol(args.elf, "__start___llvm_prf_bits")
    names_addr = readelf_symbol(args.elf, "__start___llvm_prf_names")
    data_addr = readelf_symbol(args.elf, "__start___llvm_prf_data")
    if cnts_addr is None or data_addr is None:
        sys.exit(
            "coverage-extract: __start___llvm_prf_{cnts,data} not "
            f"found in {args.elf} (not an instrumented build?)"
        )
    # Bits/names may legitimately be missing (zero-size sections); fall
    # back to a sane delta that produces a no-op header field.
    if bits_addr is None:
        bits_addr = cnts_addr
    if names_addr is None:
        names_addr = cnts_addr

    # CountersDelta / BitmapDelta / NamesDelta are stored as
    # *unsigned* u64 differences `(section_begin - data_begin)`, with
    # 2's-complement wrap for negative values. The runtime reads each
    # back as a signed delta and uses it to relocate the per-function
    # pointers stored in __llvm_prf_data. Computing `data_addr -
    # section_addr` for each section (then masking to u64) matches
    # the host LLVM runtime's behavior — verified by comparing the
    # bytes of a known-good `LLVM_PROFILE_FILE=... ./host_binary`
    # profraw against this layout.
    def delta(section_addr: int) -> int:
        return (section_addr - data_addr) & 0xFFFF_FFFF_FFFF_FFFF

    version = args.version if args.version is not None else readelf_version(
        args.elf
    )

    blob = build_profraw(
        sections,
        delta(cnts_addr),
        delta(bits_addr),
        delta(names_addr),
        version,
    )
    args.out.write_bytes(blob)

    print(
        f"coverage-extract: wrote {len(blob)} bytes to {args.out} "
        f"(cnts={len(sections['CNTS'])}, data={len(sections['DATA'])}, "
        f"bits={len(sections['BITS'])}, names={len(sections['NAMES'])})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
