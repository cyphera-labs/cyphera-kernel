#!/usr/bin/env bash
#
# tools/coverage-run.sh — boot an instrumented kernel test under
# QEMU, capture the serial-console coverage dump, reassemble it into
# a `.profraw`, merge to `.profdata`, and print an llvm-cov report.
#
# Composed of three sub-tools:
#   tools/coverage-build.sh     — produces the instrumented ELF
#   tools/run-qemu.sh           — the normal QEMU runner (re-used)
#   tools/coverage-extract.py   — parses the serial log → profraw
#
# Usage:
#   tools/coverage-run.sh [test-name]    # default: user_hello
#
# Outputs (under target/coverage/<test-name>/):
#   serial.log     — full QEMU serial output (audit trail)
#   raw.profraw    — reconstructed LLVM raw profile
#   merged.profdata — single-test merged profile
#   report.txt     — llvm-cov per-file coverage table

set -euo pipefail

TEST_NAME="${1:-user_hello}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT/target/coverage/$TEST_NAME"
mkdir -p "$OUT_DIR"

# Resolve LLVM tools that ship with the toolchain. `llvm-tools-preview`
# is in rust-toolchain.toml, so these are always present.
SYSROOT="$(rustc --print sysroot)"
LLVM_BIN="$SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu/bin"
LLVM_PROFDATA="$LLVM_BIN/llvm-profdata"
LLVM_COV="$LLVM_BIN/llvm-cov"
for t in "$LLVM_PROFDATA" "$LLVM_COV"; do
    if [[ ! -x "$t" ]]; then
        echo "coverage-run.sh: missing $t" >&2
        echo "  (try: rustup component add llvm-tools-preview)" >&2
        exit 1
    fi
done

echo "==> Building instrumented kernel for $TEST_NAME" >&2
ELF="$(bash "$ROOT/tools/coverage-build.sh" "$TEST_NAME")"
echo "    artifact: $ELF" >&2

echo "==> Booting under QEMU; capturing serial → $OUT_DIR/serial.log" >&2
bash "$ROOT/tools/run-qemu.sh" "$ELF" > "$OUT_DIR/serial.log" 2>&1 || {
    # run-qemu.sh exits non-zero on test failure; for coverage we
    # still want the dump, so warn but continue.
    echo "coverage-run.sh: WARN — run-qemu.sh exited non-zero." \
         "Continuing — coverage dump is captured pre-exit." >&2
}

echo "==> Reassembling profraw" >&2
python3 "$ROOT/tools/coverage-extract.py" \
    --serial-log "$OUT_DIR/serial.log" \
    --elf "$ELF" \
    --out "$OUT_DIR/raw.profraw"

echo "==> Merging to profdata" >&2
"$LLVM_PROFDATA" merge -sparse "$OUT_DIR/raw.profraw" \
    -o "$OUT_DIR/merged.profdata"

echo "==> Generating report" >&2
"$LLVM_COV" report "$ELF" \
    -instr-profile="$OUT_DIR/merged.profdata" \
    > "$OUT_DIR/report.txt"

echo
echo "Coverage summary ($TEST_NAME):"
tail -n 1 "$OUT_DIR/report.txt"
echo
echo "Full report: $OUT_DIR/report.txt"
