#!/usr/bin/env bash
#
# tools/coverage-merge.sh — drive `coverage-run.sh` over a list of
# integration tests, then merge the per-test .profraw files into one
# .profdata and produce an aggregate llvm-cov report.
#
# Builds on the single-test pipeline:
#
#   tools/coverage-build.sh    — instrumented `cargo rustc`
#   tools/coverage-run.sh      — build + qemu + extract + per-test report
#   tools/coverage-extract.py  — serial-log → .profraw
#
# This script wraps coverage-run.sh in a loop, then:
#
#   1. Collects every per-test target/coverage/<name>/raw.profraw
#   2. Merges them via `llvm-profdata merge -sparse` into one
#      target/coverage/aggregate.profdata
#   3. Generates a single `llvm-cov report` that points at every
#      instrumented ELF, so kernel functions get credit from every
#      run that touched them.
#   4. Writes the same data as lcov for coverage-dashboard consumers.
#
# Usage:
#   tools/coverage-merge.sh                            # default set
#   tools/coverage-merge.sh --kind smoke               # only smoke/
#   tools/coverage-merge.sh --kind subsystem           # only subsystem/
#   tools/coverage-merge.sh --tests boot_smoke,user_hello
#   tools/coverage-merge.sh --keep-going               # don't stop on failure
#
# Outputs (under target/coverage/):
#   aggregate.profdata     — merged across all tests
#   aggregate.report.txt   — llvm-cov report (per-file table)
#   aggregate.lcov         — lcov format (for coverage dashboards)
#   aggregate.txt          — single-line TOTAL summary (CI-friendly)
#   merge-manifest.txt     — list of (test, profraw, elf, status)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_DIR="$ROOT/runtime/boot/tests"
OUT_DIR="$ROOT/target/coverage"
mkdir -p "$OUT_DIR"

# Parse CLI.
KIND=""
TESTS_CSV=""
KEEP_GOING=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --kind)
            KIND="${2:-}"
            shift 2
            ;;
        --tests)
            TESTS_CSV="${2:-}"
            shift 2
            ;;
        --keep-going)
            KEEP_GOING=1
            shift
            ;;
        -h|--help)
            sed -n '1,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "coverage-merge.sh: unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

# The coverage build (coverage-build.sh → `cargo rustc --test`) compiles
# tests that `include_bytes!(env!("<NAME>_ELF_PATH"))` the userland driver
# ELFs; runtime/boot/build.rs resolves those env vars by walking
# bundles/userland/. Stage them first or the compile fails with
# "environment variable ... not defined at compile time" (same prerequisite
# as tools/test.sh). Incremental — a near no-op once cached.
"$ROOT/tools/build-userland.sh" >&2

# Resolve LLVM tools (same lookup as coverage-run.sh).
SYSROOT="$(rustc --print sysroot)"
LLVM_BIN="$SYSROOT/lib/rustlib/x86_64-unknown-linux-gnu/bin"
LLVM_PROFDATA="$LLVM_BIN/llvm-profdata"
LLVM_COV="$LLVM_BIN/llvm-cov"
for t in "$LLVM_PROFDATA" "$LLVM_COV"; do
    if [[ ! -x "$t" ]]; then
        echo "coverage-merge.sh: missing $t" >&2
        echo "  (try: rustup component add llvm-tools-preview)" >&2
        exit 1
    fi
done

# Build the test list.
list_kind() {
    local dir="$TESTS_DIR/$1"
    [[ -d "$dir" ]] || return 0
    find "$dir" -maxdepth 1 -name '*.rs' -printf '%f\n' \
        | sed 's/\.rs$//' \
        | sort
}

CANDIDATES=()
if [[ -n "$TESTS_CSV" ]]; then
    IFS=',' read -ra CANDIDATES <<<"$TESTS_CSV"
elif [[ -n "$KIND" ]]; then
    case "$KIND" in
        smoke|subsystem)
            while IFS= read -r t; do CANDIDATES+=("$t"); done \
                < <(list_kind "$KIND")
            ;;
        all)
            while IFS= read -r t; do CANDIDATES+=("$t"); done \
                < <(list_kind smoke; list_kind subsystem)
            ;;
        *)
            echo "coverage-merge.sh: --kind must be smoke|subsystem|all" >&2
            exit 2
            ;;
    esac
else
    # Default selection: everything under smoke + subsystem.
    while IFS= read -r t; do CANDIDATES+=("$t"); done \
        < <(list_kind smoke; list_kind subsystem)
fi

TESTS=("${CANDIDATES[@]}")

if [[ ${#TESTS[@]} -eq 0 ]]; then
    echo "coverage-merge.sh: empty test list after filtering" >&2
    exit 2
fi

echo "==> coverage-merge: ${#TESTS[@]} tests" >&2
echo "    out: $OUT_DIR" >&2

MANIFEST="$OUT_DIR/merge-manifest.txt"
: >"$MANIFEST"

OK_TESTS=()
PROFRAWS=()
ELFS=()
FAILED_TESTS=()

for t in "${TESTS[@]}"; do
    echo >&2
    echo "==> [coverage-merge] running: $t" >&2
    if bash "$ROOT/tools/coverage-run.sh" "$t" >&2; then
        rc=0
    else
        rc=$?
    fi

    test_out="$OUT_DIR/$t"
    profraw="$test_out/raw.profraw"
    # coverage-build.sh prints the artifact to stdout; coverage-run.sh
    # builds via coverage-build.sh. The artifact lives under
    # target/x86_64-unknown-none/coverage/deps/<test>-<hash>.
    elf=$(ls -t "$ROOT/target/x86_64-unknown-none/coverage/deps/${t}"-* 2>/dev/null \
        | grep -v '\.d$' \
        | grep -v '\.rcgu\.o$' \
        | head -1)

    status="ok"
    if [[ $rc -ne 0 ]]; then
        status="run-fail"
    fi
    if [[ ! -s "$profraw" ]]; then
        status="missing-profraw"
    fi
    if [[ -z "$elf" ]]; then
        status="missing-elf"
    fi

    printf '%s\t%s\t%s\t%s\n' "$t" "$status" "${profraw}" "${elf}" >>"$MANIFEST"

    if [[ "$status" != "ok" ]]; then
        echo "coverage-merge.sh: $t FAILED ($status)" >&2
        FAILED_TESTS+=("$t:$status")
        if [[ "$KEEP_GOING" -eq 0 ]]; then
            echo "coverage-merge.sh: aborting (use --keep-going to skip)" >&2
            exit 1
        fi
        continue
    fi

    OK_TESTS+=("$t")
    PROFRAWS+=("$profraw")
    ELFS+=("$elf")
done

if [[ ${#OK_TESTS[@]} -eq 0 ]]; then
    echo "coverage-merge.sh: every test failed; see $MANIFEST" >&2
    exit 1
fi

echo >&2
echo "==> [coverage-merge] merging ${#OK_TESTS[@]} profraws" >&2

AGG_PROFDATA="$OUT_DIR/aggregate.profdata"
"$LLVM_PROFDATA" merge -sparse "${PROFRAWS[@]}" -o "$AGG_PROFDATA"

echo "==> [coverage-merge] generating aggregate report" >&2

# llvm-cov takes the first ELF positionally and each subsequent one
# via -object. Pass every instrumented ELF so kernel functions get
# credit from any test that touched them; test-binary-only functions
# from other ELFs are silently ignored against this profdata.
OBJECT_ARGS=()
first_elf="${ELFS[0]}"
for ((i = 1; i < ${#ELFS[@]}; i++)); do
    OBJECT_ARGS+=(-object "${ELFS[$i]}")
done

REPORT_TXT="$OUT_DIR/aggregate.report.txt"
"$LLVM_COV" report "$first_elf" \
    "${OBJECT_ARGS[@]}" \
    -instr-profile="$AGG_PROFDATA" \
    > "$REPORT_TXT"

REPORT_LCOV="$OUT_DIR/aggregate.lcov"
"$LLVM_COV" export "$first_elf" \
    "${OBJECT_ARGS[@]}" \
    -instr-profile="$AGG_PROFDATA" \
    --format=lcov \
    > "$REPORT_LCOV" 2>/dev/null || {
    # lcov export is nice-to-have; don't fail the run if it errors.
    echo "coverage-merge.sh: WARN — lcov export failed (continuing)" >&2
    rm -f "$REPORT_LCOV"
}

# Capture the TOTAL line for downstream consumers (CI summaries, etc.).
SUMMARY_LINE=$(tail -n 1 "$REPORT_TXT")
echo "$SUMMARY_LINE" > "$OUT_DIR/aggregate.txt"

echo
echo "Aggregate coverage (${#OK_TESTS[@]} tests merged):"
echo "$SUMMARY_LINE"
echo
echo "Full report:  $REPORT_TXT"
echo "Lcov:         $REPORT_LCOV"
echo "Manifest:     $MANIFEST"

if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo
    echo "WARN: ${#FAILED_TESTS[@]} test(s) failed and were excluded from the merge:"
    for f in "${FAILED_TESTS[@]}"; do echo "  - $f"; done
    # When --keep-going is on, surface non-zero so CI can decide
    # whether a partial run is acceptable.
    exit 3
fi
