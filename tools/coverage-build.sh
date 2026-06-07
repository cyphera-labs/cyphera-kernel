#!/usr/bin/env bash
#
# tools/coverage-build.sh — build the kernel with LLVM source-based
# coverage instrumentation on, ready for a QEMU run that will dump
# counters over the serial console.
#
# This wraps `cargo rustc --profile coverage` with the precise rustc
# flag set the kernel needs:
#
#   -Cinstrument-coverage   : emit __llvm_prf_* counter sections +
#                             per-function metadata, plus
#                             __llvm_covmap / __llvm_covfun (the
#                             source mapping the host parser reads
#                             from the ELF).
#   -Zno-profiler-runtime   : suppress rustc's automatic
#                             `extern crate profiler_builtins` — that
#                             crate ships only for host targets, not
#                             x86_64-unknown-none, and we don't need
#                             its runtime anyway because the
#                             dump is done by `frame::coverage::dump`.
#   --cfg coverage          : flips on the `#[cfg(coverage)]` branch
#                             in `frame::io::qemu_exit::exit`, which
#                             calls the dump just before triggering
#                             isa-debug-exit.
#   -Clto=no                : ThinLTO drops the `__llvm_prf_*`
#                             sections (LTO can elide sections whose
#                             only "references" are linker bounds
#                             symbols). Pin LTO off so the counter
#                             section actually makes it into the
#                             final binary.
#   relocation / link-args  : restated from `.cargo/config.toml`
#                             because env RUSTFLAGS clobbers the
#                             config's rustflags rather than merging.
#
# Usage:
#   tools/coverage-build.sh <test-name>          # default: user_hello
#
# Output:
#   target/x86_64-unknown-none/coverage/deps/<test-name>-<hash>
#   (path is also echoed on stdout for tools/coverage-run.sh).

set -euo pipefail

TEST_NAME="${1:-user_hello}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT"

# Restate the per-target rustflags from .cargo/config.toml. Env
# RUSTFLAGS overrides (does not merge with) config rustflags, so we
# must include them explicitly or the link breaks
# (`R_X86_64_32 cannot be used against local symbol` etc.).
RUSTFLAGS=$(cat <<'EOF'
-Cinstrument-coverage
-Clto=no
-Zno-profiler-runtime
--cfg coverage
-C relocation-model=static
-C link-arg=--no-pie
-C link-arg=-zmax-page-size=4096
EOF
)
# Collapse newlines into spaces — cargo wants RUSTFLAGS as one
# whitespace-separated string.
export RUSTFLAGS="$(echo "$RUSTFLAGS" | tr '\n' ' ')"

# `cargo rustc` (not `cargo build`) so the flags only apply to the
# primary crate's compilation unit. Coverage flags inherit through
# the workspace dep graph via RUSTFLAGS-by-rustc — every rustc
# invocation in this `cargo rustc` run picks up the env, including
# transitive deps. That's what we want here (instrument the whole
# kernel + drivers + frame), but it means a parallel non-coverage
# build must use a different target dir, which the dedicated
# `coverage` profile provides.
cargo rustc \
    -p cyphera-kernel \
    --target x86_64-unknown-none \
    --profile coverage \
    --test "$TEST_NAME" \
    >&2

# Print the freshly-built artifact path (skip the `.d` depfile).
DEPS="$ROOT/target/x86_64-unknown-none/coverage/deps"
ARTIFACT=$(ls -t "$DEPS"/"$TEST_NAME"-* 2>/dev/null \
    | grep -v '\.d$' \
    | grep -v '\.rcgu\.o$' \
    | head -1)
if [[ -z "$ARTIFACT" ]]; then
    echo "coverage-build.sh: built but couldn't find $DEPS/$TEST_NAME-*" >&2
    exit 1
fi
echo "$ARTIFACT"
