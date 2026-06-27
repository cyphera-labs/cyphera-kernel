#!/usr/bin/env bash
#
# tools/test.sh — dispatch kernel test runs by kind.
#
# Tests live under runtime/boot/tests/{smoke,subsystem}/:
#
#   smoke      — kernel-only smoke (boot, frame API, virtio, basic
#                ring 3 transitions). Fast (<60s wall-clock).
#   subsystem  — kernel subsystem tests with userland test binaries
#                (fork, signal, futex, ptrace, RT + fair-share
#                scheduling, pidfd, etc.).
#
# Usage:
#   tools/test.sh smoke       — run only the smoke battery
#   tools/test.sh subsystem   — run subsystem battery
#   tools/test.sh sentinel    — run a fast representative checkpoint
#   tools/test.sh all         — run everything
#
# Pass --release to build in release mode (default).
# Pass --debug to build in debug mode.

set -euo pipefail

KIND="${1:-}"
shift || true

PROFILE_FLAG="--release"
for arg in "$@"; do
    case "$arg" in
        --debug) PROFILE_FLAG="" ;;
        --release) PROFILE_FLAG="--release" ;;
    esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_DIR="$ROOT/runtime/boot/tests"

# The smoke/subsystem tests `include_bytes!(env!("<NAME>_ELF_PATH"))` the
# userland driver ELFs at compile time, so they must exist before `cargo
# test` runs or compilation fails on a clean checkout. Build + stage them
# first; it's incremental and a near no-op once cached.
"$ROOT/tools/build-userland.sh"

list_tests_in() {
    local dir="$1"
    [ -d "$dir" ] || return 0
    find "$dir" -maxdepth 1 -name '*.rs' -printf '%f\n' \
        | sed 's/\.rs$//' \
        | sort
}

run_kind() {
    local kind="$1"
    local dir="$TESTS_DIR/$kind"
    if [ ! -d "$dir" ]; then
        echo "tools/test.sh: no such kind '$kind'" >&2
        exit 1
    fi
    local args=()
    while IFS= read -r t; do
        args+=("--test" "$t")
    done < <(list_tests_in "$dir")
    if [ ${#args[@]} -eq 0 ]; then
        echo "tools/test.sh: no tests in $dir" >&2
        return
    fi
    cargo test $PROFILE_FLAG -p cyphera-kernel "${args[@]}"
}

run_sentinel() {
    cargo test $PROFILE_FLAG -p cyphera-kernel \
        --test boot_smoke \
        --test rt \
        --test pi_futex \
        --test dl \
        --test dl_overrun \
        --test cpu_throttle \
        --test io_throttle \
        --test compat_intro \
        --test ptrace
}

case "$KIND" in
    smoke|subsystem)
        run_kind "$KIND"
        ;;
    sentinel)
        run_sentinel
        ;;
    all)
        cargo test $PROFILE_FLAG -p cyphera-kernel
        ;;
    "")
        echo "Usage: tools/test.sh {smoke|subsystem|sentinel|all} [--release|--debug]" >&2
        exit 1
        ;;
    *)
        echo "tools/test.sh: unknown kind '$KIND'" >&2
        echo "Usage: tools/test.sh {smoke|subsystem|sentinel|all}" >&2
        exit 1
        ;;
esac
