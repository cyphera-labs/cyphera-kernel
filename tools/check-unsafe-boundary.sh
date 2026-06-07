#!/usr/bin/env bash
# Enforce the unsafe-boundary: the kernel/ services layer must contain
# no `unsafe`. `unsafe` legitimately lives in the audited lower layers —
# frame/ (the privileged substrate), runtime/boot/ (bring-up, which
# invokes the unsafe `frame::init` and asm helpers), and drivers/virtio/
# (MMIO / DMA register access).
#
# Two checks over kernel/:
#   1. Its lib.rs has `#![forbid(unsafe_code)]` — compiler-enforced
#      safe boundary.
#   2. Backstop: grep for `unsafe` keyword usage in kernel/, catching
#      anyone who removes the attribute and slips one in.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SERVICE_CRATES=(kernel)

failures=0

for crate in "${SERVICE_CRATES[@]}"; do
    lib="$crate/src/lib.rs"
    if [[ ! -f "$lib" ]]; then
        echo "ERROR: $lib missing — service crate must have a lib.rs"
        failures=$((failures + 1))
        continue
    fi
    if ! grep -qE '^\#!\[forbid\(unsafe_code\)\]' "$lib"; then
        echo "ERROR: $lib must start with #![forbid(unsafe_code)]"
        failures=$((failures + 1))
    fi
    # Backstop grep. `unsafe_code` (in the attribute itself) is fine; we
    # match the `unsafe` keyword in code positions: blocks, fns, traits,
    # impls. This is conservative; flag and let humans decide.
    matches=$(grep -rE '(^|[^a-zA-Z_])unsafe[[:space:]]*(\{|fn|trait|impl)' \
        --include='*.rs' "$crate/src" 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        echo "ERROR: unsafe code found in $crate (services must be 100% safe):"
        echo "$matches"
        failures=$((failures + 1))
    fi
done

if [[ $failures -gt 0 ]]; then
    echo
    echo "unsafe-boundary check FAILED ($failures issue(s))"
    exit 1
fi
echo "✓ unsafe-boundary clean: kernel/ services layer is free of unsafe"
