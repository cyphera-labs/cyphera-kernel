#!/usr/bin/env bash
# Architecture-neutrality gate for the kernel services layer.
#
# The services layer (kernel/) is meant to be architecture-neutral: it speaks
# only frame's typed, arch-agnostic surface and never names a CPU architecture,
# reaches an arch backend, or embeds machine code. A second architecture should
# slot in behind frame without touching kernel/. This gate fails the build when
# that boundary leaks.
set -euo pipefail
cd "$(dirname "$0")/.."

# A missing target must be a hard error, not a silent pass: the ban() grep
# below is guarded with `|| true`, which would otherwise swallow a wrong-cwd
# "No such file or directory" and report OK without having checked anything.
[ -d kernel/src ] || { printf 'ERROR: kernel/src not found (wrong working directory?)\n' >&2; exit 2; }

fail=0
ban() {
    local pattern="$1" desc="$2" hits
    hits=$(grep -rnE "$pattern" kernel/src || true)
    if [ -n "$hits" ]; then
        printf '\narch leak — %s:\n%s\n' "$desc" "$hits"
        fail=1
    fi
}

ban 'frame::arch' 'kernel/ reaches a frame arch backend directly (use a frame:: neutral facade)'
ban '\bcore::arch\b' 'kernel/ uses core::arch intrinsics'
ban '(^|[^a-zA-Z_])(x86_64|aarch64|riscv32|riscv64)\s*::' 'kernel/ names an architecture crate directly (route through frame::)'
ban 'cfg\s*\(\s*target_(arch|os)' 'kernel/ branches on target_arch/target_os'
ban '(^|[^a-zA-Z_])asm!|naked_asm!|#\[naked\]' 'kernel/ embeds inline/naked assembly'

# Manifests: an arch-conditional dependency couples kernel/ to a specific
# architecture even without touching kernel/src. cfg(target_os = "none") is the
# bare-metal profile (not an arch branch), so only target_arch is banned here.
manifest_hits=$(grep -nE 'cfg\s*\(\s*target_arch' kernel/Cargo.toml kernel/build.rs 2>/dev/null || true)
if [ -n "$manifest_hits" ]; then
    printf '\narch leak — kernel/ manifest carries an arch-conditional dependency:\n%s\n' "$manifest_hits"
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    printf '\nFAIL: architecture-specific code leaked into the kernel services layer.\n'
    exit 1
fi
printf 'OK: kernel services layer is architecture-neutral.\n'
