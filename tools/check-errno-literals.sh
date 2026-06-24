#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

[ -d kernel/src ] || { printf 'ERROR: kernel/src not found (wrong working directory?)\n' >&2; exit 2; }

fail=0
ban() {
    local pattern="$1" desc="$2" hits
    hits=$(grep -rnE "$pattern" kernel/src --include='*.rs' | grep -v '/errno.rs:' || true)
    if [ -n "$hits" ]; then
        printf '\nerrno literal — %s:\n%s\n' "$desc" "$hits"
        fail=1
    fi
}

ban 'Err\(\s*-[0-9]+' 'raw negative errno literal in an Err(...) (use crate::errno::E*)'
ban 'return\s+-[0-9]+\s*(i64|i32)?\s*;' 'raw negative errno literal in a return (use crate::errno::E*)'
ban 'ok_or\(\s*-[0-9]+' 'raw negative errno literal in ok_or(...) (use crate::errno::E*)'

if [ "$fail" -ne 0 ]; then
    printf '\nFAIL: raw errno numerics found in kernel/src. The Errno definition and the ABI adapter are the only places numerics belong.\n'
    exit 1
fi
printf 'OK: no raw errno numerics in kernel services layer.\n'
