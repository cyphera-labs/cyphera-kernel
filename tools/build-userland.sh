#!/usr/bin/env bash
# build-userland.sh — build the in-tree userland test binaries and
# stage them where the kernel integration tests consume them.
#
# The subsystem/smoke tests `include_bytes!(env!("<NAME>_ELF_PATH"))`
# the userland ELFs, and runtime/boot/build.rs resolves those env
# vars by walking `bundles/userland/`. The ELFs themselves are built
# from the `selftests/` workspace. Without this step a fresh checkout
# has an empty `bundles/userland/` and `cargo test` fails to compile
# the tests that embed a userland driver.
#
# Run this once after a clean checkout (and after changing any
# selftests/ crate) before `tools/test.sh smoke|subsystem`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SELFTESTS="$ROOT/selftests"
REL="$SELFTESTS/target/x86_64-unknown-none/release"
DEST="$ROOT/bundles/userland"

echo "==> Building selftests userland binaries (release)"
( cd "$SELFTESTS" && cargo build --release )

echo "==> Staging ELFs into bundles/userland/"
mkdir -p "$DEST"
n=0
for f in "$REL"/hello "$REL"/proc_*; do
    base="$(basename "$f")"
    case "$base" in
        *.d) continue ;;
    esac
    if [ -f "$f" ] && [ -x "$f" ]; then
        cp "$f" "$DEST/$base"
        n=$((n + 1))
    fi
done
echo "    staged $n binaries → bundles/userland/"
