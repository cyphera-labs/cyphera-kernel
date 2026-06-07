#!/usr/bin/env bash
# Cyphera Kernel — minimal demo.
#
# Boots the kernel under QEMU running a tiny hello-world program as
# PID 1, so you can watch it actually load and run a real ELF in
# ring 3. Self-contained: it builds the kernel and the hello program
# from source, packs hello as /sbin/init in a one-file initrd, and
# boots it. No external rootfs, no network, nothing else in the repo
# is touched.
#
#   ./demo/run.sh           # build + boot (auto-exits after a few seconds)
#   DEMO_TIMEOUT=0 ./demo/run.sh   # boot and stay (Ctrl-A x to quit QEMU)
#
# Prereqs when run directly on a host: a Rust toolchain with the
# x86_64-unknown-none target, and qemu-system-x86_64. From inside the
# repo's dev container (`./dev demo`) these are already present.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BUILD="$HERE/.build"
rm -rf "$BUILD"
mkdir -p "$BUILD/rootfs/sbin"

echo "==> Building the kernel (release)"
( cd "$ROOT" && cargo build -p cyphera-kernel --target x86_64-unknown-none --release )
KERNEL="$ROOT/target/x86_64-unknown-none/release/cyphera-kernel"

echo "==> Building the hello-world userland program"
( cd "$ROOT/selftests" && cargo build -p hello --release --target x86_64-unknown-none )
cp "$ROOT/selftests/target/x86_64-unknown-none/release/hello" "$BUILD/rootfs/sbin/init"

echo "==> Packing the initrd (/sbin/init = hello)"
( cd "$BUILD/rootfs" && tar -cf "$BUILD/initrd.tar" . )

echo "==> Booting Cyphera Kernel under QEMU"
echo "    (the kernel lifts the initrd, then execs /sbin/init in ring 3)"
echo "    ----------------------------------------------------------------"
TIMEOUT="${DEMO_TIMEOUT:-12}"
PREFIX=()
[ "$TIMEOUT" != "0" ] && PREFIX=(timeout "$TIMEOUT")
"${PREFIX[@]}" qemu-system-x86_64 \
    -machine microvm,accel=kvm:tcg,pit=off,pic=off,rtc=off \
    -cpu max -smp 1 -m 512M \
    -kernel "$KERNEL" \
    -initrd "$BUILD/initrd.tar" \
    -nodefaults -no-user-config -no-reboot \
    -serial stdio -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -device virtio-rng-device || true
echo "    ----------------------------------------------------------------"
echo "==> Demo finished. (Expected line above: \"hello from a real ELF in ring 3\")"
