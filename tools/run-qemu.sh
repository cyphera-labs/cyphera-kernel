#!/usr/bin/env bash
# Cargo runner. Boots the kernel ELF in QEMU.
#
# Machine: `microvm` — minimal QEMU machine designed for short-lived,
# headless workloads, with PVH boot, virtio-mmio transport, and ISA
# (for our isa-debug-exit + serial console). Targets microVM-shaped
# hypervisors such as Firecracker / Cloud Hypervisor — both are
# microVM-shaped.
#
# isa-debug-exit reports `(value << 1) | 1` to the host. We use
# ExitCode::Success = 0x10 in qemu_exit::exit(), which means "test
# passed" arrives here as exit status 33. We translate that to 0 for
# cargo test.
set -uo pipefail

KERNEL="$1"
shift

# Drop libtest passthrough flags. `cargo test -- --nocapture` (and
# friends) sends them through cargo to the test binary's argv; our
# "test binary" is a kernel ELF wrapped by this runner, so they'd
# end up as qemu CLI args and qemu rejects them with
# "invalid option". Strip them here so the README-documented
# `cargo test ... -- --nocapture` invocation just works.
FORWARD_ARGS=()
while (($#)); do
    case "$1" in
        --nocapture|--ignored|--include-ignored|--show-output|--quiet|-q|--exact|--list)
            shift
            ;;
        --test-threads|--test-threads=*|--skip|--skip=*|--format|--format=*|--logfile|--logfile=*)
            [[ "$1" == *=* ]] || shift
            shift
            ;;
        *)
            FORWARD_ARGS+=("$1")
            shift
            ;;
    esac
done
set -- "${FORWARD_ARGS[@]+"${FORWARD_ARGS[@]}"}"

# Generate a 1 MiB raw block image with known content if missing.
# Sector 0 holds the magic "CYPHERA-BLK" so the virtio-blk test can
# verify reads go through end-to-end.
DISK_IMG="${CYPHERA_DISK_IMG:-/tmp/cyphera-test-disk.img}"
if [[ ! -f "$DISK_IMG" ]]; then
    dd if=/dev/zero of="$DISK_IMG" bs=512 count=2048 status=none
    printf 'CYPHERA-BLK' | dd of="$DISK_IMG" bs=1 count=11 conv=notrunc status=none
fi

# Serialize concurrent QEMU invocations against the same disk image
# via flock on a side-file. Without this, `cargo test` running test
# binaries in parallel hits qemu's internal disk-write-lock and the
# losing instance fails with "Failed to get write lock". The lock
# is documented in docs/TESTING.md and implemented here. Other
# CYPHERA_DISK_IMG values get their own
# lock file so two non-conflicting tests can still run in parallel.
LOCK_FILE="${DISK_IMG}.lock"
exec 9>"$LOCK_FILE"
flock 9

# Graphical mode: when CYPHERA_GRAPHICAL=1 is set, attach a
# virtio-gpu, virtio-keyboard, virtio-mouse and an SDL display so a
# framebuffer client can be seen and driven. Default stays headless
# so the rest of the test suite runs under cargo without popping
# windows.
GRAPHICAL_ARGS=()
if [[ "${CYPHERA_GRAPHICAL:-0}" = "1" ]]; then
    GRAPHICAL_ARGS=(
        -m 512M
        -display sdl
        -device virtio-gpu-device,xres=640,yres=400
        -device virtio-keyboard-device
        -device virtio-mouse-device
    )
    DISPLAY_FLAG=()
    MEM_FLAG=()
else
    DISPLAY_FLAG=(-display none)
    MEM_FLAG=(-m 1024M)
fi

# Audio backend selection. virtio-sound-device is always attached
# so the bring-up smoke test (and the /dev/dsp path) finds a device
# on every boot. The HOST side defaults to `none` (samples are
# allocated but discarded — silent, no PulseAudio needed, no risk
# of failing on a server host without an audio daemon).
#
# `CYPHERA_AUDIO=1` switches to `-audiodev pa,id=snd0` so the
# samples reach your speakers via PulseAudio / PipeWire-Pulse.
# Graphical mode implies audio.
AUDIO_BACKEND="${CYPHERA_AUDIO_BACKEND:-pa}"
if [[ "${CYPHERA_AUDIO:-0}" = "1" || "${CYPHERA_GRAPHICAL:-0}" = "1" ]]; then
    AUDIO_FLAGS=(
        -audiodev "${AUDIO_BACKEND},id=snd0"
        -device virtio-sound-device,audiodev=snd0,jacks=1,streams=2,chmaps=1
    )
else
    AUDIO_FLAGS=(
        -audiodev none,id=snd0
        -device virtio-sound-device,audiodev=snd0,jacks=1,streams=2,chmaps=1
    )
fi

# Per-test wall-clock timeout (default 180s, covers the slowest
# tests in the battery). A graphical run sets no timeout
# (interactive, shouldn't auto-kill); otherwise override with
# CYPHERA_TEST_TIMEOUT.
TIMEOUT_SEC="${CYPHERA_TEST_TIMEOUT:-180}"
if [[ "${CYPHERA_GRAPHICAL:-0}" = "1" ]]; then
    TIMEOUT_SEC=0  # graphical = no timeout
fi
TIMEOUT_PREFIX=()
if [[ "$TIMEOUT_SEC" -gt 0 ]]; then
    TIMEOUT_PREFIX=(timeout --foreground "$TIMEOUT_SEC")
fi

# Debug: enable QEMU's gdb stub when CYPHERA_GDB=1.
# Connect with `gdb -ex 'target remote :1234' target/.../kernel.elf`.
# CYPHERA_GDB=1: stub on, paused at start (-s -S). For attach-later.
# CYPHERA_GDB=2: stub on, run normally. For break-in mid-execution.
GDB_ARGS=()
if [[ "${CYPHERA_GDB:-0}" = "1" ]]; then
    GDB_ARGS=(-s -S)
    TIMEOUT_PREFIX=()
elif [[ "${CYPHERA_GDB:-0}" = "2" ]]; then
    GDB_ARGS=(-s)
fi
# Force TCG (no KVM) when gdb stub active — KVM doesn't support
# hardware watchpoints via gdb stub, only TCG does.
ACCEL=accel=kvm:tcg
if [[ "${CYPHERA_GDB:-0}" != "0" ]]; then
    ACCEL=accel=tcg
fi

"${TIMEOUT_PREFIX[@]}" qemu-system-x86_64 \
    -machine microvm,$ACCEL,pit=off,pic=off,rtc=on \
    -rtc base=utc,clock=host \
    -cpu max \
    -smp 2 \
    "${MEM_FLAG[@]}" \
    -kernel "$KERNEL" \
    -nodefaults \
    -no-user-config \
    -serial stdio \
    "${DISPLAY_FLAG[@]}" \
    -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -device virtio-rng-device \
    -drive id=disk0,if=none,format=raw,file="$DISK_IMG" \
    -device virtio-blk-device,drive=disk0 \
    -netdev user,id=net0 \
    -device virtio-net-device,netdev=net0,mac=52:54:00:12:34:56 \
    "${AUDIO_FLAGS[@]}" \
    "${GRAPHICAL_ARGS[@]}" \
    "${GDB_ARGS[@]}" \
    "$@"
qemu_exit=$?

# isa-debug-exit reports `(value << 1) | 1`; ExitCode::Success = 0x10
# arrives here as 33, ExitCode::Failed = 0x11 → 35. ANY other exit
# (0 from a triple fault under `-no-reboot`, 1 from a QEMU CLI
# error, etc.) must be treated as a failure: a triple fault exits 0,
# which would otherwise be misread as a passing test run.
if [[ $qemu_exit -eq 33 ]]; then
    exit 0
elif [[ $qemu_exit -eq 35 ]]; then
    exit 1
elif [[ $qemu_exit -eq 124 ]]; then
    # `timeout` reports 124 when it kills the child by SIGTERM
    # at the deadline. Treat as a test failure (kernel hang).
    echo "run-qemu.sh: TIMEOUT after ${TIMEOUT_SEC}s — kernel hung; killed" >&2
    exit 1
else
    echo "run-qemu.sh: kernel did not isa-debug-exit cleanly (qemu exit $qemu_exit)" >&2
    exit 2
fi
