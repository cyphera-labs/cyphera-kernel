#!/usr/bin/env bash
# gdb-attach.sh — bring up cyphera-kernel under QEMU with the gdb
# stub exposed on :1234, then either drop into an interactive gdb
# session or run a one-shot inspection script.
#
# Usage:
#   tools/gdb-attach.sh <initrd> [--script <gdb-cmd-file>]
#
# Default: interactive (gdb attaches, waits for your input).
# With --script: gdb runs the commands in the file then exits.
#
# Examples:
#   # Interactive — boots the kernel + initrd, attaches gdb to poke around
#   tools/gdb-attach.sh /tmp/cyphera-initrd.tar
#
#   # One-shot dump at the moment the kernel is stalled
#   tools/gdb-attach.sh /tmp/cyphera-initrd.tar --script tools/gdb-dump-state.gdb
#
# Tips inside gdb:
#   (gdb) interrupt                  # pause the running kernel
#   (gdb) info threads               # see each CPU as a "thread"
#   (gdb) thread <N>                 # switch CPU
#   (gdb) bt                         # backtrace whatever is running
#   (gdb) info functions dump_all    # locate the dump helper
#   (gdb) call <mangled_name>()      # invoke dump_all_processes
#   (gdb) print kernel::core::GLOBAL._0.lock
#   (gdb) continue                   # resume the kernel
#   (gdb) detach + quit              # let it keep running

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KERNEL_ELF="$SCRIPT_DIR/../target/x86_64-unknown-none/release/cyphera-kernel"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <initrd> [--script <gdb-cmd-file>]" >&2
    exit 2
fi

INITRD="$1"; shift
GDB_SCRIPT=""
if [ "${1:-}" = "--script" ]; then
    GDB_SCRIPT="${2:?--script requires a path}"
fi

if [ ! -f "$KERNEL_ELF" ]; then
    echo "FATAL: kernel ELF missing at $KERNEL_ELF" >&2
    echo "  Run \`cargo build --release -p cyphera-kernel\` first." >&2
    exit 1
fi
if [ ! -f "$INITRD" ]; then
    echo "FATAL: initrd missing at $INITRD" >&2
    exit 1
fi

# Launch QEMU in the background with -s (gdb stub at :1234) and
# serial → file so we can tail it separately.
SERIAL_LOG="/tmp/cyphera-gdb-serial.log"
: > "$SERIAL_LOG"

echo "==> launching QEMU with gdb stub on :1234"
echo "==> serial log:  tail -F $SERIAL_LOG"
qemu-system-x86_64 \
    -machine microvm,accel=kvm:tcg,pit=off,pic=off,rtc=off \
    -cpu max -smp 2 -m 1024M \
    -kernel "$KERNEL_ELF" \
    -initrd "$INITRD" \
    -nodefaults -no-user-config -no-reboot \
    -serial "file:$SERIAL_LOG" -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -device virtio-rng-device \
    -s \
    >/dev/null 2>&1 &
QEMU_PID=$!

cleanup() {
    if kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "==> killing QEMU (pid $QEMU_PID)"
        kill "$QEMU_PID" 2>/dev/null
        wait "$QEMU_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# Give QEMU a beat to open its gdb-stub socket.
sleep 1

if [ -n "$GDB_SCRIPT" ]; then
    echo "==> running gdb script: $GDB_SCRIPT"
    gdb -nx -batch \
        -ex "set pagination off" \
        -ex "target remote :1234" \
        -ex "source $GDB_SCRIPT" \
        "$KERNEL_ELF"
else
    echo "==> interactive gdb (type 'help' for commands)"
    gdb -nx \
        -ex "set pagination off" \
        -ex "target remote :1234" \
        "$KERNEL_ELF"
fi
