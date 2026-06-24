#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BUILD="$HERE/.build-alpine"
CACHE="$HERE/.cache/alpine-v3.20"

ALPINE_BRANCH="v3.20"
ALPINE_ARCH="x86_64"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"
APK_TOOLS_APK="apk-tools-static-2.14.4-r1.apk"
APK_TOOLS_SHA="42fe483a9fc4f8b194eb8ba24849ea7dc4f1b60570674c6c319b82a32c65b6e0"
ALPINE_KEYS_APK="alpine-keys-2.4-r1.apk"
ALPINE_KEYS_SHA="3404c993a01fcc9d349a136e9296c0d4a9d74e09a1452de6d19c30599f9f0d8e"
PACKAGES="${ALPINE_PACKAGES:-alpine-base coreutils}"

fetch() {
    local apk="$1" sha="$2" dest="$CACHE/$1"
    if [ ! -f "$dest" ] || ! echo "$sha  $dest" | sha256sum -c --status; then
        mkdir -p "$CACHE"
        curl -fsSL -o "$dest" "$ALPINE_MIRROR/$ALPINE_BRANCH/main/$ALPINE_ARCH/$apk"
        echo "$sha  $dest" | sha256sum -c --status \
            || { echo "FATAL: $apk sha256 mismatch (upstream moved? update the pin)" >&2; exit 1; }
    fi
    echo "$dest"
}

echo "==> Building the kernel (release)"
( cd "$ROOT" && cargo build -p cyphera-kernel --target x86_64-unknown-none --release )
KERNEL="$ROOT/target/x86_64-unknown-none/release/cyphera-kernel"

APK_STATIC="$CACHE/sbin/apk.static"
KEYS_DIR="$CACHE/keys"
if [ ! -x "$APK_STATIC" ] || [ ! -d "$KEYS_DIR" ]; then
    echo "==> Fetching pinned apk.static + signing keys"
    tools="$(fetch "$APK_TOOLS_APK" "$APK_TOOLS_SHA")"
    keys="$(fetch "$ALPINE_KEYS_APK" "$ALPINE_KEYS_SHA")"
    tar -xzf "$tools" -C "$CACHE" 2>/dev/null || true
    chmod +x "$APK_STATIC"
    tmp="$CACHE/.keys-extract"; rm -rf "$tmp" "$KEYS_DIR"; mkdir -p "$tmp" "$KEYS_DIR"
    tar -xzf "$keys" -C "$tmp" 2>/dev/null || true
    find "$tmp" -name '*.rsa.pub' -exec cp -n {} "$KEYS_DIR/" \;
    rm -rf "$tmp"
fi

ROOTFS="$BUILD/rootfs"
rm -rf "$BUILD"; mkdir -p "$ROOTFS"; mkdir -p "$CACHE/pkgcache"

echo "==> Bootstrapping Alpine $ALPINE_BRANCH ($PACKAGES) via apk.static, rootless"
unshare -r bash -uo pipefail -c '
    APK="$1"; KEYS="$2"; ROOT="$3"; CACHE="$4"; MIRROR="$5"; BRANCH="$6"; ARCH="$7"; shift 7
    "$APK" --keys-dir "$KEYS" --arch "$ARCH" \
        -X "$MIRROR/$BRANCH/main" -X "$MIRROR/$BRANCH/community" \
        --cache-dir "$CACHE" --root "$ROOT" --initdb \
        add "$@" || true
    for e in devfs:sysinit procfs:sysinit sysfs:sysinit hostname:boot bootmisc:boot; do
        chroot "$ROOT" rc-update add "${e%%:*}" "${e##*:}" >/dev/null 2>&1 || true
    done
' _ "$APK_STATIC" "$KEYS_DIR" "$ROOTFS" "$CACHE/pkgcache" \
    "$ALPINE_MIRROR" "$ALPINE_BRANCH" "$ALPINE_ARCH" $PACKAGES || true

[ -x "$ROOTFS/sbin/openrc" ] || { echo "FATAL: alpine bootstrap incomplete (network?)" >&2; exit 1; }
chmod -R u+rwX "$ROOTFS"
echo cyphera-alpine > "$ROOTFS/etc/hostname"

mkdir -p "$ROOTFS/run" "$ROOTFS/root"
cat > "$ROOTFS/etc/inittab" <<'INITTAB'
::sysinit:/sbin/openrc sysinit
::wait:/sbin/openrc boot
::wait:/sbin/openrc default
::respawn:/bin/sh -l
::ctrlaltdel:/sbin/openrc shutdown
::shutdown:/sbin/openrc shutdown
INITTAB

echo "==> Packing the Alpine initrd (root-owned: rootless build, archived as uid 0)"
tar --owner=0 --group=0 --numeric-owner -cf "$BUILD/initrd.tar" -C "$ROOTFS" .

echo "==> Booting Cyphera Kernel running Alpine"
echo "    A root shell opens on the console after boot. Try: uname -a, cat /proc/cpuinfo,"
echo "    ls -l /, ps, mount, apk --help. Quit QEMU with Ctrl-A then x."
echo "    ----------------------------------------------------------------"
TIMEOUT="${DEMO_TIMEOUT:-0}"
PREFIX=()
[ "$TIMEOUT" != "0" ] && PREFIX=(timeout "$TIMEOUT")
"${PREFIX[@]}" qemu-system-x86_64 \
    -machine microvm,accel=kvm:tcg,pit=off,pic=off,rtc=off \
    -cpu max -smp 2 -m 1024M \
    -kernel "$KERNEL" \
    -initrd "$BUILD/initrd.tar" \
    -nodefaults -no-user-config -no-reboot \
    -serial mon:stdio -display none \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -device virtio-rng-device || true
echo "    ----------------------------------------------------------------"
echo "==> Alpine demo finished."
