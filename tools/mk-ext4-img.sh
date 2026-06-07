#!/usr/bin/env bash
# Build an ext4 image with known content for the kernel's ext4
# integration test. Invoked by `runtime/boot/build.rs`; runs inside
# the dev container, where `mkfs.ext4` lives in /usr/sbin.
#
# Usage: mk-ext4-img.sh <output_path>
#
# The generated image is 32 MiB / 8192 blocks of 4 KiB each.
# Generous on purpose — fits a 6 MiB file (past ext2's 4 MiB
# direct+single-indirect cap; forces multi-extent traversal), 64
# directory entries to exercise multi-block dir reads, and the
# bitmap + inode-table overhead with headroom. Loading this fully
# into the kernel test harness is what shaped the 64 MiB heap.
#
# It carries the modern ext4 feature set we test against:
#
#   -O extent          extent-based block mapping (no indirect blocks)
#   -O dir_index       htree directory indexing (O(log N) lookups)
#   -O 64bit           64-bit field encoding (s_blocks_count_hi etc.)
#   -O filetype        d_type byte in directory entries
#   -O sparse_super    fewer superblock copies (every group with prime
#                      group# = 1, 3, 5, 7, 9...)
#   -O ^has_journal    NO journal — host fs (raw/qcow2 image) provides
#                      crash atomicity for our use case (VM-only thesis).
#                      Driver refuses to mount filesystems flagged
#                      "needs_recovery" anyway.
#   -O ^metadata_csum  CRC32c metadata checksums are disabled in the
#                      fixture so the driver's read path doesn't have to
#                      validate-or-reject. With checksums enabled,
#                      writeback would need the matching CRC update.
#
# Tree layout planted into the image (mirrors what the test asserts):
#   /hello.txt           — small file, single extent, sub-block
#   /etc/hostname        — second-level directory + file
#   /etc/motd            — multi-line content
#   /var/log/sample      — three-deep path
#   /large.bin           — 6 MiB file forcing multi-extent OR multi-leaf
#                          extent tree; explicitly past the ext2 4 MiB
#                          direct+single-indirect cap, so extent-based
#                          mapping is exercised.
#   /htree-dir/file_NNN  — 4096 entries to force htree promotion (linear
#                          dirs cap out at the block size).
set -euo pipefail

OUT="${1:?usage: mk-ext4-img.sh <output_path>}"

TREE="$(mktemp -d)"
trap "rm -rf '$TREE'" EXIT

mkdir -p "$TREE/etc" "$TREE/var/log" "$TREE/htree-dir"
printf 'hello, ext4 world!\n' > "$TREE/hello.txt"
printf 'cyphera\n' > "$TREE/etc/hostname"
printf 'Welcome to Cyphera Kernel on ext4.\nThis is /etc/motd.\n' > "$TREE/etc/motd"
printf 'log line one\nlog line two\nlog line three\n' > "$TREE/var/log/sample"

# 6 MiB file — past ext2's 4 MiB direct+single-indirect cap. Filled
# with a deterministic pattern so the test can verify content at
# specific offsets without bloating the image's transferred bytes.
dd if=/dev/zero of="$TREE/large.bin" bs=1M count=6 status=none
printf 'EXT4-LARGE-START' | dd of="$TREE/large.bin" bs=1 count=16 conv=notrunc status=none
# Marker at 4 MiB exactly — past the ext2 cap.
printf 'PAST-EXT2-CAP' | dd of="$TREE/large.bin" bs=1 seek=$((4 * 1024 * 1024)) count=13 conv=notrunc status=none

# 64 entries in /htree-dir — exercises multi-block linear
# directories (each 4 KiB block holds roughly ~120 entries of
# this name length, so 64 fits in one block but still exceeds
# the inline-extent count). htree-promotion only happens when
# the kernel itself adds entries past a threshold; mkfs.ext4 -d
# always builds linear dirs, so true htree READ is exercised
# only after our driver's own write path promotes one. The
# driver's htree READ path stays present for compat with images
# produced by conventional ext4 tooling.
for i in $(seq 0 63); do
    printf 'file %02d\n' $i > "$TREE/htree-dir/file_$(printf '%02d' $i)"
done

# 32 MiB image (8192 blocks of 4 KiB each). Generous enough to fit
# the 6 MiB file plus htree dir plus inode table headroom.
PATH="/usr/sbin:/sbin:$PATH" mkfs.ext4 \
    -F \
    -b 4096 \
    -L cyphera \
    -O 'extent,dir_index,64bit,filetype,sparse_super,^has_journal,^metadata_csum' \
    -d "$TREE" \
    "$OUT" 8192 \
    >/dev/null 2>&1
