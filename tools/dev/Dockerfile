FROM rust:1.96-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# QEMU comes from bookworm-backports (>= 8.2): the integration harness
# attaches a virtio-sound device, which the base bookworm QEMU (7.2)
# predates. The rest stay on the stable suite.
RUN echo 'deb http://deb.debian.org/debian bookworm-backports main' \
        > /etc/apt/sources.list.d/backports.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends -t bookworm-backports \
        qemu-system-x86 \
        lld \
        ca-certificates \
        git \
        gdb \
        less \
        ripgrep \
        e2fsprogs \
 && rm -rf /var/lib/apt/lists/*

# Install the pinned nightly used by rust-toolchain.toml. Pre-installing
# means cargo doesn't pause for ~30s on first run to fetch it. The exact
# date here mirrors rust-toolchain.toml; bump together.
RUN rustup toolchain install nightly-2026-03-01 --profile minimal \
 && rustup default nightly-2026-03-01 \
 && rustup component add --toolchain nightly-2026-03-01 \
        rust-src clippy rustfmt llvm-tools-preview \
 && rustup target add --toolchain nightly-2026-03-01 x86_64-unknown-none

WORKDIR /workspace

# Root is intentional: this is a dev/build container, not a runtime
# image. apt-get + rustup component install in the steps above require
# root; downstream `./dev test` mounts the source tree as root-owned and
# expects to write to /workspace.
# nosemgrep: dockerfile.security.missing-user.missing-user
CMD ["bash"]
