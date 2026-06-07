# NOTICE

Cyphera Kernel
Copyright 2026 Horizon Digital Engineering LLC

Cyphera Kernel is licensed under the Apache License, Version 2.0
(the "License"). This file is the NOTICE file referenced in
Section 4(d) of the License. See [LICENSE](LICENSE) for the full
license text.

This product includes software developed by third parties, listed
below. Each dependency's full license text and source are
available at the URL given. The exact resolved versions consumed
by Cyphera Kernel are pinned in `Cargo.lock` and verified by
checksum on each build.

The license policy enforced on third-party Rust crates is in
[deny.toml](deny.toml); `cargo deny check` enforces it locally and
in the maintainers' pre-release sweep (wiring it as a public-CI
gate is on the roadmap — see [SECURITY.md](SECURITY.md)). The
allowed-license set is intentionally restricted to Apache-2.0, MIT,
and BSD-shaped permissive licenses.

## Direct Rust dependencies

The crates below are listed in workspace `Cargo.toml` files as
direct dependencies. Transitive dependencies are visible in
`Cargo.lock` and carry their own license terms (also enforced by
`deny.toml`).

| Crate | Requirement | License | Source |
|---|---|---|---|
| `spin` | 0.9 | MIT | https://github.com/mvdnes/spin-rs |
| `x86_64` | 0.15 | MIT OR Apache-2.0 | https://github.com/rust-osdev/x86_64 |
| `linked_list_allocator` | 0.10 | MIT OR Apache-2.0 | https://github.com/rust-osdev/linked-list-allocator |
| `buddy_system_allocator` | 0.10 | MIT | https://github.com/rcore-os/buddy_system_allocator |
| `bitflags` | 2.12 | MIT OR Apache-2.0 | https://github.com/bitflags/bitflags |
| `object` | 0.36 | MIT OR Apache-2.0 | https://github.com/gimli-rs/object |
| `smoltcp` | 0.11 | MIT OR Apache-2.0 (used under Apache-2.0) | https://github.com/smoltcp-rs/smoltcp |
| `virtio-drivers` | 0.13 | MIT OR Apache-2.0 (used under MIT for GPL-2.0 compatibility) | https://github.com/rcore-os/virtio-drivers |
| `libfuzzer-sys` | 0.4 | MIT OR Apache-2.0 OR NCSA | https://github.com/rust-fuzz/libfuzzer |
| `arbitrary` | 1 | MIT OR Apache-2.0 | https://github.com/rust-fuzz/arbitrary |

`libfuzzer-sys` is only depended on by the `fuzz/` crate (a
separate workspace from the main kernel build). It is not
linked into the kernel ELF.

## Specifications consulted

Per the clean-room policy in [docs/CLEAN-ROOM.md](docs/CLEAN-ROOM.md),
Cyphera Kernel is implemented from public specifications and
publicly-documented interfaces — not from another operating
system's source code. The specifications consulted include:

- **Virtio v1.1** (OASIS, 2019) —
  https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html
- **Intel 64 and IA-32 Architectures Software Developer's Manual**
  (Intel) — https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- **AMD64 Architecture Programmer's Manual** (AMD) —
  https://www.amd.com/system/files/TechDocs/40332.pdf
- **POSIX.1-2017 / IEEE Std 1003.1** (IEEE / The Open Group) —
  https://pubs.opengroup.org/onlinepubs/9699919799/
- **Linux man-pages** (kernel.org / Michael Kerrisk et al.) —
  https://man7.org/linux/man-pages/ — consulted for syscall and
  ABI behavior reference; no source code from the Linux kernel
  was consulted or copied.
- **Rust Reference** and **Rust Standard Library documentation**
  (rust-lang.org).
- **IETF RFCs** consulted for protocol implementations — exact
  RFC numbers are cited in the source comments of the relevant
  networking modules.

Each piece of code in `kernel/`, `frame/`, `frame_host/`,
`drivers/`, and `runtime/` is original work written by the
Cyphera Kernel authors with reference to the specifications
above. No source code from the Linux kernel, FreeBSD, OpenBSD,
NetBSD, illumos, Darwin, or any other operating system was
consulted while writing Cyphera Kernel.

## Trademarks

"Linux" is a registered trademark of Linus Torvalds, used here in
reference to the Linux Application Binary Interface (ABI) that
Cyphera Kernel implements for userland compatibility.

All other trademarks are the property of their respective owners.

## Reporting attribution issues

If you believe a third-party dependency listed above is missing
required attribution, or if a dependency we consume is not listed
here, please open an issue at the Cyphera Kernel repository or
contact the maintainers per [SECURITY.md](SECURITY.md).
