# selftests

In-tree userland test binaries for Cyphera Kernel: 67 small
`no_std` `no_main` programs that exercise specific kernel
syscalls — capability dropping, seccomp, mmap edge cases, cgroups,
namespaces, futexes, ptrace, dynamic linking quirks, and dozens more.

## What this is

Each crate (`proc_<name>/` plus the legacy `hello/`) is a single-
binary Rust program that boots in ring 3 on the Cyphera Kernel and
exits with a known marker on success / a specific syscall number on
failure. The kernel's integration test suite consumes these binaries
via `include_bytes!` to verify syscall behaviors end-to-end.

This layout — small per-syscall-family programs grouped under
`selftests/` — keeps test-fixture maintenance decoupled from the
kernel crates: lint posture and fmt drift on these single-purpose
test binaries stay out of the kernel crates' CI gates.

## Layout

```
proc_a/           Basic process-creation smoke
proc_caps/        Capabilities (CAP_*, capget, capset)
proc_seccomp/     seccomp BPF filter behavior
proc_namespaces/  CLONE_NEWUSER / NEWPID / NEWNET / NEWUTS / NEWIPC
proc_cgroups/     cgroup v2 creation, charging, OOM kill
proc_futex/       futex wake/wait + PI-futex chain walks
proc_ptrace/      ptrace ATTACH / PEEKDATA / GETREGS / SIGTRAP
proc_*/           ... 50+ more syscall-family exercisers
hello/            Minimal hello-world, the smoke test
```

Each crate has its own `linker.ld` + `build.rs` to control output
shape. All build with `cargo build --release` against
`x86_64-unknown-none` (the kernel target).

## Build

```sh
cargo build --release
```

Produces 67 binaries at `target/x86_64-unknown-none/release/`. These
are consumed by the kernel-side integration tests via `include_bytes!`
from this workspace's release artifacts.

## Toolchain

Pinned to `nightly-2026-03-01` (the same nightly the kernel crates
use). When the kernel bumps the nightly, bump here too — the binaries
must compile against the same ABI / syscall numbers / page-table
layout assumptions the kernel exposes.

## License

Apache-2.0, the same license as the rest of the tree.
