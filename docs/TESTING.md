# Testing

Where tests live, what shape they take, and the naming
conventions that distinguish kinds of tests.

## Test kinds

Three categories, distinguished by what crosses what boundary:

### 1. **Unit / API tests** — *kernel-internal, no QEMU*

Live in `kernel/src/**/mod.rs` or sibling `tests` modules
(`#[cfg(test)] mod tests`). Run with plain `cargo test
--lib`. They exercise pure-Rust kernel data structures
without touching the boot path: `vfs::path::normalize`,
`process::Pid`, ABI-shape conversion helpers. ~milliseconds.

Goal: catch regressions in algorithms before they hit a
boot. Today we have very few of these — most invariants
get caught by integration tests instead.

### 2. **Integration tests** — *boot a kernel image, run something inside*

Live in `runtime/boot/tests/{smoke,subsystem}/<name>.rs`.
Each `*.rs` file declares a `kernel_main` that invokes
`kernel::init`, sets up some user state, registers a process,
and calls `kernel::sched::start_first()`. The test "passes" by
issuing a successful `qemu-exit` (encoded by
`frame::io::qemu_exit::ExitCode::Success`).

Two sub-shapes in this repo:

  * **smoke/** — boots-to-userspace plumbing, doesn't load
    real workloads. Fast (<60s wall-clock for the whole
    battery on KVM); break first when the boot path or
    driver layer regresses.
  * **subsystem/** — exercises one kernel subsystem against a
    small user-mode ELF test driver built from the
    `selftests/` workspace in this repo. Each test has a 1:1
    driver that exercises the kernel from user mode and
    exits 0/1.

The kind is reflected in the directory path. Cargo
`[[test]]` entries each carry the full path; test names
(`cargo test --test <name>`) stay the same regardless of
which directory the file lives in.

### 3. **Workload tests** — *external, not shipped in this release*

External-binary integration tests run from a separate workload
harness that is not part of this release. That harness depends on
host-built binary bundles and has different runtime + setup
requirements from the in-tree tests, so it ships on its own.

## User-mode ELF test drivers

The user-mode ELF binaries that subsystem tests drive the
kernel with are built from the **`selftests/`** workspace at the
top of this repo. Each subsystem test has a 1:1 driver crate
in `selftests/` (one Rust crate per driver). The built ELFs
are placed in `bundles/userland/<name>` and `include_bytes!`d
into the test at compile time via an env var emitted by
`runtime/boot/build.rs`.

Naming convention: a subsystem test `tests/subsystem/<X>.rs`
consumes `<X>_ELF_PATH` (e.g. `FILES_ELF_PATH`,
`PROC_FILES_ELF_PATH`). `runtime/boot/build.rs` walks
`bundles/userland/` and emits the env var; tests skip
cleanly when the binary isn't built.

See `selftests/README.md` for the driver inventory + build
conventions.

## Bundles

`bundles/<name>/<artifact>` holds binary blobs used by tests.
Two kinds:

  * `bundles/userland/<name>` — ELFs built from this repo's
    `selftests/` workspace; consumed by `subsystem/` tests.
  * `bundles/<external>/...` — third-party binaries staged by
    the workload harness (shipped separately) and pulled in
    only when workload tests run.

For the **external** workload bundles, `build.rs` emits a
`cargo:rustc-cfg=has_<name>` flag and those tests are gated behind
`#[cfg(has_<name>)]`, so they skip cleanly when the bundle isn't
present. The **`userland/`** driver ELFs are different: the smoke
and subsystem tests `include_bytes!(env!("<NAME>_ELF_PATH"))` them,
so they must exist at compile time or the build fails. `tools/test.sh`
(and `./dev test`) build + stage them for you first, so a clean
checkout works; you only need to build them by hand for a direct
`cargo test` invocation.

## Running

### Userland test drivers are built automatically

The `smoke/` and `subsystem/` tests `include_bytes!` userland ELFs
built from the `selftests/` workspace and staged into
`bundles/userland/` (gitignored — they're build artifacts, not
checked in). **`tools/test.sh` and `./dev test` build + stage them
for you** before running, so a clean checkout works with no extra
step.

You only need to build them by hand when invoking `cargo test`
directly (it doesn't go through the wrapper):

```
tools/build-userland.sh     # or: ./dev build-userland
```

This compiles `selftests/` (release, `x86_64-unknown-none`) and
copies the resulting binaries into `bundles/userland/`. It's
incremental, so re-running after editing a `selftests/` crate is
cheap.

### Then run the tests

Direct cargo invocation:

```
cargo test --release -p cyphera-kernel --test <name>
```

The `--release` is required (we exclude debug builds —
kernel images exceed QEMU's ELF cap in debug). Each test
takes ~5s for boot + the test logic; bundle tests take
~30s–2min.

The wrapper `tools/test.sh` dispatches by kind:

```
tools/test.sh smoke         # smoke tests (fast, <60s on KVM)
tools/test.sh subsystem     # subsystem tests
tools/test.sh all           # full in-tree battery
```

The in-tree battery runs via `tools/test.sh all` (or
`./dev test`). Real-binary workload tests run from a separate
harness that ships in a later release.

`tools/run-qemu.sh` is the cargo runner. It invokes QEMU
with the right virtio devices + serial stdio + the
isa-debug-exit shape that lets the kernel report its exit
code as a host process exit code (33 for success, 35 for
failure).

The disk image (`/tmp/cyphera-test-disk.img`) has a
`flock`-shaped lock that prevents two QEMU processes from
running concurrently. To run two tests in parallel, set
`CYPHERA_DISK_IMG=/tmp/<unique>.img` for the second.

`CYPHERA_GRAPHICAL=1` opts into an SDL window for tests
that need it (external graphical workload tests; not part of this
release).

## Adding a new test

  * **Subsystem test:** add the user-mode driver crate to
    the `selftests/` workspace in this repo, then add
    `runtime/boot/tests/subsystem/<X>.rs` with a
    `[[test]]` entry in `runtime/boot/Cargo.toml` pointing at
    `path = "tests/subsystem/<X>.rs"`. `build.rs` picks up the
    new driver via its `<X>_ELF_PATH` env-var emission once
    the ELF lands in `bundles/userland/`.
  * **Smoke test:** kernel-only tests go in `tests/smoke/`.
    No user-mode driver required — they boot, exercise some
    plumbing, and call `qemu_exit::Success`.
  * **Workload test:** real-binary workloads live in the
    separate workload harness (shipped in a later release),
    not in this tree.

Reference tests by full path
(`runtime/boot/tests/{smoke,subsystem}/<name>.rs`) so
renames + moves stay traceable.
