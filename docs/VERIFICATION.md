# Verification

Cyphera Kernel makes specific verifiable claims, not blanket
"trust us" assertions. Each claim has a recipe; you can run
them all without trusting the maintainers.

## What we claim, precisely

**Structural claim:**
The kernel services layer (`kernel/`) is built with
`#![forbid(unsafe_code)]` at the crate root — the Rust
compiler refuses to compile it if any `unsafe` block is
present. All `unsafe` code lives in a small audited substrate
(`frame/src/`), in the virtio drivers (`drivers/virtio/src/`),
and in the boot binary (`runtime/boot/src/`). Every `unsafe`
block in those production sources carries a `// SAFETY:` comment
explaining the invariant it relies on, enforced by
`clippy::undocumented_unsafe_blocks`.

**Provenance claim:**
No source code from Linux, FreeBSD, any other Rust kernel, or
any other operating system was copied or used as a structural
template for code in this repository. Reimplementation is from
public specifications. See `docs/CLEAN-ROOM.md` (which also
discloses AI-assisted development and the mitigations
applied).

**Reproducibility claim:**
Building from a release tag with the pinned toolchain
produces a bit-identical binary on the same machine, verified
across rebuilds and across working directories. See
`docs/REPRODUCIBLE-BUILDS.md`.

**Functional claim:**
The kernel boots under QEMU + microvm and runs a userland program
in ring 3 against the documented syscall ABI. `./dev demo` builds
and runs the hello-world demo; `./dev test` runs the in-tree
integration suite against the `selftests/` fixtures.

The rest of this document is the recipe for verifying these
claims yourself.

## What we do NOT claim

Boundaries we explicitly do not claim:

- **We do not claim the kernel is bug-free.** Memory safety
  in the services layer is compiler-enforced; correctness is
  not. The kernel can have logic bugs, algorithmic errors,
  and undefined behavior in unsafe blocks that current
  Kani / MIRI / fuzz coverage hasn't reached.
- **We do not claim independent verification of memory
  safety.** Our structural design *reduces the surface area*
  where memory-safety violations can occur, and we review +
  test the residual unsafe pool. **A full independent
  third-party security audit has not yet been performed.**
- **We do not claim the dependency graph is bug-free.** Rust
  crates we depend on (smoltcp, virtio-drivers, the x86_64
  crate, object, allocators) are part of our trust surface.
  `cargo-deny` enforces license + supply-chain advisory
  hygiene; it does not enforce correctness.
- **We do not claim the build pipeline is uncompromised.**
  Layer 4 below depends on Sigstore's trust roots and
  GitHub Actions' OIDC issuer. A compromise of either
  invalidates that layer's claim.

These limits exist for any kernel; we name them so you can
size your trust accordingly.

## Layer 1 — Read the source

The privilege boundary between `kernel/` (services) and
`frame/` (audited substrate) is compiler-enforced. The
simplest check:

```bash
git clone https://github.com/cyphera-labs/cyphera-kernel
cd cyphera-kernel
grep -rn 'forbid(unsafe_code)' kernel/src/lib.rs
```

Expect `kernel/src/lib.rs:2:#![forbid(unsafe_code)]`. That
single attribute is what blocks the entire services layer
from carrying `unsafe`. Try adding `unsafe { … }` anywhere
under `kernel/src/` — the compiler will refuse to build.

The audited `unsafe` pools live in:

| Location | Why it has unsafe |
|---|---|
| `frame/src/` | Page tables, interrupts, MMIO, syscall trampoline, per-CPU storage. This is the privileged substrate. |
| `drivers/virtio/src/` | virtio device MMIO + DMA. Hardware-touching by definition. |
| `runtime/boot/src/` | Long-mode bring-up, multiboot2 / PVH entry. Runs before the safe Rust environment exists. |

Every `unsafe` block in these production sources has a `// SAFETY:`
comment, enforced by `clippy::undocumented_unsafe_blocks` (run via
`./dev clippy` / the pre-release sweep with `-D warnings`). Test fixtures
under `selftests/` and the integration tests are outside this
audited-production scope.
Read `frame/` end-to-end if you want to verify the boundary
at the source level — it's the smallest of the three, and
it's where the load-bearing unsafe lives.

Dependency hygiene is checked with `cargo deny check` (part of the
pre-release quality sweep; see `SECURITY.md`). `Cargo.lock` pins every
direct and transitive crate to a specific version + checksum. The
allowed-license set is in `deny.toml`.

## Layer 2 — Replay the verification artifacts

The repository ships three kinds of automated verification
harnesses you can run yourself:

### Kani formal proofs

The `verification/` crate contains **120 Kani proofs** across
18 modules over kernel invariants — path normalization, futex wake counts,
lock-hierarchy acyclicity, capability inclusion, PTE
encoding, signal-mask combine monotonicity, and more. Each
proof is a property the kernel must maintain; Kani is a
model-checker that exhaustively explores the state space.

```bash
cargo install kani-verifier
cargo kani setup
cargo kani --package verification
# Optional count check:
cargo kani --manifest-path verification/Cargo.toml list
```

Every proof should succeed. A failure is a real
counterexample worth investigating.

### MIRI tests

MIRI is the Rust interpreter that detects undefined behavior
at runtime — stacked-borrows violations, data races,
out-of-bounds memory access, uninitialized reads. Kernel
subsystems that don't need privileged hardware access can
run under MIRI via the `host_test` cfg + the `frame_host`
shim crate.

```bash
rustup +nightly component add miri
cargo +nightly miri test --no-default-features --features host_test \
    --target x86_64-unknown-linux-gnu -p kernel
```

(`--no-default-features` is required: the default `prod` feature links
the bare-metal `frame` crate, which conflicts with the `host_test`
build's `std`; the two are mutually exclusive.)

Expect zero UB findings.

### Fuzz harnesses

The repo carries **24 `cargo-fuzz` harnesses** over
parser-shaped attack surfaces — ELF loader, tar extractor,
PAX header parser, syscall argument validation, and so on:

```bash
cargo install cargo-fuzz
cargo fuzz list                              # see all 24
cargo fuzz run elf_parse -- -max_total_time=300
```

A crash from your own fuzzing run is a real bug — please
report it.

## Layer 3 — Inspect the released binary

You can prove the released ELF is statically-linked Rust
with no external libc, without rebuilding. Download a release
asset (e.g., `cyphera-kernel-vX.Y.Z.elf` from the GitHub
releases page), then:

```bash
# 1. Statically linked, no dynamic dependencies.
file cyphera-kernel-vX.Y.Z.elf
# expect: "ELF 64-bit LSB executable, x86-64, ..., statically linked, ..."

ldd cyphera-kernel-vX.Y.Z.elf
# expect: "not a dynamic executable"

# 2. Symbol table is Rust-mangled.
nm cyphera-kernel-vX.Y.Z.elf | head -50
# expect: most symbols are `_RNv...` (Rust v0 mangling) or `_RN...` (legacy v0).

# Demangle with rustfilt (`cargo install rustfilt`):
nm cyphera-kernel-vX.Y.Z.elf | rustfilt | head -50
# expect: source-level paths like
#   <frame::cpu::per_cpu::CpuArea as ...>::...

# 3. No libc-shaped symbols anywhere.
nm cyphera-kernel-vX.Y.Z.elf \
  | grep -E '(__GI_|@GLIBC_|@@GLIBC_|musl|libc\.so|pthread_|libstdc\+\+)' \
  && echo "FOUND external libc symbols — investigate" \
  || echo "CLEAN — no external libc symbols"
```

What this proves:

- **Statically linked, zero runtime dynamic dependencies.**
  The binary IS the kernel; nothing else gets loaded.
- **Symbol provenance is Rust.** Rust v0 mangling is only
  emitted by the Rust compiler; the binary cannot fake it.
- **No external libc.** Cyphera Kernel does not pull in
  glibc, musl, newlib, relibc, or any other libc.

5-minute audit. No rebuild required.

## Layer 4 — Verify cryptographic build provenance

Every release ships with two independent cryptographic
claims, anchored to two independent trust roots:

1. **GitHub Actions attestation** — proves the binary was
   built by `release-kernel.yml` at a specific commit + time.
   Anchored to Sigstore's transparency log.
2. **Sigstore cosign signature** — keyless signature tied to
   the workflow's OIDC identity. Verifies independently of
   GitHub's attestation API via the public Rekor log.

### Verify the GitHub Actions attestation

```bash
# Requires `gh` (GitHub CLI) >= 2.42.
gh attestation verify cyphera-kernel-vX.Y.Z.elf \
  --owner cyphera-labs

# Stronger: verify the attestation came from the expected workflow.
gh attestation verify cyphera-kernel-vX.Y.Z.elf \
  --owner cyphera-labs \
  --signer-workflow cyphera-labs/cyphera-kernel/.github/workflows/release-kernel.yml
```

A successful verification confirms:
- Binary produced by THIS workflow file
- At the commit SHA recorded in the attestation
- At the time recorded in the attestation
- Rekor log entry signed by a real GitHub Actions OIDC
  identity (cannot be forged without compromising Sigstore's
  root keys)

### Verify the Sigstore cosign signature

```bash
# Requires `cosign` >= 2.x.
cosign verify-blob \
  --certificate-identity-regexp "^https://github.com/cyphera-labs/cyphera-kernel/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature cyphera-kernel-vX.Y.Z.elf.sig \
  --certificate cyphera-kernel-vX.Y.Z.elf.pem \
  cyphera-kernel-vX.Y.Z.elf
```

A successful verification confirms:
- Signature came from a workflow under
  `cyphera-labs/cyphera-kernel`
- Certificate issued by Sigstore's Fulcio CA
- Signing event logged to Rekor

Sigstore is run by the Linux Foundation, independent of
GitHub. These are two independent paths to the same fact.

## Layer 5 — Reproduce the build

The strongest verification: rebuild from source and confirm
the SHA256 matches.

```bash
git clone --branch vX.Y.Z https://github.com/cyphera-labs/cyphera-kernel
cd cyphera-kernel
cargo build --release -p cyphera-kernel
sha256sum target/x86_64-unknown-none/release/cyphera-kernel
# Compare with the cyphera-kernel-vX.Y.Z.elf.sha256 file in the GitHub release.
```

**Status:** verified bit-identical across clean rebuilds and
across working directories on the same machine. The
foundations are `codegen-units = 1` + `trim-paths = "all"` +
the pinned toolchain + `Cargo.lock`. Cross-machine builds
*should* match but are not yet CI-gated; see
`docs/REPRODUCIBLE-BUILDS.md` for the details.

## Layer 6 — Run it yourself

Memory safety + a clean build mean nothing if the kernel doesn't
run. Boot it under QEMU and exercise it:

```bash
./dev demo        # boot the kernel + run the hello-world userland in ring 3
./dev test        # run the in-tree integration suite
```

The standalone external-workload harness is out of tree and
ships in a later release. When it lands, a passing workload
will be functional proof that the kernel honors the documented
syscall ABI well enough for that specific software to execute,
and a failing one will point at a real syscall-surface or
scheduler bug.

## Verification cheat sheet

| Layer | What it proves | Effort | Trust dependency |
|---|---|---|---|
| 1 (read source) | The forbid-unsafe boundary is real; unsafe is fully inventoried | hours-days | None (your reading) |
| 2 (replay artifacts) | Kani proofs pass; MIRI finds no UB; fuzz harnesses run clean | hours | Your local toolchain |
| 3 (binary inspection) | Released binary is statically-linked Rust, no external libc | 5 minutes | The binary's structure can't lie |
| 4a (GH attestation) | Binary was built by THIS workflow at THIS commit | seconds | Sigstore + GitHub Actions OIDC |
| 4b (cosign signature) | Same fact via independent transparency log | seconds | Sigstore Fulcio + Rekor |
| 5 (reproduce build) | Source produces the exact binary that shipped | minutes | None (you control the build) |
| 6 (run it) | The hello-world demo + in-tree selftest ELFs execute in ring 3 on the kernel | minutes | Your QEMU |

Most reviewers will do Layer 3 to start (5 minutes), Layers
4a / 4b for ongoing release confidence (seconds), and Layers
1 / 2 / 5 / 6 once before they care deeply. The most
demanding reviewers will want all layers.

## See also

- `docs/REPRODUCIBLE-BUILDS.md` — what makes the build deterministic
- `docs/CLEAN-ROOM.md` — source-provenance policy + AI-assist disclosure
- `.github/workflows/release-kernel.yml` — the public release workflow
- `.github/workflows/sbom.yml` — the SBOM-generation workflow
