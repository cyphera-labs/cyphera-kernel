# Security

Cyphera Kernel is a memory-safe, Rust-based OS kernel for virtual machines and confidential-computing environments. It runs ring-3 Linux-ABI ELF binaries against a real but still-incomplete syscall surface (283 of 385 implemented, 73 missing); this first release ships a hello-world ring-3 demo plus the in-tree selftest suite. It is not a server you deploy; it is a kernel binary
that boots inside QEMU / KVM / cloud-CC enclaves. Threat model
concerns are mostly about *what runs inside the kernel*, not about
reachable network surface.

## Threat model snapshot

**What Cyphera Kernel defends against today:**

- **Memory safety in kernel services.** `kernel/` is
  `#![forbid(unsafe_code)]` — the compiler rejects any `unsafe` there.
  `unsafe` is confined to the audited lower layers: `frame/` (the
  privileged substrate), `runtime/boot/` (bring-up), and
  `drivers/virtio/` (MMIO / DMA). `tools/check-unsafe-boundary.sh`
  asserts the `kernel/` services layer stays `unsafe`-free.
- **Cross-AS access integrity.** User-pointer reads/writes go through
  `frame::user::{copy_from_user, copy_to_user}`, which validate and
  short-circuit page faults via the user-fault handler rather than
  panicking.
- **Signal-delivery + credential integrity.** SIGKILL/SIGSTOP cannot be
  caught, blocked, or ignored. `kill(2)` enforces the `man 2 kill` cred
  check. Tracer/tracee identity is invariant under signal delivery.

**What Cyphera Kernel does NOT defend against:**

- **Bare-metal driver attack surface.** Scope is explicitly VM /
  confidential-computing only. No native physical PCIe device
  support. The virtio-PCI transport is in scope; arbitrary
  bare-metal PCIe device enumeration and drivers are not. No USB,
  no audio (other than virtio-sound). The driver attack surface is
  virtio + framebuffer +
  virtio-input + UART + APIC.
- **Hypervisor compromise.** Cyphera Kernel assumes the host hypervisor is
  honest. Confidential-computing primitives (SEV-SNP, TDX) reduce the
  trust surface but are still on the roadmap, not shipped.
- **Side-channel leakage** (Spectre / MDS / etc) — not in scope as a
  defended class. Mitigations land when the upstream `x86_64` crate and
  the linker provide them.
- **Compiler / toolchain trust.** We trust rustc, LLVM, lld, and the
  pinned nightly toolchain. Same-machine rebuilds are reproducible and
  SHA-256-verifiable (see [docs/REPRODUCIBLE-BUILDS.md](docs/REPRODUCIBLE-BUILDS.md)),
  but cross-machine bit-for-bit reproducibility is not yet CI-gated, so
  reproducible builds are not yet treated as a defended security property.

## Code-quality bar

This first public release ships two GitHub Actions workflows: the
signed-release build and SBOM generation (below). The checks here are
the quality bar the code is held to — run them locally, all through
the pinned dev container:

- **Formatting + lint**: `./dev fmt` (`cargo fmt --all`; check-only
  via `cargo fmt --all -- --check`) and `./dev clippy`
  (`cargo clippy -- -D warnings`).
- **Build + test**: `./dev build` and `./dev test` (QEMU integration
  batteries; see `docs/TESTING.md`).
- **Memory-safe boundary**: `tools/check-unsafe-boundary.sh` asserts
  the `kernel/` services layer contains no `unsafe`.
- **Supply chain**: `cargo deny check` enforces a license allowlist +
  a registry allowlist (`crates.io` only) + RustSec advisory checks
  per `deny.toml`. Unknown git sources are rejected.
- **Static analysis / secret scanning**: `semgrep --config auto`,
  `trufflehog --only-verified`, and `gitleaks detect` are part of the
  maintainers' pre-release sweep.

On every published release (the shipped `release` + `sbom` workflows):

- **SBOM**: CycloneDX + SPDX SBOMs generated via syft.
- **Provenance**: SLSA build-provenance attestation generated
  alongside.
- **Signing**: Sigstore keyless cosign signs the kernel ELF and each
  SBOM. All artifacts attach to the GitHub release.

### Posture roadmap

Hardening planned but not yet wired into public CI:

- The lint / supply-chain / secret-scan / `actionlint` suite as
  enforced pull-request gates
- CodeQL Rust analysis (lands when GHAS coverage settles)
- Dependency review (Dependabot grouped updates already ship — see
  `.github/dependabot.yml`)
- Secret-scanning push protection
- OpenSSF Scorecard publishing
- Branch protection ruleset on `main`

## Reporting

Found a vulnerability? Email `security@horizondigital.dev`, or use
GitHub's private vulnerability reporting on this repository. Please
don't open a public issue for security findings — use one of the
private channels above so we can triage before disclosure.

No bounty program today; thanks + credit on request.
