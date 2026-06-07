# Reproducible builds

Building cyphera-kernel from the same source with the pinned
toolchain produces a bit-identical binary — verified across both
clean rebuilds and across different working directories on the
same machine. Same-machine rebuilds are the currently verified
property: anyone can attempt to confirm the released binary came
from the published source by rebuilding and comparing SHA256
(cross-machine reproducibility is expected but not yet CI-gated).

## What makes it reproducible

Four things, all configured in the build itself. The release build uses
these settings; cross-machine bit-identical reproducibility is expected
but is not yet a CI-gated check (see the caveat below).

- **Toolchain pinned**: `rust-toolchain.toml` fixes the exact
  nightly + components. Same toolchain = same compiler bytes.
- **Dependencies pinned**: `Cargo.lock` fixes every direct +
  transitive crate to a specific version + checksum.
- **Deterministic codegen**: `codegen-units = 1` in
  `[profile.release]` — no parallel-codegen ordering variance.
- **Source paths erased from debug info**: `trim-paths = "all"`
  in `[profile.release]` — debug sections don't carry the
  absolute source directory, so the same source produces the
  same bytes regardless of where it's checked out.

## Verifying yourself

```bash
git clone https://github.com/cyphera-labs/cyphera-kernel
cd cyphera-kernel
git checkout v0.X.Y
cargo build --release -p cyphera-kernel
sha256sum target/x86_64-unknown-none/release/cyphera-kernel

# Compare with the SHA256 attached to the GitHub Release for v0.X.Y.
# It should match.
```

Cross-machine verification (build on two different machines,
compare SHA256) should produce the same hash — but is not yet
gated by CI; if you find a mismatch, file an issue.

## References

- [Reproducible Builds project](https://reproducible-builds.org/)
- [Rust trim-paths](https://doc.rust-lang.org/cargo/reference/profiles.html#trim-paths)
