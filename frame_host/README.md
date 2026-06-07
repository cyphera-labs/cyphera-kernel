# frame_host

Host-side stubs for the subset of `frame::` that `kernel/` consumes.
Built for `x86_64-unknown-linux-gnu` (std + alloc) so the kernel
services layer can compile + run unit tests on a developer host
**and under [MIRI](https://github.com/rust-lang/miri)**.

This crate is the host-stub half of the MIRI-on-`kernel/` strategy.
The other half is the `host_test` cargo feature on `kernel/`.

## What this crate is NOT

- **Not a faithful re-implementation of `frame/`.** It's a stub set.
- **Not `no_std`.** It's std + alloc on purpose — MIRI runs on host.
- **Not for production paths.** Nothing in `runtime/boot/` ever
  links against this crate. Only `kernel`'s `host_test` feature
  pulls it in.

## What this crate IS

A set of `pub mod` items whose paths and signatures match `frame::`,
so that `kernel/` source can write:

```rust
#[cfg(host_test)]
use frame_host as frame;
```

…and have every existing `use frame::sync::SpinIrq;` /
`frame::println!(...)` keep resolving when built with
`--features host_test`.

## Running

```
# Host build + tests. `--no-default-features` drops the bare-metal
# `prod` feature (the `frame` crate), which is mutually exclusive with
# the `host_test` std build.
cargo +nightly-2026-03-01 test --no-default-features --features host_test \
    --target x86_64-unknown-linux-gnu -p kernel

# Under MIRI:
rustup component add miri --toolchain nightly-2026-03-01
cargo +nightly-2026-03-01 miri test --no-default-features --features host_test \
    --target x86_64-unknown-linux-gnu -p kernel
```

## Audit discipline

Every stub here is a place where MIRI's view of kernel code
diverges from real-hardware behavior. Documented divergences:

| Stub                          | Host behavior                  | Production semantics not modeled                  |
|-------------------------------|--------------------------------|---------------------------------------------------|
| `sync::SpinIrq<T>`            | `std::sync::Mutex<T>`          | No interrupt-disable. No ticket-lock fairness.    |
| `user::copy_from_user`        | `RwLock<HashMap>` registry     | No SMAP, no lazy page fault, no fault recovery.   |
| `user::copy_to_user`          | `RwLock<HashMap>` registry     | Same.                                              |
| `user::TrapFrame`             | Opaque placeholder             | Not constructible — paths that take `&TrapFrame` aren't host-buildable yet. |
| `println!`                    | `std::println!`                | Goes to stdout, not UART, not klog ring buffer.   |
| `cpu::per_cpu::current_cpu_id`| Always returns `0`             | No per-CPU runqueue partitioning.                 |
| `mm::*`                       | Mostly `todo!()`-shaped or empty | Real VM machinery is not modeled at all.        |

When extending a stub:

1. Match the production `frame::` item path + signature exactly.
2. Note in a comment which production semantics are NOT modeled
   (interrupts, atomicity vs IRQ, real allocator pressure, etc.).
3. Where possible, default to "fail closed" — return an error
   rather than silently behaving differently from real frame.

## Sibling crates

- `frame/` — the real privileged-primitive layer. Never depends on
  this crate.
- `verification/` — Kani proof harnesses. Restates the verified
  logic in a side crate; this crate keeps the production source as
  the verified target.

## See also

- `docs/TESTING.md` — how MIRI runs on `kernel/` via the `host_test` feature.
