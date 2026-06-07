# Architecture

## What this is

Rust is going into the Linux kernel one subsystem at a time; Cyphera
Kernel asks the other question — could an *entire* kernel, written in
safe Rust and speaking the Linux syscall ABI, slot into existing Linux
workloads? It reimplements the Linux syscall ABI so software built for
Linux runs unmodified within the implemented surface. The kernel
services layer is safe Rust (`#![forbid(unsafe_code)]`), on a syscall
surface that is real but still incomplete (see [SYSCALLS.md](SYSCALLS.md)).

This started as an experiment: *how far can the Linux-kernel ABI
be reimplemented in safe Rust if scope is restricted on purpose?*
This first public release ships the kernel source plus a
hello-world ring-3 demo (`./dev demo`) and the in-tree integration
suite (`./dev test`).

The goal is to run real, unmodified software inside real VMs
against the actual Linux ABI. The syscall surface is still
incomplete (see [SYSCALLS.md](SYSCALLS.md)); when a program
doesn't run yet, we treat the gap as a bug to fix, not an
acceptable limitation.

## How we got here — initial scope limiters

To keep a kernel-sized project tractable, we
drew a few hard lines at the start. Each one removed a large
class of code without compromising the "real software runs" property:

- **VM only — no bare metal.** virtio is the hardware abstraction
  we target. The hypervisor (KVM, QEMU, Firecracker, cloud
  hypervisors) handles physical devices; we expose a clean
  paravirtualized interface. This sidesteps tens of millions of
  lines of device-driver code that exists in Linux solely to
  support specific hardware. (PCI inside a VM IS in scope — the
  virtio-PCI transport works alongside virtio-MMIO. "No bare
  metal" means no native PCI-bus device-zoo enumeration outside
  the virtio surface.)

- **Modern Linux only — 2020 and newer.** Pre-2020 Linux
  features are below the line. If a syscall has a modern
  replacement (`openat` vs `open`, `clone3` vs `clone`,
  `epoll_create1` vs `epoll_create`), we implement the modern
  one. Bridging legacy forms to the modern ones is left to the
  libc compatibility layer; we implement the modern surface first.

- **Initial: no GUI, no sound, no desktop.** The kernel was
  built for headless server workloads first. Framebuffer +
  virtio-sound came later as a proof point that those device
  paths work end-to-end. We don't optimize for desktop use
  cases; they're a stress test of the substrate.

- **Two-layer design from the start.** A small audited
  substrate of `unsafe` Rust at the bottom; everything above
  it in `#![forbid(unsafe_code)]` Rust. Type-system-enforced
  privilege separation in a single address space is a well-
  established direction in safe-language OS research (Microsoft
  Singularity, MIT Theseus, Verus-OS work, the APSys '24
  framekernel paper, Asterinas at USENIX ATC '25). Cyphera
  Kernel is independently designed; see "Prior art" below and
  `docs/CLEAN-ROOM.md` for the source-provenance and patent
  posture.

## Where scope has expanded since

The initial limiters were deliberately narrow. As the work
proved out, scope has grown:

- **Framebuffer + virtio-sound** are wired end-to-end (audio
  plays through host PulseAudio / PipeWire).
- **virtio-PCI** works under UEFI / GRUB / multiboot2 with
  PCI-attached devices, alongside virtio-MMIO for the microvm
  path.
- **Confidential computing** (Intel TDX, AMD SEV-SNP, ARM
  CCA) is now a first-class target audience. CC platforms
  actively prefer a small, auditable kernel — a small audited
  unsafe substrate is a natural fit for an attestable TCB.
  Making CC workloads first-class is part of the roadmap.
- **AArch64** is planned after x86_64 is solidly stable.

## The two-layer kernel

Cyphera Kernel has two layers in a single address space,
separated by the Rust type system rather than by hardware
privilege levels:

```
                  ┌──────────────────────────────────────┐
                  │   Userland (ring 3)                  │
                  │   Linux userland binaries            │
                  └──────────────┬───────────────────────┘
                                 │
                            syscall ABI
                                 │
                  ┌──────────────▼───────────────────────┐
                  │   kernel/  (services, ring 0)        │
                  │   #![forbid(unsafe_code)]            │
                  │   ─ syscall dispatch                 │
                  │   ─ scheduler                        │
                  │   ─ VFS, networking, signals         │
                  │   ─ ptrace, futex, namespaces        │
                  │   ─ ELF loader                       │
                  └──────────────┬───────────────────────┘
                                 │
                              calls
                                 │
                  ┌──────────────▼───────────────────────┐
                  │   frame/  (audited substrate)        │
                  │   the main `unsafe` substrate        │
                  │   ─ page tables, MMU                 │
                  │   ─ interrupts, IDT, GDT             │
                  │   ─ user-memory access primitives    │
                  │   ─ per-CPU storage, SMP boot        │
                  │   ─ MMIO, syscall trampoline         │
                  └──────────────┬───────────────────────┘
                                 │
                              hardware
                                 │
                  ┌──────────────▼───────────────────────┐
                  │   virtio devices (paravirt)          │
                  └──────────────────────────────────────┘
```

- **`frame/`** is the audited substrate where most `unsafe`
  lives — the `kernel/` services layer is `#![forbid(unsafe_code)]`,
  and the remaining `unsafe` is in `runtime/boot/` (bring-up) and
  `drivers/virtio/` (MMIO / DMA). Every `unsafe` block carries a
  `// SAFETY:` comment. Public surface is **typed
  capabilities** — `Frame`, `PhysAddr`, `VirtAddr`,
  `PageTable`, `MmioRegion<T>`, `IrqHandle` — not generic
  request interfaces. The invariants are Kani-proved where
  formalizable (`verification/`).
- **`kernel/`** is the services layer, `#![forbid(unsafe_code)]`
  at the crate root — the compiler refuses to compile any
  `unsafe` block here. It composes the typed capabilities
  `frame/` exports; it never inspects raw memory directly.
- **No IPC overhead.** This isn't a microkernel. `kernel/`
  and `frame/` are linked together and call each other as
  ordinary Rust functions. The privilege boundary is enforced
  by the type system and the compiler — not by message-
  passing across protection rings, and not by request-time
  argument inspection on a generic interface.

**Prior art and related work.** Type-system-enforced
privilege separation in a single address space is an
established research direction. Microsoft Singularity (2003)
pioneered the broader "OS in a safe language" model.
[MIT's Theseus](https://www.theseus-os.com/) explored cell-
based isolation in Rust. The
[APSys '24 framekernel paper](https://dl.acm.org/doi/10.1145/3678015.3680492)
and the [Asterinas](https://asterinas.github.io/) kernel
([USENIX ATC '25](https://www.usenix.org/conference/atc25/presentation/peng-yuke))
explore an adjacent design space. Cyphera Kernel is
independently designed and implemented — not a port or a
reimplementation of any of these. See `docs/CLEAN-ROOM.md`
for source provenance and patent posture.

## What we build on

Cyphera Kernel is written from scratch by Cyphera Labs, but it
leans heavily on the broader Rust systems community. We
deliberately did not reinvent the parts the community had
already gotten right — especially device drivers, which are
the largest single category of code in any kernel:

- **virtio device drivers** come from the
  [`virtio-drivers`](https://github.com/rcore-os/virtio-drivers)
  crate. Our `drivers/virtio/` crate wraps
  it with a thin transport-abstraction layer so the same
  driver code works over both virtio-mmio and virtio-pci.
  This avoids reimplementing `virtio-blk`, `virtio-net`,
  `virtio-rng`, `virtio-gpu`, `virtio-input`, and
  `virtio-sound` from scratch.
- **TCP/IP stack** is [`smoltcp`](https://github.com/smoltcp-rs/smoltcp),
  wrapped by our socket layer. We did not implement TCP or
  IP from scratch.
- **CPU primitives** — page-table types, GDT / IDT helpers,
  CR-register access, MSR access — come from the
  [`x86_64`](https://crates.io/crates/x86_64) crate. We use
  the typed wrappers the community has already audited,
  rather than reimplementing raw CPU intrinsics.
- **Heap allocators** —
  [`linked_list_allocator`](https://crates.io/crates/linked_list_allocator)
  for the early-boot bootstrap heap, then
  [`buddy_system_allocator`](https://crates.io/crates/buddy_system_allocator)
  for the main kernel heap.
- **ELF parsing** for the user-program loader is
  [`object`](https://crates.io/crates/object).
- **no_std primitives** — `bitflags`, `spin`, `volatile`,
  `bit_field`, `zerocopy`, `memchr`, and a handful of others.

This is consistent with our clean-room policy
(`docs/CLEAN-ROOM.md`): we read **public crate APIs** to use
them, but we never read other kernels' or libc projects'
source code. Crates **are** public interfaces; using them is
the entire point of an open-source ecosystem.

The trade-off is real: every crate we depend on is part of our
trust surface. `cargo deny check` enforces a license allow-list
and the supply-chain advisory database (part of the pre-release
quality sweep; see `SECURITY.md`); `Cargo.lock` pins every
version + checksum; and each direct dependency is reviewed
against the same clean-room standards as our own code.

## Subsystems

What lives where in the source tree:

| Crate / dir | Responsibility |
|---|---|
| `frame/` | Audited unsafe substrate (paging, MMU, interrupts, MMIO, per-CPU, SMP, syscall trampoline) |
| `frame_host/` | Host-test stubs of `frame/`'s surface so Kani / MIRI can run kernel code on the developer machine |
| `kernel/` | Services layer: syscall dispatch, scheduler, VFS (tmpfs / devfs / procfs / sysfs / ext4 / cgroupfs), networking (smoltcp under our socket layer), signals, futex, ptrace, cgroups, namespaces, ELF loader, console |
| `drivers/virtio/` | virtio-mmio + virtio-pci transports; virtio-blk, -net, -rng, -gpu, -input, -sound |
| `runtime/boot/` | Boot binary: PVH entry, multiboot2 entry, long-mode bring-up, panic handler, `kernel_main` |
| `verification/` | Kani proof harnesses (path normalization, futex wake counts, lock-hierarchy acyclicity, more) |
| `fuzz/` | cargo-fuzz harnesses + crash corpus |
| `tools/` | Build scripts: coverage extraction, unsafe-boundary check, ext4 image gen |

## How a syscall flows

A program issues `syscall` (the x86_64 instruction). The CPU
traps into ring 0 at the address `frame/` registered with the
LSTAR MSR at boot. From there:

1. `frame/`'s **syscall trampoline** saves user registers and
   sets up the kernel stack.
2. Control enters the services-layer dispatcher, which
   matches on the syscall number and routes to the right handler.
3. The handler runs in `#![forbid(unsafe_code)]` Rust, using
   `frame/`'s safe primitives whenever it needs to touch user
   memory (`copy_from_user` / `copy_to_user`), schedule, or
   interact with hardware.
4. The result returns through the trampoline; user registers
   are restored; `sysretq` drops back to ring 3.

The whole chain is one address space — no message passing, no
IPC marshalling. The privilege boundary is `frame/`'s public
API surface.

## Prior art and how we differ

| Project | Where Cyphera differs |
|---|---|
| **Linux** | Cyphera implements the same syscall ABI, not the same source: a ring-3 ELF that stays within the implemented surface runs unmodified (this release exercises that with the hello-world demo + the in-tree selftests). Linux kernel modules do not load. |
| **Asterinas** (USENIX ATC '25, APSys '24) | An independent Rust kernel in the same broad research space (type-system-enforced privilege separation in a single address space). Cyphera Kernel is independently designed and implemented; we cite the published research as related work. We have not read Asterinas / OSTD source code while writing Cyphera Kernel. |
| **Maestro** | Maestro is a single-developer Rust kernel at ~48k lines, ~31% syscall coverage. Same proof point for "this scope is achievable." We aim higher on syscall coverage and on confidential-computing fit. |
| **Redox** | Redox has different goals: a microkernel with its own POSIX-flavored API. Cyphera Kernel is monolithic-style (single address space) and targets Linux ABI compatibility directly. |
| **Theseus** | Theseus is an experimental single-address-space OS where applications are loadable Rust crates. Different research goal. Cyphera deliberately preserves the Linux process / address-space model so existing software runs. |

## Non-goals (still)

- **Bare-metal hardware support for arbitrary devices.** No
  native PCI device zoo, no Wi-Fi drivers, no USB stack, no
  ACPI device tree, no GPU drivers (beyond virtio-gpu).
- **Linux kernel module ABI compatibility.** `*.ko` files do
  not load. Compatibility is at the syscall layer only.
- **32-bit support.** x86_64 is the active target;
  AArch64 is planned. 32-bit x86 is out of scope.
- **Pre-2020 Linux syscall surface that has modern replacements.**
  See `docs/SYSCALLS.md` for which legacy syscalls return
  `-ENOSYS` (often the same answer Linux itself gives).
- **Desktop / GUI applications as a primary use case.** The
  framebuffer path exists; it's not the optimization target.

## See also

- `docs/SYSCALLS.md` — Linux syscall implementation status (CSV-backed)
- `docs/VERIFICATION.md` — how to verify the source, the binary, and the build provenance
- `docs/REPRODUCIBLE-BUILDS.md` — what makes the build deterministic
- `docs/TESTING.md` — testing approach
- `docs/CLEAN-ROOM.md` — source-provenance policy
