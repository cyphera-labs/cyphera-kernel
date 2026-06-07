# demo/

A minimal, self-contained demo: boot Cyphera Kernel under QEMU and watch
it load and run a real userland ELF in ring 3.

```sh
./demo/run.sh
# or, from the dev container (no host Rust/QEMU needed):
./dev demo
```

It builds the kernel and a tiny hello-world program (`selftests/hello`),
packs that program as `/sbin/init` in a one-file initrd, and boots the
kernel with it. The kernel brings up memory, interrupts, virtio, and the
VFS, lifts the initrd, then `execve`s `/sbin/init` into ring 3 — which
prints:

```
hello from a real ELF in ring 3
```

and exits, at which point the kernel reports that all processes have
exited.

It is deliberately tiny — just enough to show the boot → ELF-load →
ring-3 → syscall → clean-exit path end to end, with nothing else in the
repo involved. A richer interactive demo (an interactive shell) is planned
for a later release.

By default the demo auto-exits after a few seconds. Set `DEMO_TIMEOUT=0`
to boot and stay (quit QEMU with `Ctrl-A` then `x`). Build artifacts land
in `demo/.build/` (gitignored).
