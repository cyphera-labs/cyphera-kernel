# Clean-room policy

Cyphera Kernel is a clean-room reimplementation of the Linux syscall
ABI: every source file is written from public specifications and
interface documentation, never from another operating system's
implementation source. This document describes the project's
clean-room **engineering policy**. It is not legal advice; copyright,
patent, and freedom-to-operate questions are for counsel.

The approach follows a well-known pattern — reimplement an interface
from its specification rather than copy an implementation, as ReactOS
does for Windows, Wine for Win32, and GNU coreutils did against the
POSIX spec. The interface/implementation distinction is commonly
cited via Phoenix Technologies' 1984 IBM-BIOS reimplementation and
*Google v. Oracle* (2021).

The engineering goal is no GPL/BSD source contamination and a tree
that is demonstrably not a Linux fork with the names changed.

## Allowed sources

- **CPU and platform manuals**: Intel SDM, AMD APM, the ACPI and UEFI
  specifications — they describe the hardware we target.
- **Interface standards**: POSIX (IEEE 1003.1), the man pages (which
  document the interface, not the implementation), and the x86_64
  syscall table (`syscall_64.tbl` — number → name metadata only).
- **Network protocols**: RFCs.
- **Academic papers**: e.g. Lottery Scheduling (Waldspurger), CFS
  (Molnar), CLRS, the APSys '24 and Asterinas ATC '25 papers — the
  *paper*, not the source it describes.
- **Public crate APIs**: the documented public surface of our
  dependencies (`smoltcp`, `x86_64`, `object`, `bitflags`, `spin`, and
  the rest — see `Cargo.toml`). We use their public APIs; we do not read
  their internals as a template.
- **General OS-concept references**: textbooks/notes explaining *what*
  an OS does abstractly. A chapter titled "How Linux Implements X" is
  not in this category — that is implementation reading.

## Forbidden sources

- The **Linux kernel source** — any file in the Linux tree.
- The **Asterinas source** and the **OSTD crate source**.
- Any other OS implementation source (FreeBSD, Redox, Theseus, Hubris,
  OpenBSD, Plan 9, …).
- Line-by-line walkthroughs of a specific kernel's internals (deep
  "how Linux does X" series). High-level concept explainers are fine.

## Citing sources in docs and commits

Prefer the specification over a source path:

| Use this… | …not this |
|---|---|
| Intel SDM Vol 3 §4.10.4 ("TLB Invalidation") | `linux/arch/x86/mm/tlb.c` |
| Intel SDM Vol 2, SYSCALL/SYSRET | `linux/arch/x86/entry/entry_64.S` |
| `man 2 epoll_wait` | `linux/fs/eventpoll.c` |
| RFC 793 + `smoltcp` `tcp::Socket` public API | `linux/net/ipv4/…` |

Where a concept has no published spec (e.g. "kthread"), a doc may name
the concept with a source-path pointer **as orientation only** — never
as a basis for copying code.

## Working rule

When a problem is hard, the answer is to read the spec more carefully or
ask the maintainers — not "go look at how Linux does it." When in doubt,
escalate (open an issue / ask a maintainer) *before* reading anything
that could contaminate the provenance. Asking up front is always cheaper
than remediating after.

## AI-assisted development

Cyphera Kernel is developed with substantial assistance from AI coding
tools, disclosed here plainly because a clean-room claim depends on
answering "what informed the code" in full.

Clean-room defends against *derivation from a specific implementation* —
not "who held the keyboard." The same discipline applies whether the
author is a human or a human working with an AI assistant:

- **Prompting from specs.** Tools are prompted with POSIX/RFC/SDM
  content and abstract design problems — never "show me how Linux
  implements X" or "translate this Linux source to Rust."
- **Spec-traceable review.** Code is reviewed to trace back to a
  specification, not to another OS's source — AI-suggested code
  included.
- **Verbatim-overlap rejection.** A suggestion that looks like a
  near-verbatim of a forbidden source (same names, shape, comments) is
  rejected, regardless of who wrote it.
- **Training-corpus caveat.** AI corpora are opaque and may include
  forbidden sources; we mitigate by reviewing output against specs
  rather than trusting the tool's own boundaries.

AI-attribution markers are deliberately kept out of commits, comments,
and the source tree — that is a presentation convention, separate from
provenance. The provenance answer stays: written from specifications, by
humans plus AI tooling held to the rules above.

## Patent posture

Patent analysis is a separate surface from the copyright clean-room
hygiene described above. This file is not a legal opinion and makes no
patent-specific claims. Anyone evaluating Cyphera Kernel for commercial
procurement, federal funding, or major deployment should perform their
own freedom-to-operate review.

## If contamination is suspected

If a reviewer believes a PR may derive from a forbidden source:

1. Hold the PR — not merged, not closed.
2. Ask the author what sources the affected section was written from.
3. If confirmed, remove the code and rewrite it from allowed sources, by
   an author who has not read the contaminating material.
4. Record the remediation on the PR so the provenance trail is kept.
