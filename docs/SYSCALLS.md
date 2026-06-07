# Syscalls

Cyphera Kernel tracks every Linux x86_64 syscall — implemented,
not yet implemented, or deliberately stubbed — against
[`arch/x86/entry/syscalls/syscall_64.tbl`](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl)
(the `common` + `64` ABI). The wired dispatcher lives in the
kernel's services layer.

That **385** is the count of `common` + `64` entries — the syscalls a
64-bit x86_64 program actually issues. The separate `x32` compat ABI
(numbers 512+) is out of scope and excluded, and the numbers are
non-contiguous (ours top out at 471), so the highest number is larger
than the count.

Counts: **270 of 385 implemented**. A further 15 entries (14 dead +
1 deprecated) correctly return `-ENOSYS` / `-EPERM` like mainline,
**10 out-of-scope**, **90 missing** (385 total per the documented
syscall ABI table).

Each "implemented" row is either a real implementation or an
honest "this is what Linux returns under the relevant build
configuration" answer — e.g. `add_key` returning `-EOPNOTSUPP`
matches Linux with `CONFIG_KEYS=n`, `pkey_alloc` returning
`-EOPNOTSUPP` matches a CPU without memory-protection keys, and
`uselib` / `_sysctl` / similar return `-ENOSYS` because that's
what Linux itself returns for those deprecated entry points.

`ptrace(2)` is wired up for the in-tree tracer coverage (external debugger / tool compatibility is not claimed in this release). The operations currently handled:

  - `PTRACE_TRACEME` — a program opts into being debugged by its parent
  - `PTRACE_ATTACH` / `PTRACE_DETACH` — debugger grabs / releases an already-running process
  - `PTRACE_CONT` — resume the traced process
  - `PTRACE_SYSCALL` — resume, but stop again at the next syscall (syscall-stop tracing)
  - `PTRACE_KILL` — terminate the traced process
  - `PTRACE_PEEKDATA` / `PTRACE_POKEDATA` — read / write memory of the traced process
  - `PTRACE_GETREGS` / `PTRACE_SETREGS` — read / write CPU registers of the traced process
  - `PTRACE_SINGLESTEP` — execute one instruction, then stop
  - `int3 → SIGTRAP` — the x86 breakpoint instruction becomes a signal the tracer catches (software breakpoints)
  - `PTRACE_O_TRACEFORK` auto-attach — when the traced process forks, the kernel automatically attaches the debugger to the child
  - signal-stop forwarding — signals destined for the traced process get routed through the debugger first; the debugger decides whether to deliver, suppress, or substitute

These operations are validated by `runtime/boot/tests/subsystem/ptrace.rs` (run `./dev test`): the TRACEME/ATTACH/CONT/SYSCALL stops, PEEK/POKE, GETREGS/SETREGS, SINGLESTEP, `int3`→SIGTRAP, fork auto-attach, and signal-stop forwarding. Operations beyond these aren't proven yet.

## Status table

Full per-syscall status lives in **`docs/SYSCALLS.csv`** — one
row per Linux x86_64 syscall (385 total), with columns:

| Column | Meaning |
|---|---|
| `linux_nr` | x86_64 syscall number (matches the documented ABI table linked above) |
| `name` | syscall name |
| `status` | one of `implemented` / `deprecated` / `dead` / `out-of-scope` / `missing` (see the Conventions legend below) |
| `notes` | free-form description of what's done, what's deferred, and links to relevant code |

Open `SYSCALLS.csv` in any spreadsheet tool, or grep / awk it
from the command line. Updating a syscall: edit its row in the
CSV and update the headline counts in this doc in the same
commit.

## Conventions

- **`linux_nr`** mirrors the Linux ABI table 1:1; nothing is
  omitted or renumbered.
- **`status`** is one of:
  - `implemented` — happy path works; exercised by an in-tree
    test, or (where the notes say so) manually verified.
  - `deprecated` — Linux still defines it but discourages it; we
    return `-ENOSYS` exactly as mainline does. Correct + final.
  - `dead` — Linux **removed** it (slot returns `-ENOSYS` in
    mainline); we do the same. Correct + final. `notes` gives the
    removal version.
  - `out-of-scope` — deliberately refused, never to be built.
    Two reasons, in `notes`: **`ring0 unsafe`** (would require
    unaudited ring-0 code or raw hardware access — module loading,
    kexec, iopl/ioperm) or **`32-bit not supported`** (Cyphera is
    an x86_64 64-bit-only ABI — the 32-bit TLS / LDT calls). Returns
    `-ENOSYS` or `-EPERM`, matching what stock Linux returns when
    the feature is absent / the capability is missing.
  - `missing` — a real gap we would build; dispatcher returns
    `-ENOSYS` today.

  `deprecated` + `dead` are handled/complete (the correct behavior
  *is* the `-ENOSYS`), and are counted separately — they are NOT part
  of the 270 `implemented` rows. Only `missing` is an actual to-do.
When you add or modify a syscall, update its row in the same
commit. New syscalls land at their canonical Linux number — we
do not gap or renumber.

## What's missing — a quick map

Rough grouping of the 90 currently-missing syscalls. Items
already implemented aren't listed here; see the CSV.

- **Async I/O and readiness primitives** — `io_uring_*`,
  `io_setup` / `io_destroy` / `io_getevents` / `io_submit` /
  `io_cancel`, `inotify_*`, `fanotify_*`, `select`, `pselect6`,
  `ppoll`, the legacy 1-arg `eventfd`, the legacy 3-arg
  `signalfd`, and `epoll_create` (the legacy 0-arg form;
  `epoll_create1` / `epoll_ctl` / `epoll_wait` / `eventfd2` /
  `timerfd_*` / `poll` are implemented).
- **POSIX message queues + SysV semaphores / msg queues** —
  `mq_open` / `mq_unlink` / `mq_timed{send,receive}` /
  `mq_notify` / `mq_getsetattr`; `semget` / `semop` / `semctl`
  / `semtimedop`; `msgget` / `msgsnd` / `msgrcv` / `msgctl`.
  AF_UNIX sockets and SysV shared memory cover the dominant
  IPC patterns; these are legacy / niche.
- **Modern mount API** — `open_tree`, `move_mount`, `fsopen`,
  `fsconfig`, `fsmount`, `fspick`, `mount_setattr`,
  `statmount`, `listmount`. Legacy `mount` / `umount` are
  implemented.
- **POSIX timers** — `timer_create` / `timer_settime` /
  `timer_gettime` / `timer_getoverrun` / `timer_delete`.
  `clock_gettime` / `clock_getres` / `nanosleep` / `timerfd_*`
  / `getitimer` / `setitimer` are implemented.
- **Filesystem long-tail** — `name_to_handle_at` /
  `open_by_handle_at`, `quotactl` / `quotactl_fd`,
  `file_getattr` / `file_setattr`, `userfaultfd`.
- **Memory management long-tail** — `mincore`,
  `mlock` / `munlock` / `mlockall` / `munlockall` / `mlock2`,
  the `pkey_*` family, the NUMA-policy family (`mbind` /
  `set_mempolicy` / `get_mempolicy` / `migrate_pages` /
  `move_pages`), `process_vm_*` / `process_madvise` /
  `process_mrelease`, `mseal`, `remap_file_pages`,
  `cachestat`, `map_shadow_stack`, `memfd_secret`.
- **Networking** — vector forms (`sendmsg` / `recvmsg` /
  `sendmmsg` / `recvmmsg`), `getpeername`, raw sockets, `bpf`.
  Core BSD socket calls (`socket` / `bind` / `listen` / `accept`
  / `connect` / `send` / `recv` / `shutdown` / `getsockname` /
  `getsockopt` / `setsockopt`) are implemented.
- **Privileged / namespaces / debug** — `add_key` /
  `request_key` / `keyctl`, `setns`, `bpf`, `perf_event_open`,
  the `landlock_*` family, `pidfd_getfd`, `kcmp`, `vhangup`,
  `modify_ldt`, and the legacy 32-bit `set_thread_area` /
  `get_thread_area` (the 64-bit equivalent
  `arch_prctl(ARCH_SET_FS)` is implemented).
- **Signals long-tail** — `rt_sigpending`, `rt_sigqueueinfo`,
  `rt_sigsuspend`, `rt_tgsigqueueinfo`. Core delivery
  (`rt_sigaction` / `rt_sigprocmask` / `rt_sigreturn` / `kill`
  / `tgkill` / `tkill` / `pause` / `sigaltstack` / `waitid` /
  `signalfd4` / `pidfd_send_signal`) is implemented.
- **futex2 family** — `futex_waitv` / `futex_wait` /
  `futex_wake` / `futex_requeue`. Classic `futex(2)` covers the
  dominant path.
- **Synchronization** — `membarrier`, `get_robust_list`.
  `set_robust_list` and the per-vmspace futex keying are
  implemented.

## Won't-implement

A set of entries are refused permanently, in three honest flavors
(see the `status` legend above): `dead` (Linux removed it),
`deprecated` (Linux discourages it), and `out-of-scope` (we refuse
it by design). All return a clean errno — `-ENOSYS` or `-EPERM`,
whichever stock Linux returns — never a fault:

- `init_module` / `delete_module` / `finit_module` /
  `create_module` / `get_kernel_syms` / `query_module` — loadable
  kernel modules are explicitly out of scope.
- `kexec_load` / `kexec_file_load` — no kexec-style boot
  hand-off in a VM-only kernel.
- `iopl` / `ioperm` — direct port I/O from user space (`ring0 unsafe`).
- `set_thread_area` / `get_thread_area` / `modify_ldt` —
  `out-of-scope: 32-bit not supported`. Cyphera is an x86_64
  64-bit-only ABI; 64-bit TLS goes through `arch_prctl(ARCH_SET_FS)`.
- (`swapon` / `swapoff` are NOT here — they're `missing`, i.e. a
  real feature we could build, not a refusal.)
- `acct`, `lookup_dcookie`, `nfsservctl`, `getpmsg` /
  `putpmsg`, `afs_syscall`, `tuxcall`, `security`, `_sysctl`,
  `vserver`, `uselib` — legacy or never-implemented in modern
  Linux.
- `lsm_get_self_attr` / `lsm_set_self_attr` /
  `lsm_list_modules` — LSM hooks are out of scope.

These are tracked in the CSV with `status = dead` / `deprecated` /
`out-of-scope` (NOT `missing` — they behave correctly), each with a
`notes` value giving the reason (removal version, or `ring0 unsafe`
/ `32-bit not supported`).
