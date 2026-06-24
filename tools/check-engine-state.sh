#!/usr/bin/env bash
# Engine-state ownership gate: the scheduler placement parameters are mutated
# only by the engine (kernel/src/core/*) and the module that
# defines them (kernel/src/process_model/*). Every other subsystem changes them through an
# engine door (set_sched_class / set_deadline_class / set_cpu_affinity /
# set_nice / pi_boost / pi_refresh). This fails the build if a placement field
# is written from outside the engine, so the doors stay enforced, not advisory.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -d kernel/src ] || { printf 'ERROR: kernel/src not found (wrong working directory?)\n' >&2; exit 2; }

# Scheduler-owned placement fields with no cross-subsystem name clash.
# (Process.weight is omitted on purpose: it is engine-derived from nice, and a
# cgroup controller has an identically named, legitimately-written weight.)
FIELDS='sched_class|nice|vruntime|home_cpu|cpu_affinity|dl_runtime_remaining|dl_absolute_deadline|dl_next_replenish|dl_throttled|pi_orig_class'

hits=$(grep -rnE "\.(${FIELDS})[[:space:]]*=[^=]" kernel/src --include='*.rs' \
    | grep -vE '^kernel/src/core/|^kernel/src/process_model/' \
    || true)

if [ -n "$hits" ]; then
    printf '\nengine-state leak — a scheduler placement field is written outside the engine:\n%s\n' "$hits"
    printf '\nRoute it through an engine door (sched::params::{set_class,set_deadline,set_affinity,set_nice}, pi_boost / pi_refresh, or admit_task for a new task).\n'
    exit 1
fi
state_hits=$(grep -rnE '\.(state|sched_owner)\.0[[:space:]]*=[^=]' kernel/src --include='*.rs' \
    | grep -vE '^kernel/src/core/mod.rs:' \
    || true)

if [ -n "$state_hits" ]; then
    printf '\nengine-state leak — ProcessState/SchedOwner written outside its core door:\n%s\n' "$state_hits"
    printf '\nRoute it through set_state(...) or set_sched_owner(...) in kernel/src/core/mod.rs.\n'
    exit 1
fi
printf 'OK: scheduler placement state mutated only by the engine; ProcessState/SchedOwner only via their doors.\n'
