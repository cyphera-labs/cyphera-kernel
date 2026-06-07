# One-shot kernel inspection script. Use with:
#
#   tools/gdb-attach.sh <initrd> --script tools/gdb-dump-state.gdb
#
# The kernel boots, runs for ~15 seconds (enough to reach any
# steady-state stall), then we pause it, print the state, and let it
# resume so the test can continue / time out cleanly.

set logging redirect off
set logging enabled on
set logging file /tmp/cyphera-gdb-dump.txt

# Let it run far enough to reach any reproducible stall point.
continue &
shell sleep 15

interrupt

echo \n=== CPU state ===\n
info threads
info registers

echo \n=== Backtrace (current CPU) ===\n
backtrace 30

echo \n=== Other CPUs ===\n
thread apply all backtrace 20

echo \n=== dump_all_processes via symbol lookup ===\n
# Symbol is Rust-mangled. info functions finds it.
info functions dump_all_processes

# Resume so the kernel keeps running (and our test framework can
# time out cleanly rather than hanging gdb forever).
continue &
detach
quit
