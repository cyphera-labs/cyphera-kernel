//! Thread stress test — exercises the kernel scheduler, futex subsystem,
//! and thread lifecycle under concurrent load.
//!
//! Three phases:
//!
//!  1. **Mutex contention**: 16 threads each perform 64 futex-mutex-protected
//!     counter increments (1 024 total). Verifies futex WAIT/WAKE under heavy
//!     contention and that the scheduler distributes CPU fairly enough that all
//!     threads make forward progress.
//!
//!  2. **Lifecycle churn**: 10 waves of 8 threads. Each thread increments an
//!     atomic counter and exits immediately. The main thread joins every thread
//!     via the CLEARTID futex before spawning the next wave. Exercises rapid
//!     spawn → run → exit → join under the kernel's thread-group lifecycle code.
//!
//!  3. **Barrier + parallel accumulate**: 16 threads synchronize at a reusable
//!     barrier (built on FUTEX_WAIT / FUTEX_WAKE), then each accumulates a
//!     disjoint slice of a shared read-only array. Exercises barrier semantics,
//!     post-barrier memory visibility, and concurrent read access.

#![no_std]
#![no_main]
#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

// ── Panic handler ─────────────────────────────────────────────────────────────

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    log("PANIC\n");
    sys_exit(1)
}

// ── ABI constants ─────────────────────────────────────────────────────────────

const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANON: u64 = 0x20;

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;

// FUTEX_PRIVATE_FLAG keeps futex lookups in the process's own address space,
// which is faster and is what glibc pthreads uses for process-local mutexes.
const FUTEX_WAIT: u64 = 0 | 0x80;
const FUTEX_WAKE: u64 = 1 | 0x80;

const PAGE: usize = 4096;
const THREAD_STACK_PAGES: usize = 32; // 128 KiB — comfortable margin for debug builds

// ── Thread pool ───────────────────────────────────────────────────────────────

const MAX_THREADS: usize = 32;

// The kernel writes each thread's TID here on spawn (CLONE_CHILD_SETTID) and
// zeroes it + wakes the futex when the thread exits (CLONE_CHILD_CLEARTID).
// Used by join() to block until a thread has fully exited.
const ZINIT: AtomicI32 = AtomicI32::new(0);
static TIDS: [AtomicI32; MAX_THREADS] = [ZINIT; MAX_THREADS];

// Trampoline entered by the child immediately after clone returns 0.
// Expects the child stack to contain [arg (low), func_ptr (high)] so that:
//   pop rdi  →  arg
//   pop rax  →  func_ptr
//   jmp rax  →  func(arg) — diverges (→ !)
core::arch::global_asm!(
    ".section .text",
    ".global thread_trampoline",
    "thread_trampoline:",
    "popq %rdi",
    "popq %rax",
    "jmpq *%rax",
    options(att_syntax),
);
extern "C" {
    fn thread_trampoline() -> !;
}

/// Allocate a fresh anonymous stack of `THREAD_STACK_PAGES` pages.
fn alloc_stack() -> *mut u8 {
    let r = sys_mmap(
        0,
        (THREAD_STACK_PAGES * PAGE) as u64,
        PROT_READ | PROT_WRITE,
        MAP_ANON | MAP_PRIVATE,
        u64::MAX, // fd = -1
        0,
    );
    if r < 0 {
        log("alloc_stack: mmap failed\n");
        sys_exit(1);
    }
    r as *mut u8
}

/// Spawn a new thread into slot `slot` of TIDS.
///
/// The thread starts executing `func(arg)`. `stack` must point to a region of
/// at least `THREAD_STACK_PAGES * PAGE` bytes; its *top* (high address) is used
/// as the initial RSP after the two words written by this function.
///
/// Safety: `func` must not return (it should call `sys_exit`); `stack` must
/// remain valid for the thread's lifetime; `slot` must be < MAX_THREADS.
unsafe fn spawn(func: unsafe extern "C" fn(u64) -> !, arg: u64, slot: usize, stack: *mut u8) {
    // Write [arg, func_ptr] just below the stack top so the trampoline can
    // pop them into rdi/rax.  Stack grows downward, so the earlier pop (rdi)
    // reads the lower address.
    let stack_top = stack.add(THREAD_STACK_PAGES * PAGE);
    let sp = (stack_top as *mut u64).sub(2);
    sp.write(arg);                // [sp+0] → rdi (arg)
    sp.add(1).write(func as u64); // [sp+8] → rax (func_ptr)

    let flags: u64 = CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_THREAD
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_SETTID
        | CLONE_CHILD_CLEARTID;
    let tid_ptr = TIDS[slot].as_ptr() as u64;

    let r: i64;
    asm!(
        "syscall",
        "test eax, eax",
        "jnz 2f",
        // Child: stack already points at [arg, func_ptr]; jump to trampoline.
        "jmp {tramp}",
        "2:",
        tramp = sym thread_trampoline,
        in("rax")  56u64,    // SYS_clone
        in("rdi")  flags,
        in("rsi")  sp as u64,
        in("rdx")  tid_ptr,  // ptid (PARENT_SETTID)
        in("r10")  tid_ptr,  // ctid (CHILD_SETTID / CHILD_CLEARTID)
        in("r8")   0u64,     // tls
        lateout("rax") r,
        out("rcx") _,
        out("r11") _,
    );
    if r < 0 {
        log("spawn: clone syscall failed\n");
        sys_exit(1);
    }
}

/// Block until the thread in `slot` has exited (CLEARTID clears TIDS[slot]).
fn join(slot: usize) {
    let tid = &TIDS[slot];
    loop {
        let v = tid.load(Ordering::Acquire);
        if v == 0 {
            break;
        }
        sys_futex(tid.as_ptr() as u64, FUTEX_WAIT, v as u32, 0, 0, 0);
    }
}

/// Join all threads [0, n).
fn join_all(n: usize) {
    for i in 0..n {
        join(i);
    }
}

// ── Futex mutex ───────────────────────────────────────────────────────────────

fn mutex_lock(m: &AtomicU32) {
    loop {
        if m.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        sys_futex(m.as_ptr() as u64, FUTEX_WAIT, 1, 0, 0, 0);
    }
}

fn mutex_unlock(m: &AtomicU32) {
    m.store(0, Ordering::Release);
    sys_futex(m.as_ptr() as u64, FUTEX_WAKE, 1, 0, 0, 0);
}

// ── N-thread barrier ──────────────────────────────────────────────────────────
//
// Two-phase: threads count in via BAR_IN; the last thread to arrive stores 1
// into BAR_OPEN and wakes all waiters.  The barrier is single-use per test run
// (both statics are reset before each phase that uses it).

static BAR_IN: AtomicU32 = AtomicU32::new(0);
static BAR_OPEN: AtomicU32 = AtomicU32::new(0);

fn barrier_wait(n: u32) {
    let arrived = BAR_IN.fetch_add(1, Ordering::AcqRel) + 1;
    if arrived == n {
        BAR_OPEN.store(1, Ordering::Release);
        sys_futex(BAR_OPEN.as_ptr() as u64, FUTEX_WAKE, u32::MAX, 0, 0, 0);
    } else {
        loop {
            if BAR_OPEN.load(Ordering::Acquire) != 0 {
                break;
            }
            sys_futex(BAR_OPEN.as_ptr() as u64, FUTEX_WAIT, 0, 0, 0, 0);
        }
    }
}

// ── Phase 1: contended counter ────────────────────────────────────────────────

const P1_THREADS: usize = 16;
const P1_ITERS: u64 = 64;

static P1_MUTEX: AtomicU32 = AtomicU32::new(0);
static P1_COUNTER: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn p1_worker(_arg: u64) -> ! {
    for _ in 0..P1_ITERS {
        mutex_lock(&P1_MUTEX);
        P1_COUNTER.fetch_add(1, Ordering::Relaxed);
        mutex_unlock(&P1_MUTEX);
        sys_sched_yield();
    }
    sys_exit(0)
}

fn phase1() {
    P1_COUNTER.store(0, Ordering::Relaxed);

    for slot in 0..P1_THREADS {
        let stack = alloc_stack();
        unsafe { spawn(p1_worker, 0, slot, stack) };
    }
    join_all(P1_THREADS);

    let got = P1_COUNTER.load(Ordering::Acquire);
    let want = P1_THREADS as u64 * P1_ITERS;
    if got != want {
        log("phase1: counter mismatch — ");
        log_u64(got);
        log(" != ");
        log_u64(want);
        log("\n");
        sys_exit(1);
    }
}

// ── Phase 2: lifecycle churn ──────────────────────────────────────────────────

const P2_WAVES: usize = 10;
const P2_WAVE_SIZE: usize = 8;

static P2_COUNTER: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn p2_worker(_arg: u64) -> ! {
    P2_COUNTER.fetch_add(1, Ordering::Relaxed);
    sys_sched_yield();
    sys_exit(0)
}

fn phase2() {
    P2_COUNTER.store(0, Ordering::Relaxed);

    for _wave in 0..P2_WAVES {
        // Reset the TID slots before each wave so join() sees the new values.
        for slot in 0..P2_WAVE_SIZE {
            TIDS[slot].store(0, Ordering::Relaxed);
        }
        for slot in 0..P2_WAVE_SIZE {
            let stack = alloc_stack();
            unsafe { spawn(p2_worker, 0, slot, stack) };
        }
        join_all(P2_WAVE_SIZE);
    }

    let got = P2_COUNTER.load(Ordering::Acquire);
    let want = (P2_WAVES * P2_WAVE_SIZE) as u64;
    if got != want {
        log("phase2: counter mismatch — ");
        log_u64(got);
        log(" != ");
        log_u64(want);
        log("\n");
        sys_exit(1);
    }
}

// ── Phase 3: barrier + parallel accumulate ────────────────────────────────────
//
// Each thread is assigned a disjoint slice of WORK_ARRAY. All threads
// synchronize at the barrier before starting, then sum their slice into the
// shared P3_RESULT.  The expected total is trivially computable from the array.

const P3_THREADS: usize = 16;
const WORK_LEN: usize = P3_THREADS * 64; // 64 elements per thread

// Filled at runtime in phase3() before threads are spawned.
static mut WORK_ARRAY: [u64; WORK_LEN] = [0u64; WORK_LEN];
static P3_RESULT: AtomicU64 = AtomicU64::new(0);

// arg encodes the slice start index (upper 32 bits) and length (lower 32 bits).
unsafe extern "C" fn p3_worker(arg: u64) -> ! {
    let start = (arg >> 32) as usize;
    let len = (arg & 0xFFFF_FFFF) as usize;

    // All threads meet here before touching WORK_ARRAY — ensures the main
    // thread's stores to WORK_ARRAY are visible to every worker (Release on
    // BAR_OPEN in barrier_wait synchronizes with the Acquire loads here).
    barrier_wait(P3_THREADS as u32);

    let mut sum: u64 = 0;
    for i in start..start + len {
        sum = sum.wrapping_add(WORK_ARRAY[i]);
    }
    P3_RESULT.fetch_add(sum, Ordering::Relaxed);

    sys_exit(0)
}

fn phase3() {
    // Populate the work array with a deterministic pattern and compute the
    // expected total before spawning threads.
    let mut expected: u64 = 0;
    for (i, slot) in unsafe { WORK_ARRAY.iter_mut() }.enumerate() {
        let v = (i as u64 * 6364136223846793005u64).wrapping_add(1442695040888963407);
        *slot = v;
        expected = expected.wrapping_add(v);
    }

    P3_RESULT.store(0, Ordering::Relaxed);
    BAR_IN.store(0, Ordering::Relaxed);
    BAR_OPEN.store(0, Ordering::Relaxed);

    let chunk = WORK_LEN / P3_THREADS;
    for slot in 0..P3_THREADS {
        TIDS[slot].store(0, Ordering::Relaxed);
        let start = slot * chunk;
        let arg = ((start as u64) << 32) | (chunk as u64);
        let stack = alloc_stack();
        unsafe { spawn(p3_worker, arg, slot, stack) };
    }
    join_all(P3_THREADS);

    let got = P3_RESULT.load(Ordering::Acquire);
    if got != expected {
        log("phase3: accumulate mismatch\n");
        sys_exit(1);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn _start() -> ! {
    log("[stress_threads] phase 1: contended counter (16 threads x 64 iters)\n");
    phase1();

    log("[stress_threads] phase 2: lifecycle churn (10 waves x 8 threads)\n");
    phase2();

    log("[stress_threads] phase 3: barrier + parallel accumulate (16 threads)\n");
    phase3();

    log("[stress_threads] PASS\n");
    sys_exit(0)
}

// ── Logging helpers ───────────────────────────────────────────────────────────

fn log(s: &str) {
    sys_write(1, s.as_ptr(), s.len());
}

fn log_u64(mut v: u64) {
    let mut buf = [b'0'; 20];
    let mut i = buf.len();
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    sys_write(1, buf[i..].as_ptr(), buf.len() - i);
}

// ── Raw syscall wrappers ──────────────────────────────────────────────────────

#[inline(never)]
fn sys_write(fd: u64, buf: *const u8, len: usize) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 1u64,
            in("rdi") fd,
            in("rsi") buf,
            in("rdx") len,
            lateout("rax") r,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 9u64,
            in("rdi") addr,
            in("rsi") len,
            in("rdx") prot,
            in("r10") flags,
            in("r8")  fd,
            in("r9")  off,
            lateout("rax") r,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_futex(uaddr: u64, op: u64, val: u32, timeout: u64, uaddr2: u64, val3: u64) -> i64 {
    let r: i64;
    unsafe {
        asm!(
            "syscall",
            in("rax") 202u64,
            in("rdi") uaddr,
            in("rsi") op,
            in("rdx") val as u64,
            in("r10") timeout,
            in("r8")  uaddr2,
            in("r9")  val3,
            lateout("rax") r,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    r
}

#[inline(never)]
fn sys_sched_yield() {
    unsafe {
        asm!(
            "syscall",
            in("rax") 24u64,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
}

fn sys_exit(code: i32) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") 60u64,
            in("rdi") code as u64,
            options(noreturn, nostack),
        );
    }
}
