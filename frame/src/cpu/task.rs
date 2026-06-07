use alloc::alloc::{Layout, alloc, dealloc};
use core::arch::naked_asm;
use core::ptr::NonNull;

const KERNEL_STACK_SIZE: usize = 64 * 1024;

#[repr(C, align(16))]
pub struct XSaveArea {
    bytes: [u8; 512],
}

impl XSaveArea {
    const fn fresh() -> Self {
        let mut bytes = [0u8; 512];
        bytes[0] = 0x7F;
        bytes[1] = 0x03;
        bytes[24] = 0x80;
        bytes[25] = 0x1F;
        bytes[26] = 0x00;
        bytes[27] = 0x00;
        bytes[28] = 0xBF;
        bytes[29] = 0xFF;
        Self { bytes }
    }
}

#[repr(C)]
pub struct Context {
    rsp: u64,
}

impl Context {
    pub const fn bootstrap() -> Self {
        Self { rsp: 0 }
    }
}

#[repr(C)]
pub struct Task {
    context: Context,
    xsave: XSaveArea,
    stack: NonNull<u8>,
    stack_size: usize,
}

// SAFETY: a `Task` owns its `NonNull<u8>` kstack exclusively (alloc'd
// in `spawn`, freed in `Drop`) and is never aliased — ownership moves
// wholesale to whichever CPU runs it, so transferring it across a
// thread boundary creates no shared `*mut u8` access.
unsafe impl Send for Task {}

impl Task {
    pub fn spawn(entry: extern "C" fn() -> !) -> Self {
        let layout = Layout::from_size_align(KERNEL_STACK_SIZE, 16).unwrap();
        // SAFETY: `layout` has non-zero size (KERNEL_STACK_SIZE = 64 KiB)
        // and valid align (16), which is `alloc`'s safety requirement.
        // The returned pointer may be null on OOM; it is null-checked on
        // the next line.
        let stack = unsafe { alloc(layout) };
        let stack = NonNull::new(stack).expect("Task::spawn: stack alloc failed");

        // SAFETY: `stack` is the just-allocated base of a
        // KERNEL_STACK_SIZE-byte block, so `.add(KERNEL_STACK_SIZE)`
        // computes the one-past-the-end address within the same alloc;
        // it's not dereferenced here, only used as the descending write
        // cursor's start.
        let stack_top = unsafe { stack.as_ptr().add(KERNEL_STACK_SIZE) };
        let mut sp = stack_top as *mut u64;
        // SAFETY: `sp` starts at the one-past-the-end of the
        // KERNEL_STACK_SIZE block and is decremented by one u64 before
        // each write, so all 7 stores land in `[stack .. stack_top)` —
        // well inside the alloc (7*8 = 56 bytes ≤ 64 KiB). The block is
        // 16-byte aligned, so every u64 slot is naturally aligned and
        // exclusively owned by this not-yet-published `Task`.
        unsafe {
            sp = sp.sub(1);
            sp.write(entry as *const () as u64);
            sp = sp.sub(1);
            sp.write(0);
            sp = sp.sub(1);
            sp.write(0);
            sp = sp.sub(1);
            sp.write(0);
            sp = sp.sub(1);
            sp.write(0);
            sp = sp.sub(1);
            sp.write(0);
            sp = sp.sub(1);
            sp.write(0);
        }

        Task {
            context: Context { rsp: sp as u64 },
            xsave: XSaveArea::fresh(),
            stack,
            stack_size: KERNEL_STACK_SIZE,
        }
    }

    pub fn context_ptr(&mut self) -> *mut Context {
        &mut self.context
    }

    pub fn xsave_ptr(&mut self) -> *mut u8 {
        self.xsave.bytes.as_mut_ptr()
    }

    pub fn kstack_top(&self) -> u64 {
        // SAFETY: `stack` is a NonNull<u8> pointing at a buffer of
        // exactly `stack_size` bytes (allocated in `Task::spawn`),
        // so adding `stack_size` lands at one-past-the-end — i.e.
        // the top of the kstack. We don't dereference the pointer.
        unsafe { self.stack.as_ptr().add(self.stack_size) as u64 }
    }

    pub fn kstack_bottom(&self) -> u64 {
        self.stack.as_ptr() as u64
    }

    pub fn kstack_bounds(&self) -> (u64, u64) {
        let lo = self.stack.as_ptr() as u64;
        // SAFETY: `stack` points at a buffer of exactly `stack_size`
        // bytes (set together in `spawn`), so `.add(stack_size)` is the
        // one-past-the-end address of that same alloc; cast to integer
        // without dereferencing, giving the exclusive upper bound `hi`.
        let hi = unsafe { self.stack.as_ptr().add(self.stack_size) as u64 };
        (lo, hi)
    }
}

#[inline(always)]
pub fn current_rsp() -> u64 {
    let rsp: u64;
    // SAFETY: a single `mov reg, rsp` only reads the rsp register into
    // an output GPR — it touches no memory (`nomem`), pushes nothing
    // (`nostack`), and clobbers no flags (`preserves_flags`), so it has
    // no effect on any Rust-visible state.
    unsafe {
        core::arch::asm!(
            "mov {}, rsp",
            out(reg) rsp,
            options(nomem, nostack, preserves_flags),
        );
    }
    rsp
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn peek_saved_rsp_and_rip(ctx: *mut Context) -> (u64, u64) {
    if ctx.is_null() {
        return (0, 0);
    }
    // SAFETY: this is a safe shim for `forbid(unsafe_code)` callers,
    // so it cannot enforce pointer validity itself — the caller MUST
    // pass a `ctx` obtained from `Task::context_ptr()` (a valid
    // `&mut self.context` for a live `Task`; see the fn doc). Locally
    // we only check `ctx` non-null (above); given a valid pointer,
    // reading `(*ctx).rsp` is in-bounds. The VALUE of `.rsp` is
    // whatever was last written — the initial frame from `Task::spawn`,
    // a frame saved by `switch_to`'s `mov [rdi], rsp`, OR a corrupt
    // value: this is the BADCTX detector, run specifically to catch the
    // last case, so no assumption is made about where `.rsp` points
    // (the `[rsp+48]` read below is best-effort).
    let rsp = unsafe { (*ctx).rsp };
    if rsp == 0 {
        return (0, 0);
    }
    let ret_slot = rsp as *const u64;
    // SAFETY: best-effort diagnostic read on the path to a BADCTX
    // panic. The only preconditions discharged in scope are `ctx`
    // non-null and `rsp != 0` (both checked above). WHEN the context
    // is intact, `rsp` points at a `switch_to`-saved frame and the
    // return rip sits at `rsp + 6*8` (6 callee-saved qwords are
    // popped before `ret`), so `ret_slot.add(6)` is an 8-byte-aligned
    // slot inside the same kstack alloc. But this routine reads `rsp`
    // exactly to detect a CORRUPT context, so an aliased / garbage
    // `rsp` can put `ret_slot.add(6)` outside any mapped page and the
    // read can itself fault — an accepted risk, since the caller is
    // already aborting. read_volatile forces the load and only reads
    // the slot.
    let rip = unsafe { core::ptr::read_volatile(ret_slot.add(6)) };
    (rsp, rip)
}

#[repr(C, align(16))]
struct BootstrapXSave(XSaveArea);

const BOOTSTRAP_XSAVE_INIT: BootstrapXSave = BootstrapXSave(XSaveArea::fresh());
static mut BOOTSTRAP_XSAVE: [BootstrapXSave; crate::cpu::per_cpu::MAX_CPUS] =
    [BOOTSTRAP_XSAVE_INIT; crate::cpu::per_cpu::MAX_CPUS];

pub fn bootstrap_xsave_ptr(cpu_id: u32) -> *mut u8 {
    let idx = cpu_id as usize;
    // SAFETY: `idx` indexes the `[_; MAX_CPUS]` static through a
    // slice index, so an out-of-range `idx` panics (bounds-checked)
    // rather than being UB — the returned pointer can only name a
    // real array element. Callers pass a `current_cpu_id` that is
    // bounded in practice, but soundness here does not depend on
    // that. We return a raw pointer; aliasing is the caller's
    // concern (the scheduler hands this to switch_to which fxsaves
    // through it, and there's no concurrent access from the same
    // CPU).
    unsafe {
        let table = &raw mut BOOTSTRAP_XSAVE;
        (*table)[idx].0.bytes.as_mut_ptr()
    }
}

pub fn switch_tasks(prev: &mut Task, next: &mut Task) {
    let prev_ctx = prev.context_ptr();
    let prev_xsave = prev.xsave_ptr();
    let next_ctx = next.context_ptr();
    let next_xsave = next.xsave_ptr();
    // SAFETY: `prev` and `next` are disjoint `&mut Task` (borrow checker
    // proves they're distinct objects), so the four pointers — each a
    // field of one of those live tasks — are valid, non-overlapping,
    // and 16-aligned (the xsave areas are `#[repr(C, align(16))]`).
    // Callers of `switch_tasks` invoke it with IRQs disabled, and
    // CR4.OSFXSR was set at boot, satisfying `switch_to`'s contract.
    unsafe { switch_to(prev_ctx, next_ctx, prev_xsave, next_xsave) }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn switch_from_context(prev: &mut Context, next: &mut Task, prev_xsave: *mut u8) {
    let next_ctx = next.context_ptr();
    let next_xsave = next.xsave_ptr();
    // SAFETY: `prev` is a live `&mut Context` and `next` a live
    // `&mut Task`, so the context pointers are valid and (being a bare
    // bootstrap Context vs. a Task field) non-overlapping. The caller
    // MUST pass a `prev_xsave` obtained from `bootstrap_xsave_ptr`
    // (per-CPU FXSAVE area: 16-aligned, ≥512 bytes, distinct from
    // `next`'s xsave) and invoke with IRQs off and CR4.OSFXSR set — the
    // forbid(unsafe_code) scheduler is that caller (see the shim note
    // above).
    unsafe { switch_to(prev as *mut Context, next_ctx, prev_xsave, next_xsave) }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn switch_to_ctx(
    prev: *mut Context,
    next: *mut Context,
    prev_xsave: *mut u8,
    next_xsave: *mut u8,
) {
    // SAFETY: forwards `switch_to`'s contract to the scheduler caller,
    // which guarantees all four pointers are valid, non-overlapping,
    // and (for the xsave areas) 16-aligned ≥512 bytes by keeping the
    // backing `Process` / `CpuQueue` storage alive across the switch,
    // and only calls this with IRQs disabled (CR4.OSFXSR set at boot).
    unsafe { switch_to(prev, next, prev_xsave, next_xsave) }
}

impl Drop for Task {
    fn drop(&mut self) {
        let layout = Layout::from_size_align(self.stack_size, 16).unwrap();
        // SAFETY: `stack` was returned by `alloc` in `spawn` under a
        // layout with this exact `stack_size` and align 16, and `Task`
        // owns it uniquely; `drop` runs once, so we free the same block
        // with the matching layout exactly once.
        unsafe { dealloc(self.stack.as_ptr(), layout) };
    }
}

/// # Safety
///
/// Must be called with IRQs disabled. The Context and XSAVE pointers
/// must be valid and non-overlapping. FXSAVE64 requires `CR4.OSFXSR=1`.
#[unsafe(naked)]
pub unsafe extern "C" fn switch_to(
    prev: *mut Context,
    next: *mut Context,
    prev_xsave: *mut u8,
    next_xsave: *mut u8,
) {
    naked_asm!(
        "fxsave64 [rdx]",
        "push rbp",
        "push rbx",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov [rdi], rsp",
        "mov rsp, [rsi]",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbx",
        "pop rbp",
        "fxrstor64 [rcx]",
        "ret",
    )
}
