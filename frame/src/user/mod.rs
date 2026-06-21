use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicPtr, Ordering};

use x86_64::VirtAddr;
use x86_64::registers::model_specific::{Efer, EferFlags, KernelGsBase, LStar, SFMask, Star};
use x86_64::registers::rflags::RFlags;

use crate::arch::x86_64::gdt;

global_asm!(
    include_str!("../arch/x86_64/syscall.s"),
    options(att_syntax)
);

global_asm!(
    ".global __copy_user_bytes",
    "__copy_user_bytes:",
    "    mov rcx, rdx",
    "10: rep movsb",
    "11: mov rax, rcx",
    "    ret",
    ".pushsection __ex_table, \"a\"",
    "    .balign 8",
    "    .quad 10b",
    "    .quad 11b",
    ".popsection",
);

extern "C" {
    fn __copy_user_bytes(dst: *mut u8, src: *const u8, len: usize) -> usize;
    static __start___ex_table: u8;
    static __stop___ex_table: u8;
}

pub fn fixup_exception(rip: u64) -> Option<u64> {
    let start = core::hint::black_box(core::ptr::addr_of!(__start___ex_table) as u64);
    let stop = core::hint::black_box(core::ptr::addr_of!(__stop___ex_table) as u64);
    let mut p = start;
    while p + 16 <= stop {
        // SAFETY: `[start, stop)` is the linker-bounded `__ex_table`,
        // a contiguous run of 8-byte-aligned (faulting-VA, fixup-VA)
        // u64 pairs we emit ourselves in the `global_asm!` above.
        let fault_va = unsafe { (p as *const u64).read() };
        // SAFETY: `p + 8` is still within `[start, stop)` — the loop
        // guard `p + 16 <= stop` guarantees both 8-byte u64s of this
        // (faulting-VA, fixup-VA) pair lie inside the linker-bounded,
        // 8-byte-aligned `__ex_table` we emit in the `global_asm!`.
        let fixup_va = unsafe { ((p + 8) as *const u64).read() };
        if fault_va == rip {
            return Some(fixup_va);
        }
        p += 16;
    }
    None
}

pub fn ex_table_fault_probe() -> usize {
    const UNMAPPED_USER_VA: u64 = 0x0000_7000_0000_0000;
    let mut dst = [0u8; 8];
    // SAFETY: the source is intentionally unmapped — the read faults
    // and the `__ex_table` fixup recovers it into a short-count
    // return, which is exactly the path under test.
    unsafe { __copy_user_bytes(dst.as_mut_ptr(), UNMAPPED_USER_VA as *const u8, dst.len()) }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TrapFrame {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
    pub rip_user: u64,
    pub rflags_user: u64,
    pub rsp_user: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub orig_rax: u64,
}

extern "C" {
    fn syscall_entry();
}

type Dispatcher = fn(&mut TrapFrame);

static DISPATCHER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

pub fn register_dispatcher(f: Dispatcher) {
    DISPATCHER.store(f as *mut (), Ordering::SeqCst);
}

pub type UserFaultHandler = fn(fault_addr: u64, vector: u8, error: u64) -> !;

pub type TraceTrapHook = fn(rip: &mut u64, rflags: &mut u64, vector: u8) -> bool;

static TRACE_TRAP_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

pub fn register_trace_trap_hook(f: TraceTrapHook) {
    TRACE_TRAP_HOOK.store(f as *mut (), Ordering::SeqCst);
}

pub(crate) fn trace_trap_hook() -> Option<TraceTrapHook> {
    let ptr = TRACE_TRAP_HOOK.load(Ordering::Relaxed);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: the null case is handled above, so `ptr` is the
        // non-null value `register_trace_trap_hook` stored — a
        // `TraceTrapHook` fn pointer cast to `*mut ()`. Transmuting it
        // back recovers the original fn pointer with the same layout.
        Some(unsafe { core::mem::transmute::<*mut (), TraceTrapHook>(ptr) })
    }
}

pub type UserPageFaultHook = fn(cr2: u64, error: u64) -> bool;

static USER_FAULT_HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static USER_PF_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

pub fn register_user_fault_handler(f: UserFaultHandler) {
    USER_FAULT_HANDLER.store(f as *mut (), Ordering::SeqCst);
}

pub fn register_user_pf_hook(f: UserPageFaultHook) {
    USER_PF_HOOK.store(f as *mut (), Ordering::SeqCst);
}

pub type IrqNotifyResume = fn();

static IRQ_NOTIFY_RESUME: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

pub fn register_irq_notify_resume(f: IrqNotifyResume) {
    IRQ_NOTIFY_RESUME.store(f as *mut (), Ordering::SeqCst);
}

pub(crate) fn irq_notify_resume() -> Option<IrqNotifyResume> {
    let ptr = IRQ_NOTIFY_RESUME.load(Ordering::SeqCst);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: only register_irq_notify_resume stores into this slot, and
        // it stores a valid `fn` pointer.
        Some(unsafe { core::mem::transmute::<*mut (), IrqNotifyResume>(ptr) })
    }
}

pub(crate) fn user_fault_handler() -> Option<UserFaultHandler> {
    let ptr = USER_FAULT_HANDLER.load(Ordering::SeqCst);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: only register_user_fault_handler stores into this
        // slot, and it stores a valid `fn` pointer.
        Some(unsafe { core::mem::transmute::<*mut (), UserFaultHandler>(ptr) })
    }
}

pub(crate) fn user_pf_hook() -> Option<UserPageFaultHook> {
    let ptr = USER_PF_HOOK.load(Ordering::SeqCst);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: the null case is handled above; only
        // `register_user_pf_hook` writes this slot, storing a
        // `UserPageFaultHook` fn pointer cast to `*mut ()`. The
        // transmute recovers that fn pointer (identical layout).
        Some(unsafe { core::mem::transmute::<*mut (), UserPageFaultHook>(ptr) })
    }
}

#[no_mangle]
extern "C" fn syscall_dispatch_entry(tf: *mut TrapFrame) {
    // SAFETY: `tf` points to the kernel-stack-resident TrapFrame the
    // trampoline just built; it's valid for the duration of this call.
    let tf = unsafe { &mut *tf };
    tf.orig_rax = tf.rax;
    let ptr = DISPATCHER.load(Ordering::SeqCst);
    if ptr.is_null() {
        tf.rax = (-38i64) as u64;
        return;
    }
    // SAFETY: `register_dispatcher` only ever stores valid `fn`
    // pointers, and the AtomicPtr swap is sequentially consistent.
    let dispatcher: Dispatcher = unsafe { core::mem::transmute(ptr) };
    dispatcher(tf);
}

pub fn init() {
    // SAFETY: setting EFER.SCE only enables the SYSCALL/SYSRET CPU
    // mechanism; it touches no Rust-visible memory. We immediately
    // program LSTAR/STAR/SFMASK below so the entry path is fully set
    // up before this MSR's effect (any later user `syscall`) matters,
    // and `init` runs once at boot after the GDT is loaded.
    unsafe {
        Efer::update(|f| f.insert(EferFlags::SYSTEM_CALL_EXTENSIONS));
    }

    let sel = gdt::selectors();
    Star::write(
        sel.user_code,
        sel.user_data,
        sel.kernel_code,
        sel.kernel_data,
    )
    .expect("Star::write rejected our segment selectors");

    LStar::write(VirtAddr::from_ptr(syscall_entry as *const ()));

    SFMask::write(
        RFlags::INTERRUPT_FLAG
            | RFlags::DIRECTION_FLAG
            | RFlags::TRAP_FLAG
            | RFlags::ALIGNMENT_CHECK,
    );

    KernelGsBase::write(VirtAddr::new(0));

    crate::println!(
        "user: SYSCALL/SYSRET initialized; LSTAR @ {:#x}",
        syscall_entry as *const () as usize
    );
}

pub fn install_task_kernel_rsp(kernel_rsp: u64) {
    crate::cpu::per_cpu::set_kernel_rsp(kernel_rsp);
}

#[derive(Debug, Copy, Clone)]
pub struct UserAccessFault;

#[derive(Copy, Clone)]
enum AccessKind {
    Read,
    Write,
}

fn access_ok(addr: u64, len: usize, kind: AccessKind) -> bool {
    if len == 0 {
        return true;
    }
    let end = match addr.checked_add(len as u64) {
        Some(e) => e,
        None => return false,
    };
    if end > 0x0000_8000_0000_0000 {
        return false;
    }

    let mut page = addr & !0xfff;
    let last_page = (end - 1) & !0xfff;

    loop {
        let mut vmspace = crate::mm::vm::VmSpace::current();
        let flags_now = vmspace.page_flags(crate::mm::VirtAddr::new(page));
        let need_write = matches!(kind, AccessKind::Write);
        let ok = match flags_now {
            Some((true, true, w)) => !need_write || w,
            _ => false,
        };
        if !ok {
            let present_bit = match flags_now {
                Some((true, _, _)) => 1u64,
                _ => 0,
            };
            let err = present_bit | (if need_write { 1 << 1 } else { 0 }) | (1 << 2);
            let handled = match user_pf_hook() {
                Some(h) => h(page, err),
                None => false,
            };
            if !handled {
                return false;
            }
            let mut vmspace = crate::mm::vm::VmSpace::current();
            match vmspace.page_flags(crate::mm::VirtAddr::new(page)) {
                Some((true, true, w)) if !need_write || w => {}
                _ => return false,
            }
        }
        if page == last_page {
            return true;
        }
        page += 4096;
    }
}

pub fn copy_from_user(user_addr: u64, dst: &mut [u8]) -> Result<(), UserAccessFault> {
    if !access_ok(user_addr, dst.len(), AccessKind::Read) {
        return Err(UserAccessFault);
    }
    // SAFETY: `dst` is a valid kernel slice; `user_addr` was validated
    // user-readable by access_ok and the copy is fault-recoverable.
    let not_copied =
        unsafe { __copy_user_bytes(dst.as_mut_ptr(), user_addr as *const u8, dst.len()) };
    if not_copied != 0 {
        return Err(UserAccessFault);
    }
    Ok(())
}

pub fn peek_other_vmspace(
    vmspace: &mut crate::mm::vm::VmSpace,
    user_va: u64,
    dst: &mut [u8],
) -> Result<(), UserAccessFault> {
    if dst.is_empty() {
        return Ok(());
    }
    let end = match user_va.checked_add(dst.len() as u64) {
        Some(e) => e,
        None => return Err(UserAccessFault),
    };
    if end > 0x0000_8000_0000_0000 {
        return Err(UserAccessFault);
    }

    let mut written = 0;
    while written < dst.len() {
        let va = user_va + written as u64;
        let page_off = (va & 0xfff) as usize;
        let chunk = (4096 - page_off).min(dst.len() - written);
        let pa = match vmspace.translate(crate::mm::VirtAddr::new(va & !0xfff)) {
            Some(p) => p,
            None => return Err(UserAccessFault),
        };
        let kva = crate::mm::direct_map::phys_to_virt(pa.as_u64()) + page_off as u64;
        // SAFETY: `kva` is the direct-map alias of the frame `translate`
        // resolved, plus `page_off`; the direct map covers all RAM. `chunk`
        // is clamped to the bytes left in the 4 KiB page (`4096 - page_off`)
        // and to `dst.len() - written`, so the read stays inside one mapped
        // frame and the write inside `dst`; the two never overlap (`kva` is
        // a direct-map address, `dst` a caller-owned buffer). The caller
        // holds the tracee's `VmSpace` lock, so the translation can't be
        // unmapped between `translate` and the read.
        unsafe {
            core::ptr::copy_nonoverlapping(kva as *const u8, dst[written..].as_mut_ptr(), chunk);
        }
        written += chunk;
    }
    Ok(())
}

pub struct PokeBreaks(pub alloc::vec::Vec<crate::mm::PhysFrame<crate::mm::Size4KiB>>);

pub fn poke_other_vmspace(
    vmspace: &mut crate::mm::vm::VmSpace,
    user_va: u64,
    src: &[u8],
) -> (PokeBreaks, Result<(), UserAccessFault>) {
    let mut freed: alloc::vec::Vec<crate::mm::PhysFrame<crate::mm::Size4KiB>> =
        alloc::vec::Vec::new();
    if src.is_empty() {
        return (PokeBreaks(freed), Ok(()));
    }
    let end = match user_va.checked_add(src.len() as u64) {
        Some(e) => e,
        None => return (PokeBreaks(freed), Err(UserAccessFault)),
    };
    if end > 0x0000_8000_0000_0000 {
        return (PokeBreaks(freed), Err(UserAccessFault));
    }

    let mut read = 0;
    while read < src.len() {
        let va = user_va + read as u64;
        let page_off = (va & 0xfff) as usize;
        let chunk = (4096 - page_off).min(src.len() - read);
        let page_va = crate::mm::VirtAddr::new(va & !0xfff);
        if vmspace.page_is_cow(page_va) {
            match vmspace.break_cow(page_va, None) {
                Ok(crate::mm::vm::CowBreak::Broken { old_frame }) => freed.push(old_frame),
                Ok(crate::mm::vm::CowBreak::BrokenInPlace) => {}
                Ok(_) => {}
                Err(_) => return (PokeBreaks(freed), Err(UserAccessFault)),
            }
        }
        let pa = match vmspace.translate(page_va) {
            Some(p) => p,
            None => return (PokeBreaks(freed), Err(UserAccessFault)),
        };
        let kva = crate::mm::direct_map::phys_to_virt(pa.as_u64()) + page_off as u64;
        // SAFETY: `kva` is the direct-map alias of the frame `translate`
        // resolved, plus `page_off`; the direct map covers all RAM and is
        // writable regardless of the per-process PTE write bit, so POKETEXT
        // into RO `.text` lands. `chunk` is clamped to the bytes left in the
        // 4 KiB page and to `src.len() - read`, so the write stays inside one
        // mapped frame and the read inside `src`; source (caller buffer) and
        // destination (direct map) don't overlap. The caller holds the
        // tracee's `VmSpace` lock, pinning the translation across the write.
        unsafe {
            core::ptr::copy_nonoverlapping(src[read..].as_ptr(), kva as *mut u8, chunk);
        }
        read += chunk;
    }
    (PokeBreaks(freed), Ok(()))
}

pub fn copy_to_user(user_addr: u64, src: &[u8]) -> Result<(), UserAccessFault> {
    if !access_ok(user_addr, src.len(), AccessKind::Write) {
        return Err(UserAccessFault);
    }
    // SAFETY: `src` is a valid kernel slice; `user_addr` was validated
    // user-writable by access_ok and the copy is fault-recoverable.
    let not_copied = unsafe { __copy_user_bytes(user_addr as *mut u8, src.as_ptr(), src.len()) };
    if not_copied != 0 {
        return Err(UserAccessFault);
    }
    Ok(())
}

pub fn cmpxchg_user_u32(user_addr: u64, expected: u32, new: u32) -> Result<u32, UserAccessFault> {
    if user_addr & 0x3 != 0 {
        return Err(UserAccessFault);
    }
    if !access_ok(user_addr, 4, AccessKind::Write) {
        return Err(UserAccessFault);
    }
    let prev: u32;
    let mut faulted: u32 = 0;
    // SAFETY: `user_addr` was checked 4-byte-aligned and validated
    // USER-RW for 4 bytes by `access_ok` just above, so the single
    // aligned 32-bit `lock cmpxchg` it names is a well-formed atomic
    // RMW on a mapped, writable user dword. `options(nostack)` is
    // honored (no stack refs); the only memory accessed is that
    // validated user dword named by `{ptr}` (a read-modify-write,
    // so `nomem` is intentionally NOT set), and the asm otherwise
    // touches only `eax` and `{faulted}`. The `__ex_table` entry
    // points the cmpxchg's CPL0 #PF (a concurrent fork can RO-downgrade
    // the page between access_ok and the RMW) at a fixup pad that sets
    // `{faulted}` instead of panicking — recovered into Err below.
    unsafe {
        core::arch::asm!(
            "23: lock cmpxchg [{ptr}], {new:e}",
            "    jmp 25f",
            "24: mov {faulted:e}, 1",
            "25:",
            ".pushsection __ex_table, \"a\"",
            "    .balign 8",
            "    .quad 23b",
            "    .quad 24b",
            ".popsection",
            ptr = in(reg) user_addr,
            new = in(reg) new,
            faulted = inout(reg) faulted,
            inout("eax") expected => prev,
            options(nostack),
        );
    }
    if faulted != 0 {
        return Err(UserAccessFault);
    }
    Ok(prev)
}

pub fn atomic_or_user_u32(user_addr: u64, mask: u32) -> Result<u32, UserAccessFault> {
    if user_addr & 0x3 != 0 {
        return Err(UserAccessFault);
    }
    if !access_ok(user_addr, 4, AccessKind::Write) {
        return Err(UserAccessFault);
    }
    loop {
        let mut buf = [0u8; 4];
        copy_from_user(user_addr, &mut buf)?;
        let cur = u32::from_le_bytes(buf);
        let new = cur | mask;
        if new == cur {
            return Ok(cur);
        }
        let observed = cmpxchg_user_u32(user_addr, cur, new)?;
        if observed == cur {
            return Ok(cur);
        }
    }
}

pub fn copy_cstr_from_user(user_addr: u64, dst: &mut [u8]) -> Result<usize, UserAccessFault> {
    let mut total = 0usize;
    while total < dst.len() {
        let cur = user_addr.wrapping_add(total as u64);
        let to_next_page = 4096 - (cur & 0xfff) as usize;
        let chunk = to_next_page.min(dst.len() - total);
        copy_from_user(cur, &mut dst[total..total + chunk])?;
        for i in 0..chunk {
            if dst[total + i] == 0 {
                return Ok(total + i);
            }
        }
        total += chunk;
    }
    Err(UserAccessFault)
}

pub fn start_user_process(entry: u64, user_stack_top: u64) -> ! {
    // SAFETY: `tss::set_rsp0` writes the active TSS's privileged-stack
    // pointer (the CPU loads it on user→kernel transitions). It
    // takes the *current* rsp value, which is a valid stack address
    // for at least the duration of this function call. The kernel
    // scheduler is also responsible for installing this CPU's
    // per-CPU `kernel_rsp` (via `install_task_kernel_rsp`) before
    // every task switch — first launch goes through that path too.
    // `UserMode::enter` is unsafe because it builds an IRETQ frame
    // and crosses the privilege boundary; preconditions above cover
    // its contract.
    let current_rsp: u64;
    // SAFETY: read-only inline asm — reads the current stack pointer into a
    // register with no memory effects (nomem, nostack).
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, nostack));
    }
    crate::cpu::per_cpu::set_kernel_rsp(current_rsp);
    crate::arch::x86_64::tss::set_rsp0(current_rsp);
    // SAFETY: `UserMode::enter`'s contract requires `entry` and
    // `user_stack_top` be user-accessible in the active page table and
    // the per-CPU `kernel_rsp` point at a live kernel stack. The
    // function's documented preconditions place those mappings on the
    // caller (the scheduler), and we set both `kernel_rsp` and the
    // TSS rsp0 to the current live kernel stack just above.
    unsafe { UserMode::enter(entry, user_stack_top) }
}

pub fn resume_user_from_tf(tf: &TrapFrame) -> ! {
    let current_rsp: u64;
    // SAFETY: read-only inline asm, no memory effects.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, nostack));
    }
    crate::cpu::per_cpu::set_kernel_rsp(current_rsp);
    crate::arch::x86_64::tss::set_rsp0(current_rsp);
    let tf_ptr = tf as *const TrapFrame as u64;
    // SAFETY: caller (sched::register_with_tf) ensures the active
    // VmSpace covers tf.rip_user / tf.rsp_user, and tf was
    // constructed by cloning a real syscall-entry TF. We do the
    // pushes + iretq inline rather than through a naked helper —
    // a naked helper can lose the tf pointer when the compiler
    // tail-calls or inlines its caller, so we keep the asm inside
    // one stack frame whose tf binding is alive until iretq.
    unsafe {
        core::arch::asm!(
            "push 0x1B",
            "push qword ptr [rdi + 72]",
            "push qword ptr [rdi + 64]",
            "push 0x23",
            "push qword ptr [rdi + 56]",
            "mov rbx, [rdi + 80]",
            "mov rbp, [rdi + 88]",
            "mov r12, [rdi + 96]",
            "mov r13, [rdi + 104]",
            "mov r14, [rdi + 112]",
            "mov r15, [rdi + 120]",
            "mov rax, [rdi + 0]",
            "mov rsi, [rdi + 16]",
            "mov rdx, [rdi + 24]",
            "mov r10, [rdi + 32]",
            "mov r8,  [rdi + 40]",
            "mov r9,  [rdi + 48]",
            "mov rdi, [rdi + 8]",
            "xor rcx, rcx",
            "xor r11, r11",
            "iretq",
            in("rdi") tf_ptr,
            options(noreturn),
        );
    }
}

pub struct UserMode;

impl UserMode {
    /// # Safety
    ///
    /// `entry` and `user_stack` must be valid user-accessible virtual
    /// addresses in the currently-active page table. `kernel_rsp`
    /// (set via `set_kernel_rsp` ahead of this call) must point to a
    /// valid kernel stack that survives the user code's lifetime.
    pub unsafe fn enter(entry: u64, user_stack: u64) -> ! {
        let user_cs = (gdt::selectors().user_code.0 | 3) as u64;
        let user_ss = (gdt::selectors().user_data.0 | 3) as u64;
        let user_rflags: u64 = 0x202;

        asm!(
            "push {ss}",
            "push {rsp}",
            "push {flags}",
            "push {cs}",
            "push {rip}",
            "xor rax, rax",
            "xor rbx, rbx",
            "xor rcx, rcx",
            "xor rdx, rdx",
            "xor rsi, rsi",
            "xor rdi, rdi",
            "xor rbp, rbp",
            "xor r8,  r8",
            "xor r9,  r9",
            "xor r10, r10",
            "xor r11, r11",
            "xor r12, r12",
            "xor r13, r13",
            "xor r14, r14",
            "xor r15, r15",
            "iretq",
            ss = in(reg) user_ss,
            rsp = in(reg) user_stack,
            flags = in(reg) user_rflags,
            cs = in(reg) user_cs,
            rip = in(reg) entry,
            options(noreturn),
        );
    }

    /// # Safety
    ///
    /// Same preconditions as `enter`, plus: `tf` must describe a
    /// valid user-mode resume point (rip in user-accessible code,
    /// rsp in user-accessible stack). The active page table must
    /// contain those mappings.
    #[inline(always)]
    pub unsafe fn enter_with_tf(tf: &TrapFrame) -> ! {
        enter_with_tf_naked(tf as *const TrapFrame)
    }
}

#[unsafe(naked)]
unsafe extern "C" fn enter_with_tf_naked(_tf: *const TrapFrame) -> ! {
    core::arch::naked_asm!(
        "push 0x1B",
        "push qword ptr [rdi + 72]",
        "push qword ptr [rdi + 64]",
        "push 0x23",
        "push qword ptr [rdi + 56]",
        "mov rbx, [rdi + 80]",
        "mov rbp, [rdi + 88]",
        "mov r12, [rdi + 96]",
        "mov r13, [rdi + 104]",
        "mov r14, [rdi + 112]",
        "mov r15, [rdi + 120]",
        "mov rax, [rdi + 0]",
        "mov rsi, [rdi + 16]",
        "mov rdx, [rdi + 24]",
        "mov r10, [rdi + 32]",
        "mov r8,  [rdi + 40]",
        "mov r9,  [rdi + 48]",
        "mov rdi, [rdi + 8]",
        "xor rcx, rcx",
        "xor r11, r11",
        "iretq",
    )
}
