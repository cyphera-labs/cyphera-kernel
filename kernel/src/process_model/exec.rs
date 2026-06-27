use super::*;
use crate::core::*;

use alloc::sync::Arc;
use alloc::vec::Vec;

use frame::user::TrapFrame;

#[allow(clippy::too_many_arguments)]
pub fn exec_current(
    elf_bytes: &[u8],
    exe_path: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    cred_transition: &crate::security::setid::ExecCredTransition,
    exe_inode: Option<Arc<dyn crate::vfs::Inode>>,
    exe_mnt_flags: u64,
    tf: &mut TrapFrame,
) -> cyphera_kapi::KResult<()> {
    let post_euid = cred_transition.post_euid;
    let post_egid = cred_transition.post_egid;
    let secure = cred_transition.secure;
    use frame::mm::VirtAddr;
    use frame::mm::vm::Perms;

    const STACK_VADDR: u64 = 0x7000_0000_0000;
    const STACK_PAGES: usize = 16;
    const BRK_PAD: u64 = 0x1_0000;
    const RFLAGS_USER: u64 = 0x202;

    let pid = current_pid();

    let vfork_shared = with_current_lifecycle(|l| l.vfork_shared_vm()).unwrap_or(false);

    let live_peers: Vec<Pid> = if vfork_shared {
        Vec::new()
    } else {
        let g = GLOBAL.lock();
        let my_tgid = g.processes.get(&pid).map(|p| p.tgid).unwrap_or(pid);
        g.processes
            .iter()
            .filter(|(p, pr)| {
                **p != pid
                    && pr.tgid == my_tgid
                    && !matches!(
                        *pr.state.get(),
                        ProcessState::Zombie(_)
                            | ProcessState::KilledByFault { .. }
                            | ProcessState::KilledBySignal { .. }
                    )
            })
            .map(|(p, _)| *p)
            .collect()
    };

    let fresh = frame::mm::vm::VmSpace::new_user().map_err(|_| cyphera_kapi::Errno::NOMEM)?;
    let root = fresh.root();
    let vm_arc = Arc::new(frame::sync::SpinIrq::new(fresh));

    if let Some(interp) = crate::loader::elf::interp_path(elf_bytes) {
        let ctx = crate::vfs::path::Context::global();
        if crate::vfs::path::resolve(&ctx, &ctx.root, &interp).is_err() {
            return Err(cyphera_kapi::Errno::NOENT);
        }
    }

    let (loaded, new_rsp, brk_start) = {
        let mut vm = vm_arc.lock();
        let vm = &mut *vm;

        let loaded = crate::loader::elf::load_static(elf_bytes, vm)
            .map_err(|_| cyphera_kapi::Errno::NOEXEC)?;

        let stack = vm
            .map_anon(
                VirtAddr::new(STACK_VADDR),
                STACK_PAGES,
                Perms::READ | Perms::WRITE | Perms::USER,
            )
            .map_err(|_| cyphera_kapi::Errno::NOMEM)?;
        core::mem::forget(stack);

        let stack_top = STACK_VADDR + (STACK_PAGES * 4096) as u64;
        let brk_start = (loaded.image_end + BRK_PAD + 0xfff) & !0xfff;

        let (ruid, rgid) = with_current_creds(|c| (c.ruid, c.rgid));
        let aux = crate::loader::stack_init::AuxvInfo::for_exec(
            &loaded, ruid, post_euid, rgid, post_egid, secure,
        );
        let new_rsp = crate::loader::stack_init::build_user_stack(vm, stack_top, argv, envp, &aux)
            .map_err(|_| cyphera_kapi::Errno::NOMEM)?;

        (loaded, new_rsp, brk_start)
    };

    crate::ipc::shm::detach_all_current();
    crate::mm::mmap_fault::detach_shared_file_current();

    let new_as = alloc::sync::Arc::new(crate::process_model::AddressSpace {
        vmspace: vm_arc.clone(),
        mmap: frame::sync::SpinIrq::new(MmapState::for_pid(pid)),
        brk: frame::sync::SpinIrq::new(BrkState::new(brk_start)),
        live_users: core::sync::atomic::AtomicUsize::new(1),
    });
    let leaving_as = swap_current_address_space(pid, new_as, root, vm_arc.clone());
    if let Some((old_as, old_ipc)) = leaving_as {
        release_addr_space_user(&old_as, old_ipc.as_ref());
    }

    for peer in &live_peers {
        let _ = send_signal(*peer, SIGKILL);
    }

    let proc_pid = pid;
    let closed_cloexec: Vec<Arc<crate::vfs::OpenFile>>;
    {
        let mut g = GLOBAL.lock();
        let Some(proc) = g.processes.get_mut(&proc_pid) else {
            return Ok(());
        };

        let mut cmdline: Vec<u8> = Vec::new();
        for s in argv {
            cmdline.extend_from_slice(s);
            cmdline.push(0);
        }

        if let Some(addr_space) = proc.addr_space.as_ref() {
            *addr_space.mmap.lock() = MmapState::for_pid(proc.pid);
            *addr_space.brk.lock() = BrkState::new(brk_start);
        }
        {
            use crate::process_model::{MapSegLabel, MapSegment, MapsLayout};
            let mut layout = MapsLayout::default();
            for (lo, hi, prot) in &loaded.segments {
                layout.segments.push(MapSegment {
                    start: *lo,
                    end: *hi,
                    prot: *prot,
                    label: MapSegLabel::Image,
                });
            }
            for (lo, hi, prot) in &loaded.interp_segments {
                layout.segments.push(MapSegment {
                    start: *lo,
                    end: *hi,
                    prot: *prot,
                    label: MapSegLabel::Interp,
                });
            }
            layout.segments.push(MapSegment {
                start: STACK_VADDR,
                end: STACK_VADDR + (STACK_PAGES * 4096) as u64,
                prot: Perms::READ | Perms::WRITE | Perms::USER,
                label: MapSegLabel::Stack,
            });
            proc.memory.set_maps_layout(layout);
        }
        proc.sigactions = Arc::new(frame::sync::SpinIrq::new(
            [crate::process_model::SigAction::default(); NSIG],
        ));
        proc.signals.reset_for_exec();
        if proc.trace.is_traced() {
            if proc.trace.options() & crate::ptrace::PTRACE_O_TRACEEXEC != 0 {
                let msg = proc.pid.raw() as u64;
                proc.trace.post_event_stop(
                    crate::process_model::TraceStop::EventStop(crate::ptrace::PTRACE_EVENT_EXEC),
                    msg,
                );
            } else {
                proc.trace.arm_post_exec_trap();
            }
        } else {
            proc.trace.clear_pending_event_stop();
        }
        proc.signals
            .set_altstack(crate::core::signal::AltStack::disabled());
        proc.memory.set_tls_base(0);
        proc.sched.sched_class = crate::process_model::SchedClass::default_cfs();
        proc.signals.set_itimer_interval(0);
        proc.signals.set_itimer_deadline(0);
        let key = (proc.pid.raw() as u64) | (1u64 << 63);
        crate::core::timeout::cancel_callback(key);
        let timer_ids = proc.timers.ids();
        proc.timers.clear();
        crate::syscall::posix_timer::cancel_callbacks(proc.pid, &timer_ids);
        proc.identity.set_cmdline(cmdline);
        proc.identity.set_exe_path(exe_path.to_vec());
        proc.identity.set_exe_inode(exe_inode);
        proc.identity.set_exe_mnt_flags(exe_mnt_flags);
        proc.lifecycle.mark_execd();

        {
            let mut creds = proc.creds.lock();
            crate::security::setid::apply_exec_transition(&mut creds, cred_transition);
        }
        proc.security
            .set_dumpable(if cred_transition.secure { 0 } else { 1 });
        proc.security.set_keep_caps(false);

        closed_cloexec = proc.fds.close_cloexec();

        *tf = TrapFrame {
            rax: 0,
            rdi: 0,
            rsi: 0,
            rdx: 0,
            r10: 0,
            r8: 0,
            r9: 0,
            rip_user: loaded.interp_entry.unwrap_or(loaded.entry),
            rflags_user: RFLAGS_USER,
            rsp_user: new_rsp,
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            orig_rax: 0,
            rcx: 0,
            r11: 0,
        };
    }
    drop(closed_cloexec);

    drain_vfork_done(pid);

    Ok(())
}
