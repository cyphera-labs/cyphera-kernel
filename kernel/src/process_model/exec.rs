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
    post_euid: u32,
    post_egid: u32,
    secure: bool,
    tf: &mut TrapFrame,
) -> cyphera_kapi::KResult<()> {
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
                        pr.state.0,
                        ProcessState::Zombie(_)
                            | ProcessState::KilledByFault { .. }
                            | ProcessState::KilledBySignal { .. }
                    )
            })
            .map(|(p, _)| *p)
            .collect()
    };

    let building_fresh = vfork_shared || !live_peers.is_empty();

    crate::ipc::shm::detach_all_current();
    crate::mm::mmap_fault::detach_shared_file_current();

    let (vm_arc, fresh_root) = if building_fresh {
        let fresh = frame::mm::vm::VmSpace::new_user().map_err(|_| cyphera_kapi::Errno::NOMEM)?;
        let root = fresh.root();
        (Arc::new(frame::sync::SpinIrq::new(fresh)), Some(root))
    } else {
        let g = GLOBAL.lock();
        let proc = g.processes.get(&pid).ok_or(cyphera_kapi::Errno::INVAL)?;
        (proc.vmspace().ok_or(cyphera_kapi::Errno::INVAL)?, None)
    };

    if let Some(interp) = crate::loader::elf::interp_path(elf_bytes) {
        let ctx = crate::vfs::path::Context::global();
        if crate::vfs::path::resolve(&ctx, &ctx.root, &interp).is_err() {
            return Err(cyphera_kapi::Errno::NOENT);
        }
    }

    let mut leaving_as: Option<(
        alloc::sync::Arc<crate::process_model::AddressSpace>,
        Option<alloc::sync::Arc<crate::process_model::IpcNamespace>>,
    )> = None;
    if let Some(root) = fresh_root {
        let _irq = frame::sync::IrqGuard::new();
        let cpu = this_cpu() as usize;
        let mut q = CPU_QUEUES[cpu].lock();
        {
            let mut g = GLOBAL.lock();
            if let Some(proc) = g.processes.get_mut(&pid) {
                if let Some(old) = proc.addr_space.clone() {
                    leaving_as = Some((old, proc.namespaces.ipc()));
                }
                proc.addr_space = Some(alloc::sync::Arc::new(crate::process_model::AddressSpace {
                    vmspace: vm_arc.clone(),
                    mmap: frame::sync::SpinIrq::new(MmapState::for_pid(pid)),
                    brk: frame::sync::SpinIrq::new(BrkState::new(0)),
                    live_users: core::sync::atomic::AtomicUsize::new(1),
                }));
                proc.addr_space_root = Some(root);
                proc.lifecycle.set_vfork_shared_vm(false);
            }
        }
        frame::mm::vm::VmSpace::activate_root(root);
        q.active_vmspace = Some(vm_arc.clone());
    }
    if let Some((old_as, old_ipc)) = leaving_as {
        release_addr_space_user(&old_as, old_ipc.as_ref());
    }

    for peer in &live_peers {
        let _ = send_signal(*peer, SIGKILL);
    }

    let (loaded, new_rsp, brk_start) = {
        let mut vm = vm_arc.lock();
        let vm = &mut *vm;

        vm.clear_user();

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

    let proc_pid = pid;
    {
        let mut g = GLOBAL.lock();
        let proc = g
            .processes
            .get_mut(&proc_pid)
            .ok_or(cyphera_kapi::Errno::INVAL)?;

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
        proc.signals.set_pending(0);
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
        proc.signals.reset_siginfo();
        proc.signals
            .set_altstack(crate::core::signal::AltStack::disabled());
        proc.memory.set_tls_base(0);
        proc.sched.sched_class = crate::process_model::SchedClass::default_cfs();
        proc.signals.set_itimer_interval(0);
        proc.signals.set_itimer_deadline(0);
        let key = (proc.pid.raw() as u64) | (1u64 << 63);
        crate::core::timeout::cancel_callback(key);
        proc.identity.set_cmdline(cmdline);
        proc.identity.set_exe_path(exe_path.to_vec());
        proc.fds.close_cloexec();

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

    drain_vfork_done(pid);

    Ok(())
}
