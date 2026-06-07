use frame::user::TrapFrame;

use crate::errno::{ENOSYS, EPERM};
use crate::sched;

use super::numbers::*;

pub(super) fn dispatch_if_legacy(tf: &mut TrapFrame) -> bool {
    match tf.rax {
        SYS_USELIB
        | SYS_USTAT
        | SYS_SYSFS
        | SYS__SYSCTL
        | SYS_CREATE_MODULE
        | SYS_INIT_MODULE
        | SYS_DELETE_MODULE
        | SYS_GET_KERNEL_SYMS
        | SYS_QUERY_MODULE
        | SYS_FINIT_MODULE
        | SYS_NFSSERVCTL
        | SYS_GETPMSG | SYS_PUTPMSG
        | SYS_AFS_SYSCALL | SYS_TUXCALL | SYS_SECURITY
        | SYS_VSERVER
        | SYS_LOOKUP_DCOOKIE
        | SYS_EPOLL_CTL_OLD | SYS_EPOLL_WAIT_OLD
        | SYS_RESTART_SYSCALL
        | SYS_MIGRATE_PAGES | SYS_MOVE_PAGES
        | SYS_MODIFY_LDT
        | SYS_SET_THREAD_AREA
        | SYS_GET_THREAD_AREA
        => {
            tf.rax = ENOSYS as u64;
            true
        }
        SYS_SWAPON | SYS_SWAPOFF => {
            tf.rax = ENOSYS as u64;
            true
        }
        SYS_IOPL | SYS_IOPERM
        | SYS_KEXEC_LOAD | SYS_KEXEC_FILE_LOAD
        | SYS_ACCT
        => {
            tf.rax = EPERM as u64;
            true
        }
        SYS_VHANGUP => {
            tf.rax = sys_vhangup() as u64;
            true
        }
        _ => false,
    }
}

fn sys_vhangup() -> i64 {
    let euid =
        sched::with_target_process(sched::current_pid(), |p| p.creds.lock().euid).unwrap_or(0);
    if euid != 0 {
        return EPERM;
    }
    0
}
