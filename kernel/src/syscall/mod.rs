use frame::user::TrapFrame;

use crate::core as sched;

use crate::errno::{EBADF, EFAULT, EINVAL, ENOSYS, EOPNOTSUPP, EPERM, ESRCH};

mod numbers;
use numbers::*;

mod util;

mod creds;
mod event;
mod fs;
mod ipc;
mod legacy;
mod mm;
mod net;
mod proc;
mod ptrace_dispatch;
mod scheduling;
mod signal;
mod time;
use crate::security::setid::{
    sys_setfsgid, sys_setfsuid, sys_setgid, sys_setregid, sys_setresgid, sys_setresuid,
    sys_setreuid, sys_setuid,
};
use creds::{
    apply_seccomp, sys_capget, sys_capset, sys_getgroups, sys_getresgid, sys_getresuid,
    sys_seccomp, sys_setdomainname, sys_setgroups, sys_sethostname,
};
use event::{
    sys_epoll_create1, sys_epoll_ctl, sys_epoll_pwait, sys_epoll_pwait2, sys_epoll_wait,
    sys_eventfd2, sys_poll, sys_ppoll, sys_pselect6, sys_select, sys_signalfd4, sys_timerfd_create,
    sys_timerfd_gettime, sys_timerfd_settime,
};
pub use fs::console_fg_pgrp;
pub use fs::termios_get_pub;
pub(crate) use fs::{DEFAULT_TERMIOS, resolve_user_path};
use fs::{
    sys_chdir, sys_chroot, sys_close, sys_close_range, sys_copy_file_range, sys_dup, sys_dup2,
    sys_dup3, sys_faccessat, sys_fadvise64, sys_fallocate, sys_fchdir, sys_fchmod, sys_fchmodat,
    sys_fchown, sys_fchownat, sys_fcntl, sys_fgetxattr, sys_flistxattr, sys_flock,
    sys_fremovexattr, sys_fsetxattr, sys_fstat, sys_fsync, sys_ftruncate, sys_getcwd, sys_getdents,
    sys_getdents64, sys_getxattr, sys_getxattrat, sys_ioctl, sys_linkat, sys_listxattr,
    sys_listxattrat, sys_lseek, sys_memfd_create, sys_mkdirat, sys_mknodat, sys_mount,
    sys_newfstatat, sys_openat, sys_openat2, sys_pipe, sys_pipe2, sys_pivot_root, sys_pread64,
    sys_preadv, sys_pwrite64, sys_pwritev, sys_read, sys_readahead, sys_readlinkat, sys_readv,
    sys_removexattr, sys_removexattrat, sys_renameat, sys_renameat2, sys_sendfile, sys_setxattr,
    sys_setxattrat, sys_splice, sys_stat, sys_statfs, sys_statx, sys_symlinkat,
    sys_sync_file_range, sys_tee, sys_truncate, sys_umount2, sys_unlinkat, sys_utimensat,
    sys_vmsplice, sys_write, sys_writev,
};
use ipc::{
    sys_futex, sys_futex_requeue, sys_futex_wait, sys_futex_waitv, sys_futex_wake, sys_keyctl,
    sys_shmat, sys_shmctl, sys_shmdt, sys_shmget,
};
use mm::{
    sys_brk, sys_get_mempolicy, sys_madvise, sys_mbind, sys_membarrier, sys_mincore, sys_mlock,
    sys_mlock2, sys_mlockall, sys_mmap, sys_mprotect, sys_mremap, sys_msync, sys_munlock,
    sys_munlockall, sys_munmap, sys_process_vm_readv, sys_process_vm_writev, sys_set_mempolicy,
    sys_set_mempolicy_home_node,
};
use net::{
    sys_accept, sys_bind, sys_connect, sys_getpeername, sys_getsockname, sys_getsockopt,
    sys_listen, sys_recvfrom, sys_recvmsg, sys_sendmsg, sys_sendto, sys_setsockopt, sys_shutdown,
    sys_socket, sys_socketpair,
};
pub use proc::default_rlimit;
use proc::{
    sys_arch_prctl, sys_clone, sys_clone3, sys_execve, sys_execveat, sys_exit_simple, sys_fork,
    sys_getrlimit, sys_getrusage, sys_personality, sys_prctl, sys_prlimit64, sys_set_robust_list,
    sys_set_tid_address, sys_setns, sys_setrlimit, sys_sysinfo, sys_syslog, sys_times, sys_uname,
    sys_unshare, sys_vfork, sys_wait4, sys_waitid,
};
use ptrace_dispatch::sys_ptrace;
use scheduling::{
    sys_getcpu, sys_getpriority, sys_rseq, sys_sched_get_priority_max, sys_sched_get_priority_min,
    sys_sched_getaffinity, sys_sched_getattr, sys_sched_getparam, sys_sched_getscheduler,
    sys_sched_rr_get_interval, sys_sched_setaffinity, sys_sched_setattr, sys_sched_setparam,
    sys_sched_setscheduler, sys_setpriority,
};
use signal::{
    sys_kill, sys_pause, sys_pidfd_open, sys_pidfd_send_signal, sys_rt_sigaction,
    sys_rt_sigpending, sys_rt_sigprocmask, sys_rt_sigqueueinfo, sys_rt_sigreturn,
    sys_rt_sigsuspend, sys_rt_sigtimedwait, sys_rt_tgsigqueueinfo, sys_sigaltstack, sys_tgkill,
    sys_tkill,
};
use time::{
    sys_adjtimex, sys_alarm, sys_clock_adjtime, sys_clock_getres, sys_clock_gettime,
    sys_clock_nanosleep, sys_clock_settime, sys_getitimer, sys_gettimeofday, sys_nanosleep,
    sys_setitimer, sys_settimeofday, sys_time,
};

pub(super) const AT_FDCWD: i64 = -100;
const AT_REMOVEDIR: u64 = 0x200;

pub(super) const PATH_MAX: usize = 256;

pub fn dispatch(tf: &mut TrapFrame) {
    sched::syscall_enter_account();
    if !apply_seccomp(tf) {
        sched::syscall_exit_account();
        return;
    }
    crate::ptrace::syscall_entry_hook(tf);

    if legacy::dispatch_if_legacy(tf) {
    } else {
        match tf.syscall_nr() {
            SYS_READ => {
                tf.set_ret(sys_read(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_WRITE => {
                tf.set_ret(sys_write(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_CLOSE => {
                tf.set_ret(sys_close(tf.arg(0)) as u64);
            }
            SYS_FSTAT => {
                tf.set_ret(sys_fstat(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_LSEEK => {
                tf.set_ret(sys_lseek(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_GETCWD => {
                tf.set_ret(sys_getcwd(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_CHDIR => {
                tf.set_ret(sys_chdir(tf.arg(0)) as u64);
            }
            SYS_GETDENTS64 => {
                tf.set_ret(sys_getdents64(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_OPENAT => {
                tf.set_ret(sys_openat(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_NEWFSTATAT => {
                tf.set_ret(sys_newfstatat(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_DUP => {
                tf.set_ret(sys_dup(tf.arg(0)) as u64);
            }
            SYS_DUP2 => {
                tf.set_ret(sys_dup2(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_DUP3 => {
                tf.set_ret(sys_dup3(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_FCNTL => {
                tf.set_ret(sys_fcntl(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_PREAD64 => {
                tf.set_ret(sys_pread64(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_PWRITE64 => {
                tf.set_ret(sys_pwrite64(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_READV => {
                tf.set_ret(sys_readv(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_WRITEV => {
                tf.set_ret(sys_writev(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_IOCTL => {
                tf.set_ret(sys_ioctl(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_PIPE => {
                tf.set_ret(sys_pipe(tf.arg(0)) as u64);
            }
            SYS_PIPE2 => {
                tf.set_ret(sys_pipe2(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_MKDIRAT => {
                tf.set_ret(sys_mkdirat(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_UNLINKAT => {
                tf.set_ret(sys_unlinkat(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_RENAMEAT => {
                tf.set_ret(sys_renameat(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_LINKAT => {
                tf.set_ret(
                    sys_linkat(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_SYMLINKAT => {
                tf.set_ret(sys_symlinkat(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_READLINKAT => {
                tf.set_ret(sys_readlinkat(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_STAT => {
                tf.set_ret(sys_stat(tf.arg(0), tf.arg(1), false) as u64);
            }
            SYS_LSTAT => {
                tf.set_ret(sys_stat(tf.arg(0), tf.arg(1), true) as u64);
            }
            SYS_STATX => {
                tf.set_ret(sys_statx(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64);
            }
            SYS_ACCESS => {
                tf.set_ret(sys_faccessat(AT_FDCWD as u64, tf.arg(0), tf.arg(1), 0) as u64);
            }
            SYS_FACCESSAT => {
                tf.set_ret(sys_faccessat(tf.arg(0), tf.arg(1), tf.arg(2), 0) as u64);
            }
            SYS_FACCESSAT2 => {
                tf.set_ret(sys_faccessat(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_UMASK => {
                tf.set_ret(sched::set_current_umask(tf.arg(0) as u16) as u64);
            }
            SYS_CHMOD => {
                tf.set_ret(sys_fchmodat(AT_FDCWD as u64, tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_FCHMOD => {
                tf.set_ret(sys_fchmod(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_FCHMODAT => {
                tf.set_ret(sys_fchmodat(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_CHOWN | SYS_LCHOWN => {
                tf.set_ret(
                    sys_fchownat(AT_FDCWD as u64, tf.arg(0), tf.arg(1), tf.arg(2), 0) as u64,
                );
            }
            SYS_FCHOWN => {
                tf.set_ret(sys_fchown(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_FCHOWNAT => {
                tf.set_ret(
                    sys_fchownat(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_TRUNCATE => {
                tf.set_ret(sys_truncate(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_FTRUNCATE => {
                tf.set_ret(sys_ftruncate(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_UNLINK => {
                tf.set_ret(sys_unlinkat(AT_FDCWD as u64, tf.arg(0), 0) as u64);
            }
            SYS_RMDIR => {
                tf.set_ret(sys_unlinkat(AT_FDCWD as u64, tf.arg(0), AT_REMOVEDIR) as u64);
            }
            SYS_LINK => {
                tf.set_ret(
                    sys_linkat(AT_FDCWD as u64, tf.arg(0), AT_FDCWD as u64, tf.arg(1), 0) as u64,
                );
            }
            SYS_SYMLINK => {
                tf.set_ret(sys_symlinkat(tf.arg(0), AT_FDCWD as u64, tf.arg(1)) as u64);
            }
            SYS_READLINK => {
                tf.set_ret(sys_readlinkat(AT_FDCWD as u64, tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_RENAME => {
                tf.set_ret(
                    sys_renameat2(AT_FDCWD as u64, tf.arg(0), AT_FDCWD as u64, tf.arg(1), 0) as u64,
                );
            }
            SYS_RENAMEAT2 => {
                tf.set_ret(
                    sys_renameat2(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_MKDIR => {
                tf.set_ret(sys_mkdirat(AT_FDCWD as u64, tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_MKNOD => {
                tf.set_ret(sys_mknodat(AT_FDCWD as u64, tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_MKNODAT => {
                tf.set_ret(sys_mknodat(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_STATFS => {
                tf.set_ret(sys_statfs(tf.arg(0), tf.arg(1), false) as u64);
            }
            SYS_FSTATFS => {
                tf.set_ret(sys_statfs(tf.arg(0), tf.arg(1), true) as u64);
            }
            SYS_FSYNC | SYS_FDATASYNC => {
                tf.set_ret(sys_fsync(tf.arg(0)) as u64);
            }
            SYS_SYNC => {
                tf.set_ret(0);
            }
            SYS_SYNC_FILE_RANGE => {
                tf.set_ret(sys_sync_file_range(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_CHROOT => {
                tf.set_ret(sys_chroot(tf.arg(0)) as u64);
            }
            SYS_UNSHARE => {
                tf.set_ret(sys_unshare(tf.arg(0)) as u64);
            }
            SYS_SETNS => {
                tf.set_ret(sys_setns(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_OPEN_LEGACY => {
                tf.set_ret(sys_openat(AT_FDCWD as u64, tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_CREAT => {
                const O_CREAT_WRONLY_TRUNC: u64 = 0o100 | 0o1 | 0o1000;
                tf.set_ret(
                    sys_openat(AT_FDCWD as u64, tf.arg(0), O_CREAT_WRONLY_TRUNC, tf.arg(1)) as u64,
                );
            }
            SYS_GETDENTS_LEGACY => {
                tf.set_ret(sys_getdents(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_FCHDIR => {
                tf.set_ret(sys_fchdir(tf.arg(0)) as u64);
            }
            SYS_FALLOCATE => {
                tf.set_ret(sys_fallocate(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_FLOCK => {
                tf.set_ret(sys_flock(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_FADVISE64 => {
                tf.set_ret(sys_fadvise64(tf.arg(0)) as u64);
            }
            SYS_MADVISE => {
                tf.set_ret(sys_madvise(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_POLL => {
                tf.set_ret(sys_poll(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_PPOLL => {
                tf.set_ret(sys_ppoll(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64);
            }
            SYS_SELECT => {
                tf.set_ret(
                    sys_select(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_PSELECT6 => {
                tf.set_ret(sys_pselect6(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_PREADV | SYS_PREADV2 => {
                tf.set_ret(
                    sys_preadv(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_PWRITEV | SYS_PWRITEV2 => {
                tf.set_ret(
                    sys_pwritev(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_SENDFILE => {
                tf.set_ret(sys_sendfile(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_COPY_FILE_RANGE => {
                tf.set_ret(sys_copy_file_range(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_SPLICE => {
                tf.set_ret(sys_splice(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_TEE => {
                tf.set_ret(sys_tee(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_VMSPLICE => {
                tf.set_ret(sys_vmsplice(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_PIVOT_ROOT => {
                tf.set_ret(sys_pivot_root(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_OPENAT2 => {
                tf.set_ret(sys_openat2(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_FCHMODAT2 => {
                tf.set_ret(sys_fchmodat(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SETXATTRAT => {
                tf.set_ret(sys_setxattrat(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_GETXATTRAT => {
                tf.set_ret(
                    sys_getxattrat(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_LISTXATTRAT => {
                tf.set_ret(sys_listxattrat(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_REMOVEXATTRAT => {
                tf.set_ret(sys_removexattrat(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_CLOSE_RANGE => {
                tf.set_ret(sys_close_range(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_GETGROUPS => {
                tf.set_ret(sys_getgroups(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_SETGROUPS => {
                tf.set_ret(sys_setgroups(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_GETRESUID => {
                tf.set_ret(sys_getresuid(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_GETRESGID => {
                tf.set_ret(sys_getresgid(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SETRESUID => {
                tf.set_ret(
                    sys_setresuid(tf.arg(0) as u32, tf.arg(1) as u32, tf.arg(2) as u32) as u64,
                );
            }
            SYS_SETRESGID => {
                tf.set_ret(
                    sys_setresgid(tf.arg(0) as u32, tf.arg(1) as u32, tf.arg(2) as u32) as u64,
                );
            }
            SYS_SETUID => {
                tf.set_ret(sys_setuid(tf.arg(0) as u32) as u64);
            }
            SYS_SETGID => {
                tf.set_ret(sys_setgid(tf.arg(0) as u32) as u64);
            }
            SYS_SETREUID => {
                tf.set_ret(sys_setreuid(tf.arg(0) as u32, tf.arg(1) as u32) as u64);
            }
            SYS_SETREGID => {
                tf.set_ret(sys_setregid(tf.arg(0) as u32, tf.arg(1) as u32) as u64);
            }
            SYS_SETFSUID => {
                tf.set_ret(sys_setfsuid(tf.arg(0) as u32) as u64);
            }
            SYS_SETFSGID => {
                tf.set_ret(sys_setfsgid(tf.arg(0) as u32) as u64);
            }
            SYS_UTIMENSAT => {
                tf.set_ret(sys_utimensat(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_SETXATTR => {
                tf.set_ret(sys_setxattr(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    false,
                ) as u64);
            }
            SYS_LSETXATTR => {
                tf.set_ret(
                    sys_setxattr(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4), true)
                        as u64,
                );
            }
            SYS_FSETXATTR => {
                tf.set_ret(
                    sys_fsetxattr(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_GETXATTR | SYS_LGETXATTR => {
                tf.set_ret(sys_getxattr(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_FGETXATTR => {
                tf.set_ret(sys_fgetxattr(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_LISTXATTR | SYS_LLISTXATTR => {
                tf.set_ret(sys_listxattr(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_FLISTXATTR => {
                tf.set_ret(sys_flistxattr(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_REMOVEXATTR | SYS_LREMOVEXATTR => {
                tf.set_ret(sys_removexattr(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_FREMOVEXATTR => {
                tf.set_ret(sys_fremovexattr(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_SOCKET => {
                tf.set_ret(sys_socket(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SOCKETPAIR => {
                tf.set_ret(sys_socketpair(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_BIND => {
                tf.set_ret(sys_bind(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_LISTEN => {
                tf.set_ret(sys_listen(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_ACCEPT | SYS_ACCEPT4 => {
                tf.set_ret(sys_accept(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_CONNECT => {
                tf.set_ret(sys_connect(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SENDTO => {
                tf.set_ret(sys_sendto(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_RECVFROM => {
                tf.set_ret(sys_recvfrom(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_SENDMSG => {
                tf.set_ret(sys_sendmsg(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_RECVMSG => {
                tf.set_ret(sys_recvmsg(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SHUTDOWN => {
                tf.set_ret(sys_shutdown(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_GETSOCKNAME => {
                tf.set_ret(sys_getsockname(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_GETPEERNAME => {
                tf.set_ret(sys_getpeername(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SETSOCKOPT => {
                tf.set_ret(
                    sys_setsockopt(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_GETSOCKOPT => {
                tf.set_ret(
                    sys_getsockopt(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_EPOLL_CREATE1 => {
                tf.set_ret(sys_epoll_create1(tf.arg(0)) as u64);
            }
            SYS_EPOLL_CTL => {
                tf.set_ret(sys_epoll_ctl(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_EPOLL_WAIT => {
                tf.set_ret(sys_epoll_wait(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_EPOLL_PWAIT => {
                tf.set_ret(sys_epoll_pwait(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_EPOLL_PWAIT2 => {
                tf.set_ret(sys_epoll_pwait2(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_MMAP => {
                tf.set_ret(sys_mmap(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_MUNMAP => {
                tf.set_ret(sys_munmap(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_MREMAP => {
                tf.set_ret(
                    sys_mremap(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_MSYNC => {
                tf.set_ret(sys_msync(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_BRK => {
                tf.set_ret(sys_brk(tf.arg(0)));
            }
            SYS_RT_SIGACTION => {
                tf.set_ret(sys_rt_sigaction(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_RT_SIGPROCMASK => {
                tf.set_ret(sys_rt_sigprocmask(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_RT_SIGRETURN => {
                sys_rt_sigreturn(tf);
                return;
            }
            SYS_SCHED_SETAFFINITY => {
                let (pid, size, ptr) = (tf.arg(0), tf.arg(1), tf.arg(2));
                let r = sys_sched_setaffinity(tf, pid, size, ptr) as u64;
                tf.set_ret(r);
            }
            SYS_SCHED_GETAFFINITY => {
                tf.set_ret(sys_sched_getaffinity(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SCHED_YIELD => {
                sched::yield_current(tf);
            }
            SYS_SCHED_SETSCHEDULER => {
                tf.set_ret(sys_sched_setscheduler(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SCHED_GETSCHEDULER => {
                tf.set_ret(sys_sched_getscheduler(tf.arg(0)) as u64);
            }
            SYS_SCHED_SETPARAM => {
                tf.set_ret(sys_sched_setparam(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_SCHED_GETPARAM => {
                tf.set_ret(sys_sched_getparam(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_SCHED_GET_PRIORITY_MAX => {
                tf.set_ret(sys_sched_get_priority_max(tf.arg(0)) as u64);
            }
            SYS_SCHED_GET_PRIORITY_MIN => {
                tf.set_ret(sys_sched_get_priority_min(tf.arg(0)) as u64);
            }
            SYS_SCHED_RR_GET_INTERVAL => {
                tf.set_ret(sys_sched_rr_get_interval(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_SCHED_SETATTR => {
                tf.set_ret(sys_sched_setattr(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SCHED_GETATTR => {
                tf.set_ret(sys_sched_getattr(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_NANOSLEEP => {
                tf.set_ret(sys_nanosleep(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_FORK => {
                let r = sys_fork(tf) as u64;
                tf.set_ret(r);
            }
            SYS_VFORK => {
                let r = sys_vfork(tf) as u64;
                tf.set_ret(r);
            }
            SYS_CLONE => {
                let r = sys_clone(tf) as u64;
                tf.set_ret(r);
            }
            SYS_CLONE3 => {
                tf.set_ret(sys_clone3(tf, tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_EXECVE => {
                if let Err(errno) = sys_execve(tf) {
                    tf.set_ret(errno as u64);
                }
            }
            SYS_EXECVEAT => {
                if let Err(errno) = sys_execveat(tf) {
                    tf.set_ret(errno as u64);
                }
            }
            SYS_GETPID => {
                tf.set_ret(sched::host_to_caller_local(sched::current_tgid()) as u64);
            }
            SYS_KILL => {
                tf.set_ret(sys_kill(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_EXIT => {
                sched::exit_current(tf, tf.arg(0) as i32);
            }
            SYS_EXIT_GROUP => {
                sched::exit_group_current(tf, tf.arg(0) as i32);
            }
            SYS_WAIT4 => {
                tf.set_ret(sys_wait4(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_WAITID => {
                tf.set_ret(sys_waitid(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_SIGALTSTACK => {
                tf.set_ret(sys_sigaltstack(tf.arg(0), tf.arg(1), tf.user_sp()) as u64);
            }
            SYS_TGKILL => {
                tf.set_ret(sys_tgkill(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_GETPPID => {
                let parent_host = sched::current_parent_pid();
                if parent_host == 0 {
                    tf.set_ret(0u64);
                } else {
                    tf.set_ret(
                        sched::host_to_caller_local(crate::process_model::Pid(parent_host)) as u64,
                    );
                }
            }
            SYS_GETPGRP => {
                tf.set_ret(sched::host_to_caller_local(sched::current_pgid()) as u64);
            }
            SYS_GETPGID => {
                let target_host = if tf.arg(0) as u32 == 0 {
                    sched::current_pid()
                } else {
                    match sched::caller_local_to_host(tf.arg(0) as u32) {
                        Some(p) => p,
                        None => {
                            tf.set_ret(ESRCH as u64);
                            return;
                        }
                    }
                };
                tf.set_ret(match sched::getpgid(target_host) {
                    Ok(p) => sched::host_to_caller_local(p) as u64,
                    Err(e) => e as u64,
                });
            }
            SYS_SETPGID => {
                let target_host = if tf.arg(0) as u32 == 0 {
                    sched::current_pid()
                } else {
                    match sched::caller_local_to_host(tf.arg(0) as u32) {
                        Some(p) => p,
                        None => {
                            tf.set_ret(ESRCH as u64);
                            return;
                        }
                    }
                };
                let new_pgid_host = if tf.arg(1) as u32 == 0 {
                    target_host
                } else {
                    match sched::caller_local_to_host(tf.arg(1) as u32) {
                        Some(p) => p,
                        None => {
                            tf.set_ret(ESRCH as u64);
                            return;
                        }
                    }
                };
                tf.set_ret(match sched::setpgid(target_host, new_pgid_host) {
                    Ok(()) => 0,
                    Err(e) => e as u64,
                });
            }
            SYS_SETSID => {
                tf.set_ret(match sched::setsid() {
                    Ok(p) => sched::host_to_caller_local(p) as u64,
                    Err(e) => e as u64,
                });
            }
            SYS_GETSID => {
                let target_host = if tf.arg(0) as u32 == 0 {
                    sched::current_pid()
                } else {
                    match sched::caller_local_to_host(tf.arg(0) as u32) {
                        Some(p) => p,
                        None => {
                            tf.set_ret(ESRCH as u64);
                            return;
                        }
                    }
                };
                tf.set_ret(match sched::getsid(target_host) {
                    Ok(p) => sched::host_to_caller_local(p) as u64,
                    Err(e) => e as u64,
                });
            }
            SYS_PIDFD_OPEN => {
                tf.set_ret(sys_pidfd_open(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_PIDFD_SEND_SIGNAL => {
                tf.set_ret(
                    sys_pidfd_send_signal(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64,
                );
            }
            SYS_SIGNALFD4 => {
                tf.set_ret(sys_signalfd4(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_EVENTFD2 => {
                tf.set_ret(sys_eventfd2(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_MEMFD_CREATE => {
                tf.set_ret(sys_memfd_create(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_RSEQ => {
                tf.set_ret(sys_rseq(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_PAUSE => {
                tf.set_ret(sys_pause() as u64);
            }
            SYS_RT_SIGTIMEDWAIT => {
                tf.set_ret(sys_rt_sigtimedwait(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_GETITIMER => {
                tf.set_ret(sys_getitimer(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_SETITIMER => {
                tf.set_ret(sys_setitimer(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SHMGET => {
                tf.set_ret(sys_shmget(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SHMAT => {
                tf.set_ret(sys_shmat(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SHMCTL => {
                tf.set_ret(sys_shmctl(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_SHMDT => {
                tf.set_ret(sys_shmdt(tf.arg(0)) as u64);
            }
            SYS_KEYCTL => {
                tf.set_ret(
                    sys_keyctl(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_ADD_KEY | SYS_REQUEST_KEY => {
                tf.set_ret(EOPNOTSUPP as u64);
            }
            SYS_GETRUSAGE => {
                tf.set_ret(sys_getrusage(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_TIMES => {
                tf.set_ret(sys_times(tf.arg(0)) as u64);
            }
            SYS_SYSINFO => {
                tf.set_ret(sys_sysinfo(tf.arg(0)) as u64);
            }
            SYS_SYSLOG => {
                tf.set_ret(sys_syslog(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_PTRACE => {
                tf.set_ret(sys_ptrace(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_MINCORE => {
                tf.set_ret(sys_mincore(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_ALARM => {
                tf.set_ret(sys_alarm(tf.arg(0)) as u64);
            }
            SYS_RT_SIGPENDING => {
                tf.set_ret(sys_rt_sigpending(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_RT_SIGQUEUEINFO => {
                tf.set_ret(sys_rt_sigqueueinfo(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_RT_SIGSUSPEND => {
                tf.set_ret(sys_rt_sigsuspend(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_MLOCK => {
                tf.set_ret(sys_mlock(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_MUNLOCK => {
                tf.set_ret(sys_munlock(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_MLOCKALL => {
                tf.set_ret(sys_mlockall(tf.arg(0)) as u64);
            }
            SYS_MUNLOCKALL => {
                tf.set_ret(sys_munlockall() as u64);
            }
            SYS_SETRLIMIT => {
                tf.set_ret(sys_setrlimit(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_CLOCK_NANOSLEEP => {
                tf.set_ret(sys_clock_nanosleep(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_RT_TGSIGQUEUEINFO => {
                tf.set_ret(
                    sys_rt_tgsigqueueinfo(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64,
                );
            }
            SYS_GETCPU => {
                tf.set_ret(sys_getcpu(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_PROCESS_VM_READV => {
                tf.set_ret(sys_process_vm_readv(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_PROCESS_VM_WRITEV => {
                tf.set_ret(sys_process_vm_writev(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_MEMBARRIER => {
                tf.set_ret(sys_membarrier(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_MLOCK2 => {
                tf.set_ret(sys_mlock2(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_PKEY_MPROTECT | SYS_PKEY_ALLOC | SYS_PKEY_FREE => {
                tf.set_ret(EOPNOTSUPP as u64);
            }
            SYS_READAHEAD => {
                tf.set_ret(sys_readahead(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_EPOLL_CREATE => {
                if (tf.arg(0) as i64) <= 0 {
                    tf.set_ret(EINVAL as u64);
                } else {
                    tf.set_ret(sys_epoll_create1(0) as u64);
                }
            }
            SYS_EVENTFD => {
                tf.set_ret(sys_eventfd2(tf.arg(0), 0) as u64);
            }
            SYS_MBIND => {
                tf.set_ret(sys_mbind(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_SET_MEMPOLICY => {
                tf.set_ret(sys_set_mempolicy(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_GET_MEMPOLICY => {
                tf.set_ret(
                    sys_get_mempolicy(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_SET_MEMPOLICY_HOME_NODE => {
                tf.set_ret(
                    sys_set_mempolicy_home_node(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64,
                );
            }
            SYS_SETTIMEOFDAY => {
                tf.set_ret(sys_settimeofday(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_CLOCK_SETTIME => {
                tf.set_ret(sys_clock_settime(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_ADJTIMEX => {
                tf.set_ret(sys_adjtimex(tf.arg(0)) as u64);
            }
            SYS_CLOCK_ADJTIME => {
                tf.set_ret(sys_clock_adjtime(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_FUTEX_WAITV => {
                tf.set_ret(
                    sys_futex_waitv(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64,
                );
            }
            SYS_FUTEX_WAKE => {
                tf.set_ret(sys_futex_wake(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_FUTEX_WAIT => {
                tf.set_ret(sys_futex_wait(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_FUTEX_REQUEUE => {
                tf.set_ret(sys_futex_requeue(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_PERSONALITY => {
                tf.set_ret(sys_personality(tf.arg(0)) as u64);
            }
            SYS_GETPRIORITY => {
                tf.set_ret(sys_getpriority(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_SETPRIORITY => {
                tf.set_ret(sys_setpriority(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_TKILL => {
                tf.set_ret(sys_tkill(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_TIME => {
                tf.set_ret(sys_time(tf.arg(0)) as u64);
            }
            SYS_TIMERFD_CREATE => {
                tf.set_ret(sys_timerfd_create(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_TIMERFD_SETTIME => {
                tf.set_ret(sys_timerfd_settime(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_TIMERFD_GETTIME => {
                tf.set_ret(sys_timerfd_gettime(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_MOUNT => {
                tf.set_ret(sys_mount(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64);
            }
            SYS_UMOUNT2 => {
                tf.set_ret(sys_umount2(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_CLOCK_GETTIME => {
                tf.set_ret(sys_clock_gettime(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_CLOCK_GETRES => {
                tf.set_ret(sys_clock_getres(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_GETTIMEOFDAY => {
                tf.set_ret(sys_gettimeofday(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_MPROTECT => {
                tf.set_ret(sys_mprotect(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_UNAME => {
                tf.set_ret(sys_uname(tf.arg(0)) as u64);
            }
            SYS_GETUID => {
                tf.set_ret(sched::with_current_creds(|c| {
                    c.uid_from_kernel(c.ruid) as u64
                }));
            }
            SYS_GETEUID => {
                tf.set_ret(sched::with_current_creds(|c| {
                    c.uid_from_kernel(c.euid) as u64
                }));
            }
            SYS_GETGID => {
                tf.set_ret(sched::with_current_creds(|c| {
                    c.gid_from_kernel(c.rgid) as u64
                }));
            }
            SYS_GETEGID => {
                tf.set_ret(sched::with_current_creds(|c| {
                    c.gid_from_kernel(c.egid) as u64
                }));
            }
            SYS_GETTID => {
                tf.set_ret(sched::current_local_pid() as u64);
            }
            SYS_GETRLIMIT => {
                tf.set_ret(sys_getrlimit(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_PRLIMIT64 => {
                tf.set_ret(sys_prlimit64(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            SYS_PRCTL => {
                tf.set_ret(sys_prctl(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3), tf.arg(4)) as u64);
            }
            SYS_CAPGET => {
                tf.set_ret(sys_capget(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_CAPSET => {
                tf.set_ret(sys_capset(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_SETHOSTNAME => {
                tf.set_ret(sys_sethostname(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_SETDOMAINNAME => {
                tf.set_ret(sys_setdomainname(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_SECCOMP => {
                tf.set_ret(sys_seccomp(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_ARCH_PRCTL => {
                tf.set_ret(sys_arch_prctl(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_SET_TID_ADDRESS => {
                tf.set_ret(sys_set_tid_address(tf.arg(0)) as u64);
            }
            SYS_SET_ROBUST_LIST => {
                tf.set_ret(sys_set_robust_list(tf.arg(0), tf.arg(1)) as u64);
            }
            SYS_GETRANDOM => {
                tf.set_ret(sys_getrandom(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
            }
            SYS_FUTEX => {
                tf.set_ret(sys_futex(
                    tf.arg(0),
                    tf.arg(1),
                    tf.arg(2),
                    tf.arg(3),
                    tf.arg(4),
                    tf.arg(5),
                ) as u64);
            }
            SYS_REBOOT => {
                tf.set_ret(sys_reboot(tf.arg(0), tf.arg(1), tf.arg(2), tf.arg(3)) as u64);
            }
            n => {
                frame::println!(
                    "[syscall] pid {} unhandled #{n} -> -ENOSYS",
                    sched::current_pid().0
                );
                tf.set_ret(ENOSYS as u64);
            }
        }
    }

    crate::ptrace::syscall_exit_hook(tf);
    sched::deliver_pending_signals(tf);
    sched::syscall_exit_account();
}
const REBOOT_MAGIC1: u64 = 0xfee1dead;
const REBOOT_MAGIC2: u64 = 0x28121969;
const REBOOT_MAGIC2A: u64 = 0x05121996;
const REBOOT_MAGIC2B: u64 = 0x16041998;
const REBOOT_MAGIC2C: u64 = 0x20112000;
const REBOOT_CMD_RESTART: u32 = 0x01234567;
const REBOOT_CMD_HALT: u32 = 0xCDEF0123;
const REBOOT_CMD_CAD_ON: u32 = 0x89ABCDEF;
const REBOOT_CMD_CAD_OFF: u32 = 0;
const REBOOT_CMD_POWER_OFF: u32 = 0x4321FEDC;

fn sys_reboot(magic1: u64, magic2: u64, cmd: u64, _arg: u64) -> i64 {
    if !crate::security::capable(crate::process_model::CAP_SYS_BOOT) {
        return EPERM;
    }
    if (magic1 as u32) as u64 != REBOOT_MAGIC1 {
        return EINVAL;
    }
    let m2 = magic2 as u32 as u64;
    if !matches!(
        m2,
        REBOOT_MAGIC2 | REBOOT_MAGIC2A | REBOOT_MAGIC2B | REBOOT_MAGIC2C
    ) {
        return EINVAL;
    }
    let cmd_u32 = cmd as u32;
    match cmd_u32 {
        REBOOT_CMD_CAD_OFF | REBOOT_CMD_CAD_ON => 0,
        REBOOT_CMD_HALT | REBOOT_CMD_POWER_OFF | REBOOT_CMD_RESTART => {
            frame::println!(
                "[reboot] cmd={:#x} requested by pid {}; halting VM",
                cmd_u32,
                sched::current_pid().0
            );
            frame::io::qemu_exit::exit(frame::io::qemu_exit::ExitCode::Success)
        }
        _ => EINVAL,
    }
}

const GRND_RANDOM: u64 = 0x2;
const GRND_NONBLOCK: u64 = 0x1;

fn sys_getrandom(buf: u64, count: u64, flags: u64) -> i64 {
    if flags & !(GRND_RANDOM | GRND_NONBLOCK) != 0 {
        return EINVAL;
    }
    if count == 0 {
        return 0;
    }
    let len = (count as usize).min(0x100_0000);
    let mut tmp = alloc::vec![0u8; len];
    crate::device::random::fill(&mut tmp);
    if frame::user::copy_to_user(buf, &tmp).is_err() {
        return EFAULT;
    }
    len as i64
}

#[allow(dead_code)]
pub fn dispatch_pre_sched(tf: &mut TrapFrame) {
    match tf.syscall_nr() {
        SYS_WRITE => {
            tf.set_ret(sys_write_pre_sched(tf.arg(0), tf.arg(1), tf.arg(2)) as u64);
        }
        SYS_EXIT | SYS_EXIT_GROUP => sys_exit_simple(tf.arg(0) as i32),
        n => {
            frame::println!("[syscall] unhandled #{n} -> -ENOSYS");
            tf.set_ret(ENOSYS as u64);
        }
    }
}

fn sys_write_pre_sched(fd: u64, buf: u64, count: u64) -> i64 {
    if fd != 1 && fd != 2 {
        return EBADF;
    }
    if count == 0 {
        return 0;
    }
    let n = (count as usize).min(fs::WRITE_BUF_MAX);
    let mut buffer = alloc::vec![0u8; n];
    if frame::user::copy_from_user(buf, &mut buffer).is_err() {
        return EFAULT;
    }
    frame::io::uart::write_bytes(&buffer);
    n as i64
}
pub fn install() {
    frame::user::register_dispatcher(dispatch);
    frame::user::register_user_fault_signal(crate::core::deliver_user_fault);
    frame::user::register_user_pf_hook(crate::mm::mmap_fault::try_handle);
    frame::user::register_irq_notify_resume(crate::core::irq_notify_resume_checkpoint);
}

pub fn install_pre_sched() {
    frame::user::register_dispatcher(dispatch_pre_sched);
}
