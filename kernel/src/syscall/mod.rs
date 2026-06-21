use frame::user::TrapFrame;

use crate::sched;

use crate::errno::{EBADF, EFAULT, EINVAL, ENOSYS, EOPNOTSUPP, ESRCH};

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
    sys_fremovexattr, sys_fsetxattr, sys_fstat, sys_ftruncate, sys_getcwd, sys_getdents,
    sys_getdents64, sys_getxattr, sys_getxattrat, sys_ioctl, sys_linkat, sys_listxattr,
    sys_listxattrat, sys_lseek, sys_memfd_create, sys_mkdirat, sys_mknodat, sys_mount,
    sys_newfstatat, sys_openat, sys_openat2, sys_pipe, sys_pipe2, sys_pivot_root, sys_pread64,
    sys_preadv, sys_pwrite64, sys_pwritev, sys_read, sys_readahead, sys_readlinkat, sys_readv,
    sys_removexattr, sys_removexattrat, sys_renameat, sys_renameat2, sys_sendfile, sys_setxattr,
    sys_setxattrat, sys_splice, sys_stat, sys_statfs, sys_statx, sys_symlinkat, sys_tee,
    sys_truncate, sys_umount2, sys_unlinkat, sys_utimensat, sys_vmsplice, sys_write, sys_writev,
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
        match tf.rax {
            SYS_READ => {
                tf.rax = sys_read(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_WRITE => {
                tf.rax = sys_write(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_CLOSE => {
                tf.rax = sys_close(tf.rdi) as u64;
            }
            SYS_FSTAT => {
                tf.rax = sys_fstat(tf.rdi, tf.rsi) as u64;
            }
            SYS_LSEEK => {
                tf.rax = sys_lseek(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_GETCWD => {
                tf.rax = sys_getcwd(tf.rdi, tf.rsi) as u64;
            }
            SYS_CHDIR => {
                tf.rax = sys_chdir(tf.rdi) as u64;
            }
            SYS_GETDENTS64 => {
                tf.rax = sys_getdents64(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_OPENAT => {
                tf.rax = sys_openat(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_NEWFSTATAT => {
                tf.rax = sys_newfstatat(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_DUP => {
                tf.rax = sys_dup(tf.rdi) as u64;
            }
            SYS_DUP2 => {
                tf.rax = sys_dup2(tf.rdi, tf.rsi) as u64;
            }
            SYS_DUP3 => {
                tf.rax = sys_dup3(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_FCNTL => {
                tf.rax = sys_fcntl(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_PREAD64 => {
                tf.rax = sys_pread64(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_PWRITE64 => {
                tf.rax = sys_pwrite64(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_READV => {
                tf.rax = sys_readv(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_WRITEV => {
                tf.rax = sys_writev(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_IOCTL => {
                tf.rax = sys_ioctl(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_PIPE => {
                tf.rax = sys_pipe(tf.rdi) as u64;
            }
            SYS_PIPE2 => {
                tf.rax = sys_pipe2(tf.rdi, tf.rsi) as u64;
            }
            SYS_MKDIRAT => {
                tf.rax = sys_mkdirat(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_UNLINKAT => {
                tf.rax = sys_unlinkat(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_RENAMEAT => {
                tf.rax = sys_renameat(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_LINKAT => {
                tf.rax = sys_linkat(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_SYMLINKAT => {
                tf.rax = sys_symlinkat(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_READLINKAT => {
                tf.rax = sys_readlinkat(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_STAT => {
                tf.rax = sys_stat(tf.rdi, tf.rsi, false) as u64;
            }
            SYS_LSTAT => {
                tf.rax = sys_stat(tf.rdi, tf.rsi, true) as u64;
            }
            SYS_STATX => {
                tf.rax = sys_statx(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_ACCESS => {
                tf.rax = sys_faccessat(AT_FDCWD as u64, tf.rdi, tf.rsi, 0) as u64;
            }
            SYS_FACCESSAT => {
                tf.rax = sys_faccessat(tf.rdi, tf.rsi, tf.rdx, 0) as u64;
            }
            SYS_FACCESSAT2 => {
                tf.rax = sys_faccessat(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_UMASK => {
                tf.rax = sched::set_current_umask(tf.rdi as u16) as u64;
            }
            SYS_CHMOD => {
                tf.rax = sys_fchmodat(AT_FDCWD as u64, tf.rdi, tf.rsi) as u64;
            }
            SYS_FCHMOD => {
                tf.rax = sys_fchmod(tf.rdi, tf.rsi) as u64;
            }
            SYS_FCHMODAT => {
                tf.rax = sys_fchmodat(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_CHOWN | SYS_LCHOWN => {
                tf.rax = sys_fchownat(AT_FDCWD as u64, tf.rdi, tf.rsi, tf.rdx, 0) as u64;
            }
            SYS_FCHOWN => {
                tf.rax = sys_fchown(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_FCHOWNAT => {
                tf.rax = sys_fchownat(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_TRUNCATE => {
                tf.rax = sys_truncate(tf.rdi, tf.rsi) as u64;
            }
            SYS_FTRUNCATE => {
                tf.rax = sys_ftruncate(tf.rdi, tf.rsi) as u64;
            }
            SYS_UNLINK => {
                tf.rax = sys_unlinkat(AT_FDCWD as u64, tf.rdi, 0) as u64;
            }
            SYS_RMDIR => {
                tf.rax = sys_unlinkat(AT_FDCWD as u64, tf.rdi, AT_REMOVEDIR) as u64;
            }
            SYS_LINK => {
                tf.rax = sys_linkat(AT_FDCWD as u64, tf.rdi, AT_FDCWD as u64, tf.rsi, 0) as u64;
            }
            SYS_SYMLINK => {
                tf.rax = sys_symlinkat(tf.rdi, AT_FDCWD as u64, tf.rsi) as u64;
            }
            SYS_READLINK => {
                tf.rax = sys_readlinkat(AT_FDCWD as u64, tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_RENAME => {
                tf.rax = sys_renameat2(AT_FDCWD as u64, tf.rdi, AT_FDCWD as u64, tf.rsi, 0) as u64;
            }
            SYS_RENAMEAT2 => {
                tf.rax = sys_renameat2(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_MKDIR => {
                tf.rax = sys_mkdirat(AT_FDCWD as u64, tf.rdi, tf.rsi) as u64;
            }
            SYS_MKNOD => {
                tf.rax = sys_mknodat(AT_FDCWD as u64, tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_MKNODAT => {
                tf.rax = sys_mknodat(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_STATFS => {
                tf.rax = sys_statfs(tf.rdi, tf.rsi, false) as u64;
            }
            SYS_FSTATFS => {
                tf.rax = sys_statfs(tf.rdi, tf.rsi, true) as u64;
            }
            SYS_FSYNC | SYS_FDATASYNC | SYS_SYNC | SYS_SYNC_FILE_RANGE => {
                tf.rax = 0;
            }
            SYS_CHROOT => {
                tf.rax = sys_chroot(tf.rdi) as u64;
            }
            SYS_UNSHARE => {
                tf.rax = sys_unshare(tf.rdi) as u64;
            }
            SYS_SETNS => {
                tf.rax = sys_setns(tf.rdi, tf.rsi) as u64;
            }
            SYS_OPEN_LEGACY => {
                tf.rax = sys_openat(AT_FDCWD as u64, tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_CREAT => {
                const O_CREAT_WRONLY_TRUNC: u64 = 0o100 | 0o1 | 0o1000;
                tf.rax = sys_openat(AT_FDCWD as u64, tf.rdi, O_CREAT_WRONLY_TRUNC, tf.rsi) as u64;
            }
            SYS_GETDENTS_LEGACY => {
                tf.rax = sys_getdents(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_FCHDIR => {
                tf.rax = sys_fchdir(tf.rdi) as u64;
            }
            SYS_FALLOCATE => {
                tf.rax = sys_fallocate(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_FLOCK => {
                tf.rax = sys_flock(tf.rdi, tf.rsi) as u64;
            }
            SYS_FADVISE64 => {
                tf.rax = sys_fadvise64(tf.rdi) as u64;
            }
            SYS_MADVISE => {
                tf.rax = sys_madvise(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_POLL => {
                tf.rax = sys_poll(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_PPOLL => {
                tf.rax = sys_ppoll(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_SELECT => {
                tf.rax = sys_select(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_PSELECT6 => {
                tf.rax = sys_pselect6(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_PREADV | SYS_PREADV2 => {
                tf.rax = sys_preadv(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_PWRITEV | SYS_PWRITEV2 => {
                tf.rax = sys_pwritev(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_SENDFILE => {
                tf.rax = sys_sendfile(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_COPY_FILE_RANGE => {
                tf.rax = sys_copy_file_range(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_SPLICE => {
                tf.rax = sys_splice(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_TEE => {
                tf.rax = sys_tee(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_VMSPLICE => {
                tf.rax = sys_vmsplice(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_PIVOT_ROOT => {
                tf.rax = sys_pivot_root(tf.rdi, tf.rsi) as u64;
            }
            SYS_OPENAT2 => {
                tf.rax = sys_openat2(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_FCHMODAT2 => {
                tf.rax = sys_fchmodat(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SETXATTRAT => {
                tf.rax = sys_setxattrat(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_GETXATTRAT => {
                tf.rax = sys_getxattrat(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_LISTXATTRAT => {
                tf.rax = sys_listxattrat(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_REMOVEXATTRAT => {
                tf.rax = sys_removexattrat(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_CLOSE_RANGE => {
                tf.rax = sys_close_range(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_GETGROUPS => {
                tf.rax = sys_getgroups(tf.rdi, tf.rsi) as u64;
            }
            SYS_SETGROUPS => {
                tf.rax = sys_setgroups(tf.rdi, tf.rsi) as u64;
            }
            SYS_GETRESUID => {
                tf.rax = sys_getresuid(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_GETRESGID => {
                tf.rax = sys_getresgid(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SETRESUID => {
                tf.rax = sys_setresuid(tf.rdi as u32, tf.rsi as u32, tf.rdx as u32) as u64;
            }
            SYS_SETRESGID => {
                tf.rax = sys_setresgid(tf.rdi as u32, tf.rsi as u32, tf.rdx as u32) as u64;
            }
            SYS_SETUID => {
                tf.rax = sys_setuid(tf.rdi as u32) as u64;
            }
            SYS_SETGID => {
                tf.rax = sys_setgid(tf.rdi as u32) as u64;
            }
            SYS_SETREUID => {
                tf.rax = sys_setreuid(tf.rdi as u32, tf.rsi as u32) as u64;
            }
            SYS_SETREGID => {
                tf.rax = sys_setregid(tf.rdi as u32, tf.rsi as u32) as u64;
            }
            SYS_SETFSUID => {
                tf.rax = sys_setfsuid(tf.rdi as u32) as u64;
            }
            SYS_SETFSGID => {
                tf.rax = sys_setfsgid(tf.rdi as u32) as u64;
            }
            SYS_UTIMENSAT => {
                tf.rax = sys_utimensat(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_SETXATTR => {
                tf.rax = sys_setxattr(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, false) as u64;
            }
            SYS_LSETXATTR => {
                tf.rax = sys_setxattr(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, true) as u64;
            }
            SYS_FSETXATTR => {
                tf.rax = sys_fsetxattr(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_GETXATTR | SYS_LGETXATTR => {
                tf.rax = sys_getxattr(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_FGETXATTR => {
                tf.rax = sys_fgetxattr(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_LISTXATTR | SYS_LLISTXATTR => {
                tf.rax = sys_listxattr(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_FLISTXATTR => {
                tf.rax = sys_flistxattr(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_REMOVEXATTR | SYS_LREMOVEXATTR => {
                tf.rax = sys_removexattr(tf.rdi, tf.rsi) as u64;
            }
            SYS_FREMOVEXATTR => {
                tf.rax = sys_fremovexattr(tf.rdi, tf.rsi) as u64;
            }
            SYS_SOCKET => {
                tf.rax = sys_socket(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SOCKETPAIR => {
                tf.rax = sys_socketpair(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_BIND => {
                tf.rax = sys_bind(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_LISTEN => {
                tf.rax = sys_listen(tf.rdi, tf.rsi) as u64;
            }
            SYS_ACCEPT | SYS_ACCEPT4 => {
                tf.rax = sys_accept(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_CONNECT => {
                tf.rax = sys_connect(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SENDTO => {
                tf.rax = sys_sendto(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_RECVFROM => {
                tf.rax = sys_recvfrom(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_SENDMSG => {
                tf.rax = sys_sendmsg(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_RECVMSG => {
                tf.rax = sys_recvmsg(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SHUTDOWN => {
                tf.rax = sys_shutdown(tf.rdi, tf.rsi) as u64;
            }
            SYS_GETSOCKNAME => {
                tf.rax = sys_getsockname(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_GETPEERNAME => {
                tf.rax = sys_getpeername(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SETSOCKOPT => {
                tf.rax = sys_setsockopt(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_GETSOCKOPT => {
                tf.rax = sys_getsockopt(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_EPOLL_CREATE1 => {
                tf.rax = sys_epoll_create1(tf.rdi) as u64;
            }
            SYS_EPOLL_CTL => {
                tf.rax = sys_epoll_ctl(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_EPOLL_WAIT => {
                tf.rax = sys_epoll_wait(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_EPOLL_PWAIT => {
                tf.rax = sys_epoll_pwait(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_EPOLL_PWAIT2 => {
                tf.rax = sys_epoll_pwait2(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_MMAP => {
                tf.rax = sys_mmap(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_MUNMAP => {
                tf.rax = sys_munmap(tf.rdi, tf.rsi) as u64;
            }
            SYS_MREMAP => {
                tf.rax = sys_mremap(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_MSYNC => {
                tf.rax = sys_msync(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_BRK => {
                tf.rax = sys_brk(tf.rdi);
            }
            SYS_RT_SIGACTION => {
                tf.rax = sys_rt_sigaction(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_RT_SIGPROCMASK => {
                tf.rax = sys_rt_sigprocmask(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_RT_SIGRETURN => {
                sys_rt_sigreturn(tf);
                return;
            }
            SYS_SCHED_SETAFFINITY => {
                let (pid, size, ptr) = (tf.rdi, tf.rsi, tf.rdx);
                tf.rax = sys_sched_setaffinity(tf, pid, size, ptr) as u64;
            }
            SYS_SCHED_GETAFFINITY => {
                tf.rax = sys_sched_getaffinity(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SCHED_YIELD => {
                sched::yield_current(tf);
            }
            SYS_SCHED_SETSCHEDULER => {
                tf.rax = sys_sched_setscheduler(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SCHED_GETSCHEDULER => {
                tf.rax = sys_sched_getscheduler(tf.rdi) as u64;
            }
            SYS_SCHED_SETPARAM => {
                tf.rax = sys_sched_setparam(tf.rdi, tf.rsi) as u64;
            }
            SYS_SCHED_GETPARAM => {
                tf.rax = sys_sched_getparam(tf.rdi, tf.rsi) as u64;
            }
            SYS_SCHED_GET_PRIORITY_MAX => {
                tf.rax = sys_sched_get_priority_max(tf.rdi) as u64;
            }
            SYS_SCHED_GET_PRIORITY_MIN => {
                tf.rax = sys_sched_get_priority_min(tf.rdi) as u64;
            }
            SYS_SCHED_RR_GET_INTERVAL => {
                tf.rax = sys_sched_rr_get_interval(tf.rdi, tf.rsi) as u64;
            }
            SYS_SCHED_SETATTR => {
                tf.rax = sys_sched_setattr(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SCHED_GETATTR => {
                tf.rax = sys_sched_getattr(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_NANOSLEEP => {
                tf.rax = sys_nanosleep(tf.rdi, tf.rsi) as u64;
            }
            SYS_FORK => {
                tf.rax = sys_fork(tf) as u64;
            }
            SYS_VFORK => {
                tf.rax = sys_vfork(tf) as u64;
            }
            SYS_CLONE => {
                tf.rax = sys_clone(tf) as u64;
            }
            SYS_CLONE3 => {
                tf.rax = sys_clone3(tf, tf.rdi, tf.rsi) as u64;
            }
            SYS_EXECVE => {
                if let Err(errno) = sys_execve(tf) {
                    tf.rax = errno as u64;
                }
            }
            SYS_EXECVEAT => {
                if let Err(errno) = sys_execveat(tf) {
                    tf.rax = errno as u64;
                }
            }
            SYS_GETPID => {
                tf.rax = sched::host_to_caller_local(sched::current_tgid()) as u64;
            }
            SYS_KILL => {
                tf.rax = sys_kill(tf.rdi, tf.rsi) as u64;
            }
            SYS_EXIT => {
                sched::exit_current(tf, tf.rdi as i32);
            }
            SYS_EXIT_GROUP => {
                sched::exit_group_current(tf, tf.rdi as i32);
            }
            SYS_WAIT4 => {
                tf.rax = sys_wait4(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_WAITID => {
                tf.rax = sys_waitid(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_SIGALTSTACK => {
                tf.rax = sys_sigaltstack(tf.rdi, tf.rsi, tf.rsp_user) as u64;
            }
            SYS_TGKILL => {
                tf.rax = sys_tgkill(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_GETPPID => {
                let parent_host = sched::current_parent_pid();
                if parent_host == 0 {
                    tf.rax = 0u64;
                } else {
                    tf.rax = sched::host_to_caller_local(crate::process::Pid(parent_host)) as u64;
                }
            }
            SYS_GETPGRP => {
                tf.rax = sched::host_to_caller_local(sched::current_pgid()) as u64;
            }
            SYS_GETPGID => {
                let target_host = if tf.rdi as u32 == 0 {
                    sched::current_pid()
                } else {
                    match sched::caller_local_to_host(tf.rdi as u32) {
                        Some(p) => p,
                        None => {
                            tf.rax = ESRCH as u64;
                            return;
                        }
                    }
                };
                tf.rax = match sched::getpgid(target_host) {
                    Ok(p) => sched::host_to_caller_local(p) as u64,
                    Err(e) => e as u64,
                };
            }
            SYS_SETPGID => {
                let target_host = if tf.rdi as u32 == 0 {
                    sched::current_pid()
                } else {
                    match sched::caller_local_to_host(tf.rdi as u32) {
                        Some(p) => p,
                        None => {
                            tf.rax = ESRCH as u64;
                            return;
                        }
                    }
                };
                let new_pgid_host = if tf.rsi as u32 == 0 {
                    target_host
                } else {
                    match sched::caller_local_to_host(tf.rsi as u32) {
                        Some(p) => p,
                        None => {
                            tf.rax = ESRCH as u64;
                            return;
                        }
                    }
                };
                tf.rax = match sched::setpgid(target_host, new_pgid_host) {
                    Ok(()) => 0,
                    Err(e) => e as u64,
                };
            }
            SYS_SETSID => {
                tf.rax = match sched::setsid() {
                    Ok(p) => sched::host_to_caller_local(p) as u64,
                    Err(e) => e as u64,
                };
            }
            SYS_GETSID => {
                let target_host = if tf.rdi as u32 == 0 {
                    sched::current_pid()
                } else {
                    match sched::caller_local_to_host(tf.rdi as u32) {
                        Some(p) => p,
                        None => {
                            tf.rax = ESRCH as u64;
                            return;
                        }
                    }
                };
                tf.rax = match sched::getsid(target_host) {
                    Ok(p) => sched::host_to_caller_local(p) as u64,
                    Err(e) => e as u64,
                };
            }
            SYS_PIDFD_OPEN => {
                tf.rax = sys_pidfd_open(tf.rdi, tf.rsi) as u64;
            }
            SYS_PIDFD_SEND_SIGNAL => {
                tf.rax = sys_pidfd_send_signal(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_SIGNALFD4 => {
                tf.rax = sys_signalfd4(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_EVENTFD2 => {
                tf.rax = sys_eventfd2(tf.rdi, tf.rsi) as u64;
            }
            SYS_MEMFD_CREATE => {
                tf.rax = sys_memfd_create(tf.rdi, tf.rsi) as u64;
            }
            SYS_RSEQ => {
                tf.rax = sys_rseq(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_PAUSE => {
                tf.rax = sys_pause() as u64;
            }
            SYS_RT_SIGTIMEDWAIT => {
                tf.rax = sys_rt_sigtimedwait(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_GETITIMER => {
                tf.rax = sys_getitimer(tf.rdi, tf.rsi) as u64;
            }
            SYS_SETITIMER => {
                tf.rax = sys_setitimer(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SHMGET => {
                tf.rax = sys_shmget(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SHMAT => {
                tf.rax = sys_shmat(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SHMCTL => {
                tf.rax = sys_shmctl(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_SHMDT => {
                tf.rax = sys_shmdt(tf.rdi) as u64;
            }
            SYS_KEYCTL => {
                tf.rax = sys_keyctl(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_ADD_KEY | SYS_REQUEST_KEY => {
                tf.rax = (-95i64) as u64;
            }
            SYS_GETRUSAGE => {
                tf.rax = sys_getrusage(tf.rdi, tf.rsi) as u64;
            }
            SYS_TIMES => {
                tf.rax = sys_times(tf.rdi) as u64;
            }
            SYS_SYSINFO => {
                tf.rax = sys_sysinfo(tf.rdi) as u64;
            }
            SYS_SYSLOG => {
                tf.rax = sys_syslog(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_PTRACE => {
                tf.rax = sys_ptrace(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_MINCORE => {
                tf.rax = sys_mincore(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_ALARM => {
                tf.rax = sys_alarm(tf.rdi) as u64;
            }
            SYS_RT_SIGPENDING => {
                tf.rax = sys_rt_sigpending(tf.rdi, tf.rsi) as u64;
            }
            SYS_RT_SIGQUEUEINFO => {
                tf.rax = sys_rt_sigqueueinfo(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_RT_SIGSUSPEND => {
                tf.rax = sys_rt_sigsuspend(tf.rdi, tf.rsi) as u64;
            }
            SYS_MLOCK => {
                tf.rax = sys_mlock(tf.rdi, tf.rsi) as u64;
            }
            SYS_MUNLOCK => {
                tf.rax = sys_munlock(tf.rdi, tf.rsi) as u64;
            }
            SYS_MLOCKALL => {
                tf.rax = sys_mlockall(tf.rdi) as u64;
            }
            SYS_MUNLOCKALL => {
                tf.rax = sys_munlockall() as u64;
            }
            SYS_SETRLIMIT => {
                tf.rax = sys_setrlimit(tf.rdi, tf.rsi) as u64;
            }
            SYS_CLOCK_NANOSLEEP => {
                tf.rax = sys_clock_nanosleep(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_RT_TGSIGQUEUEINFO => {
                tf.rax = sys_rt_tgsigqueueinfo(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_GETCPU => {
                tf.rax = sys_getcpu(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_PROCESS_VM_READV => {
                tf.rax = sys_process_vm_readv(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_PROCESS_VM_WRITEV => {
                tf.rax = sys_process_vm_writev(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_MEMBARRIER => {
                tf.rax = sys_membarrier(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_MLOCK2 => {
                tf.rax = sys_mlock2(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_PKEY_MPROTECT | SYS_PKEY_ALLOC | SYS_PKEY_FREE => {
                tf.rax = EOPNOTSUPP as u64;
            }
            SYS_READAHEAD => {
                tf.rax = sys_readahead(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_EPOLL_CREATE => {
                if (tf.rdi as i64) <= 0 {
                    tf.rax = EINVAL as u64;
                } else {
                    tf.rax = sys_epoll_create1(0) as u64;
                }
            }
            SYS_EVENTFD => {
                tf.rax = sys_eventfd2(tf.rdi, 0) as u64;
            }
            SYS_MBIND => {
                tf.rax = sys_mbind(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_SET_MEMPOLICY => {
                tf.rax = sys_set_mempolicy(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_GET_MEMPOLICY => {
                tf.rax = sys_get_mempolicy(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_SET_MEMPOLICY_HOME_NODE => {
                tf.rax = sys_set_mempolicy_home_node(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_SETTIMEOFDAY => {
                tf.rax = sys_settimeofday(tf.rdi, tf.rsi) as u64;
            }
            SYS_CLOCK_SETTIME => {
                tf.rax = sys_clock_settime(tf.rdi, tf.rsi) as u64;
            }
            SYS_ADJTIMEX => {
                tf.rax = sys_adjtimex(tf.rdi) as u64;
            }
            SYS_CLOCK_ADJTIME => {
                tf.rax = sys_clock_adjtime(tf.rdi, tf.rsi) as u64;
            }
            SYS_FUTEX_WAITV => {
                tf.rax = sys_futex_waitv(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_FUTEX_WAKE => {
                tf.rax = sys_futex_wake(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_FUTEX_WAIT => {
                tf.rax = sys_futex_wait(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_FUTEX_REQUEUE => {
                tf.rax = sys_futex_requeue(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_PERSONALITY => {
                tf.rax = sys_personality(tf.rdi) as u64;
            }
            SYS_GETPRIORITY => {
                tf.rax = sys_getpriority(tf.rdi, tf.rsi) as u64;
            }
            SYS_SETPRIORITY => {
                tf.rax = sys_setpriority(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_TKILL => {
                tf.rax = sys_tkill(tf.rdi, tf.rsi) as u64;
            }
            SYS_TIME => {
                tf.rax = sys_time(tf.rdi) as u64;
            }
            SYS_TIMERFD_CREATE => {
                tf.rax = sys_timerfd_create(tf.rdi, tf.rsi) as u64;
            }
            SYS_TIMERFD_SETTIME => {
                tf.rax = sys_timerfd_settime(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_TIMERFD_GETTIME => {
                tf.rax = sys_timerfd_gettime(tf.rdi, tf.rsi) as u64;
            }
            SYS_MOUNT => {
                tf.rax = sys_mount(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_UMOUNT2 => {
                tf.rax = sys_umount2(tf.rdi, tf.rsi) as u64;
            }
            SYS_CLOCK_GETTIME => {
                tf.rax = sys_clock_gettime(tf.rdi, tf.rsi) as u64;
            }
            SYS_CLOCK_GETRES => {
                tf.rax = sys_clock_getres(tf.rdi, tf.rsi) as u64;
            }
            SYS_GETTIMEOFDAY => {
                tf.rax = sys_gettimeofday(tf.rdi, tf.rsi) as u64;
            }
            SYS_MPROTECT => {
                tf.rax = sys_mprotect(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_UNAME => {
                tf.rax = sys_uname(tf.rdi) as u64;
            }
            SYS_GETUID => {
                tf.rax = sched::with_current_creds(|c| c.uid_from_kernel(c.ruid) as u64);
            }
            SYS_GETEUID => {
                tf.rax = sched::with_current_creds(|c| c.uid_from_kernel(c.euid) as u64);
            }
            SYS_GETGID => {
                tf.rax = sched::with_current_creds(|c| c.gid_from_kernel(c.rgid) as u64);
            }
            SYS_GETEGID => {
                tf.rax = sched::with_current_creds(|c| c.gid_from_kernel(c.egid) as u64);
            }
            SYS_GETTID => {
                tf.rax = sched::current_local_pid() as u64;
            }
            SYS_GETRLIMIT => {
                tf.rax = sys_getrlimit(tf.rdi, tf.rsi) as u64;
            }
            SYS_PRLIMIT64 => {
                tf.rax = sys_prlimit64(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            SYS_PRCTL => {
                tf.rax = sys_prctl(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8) as u64;
            }
            SYS_CAPGET => {
                tf.rax = sys_capget(tf.rdi, tf.rsi) as u64;
            }
            SYS_CAPSET => {
                tf.rax = sys_capset(tf.rdi, tf.rsi) as u64;
            }
            SYS_SETHOSTNAME => {
                tf.rax = sys_sethostname(tf.rdi, tf.rsi) as u64;
            }
            SYS_SETDOMAINNAME => {
                tf.rax = sys_setdomainname(tf.rdi, tf.rsi) as u64;
            }
            SYS_SECCOMP => {
                tf.rax = sys_seccomp(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_ARCH_PRCTL => {
                tf.rax = sys_arch_prctl(tf.rdi, tf.rsi) as u64;
            }
            SYS_SET_TID_ADDRESS => {
                tf.rax = sys_set_tid_address(tf.rdi) as u64;
            }
            SYS_SET_ROBUST_LIST => {
                tf.rax = sys_set_robust_list(tf.rdi, tf.rsi) as u64;
            }
            SYS_GETRANDOM => {
                tf.rax = sys_getrandom(tf.rdi, tf.rsi, tf.rdx) as u64;
            }
            SYS_FUTEX => {
                tf.rax = sys_futex(tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8, tf.r9) as u64;
            }
            SYS_REBOOT => {
                tf.rax = sys_reboot(tf.rdi, tf.rsi, tf.rdx, tf.r10) as u64;
            }
            n => {
                frame::println!(
                    "[syscall] pid {} unhandled #{n} -> -ENOSYS",
                    sched::current_pid().0
                );
                tf.rax = ENOSYS as u64;
            }
        }
    }

    crate::ptrace::syscall_exit_hook(tf);
    sched::deliver_pending_signals(tf);
    sched::syscall_exit_account();
}
const LINUX_REBOOT_MAGIC1: u64 = 0xfee1dead;
const LINUX_REBOOT_MAGIC2: u64 = 0x28121969;
const LINUX_REBOOT_MAGIC2A: u64 = 0x05121996;
const LINUX_REBOOT_MAGIC2B: u64 = 0x16041998;
const LINUX_REBOOT_MAGIC2C: u64 = 0x20112000;
const LINUX_REBOOT_CMD_RESTART: u32 = 0x01234567;
const LINUX_REBOOT_CMD_HALT: u32 = 0xCDEF0123;
const LINUX_REBOOT_CMD_CAD_ON: u32 = 0x89ABCDEF;
const LINUX_REBOOT_CMD_CAD_OFF: u32 = 0;
const LINUX_REBOOT_CMD_POWER_OFF: u32 = 0x4321FEDC;

fn sys_reboot(magic1: u64, magic2: u64, cmd: u64, _arg: u64) -> i64 {
    if !crate::security::capable(crate::process::CAP_SYS_BOOT) {
        return -1;
    }
    if (magic1 as u32) as u64 != LINUX_REBOOT_MAGIC1 {
        return EINVAL;
    }
    let m2 = magic2 as u32 as u64;
    if !matches!(
        m2,
        LINUX_REBOOT_MAGIC2 | LINUX_REBOOT_MAGIC2A | LINUX_REBOOT_MAGIC2B | LINUX_REBOOT_MAGIC2C
    ) {
        return EINVAL;
    }
    let cmd_u32 = cmd as u32;
    match cmd_u32 {
        LINUX_REBOOT_CMD_CAD_OFF | LINUX_REBOOT_CMD_CAD_ON => 0,
        LINUX_REBOOT_CMD_HALT | LINUX_REBOOT_CMD_POWER_OFF | LINUX_REBOOT_CMD_RESTART => {
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
    crate::random::fill(&mut tmp);
    if frame::user::copy_to_user(buf, &tmp).is_err() {
        return EFAULT;
    }
    len as i64
}

#[allow(dead_code)]
pub fn dispatch_pre_sched(tf: &mut TrapFrame) {
    match tf.rax {
        SYS_WRITE => {
            tf.rax = sys_write_pre_sched(tf.rdi, tf.rsi, tf.rdx) as u64;
        }
        SYS_EXIT | SYS_EXIT_GROUP => sys_exit_simple(tf.rdi as i32),
        n => {
            frame::println!("[syscall] unhandled #{n} -> -ENOSYS");
            tf.rax = ENOSYS as u64;
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
    frame::user::register_user_fault_handler(user_fault_handler);
    frame::user::register_user_pf_hook(crate::mmap_fault::try_handle);
    frame::user::register_irq_notify_resume(crate::sched::irq_notify_resume_checkpoint);
}

fn user_fault_handler(addr: u64, vector: u8, error: u64) -> ! {
    crate::sched::kill_user_fault(addr, vector, error)
}

pub fn install_pre_sched() {
    frame::user::register_dispatcher(dispatch_pre_sched);
}
