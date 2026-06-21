use alloc::vec::Vec;

use frame::io::qemu_exit::{ExitCode, exit};
use frame::user::TrapFrame;

use crate::errno::{E2BIG, EBADF, ECHILD, EFAULT, EINVAL, ENAMETOOLONG, ENOEXEC, ENOSYS, EPERM};
use crate::process::Rlimit;
use crate::sched;

use super::{AT_FDCWD, PATH_MAX, resolve_user_path};

pub(super) fn sys_fork(tf: &TrapFrame) -> i64 {
    match sched::fork_current(tf, false) {
        Ok(pid) => sched::host_to_caller_local(pid) as i64,
        Err(e) => e.errno(),
    }
}

pub(super) fn sys_vfork(tf: &TrapFrame) -> i64 {
    match sched::fork_current(tf, true) {
        Ok(child_host) => {
            sched::park_on_vfork_done(child_host);
            sched::host_to_caller_local(child_host) as i64
        }
        Err(e) => e.errno(),
    }
}

#[repr(C)]
struct Utsname {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

fn fill_utsname_field(dst: &mut [u8; 65], src: &[u8]) {
    let n = src.len().min(64);
    dst[..n].copy_from_slice(&src[..n]);
}

pub(super) fn sys_uname(buf: u64) -> i64 {
    if buf == 0 {
        return EFAULT;
    }
    let mut u = Utsname {
        sysname: [0u8; 65],
        nodename: [0u8; 65],
        release: [0u8; 65],
        version: [0u8; 65],
        machine: [0u8; 65],
        domainname: [0u8; 65],
    };
    fill_utsname_field(&mut u.sysname, b"Linux");
    let (host_str, dom_str) =
        sched::with_current_uts(|n| (n.hostname.lock().clone(), n.domainname.lock().clone()));
    fill_utsname_field(&mut u.nodename, host_str.as_bytes());
    fill_utsname_field(&mut u.release, b"6.1.0");
    fill_utsname_field(
        &mut u.version,
        concat!("#1 SMP Cyphera ", env!("CARGO_PKG_VERSION")).as_bytes(),
    );
    fill_utsname_field(&mut u.machine, b"x86_64");
    fill_utsname_field(&mut u.domainname, dom_str.as_bytes());
    const FIELD_BYTES: usize = 65;
    let mut offset = 0u64;
    for field in [
        &u.sysname,
        &u.nodename,
        &u.release,
        &u.version,
        &u.machine,
        &u.domainname,
    ] {
        if frame::user::copy_to_user(buf + offset, field).is_err() {
            return EFAULT;
        }
        offset += FIELD_BYTES as u64;
    }
    0
}

const RLIMIT_NOFILE: u64 = 7;
const RLIMIT_STACK: u64 = 3;
const RLIMIT_AS: u64 = 9;
const RLIMIT_INFINITY: u64 = u64::MAX;

pub fn default_rlimit(resource: u64) -> Rlimit {
    match resource {
        RLIMIT_NOFILE => Rlimit {
            cur: crate::vfs::fd::MAX_FDS as u64,
            max: crate::vfs::fd::HARD_MAX_FDS as u64,
        },
        RLIMIT_STACK => Rlimit {
            cur: 8 * 1024 * 1024,
            max: RLIMIT_INFINITY,
        },
        RLIMIT_AS => Rlimit {
            cur: 1 << 47,
            max: RLIMIT_INFINITY,
        },
        _ => Rlimit {
            cur: RLIMIT_INFINITY,
            max: RLIMIT_INFINITY,
        },
    }
}

fn write_rlimit_to_user(ptr: u64, r: Rlimit) -> i64 {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&r.cur.to_le_bytes());
    buf[8..16].copy_from_slice(&r.max.to_le_bytes());
    if frame::user::copy_to_user(ptr, &buf).is_err() {
        return EFAULT;
    }
    0
}

fn read_rlimit_from_user(ptr: u64) -> Result<Rlimit, i64> {
    let mut buf = [0u8; 16];
    if frame::user::copy_from_user(ptr, &mut buf).is_err() {
        return Err(EFAULT);
    }
    let cur = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let max = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    Ok(Rlimit { cur, max })
}

pub(super) fn sys_getrlimit(resource: u64, rlim_ptr: u64) -> i64 {
    if rlim_ptr == 0 {
        return EFAULT;
    }
    let r = sched::current_rlimit(resource);
    write_rlimit_to_user(rlim_ptr, r)
}

pub(super) fn sys_prlimit64(pid: u64, resource: u64, new_rlim: u64, old_rlim: u64) -> i64 {
    if pid != 0 && pid != sched::current_pid().raw() as u64 {
        return EINVAL;
    }
    if (resource as usize) >= 16 {
        return EINVAL;
    }
    if old_rlim != 0 {
        let r = sched::current_rlimit(resource);
        let rc = write_rlimit_to_user(old_rlim, r);
        if rc != 0 {
            return rc;
        }
    }
    if new_rlim != 0 {
        let r = match read_rlimit_from_user(new_rlim) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if r.cur > r.max {
            return EINVAL;
        }
        if resource == RLIMIT_NOFILE {
            if r.max as usize > crate::vfs::fd::HARD_MAX_FDS {
                return EINVAL;
            }
            sched::with_current_fds(|t| {
                t.set_soft_cap(r.cur as usize);
            });
        }
        sched::set_current_rlimit(resource, r);
    }
    0
}

pub(super) fn sys_setrlimit(resource: u64, rlim_ptr: u64) -> i64 {
    sys_prlimit64(0, resource, rlim_ptr, 0)
}

const PR_SET_PDEATHSIG: u64 = 1;
const PR_GET_PDEATHSIG: u64 = 2;
const PR_SET_DUMPABLE: u64 = 4;
const PR_GET_DUMPABLE: u64 = 3;
const PR_SET_KEEPCAPS: u64 = 8;
const PR_GET_KEEPCAPS: u64 = 7;
const PR_SET_NAME: u64 = 15;
const PR_GET_NAME: u64 = 16;
const PR_SET_SECCOMP: u64 = 22;
const PR_GET_SECCOMP: u64 = 21;
const PR_SET_CHILD_SUBREAPER: u64 = 36;
const PR_GET_CHILD_SUBREAPER: u64 = 37;
const PR_SET_NO_NEW_PRIVS: u64 = 38;
const PR_GET_NO_NEW_PRIVS: u64 = 39;

pub(super) fn sys_prctl(option: u64, arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> i64 {
    match option {
        PR_SET_NAME => {
            if arg2 == 0 {
                return EFAULT;
            }
            let mut name = [0u8; 16];
            let len = match frame::user::copy_cstr_from_user(arg2, &mut name) {
                Ok(n) => n.min(15),
                Err(_) => return EFAULT,
            };
            if len < 16 {
                name[len] = 0;
            }
            sched::set_current_name(name);
            0
        }
        PR_GET_NAME => {
            if arg2 == 0 {
                return EFAULT;
            }
            let name = sched::current_name();
            if frame::user::copy_to_user(arg2, &name).is_err() {
                return EFAULT;
            }
            0
        }
        PR_SET_NO_NEW_PRIVS => {
            if arg2 != 1 {
                return EINVAL;
            }
            sched::set_current_no_new_privs();
            0
        }
        PR_GET_NO_NEW_PRIVS => {
            if sched::current_no_new_privs() {
                1
            } else {
                0
            }
        }
        PR_SET_SECCOMP => match arg2 {
            1 => super::creds::sys_seccomp(0, 0, 0),
            2 => super::creds::sys_seccomp(1, 0, _arg3),
            _ => EINVAL,
        },
        PR_GET_SECCOMP => {
            let has = sched::current_seccomp_chain()
                .map(|c| !c.is_empty())
                .unwrap_or(false);
            if has { 2 } else { 0 }
        }
        23 => {
            if arg2 > 63 {
                return EINVAL;
            }
            if crate::security::capbset_read(arg2 as u32) {
                1
            } else {
                0
            }
        }
        24 => {
            if arg2 > 63 {
                return EINVAL;
            }
            if !crate::security::has_cap(crate::process::CAP_SETPCAP) {
                return EPERM;
            }
            crate::security::capbset_drop(arg2 as u32);
            0
        }
        PR_SET_CHILD_SUBREAPER => {
            sched::with_current_lifecycle(|l| {
                l.set_child_subreaper(arg2 != 0);
            });
            0
        }
        PR_GET_CHILD_SUBREAPER => {
            if arg2 == 0 {
                return EFAULT;
            }
            let v: i32 = sched::with_current_lifecycle(|l| if l.child_subreaper() { 1 } else { 0 })
                .unwrap_or(0);
            if frame::user::copy_to_user(arg2, &v.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        PR_SET_PDEATHSIG => {
            if arg2 > 64 {
                return EINVAL;
            }
            sched::set_current_pdeathsig(arg2 as u32);
            0
        }
        PR_GET_PDEATHSIG => {
            if arg2 == 0 {
                return EFAULT;
            }
            let v: i32 = sched::current_pdeathsig() as i32;
            if frame::user::copy_to_user(arg2, &v.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        PR_SET_DUMPABLE => {
            if arg2 > 1 {
                return EINVAL;
            }
            sched::set_current_dumpable(arg2 as u32);
            0
        }
        PR_GET_DUMPABLE => sched::current_dumpable() as i64,
        PR_SET_KEEPCAPS => {
            if arg2 > 1 {
                return EINVAL;
            }
            sched::set_current_keep_caps(arg2 != 0);
            0
        }
        PR_GET_KEEPCAPS => {
            if sched::current_keep_caps() {
                1
            } else {
                0
            }
        }
        _ => EINVAL,
    }
}

const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_SET_GS: u64 = 0x1001;
const ARCH_GET_GS: u64 = 0x1004;

pub(super) fn sys_arch_prctl(code: u64, addr: u64) -> i64 {
    match code {
        ARCH_SET_FS => {
            frame::cpu::set_user_fs_base(addr);
            sched::set_current_fs_base(addr);
            0
        }
        ARCH_GET_FS => {
            if addr == 0 {
                return EFAULT;
            }
            let v = frame::cpu::get_user_fs_base();
            if frame::user::copy_to_user(addr, &v.to_le_bytes()).is_err() {
                return EFAULT;
            }
            0
        }
        ARCH_SET_GS | ARCH_GET_GS => EINVAL,
        _ => EINVAL,
    }
}

pub(super) fn sys_set_tid_address(addr: u64) -> i64 {
    sched::set_current_clear_child_tid(addr);
    sched::current_local_pid() as i64
}

pub(super) fn sys_set_robust_list(head: u64, _len: u64) -> i64 {
    sched::set_current_robust_list(head);
    0
}

pub(super) fn sys_wait4(pid: u64, status_ptr: u64, options: u64, _rusage: u64) -> i64 {
    let raw = pid as i64;
    let target: i64 = if raw > 0 {
        match sched::caller_local_to_host(raw as u32) {
            Some(p) => p.0 as i64,
            None => return ECHILD,
        }
    } else {
        raw
    };
    match sched::wait4_current(target, options) {
        Ok(Some((_host, local_in_caller, status))) => {
            if status_ptr != 0 {
                let bytes = status.to_le_bytes();
                if frame::user::copy_to_user(status_ptr, &bytes).is_err() {
                    return EFAULT;
                }
            }
            local_in_caller as i64
        }
        Ok(None) => 0,
        Err(e) => e.errno(),
    }
}

const P_ALL: u64 = 0;
const P_PID: u64 = 1;
const P_PGID: u64 = 2;

pub(super) fn sys_waitid(idtype: u64, id: u64, info_ptr: u64, options: u64) -> i64 {
    let target: i64 = match idtype {
        P_ALL => -1,
        P_PID => {
            if id == 0 || (id as i64) < 0 {
                return EINVAL;
            }
            match sched::caller_local_to_host(id as u32) {
                Some(p) => p.0 as i64,
                None => return ECHILD,
            }
        }
        P_PGID => {
            if id == 0 {
                0
            } else {
                match sched::caller_local_to_host(id as u32) {
                    Some(p) => -(p.0 as i64),
                    None => return ECHILD,
                }
            }
        }
        _ => return EINVAL,
    };

    match sched::wait4_current(target, options) {
        Ok(Some((_host, local_in_caller, status))) => {
            if info_ptr != 0 {
                let raw = status as u32;
                let (si_code, si_status) = if raw & 0x7f == 0 {
                    (1i32, ((raw >> 8) & 0xff) as i32)
                } else {
                    (2i32, (raw & 0x7f) as i32)
                };
                let pinfo = crate::signal::SigInfo::for_child(local_in_caller, si_status, si_code);
                let bytes = pinfo.expand(crate::process::SIGCHLD).to_bytes();
                if frame::user::copy_to_user(info_ptr, &bytes).is_err() {
                    return EFAULT;
                }
            }
            0
        }
        Ok(None) => 0,
        Err(e) => e.errno(),
    }
}

const EXEC_MAX_ARGS: usize = 1024;
const EXEC_MAX_ARG_LEN: usize = 4096;
const EXEC_MAX_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn sys_execve(tf: &mut TrapFrame) -> Result<(), i64> {
    use alloc::vec;

    let mut path_buf = [0u8; PATH_MAX];
    let len = frame::user::copy_cstr_from_user(tf.rdi, &mut path_buf).map_err(|_| ENAMETOOLONG)?;
    let path = core::str::from_utf8(&path_buf[..len]).map_err(|_| EINVAL)?;

    let normalized = resolve_user_path(AT_FDCWD, path)?;

    if (normalized.starts_with("/proc/self/fd/") || normalized.starts_with("/proc/self/exe"))
        && sched::with_current_lifecycle(|l| l.did_memfd_exec()).unwrap_or(false)
    {
        return Err(-13);
    }

    let argv: Vec<Vec<u8>> = read_user_string_vec(tf.rsi, EXEC_MAX_ARGS, EXEC_MAX_ARG_LEN)?;
    let envp: Vec<Vec<u8>> = read_user_string_vec(tf.rdx, EXEC_MAX_ARGS, EXEC_MAX_ARG_LEN)?;

    let argv = if argv.is_empty() {
        alloc::vec![normalized.as_bytes().to_vec()]
    } else {
        argv
    };
    let envp_refs: Vec<&[u8]> = envp.iter().map(|v| v.as_slice()).collect();

    const MAX_SHEBANG_DEPTH: usize = 4;
    let mut normalized = normalized;
    let mut argv = argv;
    let buf: Vec<u8>;
    let exe_mode: u16;
    let exe_uid: u32;
    let exe_gid: u32;
    let mut depth = 0usize;
    loop {
        let ctx = crate::vfs::path::Context::current();
        let inode =
            crate::vfs::path::resolve(&ctx, &ctx.root, &normalized).map_err(|e| e.errno())?;
        let stat = inode.stat();
        let exec_ok =
            sched::with_current_creds(|c| c.can_access(stat.uid, stat.gid, stat.mode, 0o1));
        if !exec_ok {
            return Err(-13);
        }
        let size = stat.size as usize;
        if size == 0 {
            return Err(ENOEXEC);
        }
        if size > EXEC_MAX_BYTES {
            return Err(E2BIG);
        }
        let mut tmp = vec![0u8; size];
        let mut total = 0usize;
        while total < size {
            let n = inode
                .read_at(total as u64, &mut tmp[total..])
                .map_err(|e| e.errno())?;
            if n == 0 {
                break;
            }
            total += n;
        }
        if total != size {
            return Err(ENOEXEC);
        }
        if tmp.len() >= 2 && tmp[0] == b'#' && tmp[1] == b'!' {
            if depth >= MAX_SHEBANG_DEPTH {
                return Err(-40);
            }
            depth += 1;
            let line_end = tmp[2..]
                .iter()
                .position(|&b| b == b'\n' || b == b'\r')
                .unwrap_or(tmp.len() - 2);
            let line = &tmp[2..2 + line_end];
            let line = match line.iter().position(|&b| b != b' ' && b != b'\t') {
                Some(i) => &line[i..],
                None => return Err(ENOEXEC),
            };
            let split = line
                .iter()
                .position(|&b| b == b' ' || b == b'\t')
                .unwrap_or(line.len());
            let interp_path = &line[..split];
            let interp_arg = if split < line.len() {
                let rest = &line[split..];
                let arg_start = rest
                    .iter()
                    .position(|&b| b != b' ' && b != b'\t')
                    .unwrap_or(rest.len());
                &rest[arg_start..]
            } else {
                &[][..]
            };
            let mut new_argv: Vec<Vec<u8>> = Vec::with_capacity(argv.len() + 2);
            new_argv.push(interp_path.to_vec());
            if !interp_arg.is_empty() {
                new_argv.push(interp_arg.to_vec());
            }
            new_argv.push(normalized.as_bytes().to_vec());
            for a in argv.iter().skip(1) {
                new_argv.push(a.clone());
            }
            argv = new_argv;
            let interp_str = core::str::from_utf8(interp_path).map_err(|_| EINVAL)?;
            normalized = resolve_user_path(AT_FDCWD, interp_str)?;
            continue;
        }
        exe_mode = stat.mode;
        exe_uid = stat.uid;
        exe_gid = stat.gid;
        buf = tmp;
        break;
    }
    let argv_refs: Vec<&[u8]> = argv.iter().map(|v| v.as_slice()).collect();

    let exe_for_proc: &[u8] = if !argv_refs.is_empty() && argv_refs[0].starts_with(b"/") {
        argv_refs[0]
    } else {
        normalized.as_bytes()
    };
    let (ruid, pre_euid, rgid, pre_egid) =
        sched::with_current_creds(|c| (c.ruid, c.euid, c.rgid, c.egid));
    let nosuid = false;
    let t = crate::security::setid::exec_transition(
        exe_mode, exe_uid, exe_gid, ruid, pre_euid, rgid, pre_egid, nosuid,
    );
    sched::exec_current(
        &buf,
        exe_for_proc,
        &argv_refs,
        &envp_refs,
        t.post_euid,
        t.post_egid,
        t.secure,
        tf,
    )
    .map_err(|e| e.errno())?;

    {
        let base = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
        let mut comm = [0u8; 16];
        let n = base.len().min(15);
        comm[..n].copy_from_slice(&base.as_bytes()[..n]);
        sched::set_current_name(comm);
    }

    if t.suid_owner.is_some() || t.sgid_owner.is_some() {
        sched::with_current_creds_mut(|c| crate::security::setid::apply_exec_transition(c, &t));
    }
    Ok(())
}

pub(super) fn sys_execveat(tf: &mut TrapFrame) -> Result<(), i64> {
    use alloc::vec;

    let dirfd = tf.rdi as i32;
    let pathname_ptr = tf.rsi;
    let argv_ptr = tf.rdx;
    let envp_ptr = tf.r10;
    let flags = tf.r8;

    const AT_EMPTY_PATH: u64 = 0x1000;

    let mut path_buf = [0u8; PATH_MAX];
    let len = if pathname_ptr == 0 {
        0
    } else {
        frame::user::copy_cstr_from_user(pathname_ptr, &mut path_buf).map_err(|_| ENAMETOOLONG)?
    };
    let path = core::str::from_utf8(&path_buf[..len]).map_err(|_| EINVAL)?;

    let argv: Vec<Vec<u8>> = read_user_string_vec(argv_ptr, EXEC_MAX_ARGS, EXEC_MAX_ARG_LEN)?;
    let envp: Vec<Vec<u8>> = read_user_string_vec(envp_ptr, EXEC_MAX_ARGS, EXEC_MAX_ARG_LEN)?;

    if (flags & AT_EMPTY_PATH) != 0 && path.is_empty() {
        if sched::with_current_lifecycle(|l| l.did_memfd_exec()).unwrap_or(false) {
            return Err(-38);
        }
        let file = sched::with_current_fds(|t| t.get(dirfd)).ok_or(crate::errno::EBADF)?;
        let inode = file.inode.clone();
        let stat = inode.stat();
        let size = stat.size as usize;
        if size == 0 {
            return Err(ENOEXEC);
        }
        if size > EXEC_MAX_BYTES {
            return Err(E2BIG);
        }
        let mut buf = vec![0u8; size];
        let mut total = 0usize;
        while total < size {
            let n = inode
                .read_at(total as u64, &mut buf[total..])
                .map_err(|e| e.errno())?;
            if n == 0 {
                break;
            }
            total += n;
        }
        if total != size {
            return Err(ENOEXEC);
        }
        let argv = if argv.is_empty() {
            alloc::vec![b"/proc/self/fd".to_vec()]
        } else {
            argv
        };
        let argv_refs: Vec<&[u8]> = argv.iter().map(|v| v.as_slice()).collect();
        let envp_refs: Vec<&[u8]> = envp.iter().map(|v| v.as_slice()).collect();
        let (cur_euid, cur_egid) = sched::with_current_creds(|c| (c.euid, c.egid));
        sched::exec_current(
            &buf,
            argv_refs[0],
            &argv_refs,
            &envp_refs,
            cur_euid,
            cur_egid,
            false,
            tf,
        )
        .map_err(|e| e.errno())?;
        sched::with_current_lifecycle(|l| l.set_did_memfd_exec(true));
        return Ok(());
    }

    Err(-38)
}

fn read_user_string_vec(
    user_arr: u64,
    max_entries: usize,
    max_str_len: usize,
) -> Result<Vec<Vec<u8>>, i64> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    if user_arr == 0 {
        return Ok(out);
    }
    for i in 0..max_entries {
        let mut ptr_buf = [0u8; 8];
        frame::user::copy_from_user(user_arr + (i as u64) * 8, &mut ptr_buf).map_err(|_| EFAULT)?;
        let ptr = u64::from_le_bytes(ptr_buf);
        if ptr == 0 {
            return Ok(out);
        }
        let mut buf = alloc::vec![0u8; max_str_len];
        let len = frame::user::copy_cstr_from_user(ptr, &mut buf).map_err(|_| E2BIG)?;
        buf.truncate(len);
        out.push(buf);
    }
    Err(E2BIG)
}

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_VFORK: u64 = 0x0000_4000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;

const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_NEWUTS: u64 = 0x0400_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const CLONE_NEWTIME: u64 = 0x0000_0080;
const CLONE_NEWNET: u64 = 0x4000_0000;

pub(super) fn sys_clone(tf: &TrapFrame) -> i64 {
    do_clone(tf, tf.rdi, tf.rsi, tf.rdx, tf.r10, tf.r8)
}

fn do_clone(tf: &TrapFrame, flags: u64, child_stack: u64, ptid: u64, ctid: u64, tls: u64) -> i64 {
    let pthread_bundle = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
    let is_pthread = (flags & pthread_bundle) == pthread_bundle;

    let child_pid_result = if is_pthread {
        sched::clone_thread_current(tf, child_stack)
    } else {
        let is_vfork_via_clone = (flags & CLONE_VFORK) != 0
            && (flags & CLONE_VM) != 0
            && (flags & (CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD)) == 0;
        let unsupported_mask = if is_vfork_via_clone {
            CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
        } else {
            CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
        };
        if flags & unsupported_mask != 0 {
            frame::println!(
                "[syscall] do_clone: flags {:#x} include unsupported bit; -ENOSYS",
                flags
            );
            return ENOSYS;
        }
        if (flags & (CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNET)) != 0
            && !crate::security::has_cap(crate::process::CAP_SYS_ADMIN)
        {
            return EPERM;
        }
        if (flags & CLONE_NEWPID) != 0 {
            let parent_ns = sched::with_current_pid_ns(|p| p.clone());
            let new_ns = crate::process::PidNamespace::child(parent_ns);
            sched::set_current_pending_pid_ns(Some(new_ns));
        }
        if (flags & CLONE_NEWIPC) != 0 {
            sched::set_current_pending_ipc_ns(Some(crate::process::IpcNamespace::fresh()));
        }
        if (flags & CLONE_NEWNET) != 0 {
            sched::set_current_pending_net_ns(Some(crate::net::new_namespace()));
        }
        if child_stack != 0 {
            let mut tf_for_child = tf.clone();
            tf_for_child.rsp_user = child_stack;
            sched::fork_current(&tf_for_child, is_vfork_via_clone)
        } else {
            sched::fork_current(tf, is_vfork_via_clone)
        }
    };

    let child_pid = match child_pid_result {
        Ok(p) => p,
        Err(e) => return e.errno(),
    };

    let tid_local = sched::host_to_caller_local(child_pid) as i32;
    let tid_bytes = tid_local.to_le_bytes();
    if (flags & CLONE_PARENT_SETTID) != 0 && ptid != 0 {
        let _ = frame::user::copy_to_user(ptid, &tid_bytes);
    }
    if (flags & CLONE_CHILD_CLEARTID) != 0 {
        sched::set_clear_child_tid(child_pid, ctid);
    }
    if (flags & CLONE_CHILD_SETTID) != 0 && ctid != 0 && is_pthread {
        let _ = frame::user::copy_to_user(ctid, &tid_bytes);
    }
    if (flags & CLONE_SETTLS) != 0 {
        sched::set_fs_base(child_pid, tls);
    }
    if (flags & CLONE_VFORK) != 0 {
        sched::park_on_vfork_done(child_pid);
    }
    tid_local as i64
}

pub(super) fn sys_clone3(tf: &TrapFrame, args_ptr: u64, size: u64) -> i64 {
    const SIZE_V0: u64 = 64;
    const SIZE_V1: u64 = 88;
    if size < SIZE_V0 {
        return EINVAL;
    }
    if args_ptr == 0 {
        return EFAULT;
    }
    let mut buf = [0u8; SIZE_V1 as usize];
    let read_len = core::cmp::min(size, SIZE_V1) as usize;
    if frame::user::copy_from_user(args_ptr, &mut buf[..read_len]).is_err() {
        return EFAULT;
    }
    let read_u64 =
        |off: usize| -> u64 { u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()) };
    let flags = read_u64(0);
    let pidfd_ptr = read_u64(8);
    let ctid = read_u64(16);
    let ptid = read_u64(24);
    let exit_signal = read_u64(32);
    let stack = read_u64(40);
    let stack_size = read_u64(48);
    let tls = read_u64(56);
    let set_tid = if size as usize >= 72 { read_u64(64) } else { 0 };
    let set_tid_size = if size as usize >= 80 { read_u64(72) } else { 0 };
    let _cgroup = if size as usize >= 88 { read_u64(80) } else { 0 };

    if set_tid != 0 || set_tid_size != 0 {
        return EINVAL;
    }
    const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
    const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
    if flags & (CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP) != 0 {
        return EINVAL;
    }
    const CLONE_PIDFD: u64 = 0x1000;
    if (flags & CLONE_PIDFD) != 0 && pidfd_ptr == 0 {
        return EINVAL;
    }
    let child_stack = if stack == 0 {
        0
    } else {
        stack.wrapping_add(stack_size)
    };

    let merged_flags = (flags & !0xff) | (exit_signal & 0xff);

    let ret = do_clone(tf, merged_flags, child_stack, ptid, ctid, tls);

    if (flags & CLONE_PIDFD) != 0 && ret > 0 {
        if let Some(host) = sched::caller_local_to_host(ret as u32) {
            match crate::syscall::signal::install_pidfd(host, false) {
                Ok(fd) => {
                    if frame::user::copy_to_user(pidfd_ptr, &fd.to_le_bytes()).is_err() {
                        return EFAULT;
                    }
                }
                Err(e) => return e,
            }
        }
    }
    ret
}

pub(super) fn sys_getrusage(who: u64, usage_ptr: u64) -> i64 {
    if usage_ptr == 0 {
        return EFAULT;
    }
    const RUSAGE_SELF: u64 = 0;
    const RUSAGE_THREAD: u64 = 1;
    const RUSAGE_CHILDREN: u64 = (-1i64) as u64;
    let (utime_ns, stime_ns) = if who == RUSAGE_SELF || who == RUSAGE_THREAD {
        sched::cpu_accounting(sched::current_pid())
            .map(|a| (a.utime_ns, a.stime_ns))
            .unwrap_or((0, 0))
    } else if who == RUSAGE_CHILDREN {
        sched::cpu_accounting(sched::current_pid())
            .map(|a| (a.cutime_ns, a.cstime_ns))
            .unwrap_or((0, 0))
    } else {
        (0, 0)
    };
    let utime_sec = (utime_ns / 1_000_000_000) as i64;
    let utime_usec = ((utime_ns % 1_000_000_000) / 1_000) as i64;
    let stime_sec = (stime_ns / 1_000_000_000) as i64;
    let stime_usec = ((stime_ns % 1_000_000_000) / 1_000) as i64;
    let mut buf = [0u8; 144];
    buf[0..8].copy_from_slice(&utime_sec.to_ne_bytes());
    buf[8..16].copy_from_slice(&utime_usec.to_ne_bytes());
    buf[16..24].copy_from_slice(&stime_sec.to_ne_bytes());
    buf[24..32].copy_from_slice(&stime_usec.to_ne_bytes());
    if frame::user::copy_to_user(usage_ptr, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_times(buf_ptr: u64) -> i64 {
    let (utime_ns, stime_ns, cutime_ns, cstime_ns) = sched::cpu_accounting(sched::current_pid())
        .map(|a| (a.utime_ns, a.stime_ns, a.cutime_ns, a.cstime_ns))
        .unwrap_or((0, 0, 0, 0));
    let utime_clk = (utime_ns / 10_000_000) as i64;
    let stime_clk = (stime_ns / 10_000_000) as i64;
    let cutime_clk = (cutime_ns / 10_000_000) as i64;
    let cstime_clk = (cstime_ns / 10_000_000) as i64;
    if buf_ptr != 0 {
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&utime_clk.to_ne_bytes());
        buf[8..16].copy_from_slice(&stime_clk.to_ne_bytes());
        buf[16..24].copy_from_slice(&cutime_clk.to_ne_bytes());
        buf[24..32].copy_from_slice(&cstime_clk.to_ne_bytes());
        if frame::user::copy_to_user(buf_ptr, &buf).is_err() {
            return EFAULT;
        }
    }
    let ns = frame::cpu::clock::nanos_since_boot();
    (ns / 10_000_000) as i64
}

pub(super) fn sys_personality(_persona: u64) -> i64 {
    0
}

pub(super) fn sys_sysinfo(info_ptr: u64) -> i64 {
    if info_ptr == 0 {
        return EFAULT;
    }
    let stats = frame::mm::frame_alloc::stats();
    let total_ram_bytes = (stats.total as u64) * 4096;
    let free_ram_bytes = (stats.total.saturating_sub(stats.in_use) as u64) * 4096;
    let uptime_sec = (frame::cpu::clock::nanos_since_boot() / 1_000_000_000) as i64;
    let (l1, l5, l15) = sched::loadavg_for_sysinfo();
    let loads = [l1, l5, l15];
    let procs = sched::process_count_alive() as u16;

    let mut buf = [0u8; 112];
    buf[0..8].copy_from_slice(&uptime_sec.to_ne_bytes());
    buf[8..16].copy_from_slice(&loads[0].to_ne_bytes());
    buf[16..24].copy_from_slice(&loads[1].to_ne_bytes());
    buf[24..32].copy_from_slice(&loads[2].to_ne_bytes());
    buf[32..40].copy_from_slice(&total_ram_bytes.to_ne_bytes());
    buf[40..48].copy_from_slice(&free_ram_bytes.to_ne_bytes());
    buf[80..82].copy_from_slice(&procs.to_ne_bytes());
    let mem_unit: u32 = 1;
    buf[104..108].copy_from_slice(&mem_unit.to_ne_bytes());

    if frame::user::copy_to_user(info_ptr, &buf).is_err() {
        return EFAULT;
    }
    0
}

pub(super) fn sys_syslog(typ: u64, buf_ptr: u64, len: u64) -> i64 {
    match typ {
        0 | 1 | 6 | 7 | 8 => 0,
        2..=4 => {
            if buf_ptr == 0 || len == 0 {
                return EINVAL;
            }
            let snapshot = crate::klog::snapshot();
            let n = snapshot.len().min(len as usize);
            if n > 0 && frame::user::copy_to_user(buf_ptr, &snapshot[..n]).is_err() {
                return EFAULT;
            }
            if typ == 4 {
                crate::klog::clear();
            }
            n as i64
        }
        5 => {
            crate::klog::clear();
            0
        }
        9 => crate::klog::unread_bytes() as i64,
        10 => crate::klog::capacity() as i64,
        _ => EINVAL,
    }
}

pub(super) fn sys_unshare(flags: u64) -> i64 {
    if flags & CLONE_NEWUSER != 0 {
        let mut err: i64 = 0;
        sched::with_current_creds_mut(|c| {
            let parent = c
                .user_ns
                .clone()
                .unwrap_or_else(crate::process::UserNamespace::host);
            let new_ns = match crate::process::UserNamespace::new_child(parent, c.euid) {
                Ok(n) => n,
                Err(_) => {
                    err = EINVAL;
                    return;
                }
            };
            c.user_ns = Some(new_ns);
            c.caps_eff = crate::process::ALL_CAPS_MASK;
            c.caps_perm = crate::process::ALL_CAPS_MASK;
            c.caps_inh = crate::process::ALL_CAPS_MASK;
            c.caps_bnd = crate::process::ALL_CAPS_MASK;
        });
        if err != 0 {
            return err;
        }
    }
    const PRIV_NS: u64 = CLONE_NEWNS
        | CLONE_NEWUTS
        | CLONE_NEWIPC
        | CLONE_NEWPID
        | CLONE_NEWCGROUP
        | CLONE_NEWTIME
        | CLONE_NEWNET;
    if flags & PRIV_NS != 0 && !crate::security::has_cap(crate::process::CAP_SYS_ADMIN) {
        return EPERM;
    }
    if flags & CLONE_NEWNS != 0 {
        let snap = match sched::with_current_mount_table(|m| m.clone()).flatten() {
            Some(existing) => existing.snapshot(),
            None => crate::vfs::global_mount_table().snapshot(),
        };
        sched::set_current_mount_table(Some(snap));
    }
    if flags & CLONE_NEWUTS != 0 {
        let snap = sched::with_current_uts(|u| u.snapshot());
        sched::set_current_uts(Some(snap));
    }
    if flags & CLONE_NEWIPC != 0 {
        sched::set_current_ipc(Some(crate::process::IpcNamespace::fresh()));
    }
    if flags & CLONE_NEWNET != 0 {
        sched::set_current_net(Some(crate::net::new_namespace()));
    }
    if flags & CLONE_NEWPID != 0 {
        let parent = sched::with_current_pid_ns(|p| p.clone());
        let new_ns = crate::process::PidNamespace::child(parent);
        sched::set_current_pending_pid_ns(Some(new_ns));
    }
    if flags & CLONE_NEWCGROUP != 0 {
        let root = sched::process_cgroup(sched::current_pid()).unwrap_or_else(crate::cgroup::root);
        sched::set_current_cgroup_ns(Some(crate::process::CgroupNamespace::new(root)));
    }
    if flags & CLONE_NEWTIME != 0 {
        sched::set_current_time_ns(Some(crate::process::TimeNamespace::fresh()));
    }
    0
}

pub(super) fn sys_setns(fd: u64, nstype: u64) -> i64 {
    use crate::fdtypes::NamespaceHandle;
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let handle = match file.inode.as_namespace_handle() {
        Some(h) => h.clone(),
        None => return EINVAL,
    };
    if nstype != 0 && nstype != handle.type_flag() {
        return EINVAL;
    }
    if !crate::security::has_cap(crate::process::CAP_SYS_ADMIN) {
        return EPERM;
    }
    match handle {
        NamespaceHandle::Uts(ns) => sched::set_current_uts(Some(ns)),
        NamespaceHandle::Ipc(ns) => sched::set_current_ipc(Some(ns)),
        NamespaceHandle::Cgroup(ns) => sched::set_current_cgroup_ns(Some(ns)),
        NamespaceHandle::Time(ns) => sched::set_current_time_ns(Some(ns)),
        NamespaceHandle::Net(ns) => sched::set_current_net(Some(ns)),
        NamespaceHandle::Pid(ns) => sched::set_current_pending_pid_ns(Some(ns)),
    }
    0
}

pub(super) fn sys_exit_simple(code: i32) -> ! {
    if code == 0 {
        exit(ExitCode::Success)
    } else {
        exit(ExitCode::Failed)
    }
}
