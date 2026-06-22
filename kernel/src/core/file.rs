use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{CPU_QUEUES, GLOBAL, current_pid, this_cpu};
use crate::process_model::{CwdState, Pid};
use crate::vfs::Inode;

fn with_current_files_mut<R>(
    f: impl FnOnce(&mut crate::process_model::FileContext) -> R,
) -> Option<R> {
    let pid = current_pid();
    GLOBAL
        .lock()
        .processes
        .get_mut(&pid)
        .map(|p| f(&mut p.files))
}

pub fn with_current_fds<R>(f: impl FnOnce(&crate::vfs::fd::FdTable) -> R) -> R {
    let pid = current_pid();
    let g = GLOBAL.lock();
    match g.processes.get(&pid) {
        Some(p) => f(&p.fds),
        None => {
            let empty = crate::vfs::fd::FdTable::new();
            f(&empty)
        }
    }
}

pub fn with_current_cwd<R>(f: impl FnOnce(&CwdState) -> R) -> Option<R> {
    let pid = CPU_QUEUES[this_cpu() as usize].lock().current?;
    let g = GLOBAL.lock();
    g.processes.get(&pid)?.files.cwd().map(f)
}

pub fn set_current_cwd(inode: Arc<dyn Inode>, path: String) {
    with_current_files_mut(|files| files.set_cwd(CwdState { inode, path })).unwrap();
}

pub fn with_current_fs_root<R>(f: impl FnOnce(&Arc<dyn Inode>) -> R) -> Option<R> {
    let pid = CPU_QUEUES[this_cpu() as usize].lock().current?;
    let g = GLOBAL.lock();
    g.processes.get(&pid)?.files.fs_root().map(f)
}

pub fn set_current_fs_root(inode: Arc<dyn Inode>) {
    with_current_files_mut(|files| files.set_fs_root(inode));
}

pub fn with_current_mount_table<R>(
    f: impl FnOnce(&Option<Arc<crate::vfs::MountTable>>) -> R,
) -> Option<R> {
    let pid = CPU_QUEUES[this_cpu() as usize].lock().current?;
    let g = GLOBAL.lock();
    Some(f(g.processes.get(&pid)?.files.mount_table()))
}

pub fn set_current_mount_table(table: Option<Arc<crate::vfs::MountTable>>) {
    with_current_files_mut(|files| files.set_mount_table(table));
}

pub fn current_umask() -> u16 {
    let pid = current_pid();
    GLOBAL
        .lock()
        .processes
        .get(&pid)
        .map(|p| p.files.umask())
        .unwrap_or(0o022)
}

pub fn set_current_umask(new: u16) -> u16 {
    with_current_files_mut(|files| {
        let prev = files.umask();
        files.set_umask(new & 0o777);
        prev
    })
    .unwrap_or(0)
}

pub fn process_open_fds(pid: Pid) -> Option<Vec<i32>> {
    let g = GLOBAL.lock();
    let proc = g.processes.get(&pid)?;
    let mut out = Vec::new();
    for i in 0..1024 {
        if proc.fds.get(i).is_some() {
            out.push(i);
        }
    }
    Some(out)
}

pub fn process_fd_size(pid: Pid) -> Option<usize> {
    GLOBAL.lock().processes.get(&pid).map(|p| p.fds.soft_cap())
}
