pub(super) fn sys_ptrace(request: u64, pid: u64, addr: u64, data: u64) -> i64 {
    crate::ptrace::do_ptrace(request, pid, addr, data)
}
