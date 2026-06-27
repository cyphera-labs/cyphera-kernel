use super::*;

pub(crate) fn sys_write(fd: u64, buf: u64, count: u64) -> i64 {
    if count == 0 {
        return 0;
    }
    let n = (count as usize).min(WRITE_BUF_MAX);
    let mut buffer = alloc::vec![0u8; n];
    if frame::user::copy_from_user(buf, &mut buffer).is_err() {
        return EFAULT;
    }
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    match file.write(&buffer) {
        Ok(w) => {
            if crate::fsnotify::watching()
                && matches!(file.inode.kind(), crate::vfs::InodeKind::Regular)
            {
                crate::fsnotify::self_event(file.inode.as_ref(), crate::fsnotify::IN_MODIFY);
            }
            w as i64
        }
        Err(e) => write_err_to_errno(e),
    }
}

pub(crate) fn write_err_to_errno(e: Errno) -> i64 {
    if e == Errno::PIPE {
        const SIGPIPE: u32 = 13;
        let pid = sched::current_pid();
        let info = crate::core::signal::SigInfo::for_fault(SIGPIPE, 0);
        let _ = sched::send_signal_with_info(pid, SIGPIPE, info);
    }
    e.as_neg_i64()
}

pub(crate) fn sys_read(fd: u64, buf: u64, count: u64) -> i64 {
    if count == 0 {
        return 0;
    }
    let n = (count as usize).min(READ_BUF_MAX);
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let mut tmp = alloc::vec![0u8; n];
    let read = match file.read(&mut tmp) {
        Ok(r) => r,
        Err(e) => return e.as_neg_i64(),
    };
    if read > 0 && frame::user::copy_to_user(buf, &tmp[..read]).is_err() {
        return EFAULT;
    }
    read as i64
}

pub(crate) fn sys_lseek(fd: u64, offset: u64, whence: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let w = match whence {
        0 => Whence::Set,
        1 => Whence::Cur,
        2 => Whence::End,
        _ => return EINVAL,
    };
    match file.seek(w, offset as i64) {
        Ok(p) => p as i64,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_fsync(fd: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if matches!(file.inode.kind(), InodeKind::Pipe | InodeKind::Socket) {
        return EINVAL;
    }
    let inode_id = file.inode.inode_id();
    match crate::fs::pagecache::writeback(inode_id, 0, u64::MAX, &*file.inode) {
        Ok(_) => 0,
        Err(_) => EIO,
    }
}

pub(crate) fn sys_sync_file_range(fd: u64, offset: u64, nbytes: u64, flags: u64) -> i64 {
    const SYNC_FILE_RANGE_WAIT_BEFORE: u64 = 1;
    const SYNC_FILE_RANGE_WRITE: u64 = 2;
    const SYNC_FILE_RANGE_WAIT_AFTER: u64 = 4;
    const VALID: u64 =
        SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    if flags & !VALID != 0 {
        return EINVAL;
    }
    if (offset as i64) < 0 || (nbytes as i64) < 0 {
        return EINVAL;
    }
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if matches!(file.inode.kind(), InodeKind::Pipe | InodeKind::Socket) {
        return crate::errno::ESPIPE;
    }
    let end = if nbytes == 0 {
        u64::MAX
    } else {
        offset.saturating_add(nbytes)
    };
    let inode_id = file.inode.inode_id();
    match crate::fs::pagecache::writeback(inode_id, offset, end, &*file.inode) {
        Ok(_) => 0,
        Err(_) => EIO,
    }
}

pub(crate) fn sys_dup(fd: u64) -> i64 {
    sched::with_current_fds(|t| match t.get(fd as i32) {
        Some(of) => t.install(of).unwrap_or(EMFILE as i32) as i64,
        None => EBADF,
    })
}

pub(crate) fn sys_dup2(oldfd: u64, newfd: u64) -> i64 {
    let (ret, displaced) =
        sched::with_current_fds(|t| match t.dup_to(oldfd as i32, newfd as i32, 0) {
            Ok((fd, displaced)) => (fd as i64, displaced),
            Err(e) => (e as i64, None),
        });
    drop(displaced);
    ret
}

pub(crate) fn sys_dup3(oldfd: u64, newfd: u64, flags: u64) -> i64 {
    if oldfd == newfd {
        return EINVAL;
    }
    let cloexec = if (flags & 0o2_000_000) != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    let (ret, displaced) =
        sched::with_current_fds(|t| match t.dup_to(oldfd as i32, newfd as i32, cloexec) {
            Ok((fd, displaced)) => (fd as i64, displaced),
            Err(e) => (e as i64, None),
        });
    drop(displaced);
    ret
}

pub(crate) fn sys_pread64(fd: u64, buf: u64, count: u64, offset: u64) -> i64 {
    if count == 0 {
        return 0;
    }
    let n = (count as usize).min(READ_BUF_MAX);
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if !file.flags().is_readable() {
        return EBADF;
    }
    let mut tmp = alloc::vec![0u8; n];
    let read = match file.inode.read_at(offset, &mut tmp) {
        Ok(r) => r,
        Err(e) => return e.as_neg_i64(),
    };
    if read > 0 && frame::user::copy_to_user(buf, &tmp[..read]).is_err() {
        return EFAULT;
    }
    read as i64
}

pub(crate) fn sys_pwrite64(fd: u64, buf: u64, count: u64, offset: u64) -> i64 {
    if count == 0 {
        return 0;
    }
    let n = (count as usize).min(WRITE_BUF_MAX);
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if !file.flags().is_writable() {
        return EBADF;
    }
    let mut buffer = alloc::vec![0u8; n];
    if frame::user::copy_from_user(buf, &mut buffer).is_err() {
        return EFAULT;
    }
    match file.inode.write_at(offset, &buffer) {
        Ok(w) => {
            if crate::fsnotify::watching()
                && matches!(file.inode.kind(), crate::vfs::InodeKind::Regular)
            {
                crate::fsnotify::self_event(file.inode.as_ref(), crate::fsnotify::IN_MODIFY);
            }
            w as i64
        }
        Err(e) => write_err_to_errno(e),
    }
}

pub(crate) fn sys_readv(fd: u64, iov: u64, iovcnt: u64) -> i64 {
    let vecs = match read_iovecs(iov, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut total: i64 = 0;
    for (base, len) in vecs {
        if len == 0 {
            continue;
        }
        let r = sys_read(fd, base, len as u64);
        if r < 0 {
            return if total == 0 { r } else { total };
        }
        total += r;
        if (r as usize) < len {
            break;
        }
    }
    total
}

pub(crate) fn sys_writev(fd: u64, iov: u64, iovcnt: u64) -> i64 {
    let vecs = match read_iovecs(iov, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut total: i64 = 0;
    for (base, len) in vecs {
        if len == 0 {
            continue;
        }
        let r = sys_write(fd, base, len as u64);
        if r < 0 {
            return if total == 0 { r } else { total };
        }
        total += r;
        if (r as usize) < len {
            break;
        }
    }
    total
}

pub(crate) fn sys_pipe(fds_ptr: u64) -> i64 {
    sys_pipe2(fds_ptr, 0)
}

pub(crate) fn sys_pipe2(fds_ptr: u64, flags: u64) -> i64 {
    let cloexec = if (flags & 0o2_000_000) != 0 {
        vfs::fd::FD_CLOEXEC
    } else {
        0
    };
    let pipe = vfs::pipe::Pipe::new();
    let inode_dyn: Arc<dyn Inode> = pipe;
    let read_end = Arc::new(OpenFile::new(inode_dyn.clone(), OpenFlags::RDONLY));
    let write_end = Arc::new(OpenFile::new(inode_dyn, OpenFlags::WRONLY));

    let (rfd, wfd) = sched::with_current_fds(|t| {
        let r = t.install_from(read_end, 0, cloexec);
        let w = match r {
            Ok(_) => t.install_from(write_end, 0, cloexec),
            Err(e) => Err(e),
        };
        (r, w)
    });

    let rfd = match rfd {
        Ok(f) => f,
        Err(e) => return e as i64,
    };
    let wfd = match wfd {
        Ok(f) => f,
        Err(e) => {
            let removed = sched::with_current_fds(|t| t.remove(rfd));
            drop(removed);
            return e as i64;
        }
    };

    let buf: [u8; 8] = {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&rfd.to_le_bytes());
        b[4..8].copy_from_slice(&wfd.to_le_bytes());
        b
    };
    if frame::user::copy_to_user(fds_ptr, &buf).is_err() {
        let removed = sched::with_current_fds(|t| {
            let r = t.remove(rfd);
            let w = t.remove(wfd);
            (r, w)
        });
        drop(removed);
        return EFAULT;
    }
    0
}

pub(crate) fn sys_truncate(pathname: u64, len: u64) -> i64 {
    let inode = match resolve_path_writable(AT_FDCWD as u64, pathname, true) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let st = inode.stat();
    if st.kind == InodeKind::Directory {
        return EISDIR;
    }
    if !sched::with_current_creds(|c| c.can_access(st.uid, st.gid, st.mode, 0o2)) {
        return EACCES;
    }
    match inode.truncate(len) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_ftruncate(fd: u64, len: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if !file.flags().is_writable() {
        return EINVAL;
    }
    match file.inode.truncate(len) {
        Ok(()) => 0,
        Err(e) => e.as_neg_i64(),
    }
}

pub(crate) fn sys_fallocate(fd: u64, mode: u64, offset: u64, len: u64) -> i64 {
    const FALLOC_FL_KEEP_SIZE: u64 = 0x01;
    const FALLOC_FL_PUNCH_HOLE: u64 = 0x02;
    const FALLOC_FL_ZERO_RANGE: u64 = 0x10;
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if fd_mount_is_rdonly(&file) {
        return crate::errno::EROFS;
    }
    let inode = file.inode.clone();
    let cur = inode.stat().size;

    if mode & FALLOC_FL_PUNCH_HOLE != 0 {
        if mode & FALLOC_FL_KEEP_SIZE == 0 {
            return EINVAL;
        }
        let end = offset.saturating_add(len).min(cur);
        if end > offset {
            let chunk = [0u8; 4096];
            let mut pos = offset;
            while pos < end {
                let n = (end - pos).min(chunk.len() as u64) as usize;
                if let Err(e) = inode.write_at(pos, &chunk[..n]) {
                    return e.as_neg_i64();
                }
                pos += n as u64;
            }
        }
        return 0;
    }

    if mode & FALLOC_FL_ZERO_RANGE != 0 {
        let target = offset.saturating_add(len);
        if target > cur && (mode & FALLOC_FL_KEEP_SIZE == 0) {
            if let Err(e) = inode.truncate(target) {
                return e.as_neg_i64();
            }
        }
        let end = offset.saturating_add(len);
        let chunk = [0u8; 4096];
        let mut pos = offset;
        while pos < end {
            let n = (end - pos).min(chunk.len() as u64) as usize;
            if let Err(e) = inode.write_at(pos, &chunk[..n]) {
                return e.as_neg_i64();
            }
            pos += n as u64;
        }
        return 0;
    }

    let target = offset.saturating_add(len);
    if target > cur && (mode & FALLOC_FL_KEEP_SIZE == 0) {
        if let Err(e) = inode.truncate(target) {
            return e.as_neg_i64();
        }
    }
    0
}

pub(crate) fn sys_fadvise64(fd: u64) -> i64 {
    let exists = sched::with_current_fds(|t| t.get(fd as i32).is_some());
    if !exists {
        return EBADF;
    }
    0
}

pub(crate) fn sys_preadv(fd: u64, iov: u64, iovcnt: u64, offset_lo: u64, offset_hi: u64) -> i64 {
    let off = offset_lo | (offset_hi << 32);
    let vecs = match read_iovecs(iov, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut total: i64 = 0;
    let mut cursor = off;
    for (base, len) in vecs {
        if len == 0 {
            continue;
        }
        let r = sys_pread64(fd, base, len as u64, cursor);
        if r < 0 {
            return if total == 0 { r } else { total };
        }
        total += r;
        cursor = cursor.saturating_add(r as u64);
        if (r as usize) < len {
            break;
        }
    }
    total
}

pub(crate) fn sys_pwritev(fd: u64, iov: u64, iovcnt: u64, offset_lo: u64, offset_hi: u64) -> i64 {
    let off = offset_lo | (offset_hi << 32);
    let vecs = match read_iovecs(iov, iovcnt) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut total: i64 = 0;
    let mut cursor = off;
    for (base, len) in vecs {
        if len == 0 {
            continue;
        }
        let r = sys_pwrite64(fd, base, len as u64, cursor);
        if r < 0 {
            return if total == 0 { r } else { total };
        }
        total += r;
        cursor = cursor.saturating_add(r as u64);
        if (r as usize) < len {
            break;
        }
    }
    total
}

pub(crate) fn sys_sendfile(out_fd: u64, in_fd: u64, offset_ptr: u64, count: u64) -> i64 {
    const CHUNK: usize = 4096;
    let mut buf = [0u8; CHUNK];
    let in_file = match sched::with_current_fds(|t| t.get(in_fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let out_file = match sched::with_current_fds(|t| t.get(out_fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };

    let mut offset_buf = [0u8; 8];
    let mut have_offset = false;
    let mut offset: u64 = 0;
    if offset_ptr != 0 {
        if frame::user::copy_from_user(offset_ptr, &mut offset_buf).is_err() {
            return EFAULT;
        }
        offset = u64::from_le_bytes(offset_buf);
        have_offset = true;
    }

    let mut transferred: usize = 0;
    while (transferred as u64) < count {
        let want = ((count - transferred as u64) as usize).min(CHUNK);
        let in_inode = in_file.inode.clone();
        let r = if have_offset {
            in_inode.read_at(offset, &mut buf[..want])
        } else {
            in_file.read(&mut buf[..want])
        };
        let n = match r {
            Ok(n) => n,
            Err(e) => return e.as_neg_i64(),
        };
        if n == 0 {
            break;
        }
        let w = match out_file.write(&buf[..n]) {
            Ok(w) => w,
            Err(e) => return write_err_to_errno(e),
        };
        transferred += w;
        if have_offset {
            offset = offset.saturating_add(w as u64);
        }
        if w < n {
            break;
        }
    }
    if have_offset {
        offset_buf.copy_from_slice(&offset.to_le_bytes());
        let _ = frame::user::copy_to_user(offset_ptr, &offset_buf);
    }
    transferred as i64
}

pub(crate) fn sys_copy_file_range(
    fd_in: u64,
    off_in_ptr: u64,
    fd_out: u64,
    off_out_ptr: u64,
    len: u64,
    _flags: u64,
) -> i64 {
    const CHUNK: usize = 4096;
    let mut buf = [0u8; CHUNK];

    let in_file = match sched::with_current_fds(|t| t.get(fd_in as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let out_file = match sched::with_current_fds(|t| t.get(fd_out as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if !out_file.flags().is_writable() {
        return EBADF;
    }
    if fd_mount_is_rdonly(&out_file) {
        return crate::errno::EROFS;
    }

    let mut in_off = read_optional_off(off_in_ptr).unwrap_or(0);
    let in_use_off = off_in_ptr != 0;
    let mut out_off = read_optional_off(off_out_ptr).unwrap_or(0);
    let out_use_off = off_out_ptr != 0;

    let mut transferred: usize = 0;
    while (transferred as u64) < len {
        let want = ((len - transferred as u64) as usize).min(CHUNK);
        let n = match if in_use_off {
            in_file.inode.clone().read_at(in_off, &mut buf[..want])
        } else {
            in_file.read(&mut buf[..want])
        } {
            Ok(n) => n,
            Err(e) => return e.as_neg_i64(),
        };
        if n == 0 {
            break;
        }
        let w = match if out_use_off {
            out_file.inode.clone().write_at(out_off, &buf[..n])
        } else {
            out_file.write(&buf[..n])
        } {
            Ok(w) => w,
            Err(e) => return write_err_to_errno(e),
        };
        transferred += w;
        if in_use_off {
            in_off = in_off.saturating_add(w as u64);
        }
        if out_use_off {
            out_off = out_off.saturating_add(w as u64);
        }
        if w < n {
            break;
        }
    }
    if in_use_off {
        let _ = frame::user::copy_to_user(off_in_ptr, &in_off.to_le_bytes());
    }
    if out_use_off {
        let _ = frame::user::copy_to_user(off_out_ptr, &out_off.to_le_bytes());
    }
    transferred as i64
}

fn read_optional_off(ptr: u64) -> Result<u64, i64> {
    if ptr == 0 {
        return Ok(0);
    }
    let mut b = [0u8; 8];
    if frame::user::copy_from_user(ptr, &mut b).is_err() {
        return Err(EFAULT);
    }
    Ok(u64::from_le_bytes(b))
}

pub(crate) fn sys_splice(
    fd_in: u64,
    off_in_ptr: u64,
    fd_out: u64,
    off_out_ptr: u64,
    len: u64,
    _flags: u64,
) -> i64 {
    sys_copy_file_range(fd_in, off_in_ptr, fd_out, off_out_ptr, len, 0)
}

pub(crate) fn sys_tee(fd_in: u64, fd_out: u64, len: u64, _flags: u64) -> i64 {
    let f_in = match sched::with_current_fds(|t| t.get(fd_in as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let f_out = match sched::with_current_fds(|t| t.get(fd_out as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    let chunk = (len as usize).min(4096);
    if chunk == 0 {
        return 0;
    }
    let mut buf = [0u8; 4096];
    let n = match f_in.inode.peek_at(&mut buf[..chunk]) {
        Ok(n) => n,
        Err(Errno::NOSYS) => return EINVAL,
        Err(e) => return e.as_neg_i64(),
    };
    if n == 0 {
        return 0;
    }
    match f_out.write(&buf[..n]) {
        Ok(written) => written as i64,
        Err(e) => write_err_to_errno(e),
    }
}

pub(crate) fn sys_vmsplice(fd: u64, iov: u64, iovcnt: u64, _flags: u64) -> i64 {
    let file = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(f) => f,
        None => return EBADF,
    };
    if file.flags().is_writable() {
        sys_writev(fd, iov, iovcnt)
    } else {
        sys_readv(fd, iov, iovcnt)
    }
}

pub(crate) fn sys_readahead(fd: u64, _offset: u64, _count: u64) -> i64 {
    let kind = match sched::with_current_fds(|t| t.get(fd as i32)) {
        Some(of) => of.inode.kind(),
        None => return EBADF,
    };
    if !matches!(kind, crate::vfs::InodeKind::Regular) {
        return EINVAL;
    }
    0
}
