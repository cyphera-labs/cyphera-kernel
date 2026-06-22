#![allow(dead_code)]

use cyphera_kapi::Errno;

pub const EPERM: i64 = Errno::PERM.as_neg_i64();
pub const ENOENT: i64 = Errno::NOENT.as_neg_i64();
pub const ESRCH: i64 = Errno::SRCH.as_neg_i64();
pub const EINTR: i64 = Errno::INTR.as_neg_i64();
pub const EIO: i64 = Errno::IO.as_neg_i64();
pub const ENXIO: i64 = Errno::NXIO.as_neg_i64();
pub const E2BIG: i64 = Errno::TOOBIG.as_neg_i64();
pub const ENOEXEC: i64 = Errno::NOEXEC.as_neg_i64();
pub const EBADF: i64 = Errno::BADF.as_neg_i64();
pub const ECHILD: i64 = Errno::CHILD.as_neg_i64();
pub const EAGAIN: i64 = Errno::AGAIN.as_neg_i64();
pub const ENOMEM: i64 = Errno::NOMEM.as_neg_i64();
pub const EACCES: i64 = Errno::ACCES.as_neg_i64();
pub const EFAULT: i64 = Errno::FAULT.as_neg_i64();
pub const EBUSY: i64 = Errno::BUSY.as_neg_i64();
pub const EEXIST: i64 = Errno::EXIST.as_neg_i64();
pub const EXDEV: i64 = Errno::XDEV.as_neg_i64();
pub const ENODEV: i64 = Errno::NODEV.as_neg_i64();
pub const ENOTDIR: i64 = Errno::NOTDIR.as_neg_i64();
pub const EISDIR: i64 = Errno::ISDIR.as_neg_i64();
pub const EINVAL: i64 = Errno::INVAL.as_neg_i64();
pub const ENFILE: i64 = Errno::NFILE.as_neg_i64();
pub const EMFILE: i64 = Errno::MFILE.as_neg_i64();
pub const ENOTTY: i64 = Errno::NOTTY.as_neg_i64();
pub const ETXTBSY: i64 = Errno::TXTBSY.as_neg_i64();
pub const EFBIG: i64 = Errno::FBIG.as_neg_i64();
pub const ENOSPC: i64 = Errno::NOSPC.as_neg_i64();
pub const ESPIPE: i64 = Errno::SPIPE.as_neg_i64();
pub const EROFS: i64 = Errno::ROFS.as_neg_i64();
pub const EMLINK: i64 = Errno::MLINK.as_neg_i64();
pub const EPIPE: i64 = Errno::PIPE.as_neg_i64();
pub const EDOM: i64 = Errno::DOM.as_neg_i64();
pub const ERANGE: i64 = Errno::RANGE.as_neg_i64();
pub const EDEADLK: i64 = Errno::DEADLK.as_neg_i64();
pub const ENAMETOOLONG: i64 = Errno::NAMETOOLONG.as_neg_i64();
pub const ENOLCK: i64 = Errno::NOLCK.as_neg_i64();
pub const ENOSYS: i64 = Errno::NOSYS.as_neg_i64();
pub const ENOTEMPTY: i64 = Errno::NOTEMPTY.as_neg_i64();
pub const ELOOP: i64 = Errno::LOOP.as_neg_i64();

pub const ENODATA: i64 = Errno::NODATA.as_neg_i64();
pub const ETIME: i64 = Errno::TIME.as_neg_i64();

pub const EOVERFLOW: i64 = Errno::OVERFLOW.as_neg_i64();

pub const ENOTSOCK: i64 = Errno::NOTSOCK.as_neg_i64();
pub const EDESTADDRREQ: i64 = Errno::DESTADDRREQ.as_neg_i64();
pub const EMSGSIZE: i64 = Errno::MSGSIZE.as_neg_i64();
pub const EPROTOTYPE: i64 = Errno::PROTOTYPE.as_neg_i64();
pub const ENOPROTOOPT: i64 = Errno::NOPROTOOPT.as_neg_i64();
pub const EPROTONOSUPPORT: i64 = Errno::PROTONOSUPPORT.as_neg_i64();
pub const ESOCKTNOSUPPORT: i64 = Errno::SOCKTNOSUPPORT.as_neg_i64();
pub const EOPNOTSUPP: i64 = Errno::OPNOTSUPP.as_neg_i64();
pub const EPFNOSUPPORT: i64 = Errno::PFNOSUPPORT.as_neg_i64();
pub const EAFNOSUPPORT: i64 = Errno::AFNOSUPPORT.as_neg_i64();
pub const EADDRINUSE: i64 = Errno::ADDRINUSE.as_neg_i64();
pub const EADDRNOTAVAIL: i64 = Errno::ADDRNOTAVAIL.as_neg_i64();
pub const ENETDOWN: i64 = Errno::NETDOWN.as_neg_i64();
pub const ENETUNREACH: i64 = Errno::NETUNREACH.as_neg_i64();
pub const ENETRESET: i64 = Errno::NETRESET.as_neg_i64();
pub const ECONNABORTED: i64 = Errno::CONNABORTED.as_neg_i64();
pub const ECONNRESET: i64 = Errno::CONNRESET.as_neg_i64();
pub const ENOBUFS: i64 = Errno::NOBUFS.as_neg_i64();
pub const EISCONN: i64 = Errno::ISCONN.as_neg_i64();
pub const ENOTCONN: i64 = Errno::NOTCONN.as_neg_i64();
pub const ESHUTDOWN: i64 = Errno::SHUTDOWN.as_neg_i64();
pub const ETOOMANYREFS: i64 = Errno::TOOMANYREFS.as_neg_i64();
pub const ETIMEDOUT: i64 = Errno::TIMEDOUT.as_neg_i64();
pub const ECONNREFUSED: i64 = Errno::CONNREFUSED.as_neg_i64();
pub const EHOSTDOWN: i64 = Errno::HOSTDOWN.as_neg_i64();
pub const EHOSTUNREACH: i64 = Errno::HOSTUNREACH.as_neg_i64();

pub const EALREADY: i64 = Errno::ALREADY.as_neg_i64();
pub const EINPROGRESS: i64 = Errno::INPROGRESS.as_neg_i64();

pub const ENOTSUP: i64 = EOPNOTSUPP;

pub const ECANCELED: i64 = Errno::CANCELED.as_neg_i64();

const _: () = {
    assert!(EPERM == -1);
    assert!(EINVAL == -22);
    assert!(EAGAIN == -11);
    assert!(ELOOP == -40);
    assert!(EOVERFLOW == -75);
    assert!(ECONNREFUSED == -111);
    assert!(ECANCELED == -125);
    assert!(ENOTSUP == EOPNOTSUPP);
};
