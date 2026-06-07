#![allow(dead_code)]

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EINTR: i64 = -4;
pub const EIO: i64 = -5;
pub const ENXIO: i64 = -6;
pub const E2BIG: i64 = -7;
pub const ENOEXEC: i64 = -8;
pub const EBADF: i64 = -9;
pub const ECHILD: i64 = -10;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EBUSY: i64 = -16;
pub const EEXIST: i64 = -17;
pub const EXDEV: i64 = -18;
pub const ENODEV: i64 = -19;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const ENFILE: i64 = -23;
pub const EMFILE: i64 = -24;
pub const ENOTTY: i64 = -25;
pub const ETXTBSY: i64 = -26;
pub const EFBIG: i64 = -27;
pub const ENOSPC: i64 = -28;
pub const ESPIPE: i64 = -29;
pub const EROFS: i64 = -30;
pub const EMLINK: i64 = -31;
pub const EPIPE: i64 = -32;
pub const EDOM: i64 = -33;
pub const ERANGE: i64 = -34;
pub const EDEADLK: i64 = -35;
pub const ENAMETOOLONG: i64 = -36;
pub const ENOLCK: i64 = -37;
pub const ENOSYS: i64 = -38;
pub const ENOTEMPTY: i64 = -39;
pub const ELOOP: i64 = -40;

pub const ENODATA: i64 = -61;
pub const ETIME: i64 = -62;

pub const EOVERFLOW: i64 = -75;

pub const ENOTSOCK: i64 = -88;
pub const EDESTADDRREQ: i64 = -89;
pub const EMSGSIZE: i64 = -90;
pub const EPROTOTYPE: i64 = -91;
pub const ENOPROTOOPT: i64 = -92;
pub const EPROTONOSUPPORT: i64 = -93;
pub const ESOCKTNOSUPPORT: i64 = -94;
pub const EOPNOTSUPP: i64 = -95;
pub const EPFNOSUPPORT: i64 = -96;
pub const EAFNOSUPPORT: i64 = -97;
pub const EADDRINUSE: i64 = -98;
pub const EADDRNOTAVAIL: i64 = -99;
pub const ENETDOWN: i64 = -100;
pub const ENETUNREACH: i64 = -101;
pub const ENETRESET: i64 = -102;
pub const ECONNABORTED: i64 = -103;
pub const ECONNRESET: i64 = -104;
pub const ENOBUFS: i64 = -105;
pub const EISCONN: i64 = -106;
pub const ENOTCONN: i64 = -107;
pub const ESHUTDOWN: i64 = -108;
pub const ETOOMANYREFS: i64 = -109;
pub const ETIMEDOUT: i64 = -110;
pub const ECONNREFUSED: i64 = -111;
pub const EHOSTDOWN: i64 = -112;
pub const EHOSTUNREACH: i64 = -113;

pub const EALREADY: i64 = -114;
pub const EINPROGRESS: i64 = -115;

pub const ENOTSUP: i64 = EOPNOTSUPP;

pub const ECANCELED: i64 = -125;
