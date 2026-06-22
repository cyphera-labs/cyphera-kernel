#![no_std]
#![forbid(unsafe_code)]

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pid(pub u32);

impl Pid {
    pub fn raw(self) -> u32 {
        self.0
    }

    pub const fn from_raw(raw: u32) -> Self {
        Pid(raw)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WaitKey {
    pub vmspace_id: u64,
    pub vaddr: u64,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Errno(pub u16);

impl Errno {
    pub const fn as_neg_i64(self) -> i64 {
        -(self.0 as i64)
    }

    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl Errno {
    pub const PERM: Errno = Errno(1);
    pub const NOENT: Errno = Errno(2);
    pub const SRCH: Errno = Errno(3);
    pub const INTR: Errno = Errno(4);
    pub const IO: Errno = Errno(5);
    pub const NXIO: Errno = Errno(6);
    pub const TOOBIG: Errno = Errno(7);
    pub const NOEXEC: Errno = Errno(8);
    pub const BADF: Errno = Errno(9);
    pub const CHILD: Errno = Errno(10);
    pub const AGAIN: Errno = Errno(11);
    pub const NOMEM: Errno = Errno(12);
    pub const ACCES: Errno = Errno(13);
    pub const FAULT: Errno = Errno(14);
    pub const BUSY: Errno = Errno(16);
    pub const EXIST: Errno = Errno(17);
    pub const XDEV: Errno = Errno(18);
    pub const NODEV: Errno = Errno(19);
    pub const NOTDIR: Errno = Errno(20);
    pub const ISDIR: Errno = Errno(21);
    pub const INVAL: Errno = Errno(22);
    pub const NFILE: Errno = Errno(23);
    pub const MFILE: Errno = Errno(24);
    pub const NOTTY: Errno = Errno(25);
    pub const TXTBSY: Errno = Errno(26);
    pub const FBIG: Errno = Errno(27);
    pub const NOSPC: Errno = Errno(28);
    pub const SPIPE: Errno = Errno(29);
    pub const ROFS: Errno = Errno(30);
    pub const MLINK: Errno = Errno(31);
    pub const PIPE: Errno = Errno(32);
    pub const DOM: Errno = Errno(33);
    pub const RANGE: Errno = Errno(34);
    pub const DEADLK: Errno = Errno(35);
    pub const NAMETOOLONG: Errno = Errno(36);
    pub const NOLCK: Errno = Errno(37);
    pub const NOSYS: Errno = Errno(38);
    pub const NOTEMPTY: Errno = Errno(39);
    pub const LOOP: Errno = Errno(40);
    pub const NODATA: Errno = Errno(61);
    pub const TIME: Errno = Errno(62);
    pub const OVERFLOW: Errno = Errno(75);
    pub const NOTSOCK: Errno = Errno(88);
    pub const DESTADDRREQ: Errno = Errno(89);
    pub const MSGSIZE: Errno = Errno(90);
    pub const PROTOTYPE: Errno = Errno(91);
    pub const NOPROTOOPT: Errno = Errno(92);
    pub const PROTONOSUPPORT: Errno = Errno(93);
    pub const SOCKTNOSUPPORT: Errno = Errno(94);
    pub const OPNOTSUPP: Errno = Errno(95);
    pub const PFNOSUPPORT: Errno = Errno(96);
    pub const AFNOSUPPORT: Errno = Errno(97);
    pub const ADDRINUSE: Errno = Errno(98);
    pub const ADDRNOTAVAIL: Errno = Errno(99);
    pub const NETDOWN: Errno = Errno(100);
    pub const NETUNREACH: Errno = Errno(101);
    pub const NETRESET: Errno = Errno(102);
    pub const CONNABORTED: Errno = Errno(103);
    pub const CONNRESET: Errno = Errno(104);
    pub const NOBUFS: Errno = Errno(105);
    pub const ISCONN: Errno = Errno(106);
    pub const NOTCONN: Errno = Errno(107);
    pub const SHUTDOWN: Errno = Errno(108);
    pub const TOOMANYREFS: Errno = Errno(109);
    pub const TIMEDOUT: Errno = Errno(110);
    pub const CONNREFUSED: Errno = Errno(111);
    pub const HOSTDOWN: Errno = Errno(112);
    pub const HOSTUNREACH: Errno = Errno(113);
    pub const ALREADY: Errno = Errno(114);
    pub const INPROGRESS: Errno = Errno(115);
    pub const CANCELED: Errno = Errno(125);
}

pub type KResult<T> = Result<T, Errno>;

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct PollMask: u32 {
        const IN  = 0x001;
        const OUT = 0x004;
        const ERR = 0x008;
        const HUP = 0x010;
    }
}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct OpenFlags: u32 {
        const RDONLY    = 0o0;
        const WRONLY    = 0o1;
        const RDWR      = 0o2;
        const CREAT     = 0o100;
        const EXCL      = 0o200;
        const TRUNC     = 0o1000;
        const APPEND    = 0o2000;
        const NONBLOCK  = 0o4000;
        const DIRECTORY = 0o200000;
        const NOFOLLOW  = 0o400000;
        const CLOEXEC   = 0o2000000;
        const PATH      = 0o10000000;
    }
}

impl OpenFlags {
    pub fn is_writable(self) -> bool {
        self.contains(OpenFlags::WRONLY) || self.contains(OpenFlags::RDWR)
    }
    pub fn is_readable(self) -> bool {
        !self.contains(OpenFlags::WRONLY)
    }
}
