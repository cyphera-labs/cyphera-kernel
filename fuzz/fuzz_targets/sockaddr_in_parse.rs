#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|buf: &[u8]| {
    let result = parse_sockaddr_in(buf);

    match result {
        Ok(ep) => {
            assert!(buf.len() >= 8, "Ok on too-short buffer: {} bytes", buf.len());
            let fam = u16::from_le_bytes([buf[0], buf[1]]);
            assert_eq!(fam, 2, "Ok on non-AF_INET family: {:#x}", fam);

            let mut out = [0u8; 16];
            let n = write_sockaddr_in(&ep, &mut out);
            assert_eq!(n, 16);
            assert_eq!(&out[..8], &buf[..8], "round-trip lost family/port/addr");
        }
        Err(_) => {
        }
    }
});

#[derive(Debug, Clone, Copy)]
struct Ipv4Addr([u8; 4]);

impl Ipv4Addr {
    fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }
    fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy)]
struct IpEndpoint {
    addr: Ipv4Addr,
    port: u16,
}

#[derive(Debug)]
#[allow(dead_code)]
enum FsError {
    InvalidArgument,
}

fn parse_sockaddr_in(buf: &[u8]) -> Result<IpEndpoint, FsError> {
    if buf.len() < 8 {
        return Err(FsError::InvalidArgument);
    }
    let fam = u16::from_le_bytes([buf[0], buf[1]]);
    if fam != 2 {
        return Err(FsError::InvalidArgument);
    }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let addr = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
    Ok(IpEndpoint { addr, port })
}

fn write_sockaddr_in(ep: &IpEndpoint, out: &mut [u8]) -> usize {
    out[0..2].copy_from_slice(&2u16.to_le_bytes());
    out[2..4].copy_from_slice(&ep.port.to_be_bytes());
    out[4..8].copy_from_slice(ep.addr.as_bytes());
    for b in &mut out[8..16] {
        *b = 0;
    }
    16
}
