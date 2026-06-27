extern crate alloc;

use cyphera_kapi::{Errno, KResult};

pub fn block_read(lba: u64, buf: &mut [u8]) -> KResult<()> {
    if buf.is_empty() || !buf.len().is_multiple_of(512) {
        return Err(Errno::INVAL);
    }
    apply_io_quota(false, buf.len() as u64);
    ::virtio::read_block_sector(lba, buf).map_err(|_| Errno::IO)
}

pub fn block_write(lba: u64, buf: &[u8]) -> KResult<()> {
    if buf.is_empty() || !buf.len().is_multiple_of(512) {
        return Err(Errno::INVAL);
    }
    apply_io_quota(true, buf.len() as u64);
    ::virtio::write_block_sector(lba, buf).map_err(|_| Errno::IO)
}

fn apply_io_quota(write: bool, bytes: u64) {
    let cg = match crate::core::current_cgroup() {
        Some(c) => c,
        None => return,
    };
    for _ in 0..2 {
        let now = frame::cpu::clock::nanos_since_boot();
        let result = {
            let mut io_ctl = cg.io.lock();
            if write {
                io_ctl.charge_write(bytes, now)
            } else {
                io_ctl.charge_read(bytes, now)
            }
        };
        match result {
            Ok(()) => return,
            Err(retry_after_ns) => {
                let deadline = now.saturating_add(retry_after_ns.max(1_000_000));
                crate::core::sleep_until(deadline);
            }
        }
    }
    let now = frame::cpu::clock::nanos_since_boot();
    let mut io_ctl = cg.io.lock();
    if write {
        let _ = io_ctl.charge_write(bytes, now);
    } else {
        let _ = io_ctl.charge_read(bytes, now);
    }
}
