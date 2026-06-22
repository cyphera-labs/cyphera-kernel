use super::*;

#[cfg(host_test)]
#[allow(unused_imports)]
use frame_host as frame;

const ROBUST_LIST_LIMIT: u32 = 2048;

pub fn exit_robust_list(vmspace_id: u64, head_addr: u64) {
    if head_addr == 0 {
        return;
    }

    let mut head_buf = [0u8; 24];
    if frame::user::copy_from_user(head_addr, &mut head_buf).is_err() {
        return;
    }
    let list = u64::from_le_bytes(head_buf[0..8].try_into().unwrap());
    let futex_offset = i64::from_le_bytes(head_buf[8..16].try_into().unwrap());
    let pending = u64::from_le_bytes(head_buf[16..24].try_into().unwrap());

    if pending != 0 && pending != head_addr {
        let futex_addr = (pending as i64).wrapping_add(futex_offset) as u64;
        handle_futex_death(vmspace_id, futex_addr);
    }

    let mut entry = list;
    let mut limit = ROBUST_LIST_LIMIT;
    while entry != head_addr && entry != 0 && limit > 0 {
        let mut next_buf = [0u8; 8];
        if frame::user::copy_from_user(entry, &mut next_buf).is_err() {
            break;
        }
        let next = u64::from_le_bytes(next_buf);

        if entry != pending {
            let futex_addr = (entry as i64).wrapping_add(futex_offset) as u64;
            handle_futex_death(vmspace_id, futex_addr);
        }

        entry = next;
        limit -= 1;
    }
}

fn handle_futex_death(vmspace_id: u64, futex_addr: u64) {
    if futex_addr & 0x3 != 0 {
        return;
    }
    let mut buf = [0u8; 4];
    if frame::user::copy_from_user(futex_addr, &mut buf).is_err() {
        return;
    }
    let val = u32::from_le_bytes(buf) | FUTEX_OWNER_DIED;
    if frame::user::copy_to_user(futex_addr, &val.to_le_bytes()).is_err() {
        return;
    }
    let _ = wake(vmspace_id, futex_addr, 1);
}

pub fn clear_child_tid(vmspace_id: u64, addr: u64) {
    if addr == 0 || addr & 0x3 != 0 {
        return;
    }
    let zero: [u8; 4] = [0; 4];
    if frame::user::copy_to_user(addr, &zero).is_err() {
        return;
    }
    let _ = wake(vmspace_id, addr, 1);
}
