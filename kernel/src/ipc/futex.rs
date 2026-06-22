extern crate alloc;

mod robust;
mod state;
mod wait;
mod wake;

pub use robust::*;
pub use state::*;
pub use wait::*;
pub use wake::*;

#[cfg(not(host_test))]
mod pi;
#[cfg(not(host_test))]
pub use pi::{cmp_requeue_pi, lock_pi, pi_owner_died, trylock_pi, unlock_pi, wait_requeue_pi};

#[cfg(host_test)]
#[cfg(test)]
mod host_tests {
    use super::*;

    #[cfg(host_test)]
    #[allow(unused_imports)]
    use frame_host as frame;

    use alloc::sync::Arc;

    fn put_user_u32(addr: u64, val: u32) {
        frame::user::register_user_buffer(addr, val.to_le_bytes().to_vec());
    }

    fn reset_globals() {
        FUTEXES.lock().clear();
        BITSET_MASKS.lock().clear();
        crate::core::reset_for_test();
    }

    #[test]
    fn wake_no_waiters_returns_zero() {
        reset_globals();
        let n = wake(1, 0x1000, 1);
        assert_eq!(n, 0);
    }

    #[test]
    fn wake_misaligned_uaddr_rejects() {
        reset_globals();
        let n = wake(1, 0x1001, 1);
        assert_eq!(n, EINVAL);
    }

    #[test]
    fn wait_misaligned_uaddr_rejects() {
        reset_globals();
        let r = wait(1, 0x2003, 0, None);
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn wait_value_mismatch_returns_eagain() {
        reset_globals();
        let addr = 0x1000u64;
        put_user_u32(addr, 42);
        let r = wait(1, addr, 7, None);
        assert_eq!(r, EAGAIN);
    }

    #[test]
    fn wait_bad_pointer_returns_efault() {
        reset_globals();
        let r = wait(1, 0xdead_0000, 0, None);
        assert_eq!(r, EFAULT);
    }

    #[test]
    fn wake_bitset_mask_zero_rejects() {
        reset_globals();
        let r = wake_bitset(1, 0x1000, 1, 0);
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn wait_bitset_mask_zero_rejects() {
        reset_globals();
        let r = wait_bitset(1, 0x1000, 0, 0, None);
        assert_eq!(r, EINVAL);
    }

    #[test]
    fn key_ordering_is_total_and_consistent() {
        let k1 = Key {
            vmspace_id: 1,
            vaddr: 0x1000,
        };
        let k2 = Key {
            vmspace_id: 1,
            vaddr: 0x2000,
        };
        let k3 = Key {
            vmspace_id: 2,
            vaddr: 0x500,
        };
        assert!(k1 < k2);
        assert!(k2 < k3);
        assert!(k1 < k3);
    }

    #[test]
    fn queue_for_returns_same_arc_for_repeat_key() {
        reset_globals();
        let k = Key {
            vmspace_id: 1,
            vaddr: 0x3000,
        };
        let q1 = queue_for(k);
        let q2 = queue_for(k);
        assert!(Arc::ptr_eq(&q1, &q2));
    }

    #[test]
    fn queue_for_returns_different_arcs_for_different_keys() {
        reset_globals();
        let k1 = Key {
            vmspace_id: 1,
            vaddr: 0x1000,
        };
        let k2 = Key {
            vmspace_id: 1,
            vaddr: 0x2000,
        };
        let q1 = queue_for(k1);
        let q2 = queue_for(k2);
        assert!(!Arc::ptr_eq(&q1, &q2));
    }

    #[test]
    fn queue_for_partitions_by_vmspace_id() {
        reset_globals();
        let same_vaddr = 0x4000u64;
        let q1 = queue_for(Key {
            vmspace_id: 10,
            vaddr: same_vaddr,
        });
        let q2 = queue_for(Key {
            vmspace_id: 20,
            vaddr: same_vaddr,
        });
        assert!(!Arc::ptr_eq(&q1, &q2));
    }

    #[test]
    fn drop_vmspace_sweeps_only_target_vmspace() {
        reset_globals();
        let _ = queue_for(Key {
            vmspace_id: 1,
            vaddr: 0x1000,
        });
        let _ = queue_for(Key {
            vmspace_id: 1,
            vaddr: 0x2000,
        });
        let _ = queue_for(Key {
            vmspace_id: 2,
            vaddr: 0x1000,
        });
        assert_eq!(FUTEXES.lock().len(), 3);
        drop_vmspace(1);
        let remaining = FUTEXES.lock();
        assert_eq!(remaining.len(), 1);
        assert!(remaining.contains_key(&Key {
            vmspace_id: 2,
            vaddr: 0x1000
        }));
    }

    #[test]
    fn wake_op_set_kind_writes_user_word() {
        reset_globals();
        let uaddr1 = 0x6000u64;
        let uaddr2 = 0x7000u64;
        put_user_u32(uaddr1, 0);
        put_user_u32(uaddr2, 42);
        let op_word = ((99u32 & 0xfff) << 12) | (42u32 & 0xfff);
        let r = wake_op(1, uaddr1, uaddr2, 0, 0, op_word);
        assert_eq!(r, 0);
        let buf = frame::user::take_user_buffer(uaddr2).unwrap();
        let new_val = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(new_val, 99);
    }

    fn read_user_u32(addr: u64) -> u32 {
        let buf = frame::user::take_user_buffer(addr).unwrap();
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
    }

    fn op_word(op_kind: u32, op_arg: u32) -> u32 {
        (op_kind << 28) | ((op_arg & 0xfff) << 12)
    }

    #[test]
    fn wake_op_add_through_cmpxchg_loop() {
        reset_globals();
        put_user_u32(0x6100, 0);
        put_user_u32(0x7100, 10);
        assert_eq!(wake_op(1, 0x6100, 0x7100, 0, 0, op_word(1, 5)), 0);
        assert_eq!(read_user_u32(0x7100), 15);
    }

    #[test]
    fn wake_op_or_through_cmpxchg_loop() {
        reset_globals();
        put_user_u32(0x6200, 0);
        put_user_u32(0x7200, 0x1);
        assert_eq!(wake_op(1, 0x6200, 0x7200, 0, 0, op_word(2, 0x2)), 0);
        assert_eq!(read_user_u32(0x7200), 0x3);
    }

    #[test]
    fn wake_op_andn_through_cmpxchg_loop() {
        reset_globals();
        put_user_u32(0x6300, 0);
        put_user_u32(0x7300, 0x7);
        assert_eq!(wake_op(1, 0x6300, 0x7300, 0, 0, op_word(3, 0x1)), 0);
        assert_eq!(read_user_u32(0x7300), 0x6);
    }

    #[test]
    fn wake_op_xor_through_cmpxchg_loop() {
        reset_globals();
        put_user_u32(0x6400, 0);
        put_user_u32(0x7400, 0x5);
        assert_eq!(wake_op(1, 0x6400, 0x7400, 0, 0, op_word(4, 0x3)), 0);
        assert_eq!(read_user_u32(0x7400), 0x6);
    }

    #[test]
    fn wake_op_bad_op_kind_is_einval() {
        reset_globals();
        put_user_u32(0x6500, 0);
        put_user_u32(0x7500, 0);
        assert_eq!(wake_op(1, 0x6500, 0x7500, 0, 0, 5u32 << 28), EINVAL);
    }

    #[test]
    fn wake_op_unregistered_uaddr2_is_efault() {
        reset_globals();
        put_user_u32(0x6600, 0);
        assert_eq!(wake_op(1, 0x6600, 0x7600, 0, 0, op_word(0, 99)), EFAULT);
    }

    #[test]
    fn clear_child_tid_zeros_user_word() {
        reset_globals();
        let addr = 0x8000u64;
        put_user_u32(addr, 0x1234_5678);
        clear_child_tid(1, addr);
        let buf = frame::user::take_user_buffer(addr).unwrap();
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 0);
    }

    #[test]
    fn clear_child_tid_misaligned_is_noop() {
        reset_globals();
        let addr = 0x8003u64;
        clear_child_tid(1, addr);
        assert!(frame::user::take_user_buffer(addr).is_none());
    }

    #[test]
    fn clear_child_tid_zero_addr_is_noop() {
        reset_globals();
        clear_child_tid(1, 0);
    }

    #[test]
    fn concurrent_wake_and_wait_no_data_race() {
        reset_globals();
        let addr = 0x9000u64;
        put_user_u32(addr, 0);

        let waiter = std::thread::spawn(move || {
            let r = wait(1, addr, 0, None);
            assert_eq!(r, 0);
        });

        for _ in 0..32 {
            std::thread::yield_now();
        }
        let woken = wake(1, addr, 1);
        assert!(woken == 0 || woken == 1);
        waiter.join().unwrap();
    }
}
