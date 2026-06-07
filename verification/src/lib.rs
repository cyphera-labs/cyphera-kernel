#![no_std]

pub mod alloc_no_overlap;
pub mod anon_alloc_symmetry;
pub mod caps_perm_subset;
pub mod cgroup_tree_acyclic;
pub mod cstr_copy;
pub mod futex_bitset_wake;
pub mod futex_wake_count;
pub mod lock_order;
pub mod path_normalize;
pub mod pidns_translate_safety;
pub mod pte_encoding;
pub mod seccomp_filter_validate;
pub mod shm_segment_bounds;
pub mod signal_mask_combine;
pub mod time_arith;
pub mod user_copy_contract;
pub mod user_range_check;
pub mod vmspace_no_overlap;
