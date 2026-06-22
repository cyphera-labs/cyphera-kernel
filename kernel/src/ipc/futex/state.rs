#[cfg(host_test)]
#[allow(unused_imports)]
use frame_host as frame;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use frame::sync::SpinIrq;

use crate::core::wait::WaitQueue;

pub use cyphera_kapi::WaitKey as Key;

pub(crate) static FUTEXES: SpinIrq<BTreeMap<Key, Arc<WaitQueue>>> = SpinIrq::new(BTreeMap::new());

pub(crate) static BITSET_MASKS: SpinIrq<BTreeMap<crate::process_model::Pid, u32>> =
    SpinIrq::new(BTreeMap::new());

pub(crate) fn queue_for(key: Key) -> Arc<WaitQueue> {
    let mut t = FUTEXES.lock();
    t.entry(key)
        .or_insert_with(|| Arc::new(WaitQueue::new()))
        .clone()
}

pub(crate) use crate::errno::{EAGAIN, EFAULT, EINTR, EINVAL, ETIMEDOUT};

pub(crate) const FUTEX_OWNER_DIED: u32 = 0x4000_0000;

pub fn drop_vmspace(vmspace_id: u64) {
    let mut t = FUTEXES.lock();
    t.retain(|k, _| k.vmspace_id != vmspace_id);
    #[cfg(not(host_test))]
    super::pi::drop_vmspace_pi(vmspace_id);
}
