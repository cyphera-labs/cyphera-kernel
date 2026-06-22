use super::*;

#[derive(Clone, Copy)]
pub(crate) struct EnqProv {
    seq: u64,
    site: &'static str,
    enq_cpu: u32,
    owner_at_enq: SchedOwner,
    state_kind: u8,
}

pub(crate) fn state_kind(s: &ProcessState) -> u8 {
    match s {
        ProcessState::Runnable => 0,
        ProcessState::Running => 1,
        ProcessState::Parked => 2,
        ProcessState::Zombie(_) => 3,
        ProcessState::KilledByFault { .. } => 4,
        ProcessState::Stopped => 5,
        ProcessState::DlThrottled => 6,
        ProcessState::CgroupThrottled => 7,
        ProcessState::Traced => 8,
        ProcessState::KilledBySignal { .. } => 9,
    }
}

pub(crate) fn fmt_state_kind(k: u8) -> &'static str {
    match k {
        0 => "Runnable",
        1 => "Running",
        2 => "Parked",
        3 => "Zombie",
        4 => "KilledByFault",
        5 => "Stopped",
        6 => "DlThrottled",
        7 => "CgroupThrottled",
        8 => "Traced",
        9 => "KilledBySignal",
        _ => "?",
    }
}

static ENQ_SEQ: AtomicU64 = AtomicU64::new(0);
static ENQ_LOG: SpinIrq<BTreeMap<Pid, EnqProv>> = SpinIrq::new(BTreeMap::new());

pub(crate) fn record_enqueue(pid: Pid, site: &'static str, proc: &Process) {
    let prov = EnqProv {
        seq: ENQ_SEQ.fetch_add(1, Ordering::SeqCst),
        site,
        enq_cpu: this_cpu(),
        owner_at_enq: proc.sched_owner.0,
        state_kind: state_kind(&proc.state.0),
    };
    ENQ_LOG.lock().insert(pid, prov);
}

pub(crate) fn record_dequeue(pid: Pid) {
    ENQ_LOG.lock().remove(&pid);
}

pub(crate) fn dump_enq_log(pid: Pid) -> Option<EnqProv> {
    ENQ_LOG.lock().get(&pid).copied()
}

pub(crate) fn print_stale_pid_provenance(pid: Pid, picker_cpu: u32, picker_site: &'static str) {
    let cur_seq = ENQ_SEQ.load(Ordering::Relaxed);
    match dump_enq_log(pid) {
        Some(p) => frame::println!(
            "[STALE-RQ] pid={} picker_cpu={} picker={} | last_enq: site={} seq={} enq_cpu={} owner={:?} state={} | cur_seq={}",
            pid.0,
            picker_cpu,
            picker_site,
            p.site,
            p.seq,
            p.enq_cpu,
            p.owner_at_enq,
            fmt_state_kind(p.state_kind),
            cur_seq,
        ),
        None => frame::println!(
            "[STALE-RQ] pid={} picker_cpu={} picker={} | NO last_enq record (already dequeued, but pid was on the runqueue?!) | cur_seq={}",
            pid.0,
            picker_cpu,
            picker_site,
            cur_seq,
        ),
    }
}
