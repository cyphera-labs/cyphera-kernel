#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedOwner {
    None,
    Running { cpu: u32 },
    Runnable { cpu: u32 },
    Parked { waitq_addr: usize },
    Stopped,
    Traced,
    Zombie,
    Reaping,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Runnable,
    Running,
    Parked,
    Zombie(i32),
    KilledByFault { vector: u8, addr: u64, error: u64 },
    Stopped,
    DlThrottled,
    CgroupThrottled,
    Traced,
    KilledBySignal { signal: u32 },
}

pub(crate) fn sched_owner_transition_ok(cur: SchedOwner, new: SchedOwner) -> bool {
    match (cur, new) {
        (SchedOwner::None, SchedOwner::Runnable { .. }) => true,
        (SchedOwner::None, SchedOwner::Running { .. }) => true,

        (SchedOwner::Runnable { cpu: a }, SchedOwner::Running { cpu: b }) => a == b,
        (SchedOwner::Running { cpu: a }, SchedOwner::Runnable { cpu: b }) => a == b,

        (SchedOwner::Running { .. }, SchedOwner::Parked { .. }) => true,
        (SchedOwner::Parked { .. }, SchedOwner::Runnable { .. }) => true,

        (SchedOwner::Parked { .. }, SchedOwner::Running { cpu: _ }) => true,

        (SchedOwner::Runnable { .. }, SchedOwner::Runnable { .. }) => true,

        (SchedOwner::Running { .. }, SchedOwner::Stopped) => true,
        (SchedOwner::Running { .. }, SchedOwner::Traced) => true,
        (SchedOwner::Stopped, SchedOwner::Runnable { .. }) => true,
        (SchedOwner::Traced, SchedOwner::Runnable { .. }) => true,

        (SchedOwner::Running { .. }, SchedOwner::Zombie) => true,
        (SchedOwner::Runnable { .. }, SchedOwner::Zombie) => true,
        (SchedOwner::Parked { .. }, SchedOwner::Zombie) => true,
        (SchedOwner::Stopped, SchedOwner::Zombie) => true,
        (SchedOwner::Traced, SchedOwner::Zombie) => true,

        (SchedOwner::Zombie, SchedOwner::Reaping) => true,
        (SchedOwner::Reaping, SchedOwner::None) => true,

        (a, b) if a == b => true,

        _ => false,
    }
}

pub(crate) fn state_is_terminal(s: &ProcessState) -> bool {
    matches!(
        s,
        ProcessState::Zombie(_)
            | ProcessState::KilledByFault { .. }
            | ProcessState::KilledBySignal { .. }
    )
}

pub(crate) fn state_transition_ok(cur: &ProcessState, new: &ProcessState) -> bool {
    use ProcessState::*;

    if state_is_terminal(new) {
        return true;
    }
    if state_is_terminal(cur) {
        return false;
    }

    match (cur, new) {
        (Running, Runnable) => true,
        (Runnable, Running) => true,

        (Running, Parked) => true,
        (Parked, Runnable) => true,

        (Running, Stopped) => true,
        (Stopped, Runnable) => true,

        (Running, Traced) => true,
        (Stopped, Traced) => true,
        (Traced, Runnable) => true,

        (Running, CgroupThrottled) => true,
        (Runnable, CgroupThrottled) => true,
        (CgroupThrottled, Runnable) => true,

        (Running, DlThrottled) => true,
        (DlThrottled, Runnable) => true,

        (a, b) if a == b => true,

        _ => false,
    }
}

pub(crate) fn state_owner_consistent(state: &ProcessState, owner: SchedOwner) -> bool {
    use ProcessState as S;

    if state_is_terminal(state) {
        return true;
    }
    if matches!(owner, SchedOwner::Zombie | SchedOwner::Reaping) {
        return true;
    }

    matches!(
        (state, owner),
        (S::Runnable, SchedOwner::Runnable { .. })
            | (S::Runnable, SchedOwner::None)
            | (S::Running, SchedOwner::Running { .. })
            | (S::Running, SchedOwner::Runnable { .. })
            | (S::Runnable, SchedOwner::Running { .. })
            | (S::Parked, SchedOwner::Parked { .. })
            | (S::Stopped, SchedOwner::Stopped)
            | (S::Traced, SchedOwner::Traced)
            | (
                S::DlThrottled | S::CgroupThrottled,
                SchedOwner::Parked { .. }
                    | SchedOwner::Running { .. }
                    | SchedOwner::Runnable { .. }
            )
            | (
                S::Parked | S::Stopped | S::Traced,
                SchedOwner::Running { .. }
            )
            | (S::Runnable, SchedOwner::Parked { .. })
            | (S::Runnable, SchedOwner::Stopped)
            | (S::Runnable, SchedOwner::Traced)
            | (S::Traced, SchedOwner::Stopped)
    )
}

#[cfg(test)]
mod transition_tests {
    use super::*;

    #[test]
    fn sched_owner_legal_transitions_pass() {
        assert!(sched_owner_transition_ok(
            SchedOwner::None,
            SchedOwner::Runnable { cpu: 0 }
        ));
        assert!(sched_owner_transition_ok(
            SchedOwner::Running { cpu: 1 },
            SchedOwner::Parked { waitq_addr: 0 }
        ));
        assert!(sched_owner_transition_ok(
            SchedOwner::Parked { waitq_addr: 0 },
            SchedOwner::Runnable { cpu: 1 }
        ));
        assert!(sched_owner_transition_ok(
            SchedOwner::Running { cpu: 0 },
            SchedOwner::Zombie
        ));
        assert!(sched_owner_transition_ok(
            SchedOwner::Zombie,
            SchedOwner::Reaping
        ));
        assert!(sched_owner_transition_ok(
            SchedOwner::Reaping,
            SchedOwner::None
        ));
    }

    #[test]
    fn sched_owner_illegal_transitions_fail() {
        assert!(!sched_owner_transition_ok(
            SchedOwner::Running { cpu: 0 },
            SchedOwner::Runnable { cpu: 1 }
        ));
        assert!(!sched_owner_transition_ok(
            SchedOwner::Zombie,
            SchedOwner::Runnable { cpu: 0 }
        ));
        assert!(!sched_owner_transition_ok(
            SchedOwner::Reaping,
            SchedOwner::Running { cpu: 0 }
        ));
        assert!(!sched_owner_transition_ok(
            SchedOwner::None,
            SchedOwner::Zombie
        ));
    }

    #[test]
    fn state_terminal_is_absorbing() {
        assert!(state_transition_ok(
            &ProcessState::Running,
            &ProcessState::Zombie(0)
        ));
        assert!(state_transition_ok(
            &ProcessState::Parked,
            &ProcessState::KilledBySignal { signal: 9 }
        ));
        assert!(state_transition_ok(
            &ProcessState::Zombie(0),
            &ProcessState::Zombie(1)
        ));
    }

    #[test]
    fn state_resurrection_rejected() {
        assert!(!state_transition_ok(
            &ProcessState::Zombie(0),
            &ProcessState::Runnable
        ));
        assert!(!state_transition_ok(
            &ProcessState::KilledByFault {
                vector: 14,
                addr: 0,
                error: 0,
            },
            &ProcessState::Running
        ));
        assert!(!state_transition_ok(
            &ProcessState::KilledBySignal { signal: 9 },
            &ProcessState::Runnable
        ));
    }

    #[test]
    fn state_legal_nonterminal_edges_pass() {
        assert!(state_transition_ok(
            &ProcessState::Running,
            &ProcessState::Runnable
        ));
        assert!(state_transition_ok(
            &ProcessState::Running,
            &ProcessState::Parked
        ));
        assert!(state_transition_ok(
            &ProcessState::Parked,
            &ProcessState::Runnable
        ));
        assert!(state_transition_ok(
            &ProcessState::Stopped,
            &ProcessState::Traced
        ));
        assert!(state_transition_ok(
            &ProcessState::Runnable,
            &ProcessState::CgroupThrottled
        ));
        assert!(state_transition_ok(
            &ProcessState::DlThrottled,
            &ProcessState::Runnable
        ));
    }

    #[test]
    fn state_illegal_nonterminal_edges_fail() {
        assert!(!state_transition_ok(
            &ProcessState::Parked,
            &ProcessState::Stopped
        ));
        assert!(!state_transition_ok(
            &ProcessState::Parked,
            &ProcessState::Running
        ));
        assert!(!state_transition_ok(
            &ProcessState::Stopped,
            &ProcessState::Parked
        ));
        assert!(!state_transition_ok(
            &ProcessState::DlThrottled,
            &ProcessState::CgroupThrottled
        ));
    }

    #[test]
    fn state_owner_rest_pairs_consistent() {
        assert!(state_owner_consistent(
            &ProcessState::Running,
            SchedOwner::Running { cpu: 0 }
        ));
        assert!(state_owner_consistent(
            &ProcessState::Runnable,
            SchedOwner::Runnable { cpu: 0 }
        ));
        assert!(state_owner_consistent(
            &ProcessState::Parked,
            SchedOwner::Parked { waitq_addr: 7 }
        ));
        assert!(state_owner_consistent(
            &ProcessState::Stopped,
            SchedOwner::Stopped
        ));
        assert!(state_owner_consistent(
            &ProcessState::Traced,
            SchedOwner::Traced
        ));
        assert!(state_owner_consistent(
            &ProcessState::DlThrottled,
            SchedOwner::Parked { waitq_addr: 0 }
        ));
        assert!(state_owner_consistent(
            &ProcessState::CgroupThrottled,
            SchedOwner::Parked { waitq_addr: 0 }
        ));
    }

    #[test]
    fn state_owner_blessed_transients_consistent() {
        assert!(state_owner_consistent(
            &ProcessState::Runnable,
            SchedOwner::Parked { waitq_addr: 9 }
        ));
        assert!(state_owner_consistent(
            &ProcessState::Runnable,
            SchedOwner::Traced
        ));
        assert!(state_owner_consistent(
            &ProcessState::Traced,
            SchedOwner::Stopped
        ));
        assert!(state_owner_consistent(
            &ProcessState::Parked,
            SchedOwner::Running { cpu: 1 }
        ));
        assert!(state_owner_consistent(
            &ProcessState::Running,
            SchedOwner::Runnable { cpu: 1 }
        ));
        assert!(state_owner_consistent(
            &ProcessState::Zombie(0),
            SchedOwner::Stopped
        ));
        assert!(state_owner_consistent(
            &ProcessState::Runnable,
            SchedOwner::Zombie
        ));
    }

    #[test]
    fn state_owner_divergence_rejected() {
        assert!(!state_owner_consistent(
            &ProcessState::Parked,
            SchedOwner::Stopped
        ));
        assert!(!state_owner_consistent(
            &ProcessState::Stopped,
            SchedOwner::Parked { waitq_addr: 0 }
        ));
        assert!(!state_owner_consistent(
            &ProcessState::Running,
            SchedOwner::Parked { waitq_addr: 0 }
        ));
        assert!(!state_owner_consistent(
            &ProcessState::Traced,
            SchedOwner::Runnable { cpu: 0 }
        ));
    }
}
