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
    !state_is_terminal(cur) || state_is_terminal(new)
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
}
