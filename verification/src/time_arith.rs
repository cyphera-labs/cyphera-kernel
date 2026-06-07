pub const EINVAL: i64 = 22;

pub fn split_secs_nsecs(nanos: u64) -> (i64, i64) {
    let sec = (nanos / 1_000_000_000) as i64;
    let nsec = (nanos % 1_000_000_000) as i64;
    (sec, nsec)
}

pub fn relative_deadline(tv_sec: u64, tv_nsec: u64, now: u64) -> Result<u64, i64> {
    if tv_nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }
    let dur = tv_sec.saturating_mul(1_000_000_000).saturating_add(tv_nsec);
    Ok(now.saturating_add(dur))
}

pub fn absolute_or_relative(tv_sec: u64, tv_nsec: u64, clockid: u64) -> Result<u64, i64> {
    if clockid != 0 && clockid != 1 {
        return Err(EINVAL);
    }
    if tv_nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }
    let abs = tv_sec.saturating_mul(1_000_000_000).saturating_add(tv_nsec);
    Ok(abs)
}

pub fn validate_futex2_flags(flags: u32) -> Result<(), i64> {
    const FUTEX2_SIZE_MASK: u32 = 0x3;
    const FUTEX2_SIZE_U32: u32 = 2;
    let size = flags & FUTEX2_SIZE_MASK;
    if size != FUTEX2_SIZE_U32 {
        return Err(EINVAL);
    }
    Ok(())
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn split_secs_nsecs_non_negative() {
        let nanos: u64 = kani::any();
        let (sec, nsec) = split_secs_nsecs(nanos);
        assert!(sec >= 0);
        assert!(nsec >= 0);
    }

    #[kani::proof]
    fn split_secs_nsecs_nsec_in_range() {
        let nanos: u64 = kani::any();
        let (_sec, nsec) = split_secs_nsecs(nanos);
        assert!(nsec >= 0);
        assert!(nsec < 1_000_000_000);
    }

    #[kani::proof]
    fn split_secs_nsecs_reconstructs() {
        let nanos: u64 = kani::any();
        kani::assume(nanos < (1u64 << 40));

        let (sec, nsec) = split_secs_nsecs(nanos);
        let reconstructed = (sec as u64) * 1_000_000_000 + (nsec as u64);
        assert_eq!(reconstructed, nanos);
    }

    #[kani::proof]
    fn relative_deadline_rejects_bad_nsec() {
        let tv_sec: u64 = kani::any();
        let tv_nsec: u64 = kani::any();
        let now: u64 = kani::any();
        kani::assume(tv_nsec >= 1_000_000_000);

        assert!(matches!(
            relative_deadline(tv_sec, tv_nsec, now),
            Err(EINVAL)
        ));
    }

    #[kani::proof]
    fn relative_deadline_monotonic() {
        let tv_sec: u64 = kani::any();
        let tv_nsec: u64 = kani::any();
        let now: u64 = kani::any();
        kani::assume(tv_nsec < 1_000_000_000);

        match relative_deadline(tv_sec, tv_nsec, now) {
            Ok(deadline) => assert!(deadline >= now),
            Err(_) => panic!("rejected a valid nsec"),
        }
    }

    #[kani::proof]
    fn absolute_or_relative_rejects_bad_clock() {
        let tv_sec: u64 = kani::any();
        let tv_nsec: u64 = kani::any();
        let clockid: u64 = kani::any();
        kani::assume(clockid != 0);
        kani::assume(clockid != 1);

        assert!(matches!(
            absolute_or_relative(tv_sec, tv_nsec, clockid),
            Err(EINVAL)
        ));
    }

    #[kani::proof]
    fn absolute_or_relative_rejects_bad_nsec() {
        let tv_sec: u64 = kani::any();
        let tv_nsec: u64 = kani::any();
        let clockid: u64 = kani::any();
        kani::assume(clockid == 0 || clockid == 1);
        kani::assume(tv_nsec >= 1_000_000_000);

        assert!(matches!(
            absolute_or_relative(tv_sec, tv_nsec, clockid),
            Err(EINVAL)
        ));
    }

    #[kani::proof]
    fn absolute_or_relative_total() {
        let tv_sec: u64 = kani::any();
        let tv_nsec: u64 = kani::any();
        let clockid: u64 = kani::any();
        kani::assume(clockid == 0 || clockid == 1);
        kani::assume(tv_nsec < 1_000_000_000);

        let _ = absolute_or_relative(tv_sec, tv_nsec, clockid);
    }

    #[kani::proof]
    fn futex2_flags_accept_iff_size_u32() {
        let flags: u32 = kani::any();
        let result = validate_futex2_flags(flags);
        let low = flags & 0x3;
        if low == 2 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(EINVAL)));
        }
    }

    #[kani::proof]
    fn futex2_flags_high_bits_irrelevant() {
        let flags: u32 = kani::any();
        let extra: u32 = kani::any();
        let masked_extra = extra & !0x3;
        let with_extra = flags | masked_extra;

        assert_eq!(
            validate_futex2_flags(flags).is_ok(),
            validate_futex2_flags(with_extra).is_ok(),
        );
    }
}
