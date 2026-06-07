#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    op: u64,
    flags: u32,
    op_pick: u8,
}

fuzz_target!(|input: Input| {
    let op = match input.op_pick % 16 {
        0 => FUTEX_WAIT,
        1 => FUTEX_WAKE,
        2 => FUTEX_REQUEUE,
        3 => FUTEX_CMP_REQUEUE,
        4 => FUTEX_WAKE_OP,
        5 => FUTEX_LOCK_PI,
        6 => FUTEX_UNLOCK_PI,
        7 => FUTEX_TRYLOCK_PI,
        8 => FUTEX_WAIT_BITSET,
        9 => FUTEX_WAKE_BITSET,
        10 => FUTEX_WAIT_REQUEUE_PI,
        11 => FUTEX_CMP_REQUEUE_PI,
        12 => FUTEX_LOCK_PI2,
        13 => FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
        14 => FUTEX_WAKE | FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME,
        _ => input.op,
    };

    let raw_op = op & FUTEX_OP_MASK;
    let dispatch = classify_futex_op(raw_op);

    assert_eq!(
        raw_op,
        op & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME),
        "raw_op stripped wrong bits"
    );
    let known = matches!(
        raw_op,
        FUTEX_WAIT
            | FUTEX_WAKE
            | FUTEX_REQUEUE
            | FUTEX_CMP_REQUEUE
            | FUTEX_WAKE_OP
            | FUTEX_LOCK_PI
            | FUTEX_UNLOCK_PI
            | FUTEX_TRYLOCK_PI
            | FUTEX_WAIT_BITSET
            | FUTEX_WAKE_BITSET
            | FUTEX_WAIT_REQUEUE_PI
            | FUTEX_CMP_REQUEUE_PI
            | FUTEX_LOCK_PI2
    );
    assert_eq!(dispatch.is_some(), known, "dispatch/known mismatch for raw_op={:#x}", raw_op);

    let f2 = validate_futex2_flags(input.flags);
    let size = input.flags & FUTEX2_SIZE_MASK;
    if size == FUTEX2_SIZE_U32 {
        assert!(f2.is_ok(), "FUTEX2_SIZE_U32 rejected (flags={:#x})", input.flags);
    } else {
        assert!(f2.is_err(), "non-U32 size accepted (size={}, flags={:#x})", size, input.flags);
    }
});

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_REQUEUE: u64 = 3;
const FUTEX_CMP_REQUEUE: u64 = 4;
const FUTEX_WAKE_OP: u64 = 5;
const FUTEX_LOCK_PI: u64 = 6;
const FUTEX_UNLOCK_PI: u64 = 7;
const FUTEX_TRYLOCK_PI: u64 = 8;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_WAIT_REQUEUE_PI: u64 = 11;
const FUTEX_CMP_REQUEUE_PI: u64 = 12;
const FUTEX_LOCK_PI2: u64 = 13;
const FUTEX_PRIVATE_FLAG: u64 = 0x80;
const FUTEX_CLOCK_REALTIME: u64 = 0x100;
const FUTEX_OP_MASK: u64 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum FutexDispatch {
    Wait,
    Wake,
    Requeue,
    CmpRequeue,
    WakeOp,
    LockPi,
    UnlockPi,
    TrylockPi,
    WaitBitset,
    WakeBitset,
    WaitRequeuePi,
    CmpRequeuePi,
}

fn classify_futex_op(raw_op: u64) -> Option<FutexDispatch> {
    Some(match raw_op {
        FUTEX_WAIT => FutexDispatch::Wait,
        FUTEX_WAKE => FutexDispatch::Wake,
        FUTEX_REQUEUE => FutexDispatch::Requeue,
        FUTEX_CMP_REQUEUE => FutexDispatch::CmpRequeue,
        FUTEX_WAKE_OP => FutexDispatch::WakeOp,
        FUTEX_LOCK_PI | FUTEX_LOCK_PI2 => FutexDispatch::LockPi,
        FUTEX_UNLOCK_PI => FutexDispatch::UnlockPi,
        FUTEX_TRYLOCK_PI => FutexDispatch::TrylockPi,
        FUTEX_WAIT_BITSET => FutexDispatch::WaitBitset,
        FUTEX_WAKE_BITSET => FutexDispatch::WakeBitset,
        FUTEX_WAIT_REQUEUE_PI => FutexDispatch::WaitRequeuePi,
        FUTEX_CMP_REQUEUE_PI => FutexDispatch::CmpRequeuePi,
        _ => return None,
    })
}

const FUTEX2_SIZE_MASK: u32 = 0x3;
const FUTEX2_SIZE_U32: u32 = 2;

fn validate_futex2_flags(flags: u32) -> Result<(), ()> {
    let size = flags & FUTEX2_SIZE_MASK;
    if size != FUTEX2_SIZE_U32 {
        return Err(());
    }
    Ok(())
}
