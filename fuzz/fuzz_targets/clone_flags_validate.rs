#![no_main]

use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input {
    flags: u64,
    shape_pick: u8,
}

fuzz_target!(|input: Input| {
    let pthread_bundle = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
    let flags = match input.shape_pick % 8 {
        0 => pthread_bundle,
        1 => pthread_bundle | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID,
        2 => CLONE_VFORK | CLONE_VM,
        3 => CLONE_VFORK | CLONE_VM | CLONE_NEWPID,
        4 => 17,
        5 => CLONE_THREAD,
        6 => CLONE_VM,
        _ => input.flags,
    };

    let result = classify_clone(flags);
    let is_pthread = (flags & pthread_bundle) == pthread_bundle;
    let is_vfork = (flags & CLONE_VFORK) != 0
        && (flags & CLONE_VM) != 0
        && (flags & (CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD)) == 0;

    match result {
        Classification::Pthread => {
            assert!(is_pthread, "Pthread w/o full bundle: flags={:#x}", flags);
        }
        Classification::ForkLike => {
            assert!(!is_pthread);
            let unsupported_mask = if is_vfork {
                CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
            } else {
                CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
            };
            assert_eq!(
                flags & unsupported_mask,
                0,
                "ForkLike but flags has unsupported bits: flags={:#x} mask={:#x}",
                flags,
                unsupported_mask
            );
        }
        Classification::Rejected => {
            assert!(!is_pthread);
            let unsupported_mask = if is_vfork {
                CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
            } else {
                CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
            };
            assert_ne!(
                flags & unsupported_mask,
                0,
                "Rejected but no unsupported bit set: flags={:#x}",
                flags
            );
        }
    }
});

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_VFORK: u64 = 0x0000_4000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;

#[derive(Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum Classification {
    Pthread,
    ForkLike,
    Rejected,
}

fn classify_clone(flags: u64) -> Classification {
    let pthread_bundle = CLONE_VM | CLONE_THREAD | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
    let is_pthread = (flags & pthread_bundle) == pthread_bundle;
    if is_pthread {
        return Classification::Pthread;
    }
    let is_vfork_via_clone = (flags & CLONE_VFORK) != 0
        && (flags & CLONE_VM) != 0
        && (flags & (CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD)) == 0;
    let unsupported_mask = if is_vfork_via_clone {
        CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
    } else {
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
    };
    if flags & unsupported_mask != 0 {
        Classification::Rejected
    } else {
        Classification::ForkLike
    }
}
