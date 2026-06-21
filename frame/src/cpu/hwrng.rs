use core::arch::x86_64::{__cpuid, __cpuid_count};

const RETRIES: usize = 64;

fn has_rdrand() -> bool {
    (__cpuid(1).ecx & (1 << 30)) != 0
}

fn has_rdseed() -> bool {
    (__cpuid_count(7, 0).ebx & (1 << 18)) != 0
}

fn rdseed_word() -> Option<u64> {
    if !has_rdseed() {
        return None;
    }
    for _ in 0..RETRIES {
        let v: u64;
        let ok: u8;
        // SAFETY: RDSEED is present (CPUID-gated above). It writes a 64-bit
        // sample to `v` and reports success in CF, captured by SETC into `ok`;
        // it touches no memory or stack. Not marked `pure` — each execution
        // yields a fresh value and must not be hoisted or deduplicated.
        unsafe {
            core::arch::asm!(
                "rdseed {v}",
                "setc {ok}",
                v = out(reg) v,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok == 1 {
            return Some(v);
        }
        core::hint::spin_loop();
    }
    None
}

fn rdrand_word() -> Option<u64> {
    if !has_rdrand() {
        return None;
    }
    for _ in 0..RETRIES {
        let v: u64;
        let ok: u8;
        // SAFETY: RDRAND is present (CPUID-gated above); same contract as
        // rdseed_word — 64-bit value in `v`, success in CF, no mem/stack.
        unsafe {
            core::arch::asm!(
                "rdrand {v}",
                "setc {ok}",
                v = out(reg) v,
                ok = out(reg_byte) ok,
                options(nomem, nostack),
            );
        }
        if ok == 1 {
            return Some(v);
        }
        core::hint::spin_loop();
    }
    None
}

pub fn word() -> Option<u64> {
    rdseed_word().or_else(rdrand_word)
}

pub fn fill(out: &mut [u8]) -> usize {
    let mut n = 0;
    while n < out.len() {
        let Some(w) = word() else { break };
        let take = (out.len() - n).min(8);
        out[n..n + take].copy_from_slice(&w.to_le_bytes()[..take]);
        n += take;
    }
    n
}

pub fn available() -> bool {
    has_rdseed() || has_rdrand()
}
