use core::arch::x86_64::__cpuid;
use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::registers::model_specific::Msr;

use crate::boot::KERNEL_VMA_OFFSET;

const FALLBACK_TSC_HZ: u64 = 2_000_000_000;

const KVM_CPUID_SIGNATURE: u32 = 0x4000_0000;
const KVM_CPUID_FEATURES: u32 = 0x4000_0001;
const KVM_FEATURE_CLOCKSOURCE2: u32 = 1 << 3;

const MSR_KVM_WALL_CLOCK_NEW: u32 = 0x4b56_4d00;
const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;

static TSC_HZ: AtomicU64 = AtomicU64::new(FALLBACK_TSC_HZ);
static BOOT_TSC: AtomicU64 = AtomicU64::new(0);

#[allow(clippy::declare_interior_mutable_const)]
const PVCLOCK_PER_CPU_INIT: AtomicU64 = AtomicU64::new(0);
static PVCLOCK_TIME_INFO: [AtomicU64; crate::cpu::per_cpu::MAX_CPUS] =
    [PVCLOCK_PER_CPU_INIT; crate::cpu::per_cpu::MAX_CPUS];

static PVCLOCK_WALL_CLOCK: AtomicU64 = AtomicU64::new(0);

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct PvclockVcpuTimeInfo {
    version: u32,
    pad0: u32,
    tsc_timestamp: u64,
    system_time: u64,
    tsc_to_system_mul: u32,
    tsc_shift: i8,
    flags: u8,
    pad: [u8; 2],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct PvclockWallClock {
    version: u32,
    sec: u32,
    nsec: u32,
}

pub fn init() {
    if BOOT_TSC.load(Ordering::Relaxed) != 0 {
        return;
    }

    let kvm = setup_kvm_pvclock_bsp();

    let hz = if kvm {
        tsc_hz_from_pvclock().unwrap_or_else(tsc_hz_from_cpuid)
    } else {
        tsc_hz_from_cpuid()
    };
    TSC_HZ.store(hz.max(1), Ordering::SeqCst);

    BOOT_TSC.store(rdtsc(), Ordering::SeqCst);

    let wall_src = if kvm {
        "pvclock"
    } else if let Some(epoch_ns) = super::rtc::read_cmos_unix_nanos() {
        set_wall_clock_target(epoch_ns);
        "rtc"
    } else if let Some(secs) = option_env!("SOURCE_DATE_EPOCH").and_then(|s| s.parse::<u64>().ok())
    {
        set_wall_clock_target(secs.saturating_mul(1_000_000_000));
        "source-date"
    } else {
        "uptime"
    };

    crate::println!(
        "clock: tsc {} MHz; pvclock={}; wall={}",
        hz / 1_000_000,
        if kvm { "yes" } else { "no" },
        wall_src
    );
}

#[inline]
pub fn tsc_hz() -> u64 {
    TSC_HZ.load(Ordering::Relaxed)
}

#[inline]
pub fn rdtsc() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: RDTSC is unprivileged on x86_64 and only reads the
    // time-stamp counter into EAX/EDX (declared as the sole outputs);
    // it touches no memory and clobbers no other register. `nomem`
    // holds because it reads no Rust-visible memory, `nostack` because
    // it uses no stack, and `preserves_flags` because RDTSC leaves
    // RFLAGS untouched.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

pub fn record_boot_tsc() {
    if BOOT_TSC.load(Ordering::Relaxed) == 0 {
        BOOT_TSC.store(rdtsc(), Ordering::SeqCst);
    }
}

pub fn nanos_since_boot() -> u64 {
    let start = BOOT_TSC.load(Ordering::Relaxed);
    if start == 0 {
        return 0;
    }
    let delta = rdtsc().wrapping_sub(start);
    let hz = tsc_hz();
    cycles_to_nanos(delta, hz)
}

pub fn wall_clock_nanos() -> u64 {
    let raw = wall_clock_nanos_raw();
    let offset = WALL_CLOCK_OFFSET_NS.load(Ordering::Relaxed);
    let base = if raw != 0 {
        raw
    } else if offset != 0 {
        nanos_since_boot()
    } else {
        return 0;
    };
    if offset >= 0 {
        base.saturating_add(offset as u64)
    } else {
        base.saturating_sub((-offset) as u64)
    }
}

fn wall_clock_nanos_raw() -> u64 {
    let _irq = crate::sync::IrqGuard::new();
    let cpu = crate::cpu::per_cpu::current_cpu_id() as usize;
    if cpu >= crate::cpu::per_cpu::MAX_CPUS {
        return 0;
    }
    let time_info_va = PVCLOCK_TIME_INFO[cpu].load(Ordering::Relaxed);
    let wall_va = PVCLOCK_WALL_CLOCK.load(Ordering::Relaxed);
    if time_info_va == 0 || wall_va == 0 {
        return 0;
    }
    let (sys_ns, _stable) = match read_pvclock_time_info(time_info_va) {
        Some(v) => v,
        None => return 0,
    };
    let (boot_sec, boot_nsec) = match read_pvclock_wall_clock(wall_va) {
        Some(v) => v,
        None => return 0,
    };
    (boot_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(boot_nsec as u64)
        .saturating_add(sys_ns)
}

static WALL_CLOCK_OFFSET_NS: core::sync::atomic::AtomicI64 = core::sync::atomic::AtomicI64::new(0);

pub fn wall_clock_offset_ns() -> i64 {
    WALL_CLOCK_OFFSET_NS.load(Ordering::Relaxed)
}

pub fn set_wall_clock_target(target_ns: u64) {
    let raw = wall_clock_nanos_raw();
    let base = if raw != 0 { raw } else { nanos_since_boot() };
    WALL_CLOCK_OFFSET_NS.store(target_ns as i64 - base as i64, Ordering::Relaxed);
}

pub fn shift_wall_clock_offset(delta_ns: i64) {
    let prev = WALL_CLOCK_OFFSET_NS.load(Ordering::Relaxed);
    WALL_CLOCK_OFFSET_NS.store(prev.saturating_add(delta_ns), Ordering::Relaxed);
}

pub fn busy_wait_nanos(nanos: u64) {
    if nanos == 0 {
        return;
    }
    let hz = tsc_hz();
    let cycles = nanos_to_cycles(nanos, hz);
    let start = rdtsc();
    while rdtsc().wrapping_sub(start) < cycles {
        super::pause();
    }
}

fn setup_kvm_pvclock_bsp() -> bool {
    if !kvm_present() {
        return false;
    }
    let features = __cpuid(KVM_CPUID_FEATURES);
    if features.eax & KVM_FEATURE_CLOCKSOURCE2 == 0 {
        return false;
    }

    let time_frame = match crate::mm::frame_alloc::alloc_frame() {
        Some(f) => f,
        None => return false,
    };
    let wall_frame = match crate::mm::frame_alloc::alloc_frame() {
        Some(f) => f,
        None => return false,
    };
    let time_pa = time_frame.start_address().as_u64();
    let wall_pa = wall_frame.start_address().as_u64();

    let time_va = time_pa | KERNEL_VMA_OFFSET;
    let wall_va = wall_pa | KERNEL_VMA_OFFSET;
    // SAFETY: time_va/wall_va are the kernel high-VA aliases (physical
    // base | KERNEL_VMA_OFFSET) of the two frames just handed out by
    // alloc_frame, so each is mapped, 4096-byte page-aligned, and owned
    // exclusively by this code path (the frames are not published into
    // PVCLOCK_* until after this write). Writing exactly one page of
    // zeros stays within the allocated frame.
    unsafe {
        core::ptr::write_bytes(time_va as *mut u8, 0, 4096);
        core::ptr::write_bytes(wall_va as *mut u8, 0, 4096);
    }

    // SAFETY: MSR_KVM_SYSTEM_TIME_NEW / MSR_KVM_WALL_CLOCK_NEW are the
    // documented per-vCPU clocksource MSRs, present because the
    // KVM_FEATURE_CLOCKSOURCE2 CPUID bit was confirmed above. We write
    // the guest physical addresses of the freshly zeroed, kernel-owned
    // frames (time_pa with bit 0 set to arm publishing); the host
    // hypervisor only ever writes the pvclock layout into those pages,
    // affecting no other Rust-visible memory.
    unsafe {
        Msr::new(MSR_KVM_SYSTEM_TIME_NEW).write(time_pa | 1);
        Msr::new(MSR_KVM_WALL_CLOCK_NEW).write(wall_pa);
    }

    PVCLOCK_TIME_INFO[0].store(time_va, Ordering::SeqCst);
    PVCLOCK_WALL_CLOCK.store(wall_va, Ordering::SeqCst);
    true
}

pub fn init_ap(cpu_id: u32) {
    let cpu = cpu_id as usize;
    if cpu >= crate::cpu::per_cpu::MAX_CPUS {
        return;
    }
    if PVCLOCK_WALL_CLOCK.load(Ordering::Relaxed) == 0 {
        return;
    }
    if PVCLOCK_TIME_INFO[cpu].load(Ordering::Relaxed) != 0 {
        return;
    }

    let frame_ = match crate::mm::frame_alloc::alloc_frame() {
        Some(f) => f,
        None => return,
    };
    let pa = frame_.start_address().as_u64();
    let va = pa | KERNEL_VMA_OFFSET;
    // SAFETY: va is the kernel high-VA alias of the frame just returned
    // by alloc_frame, so it is mapped, page-aligned, and owned solely by
    // this AP path until stored into PVCLOCK_TIME_INFO below; zeroing one
    // page stays in bounds. MSR_KVM_SYSTEM_TIME_NEW is the per-vCPU
    // clocksource MSR and is present VM-wide (PVCLOCK_WALL_CLOCK is
    // non-zero, so the BSP confirmed KVM_FEATURE_CLOCKSOURCE2); writing
    // this vCPU's frame GPA with the enable bit only points the host at
    // this owned page.
    unsafe {
        core::ptr::write_bytes(va as *mut u8, 0, 4096);
        Msr::new(MSR_KVM_SYSTEM_TIME_NEW).write(pa | 1);
    }
    PVCLOCK_TIME_INFO[cpu].store(va, Ordering::SeqCst);
}

fn kvm_present() -> bool {
    let sig = __cpuid(KVM_CPUID_SIGNATURE);
    let ok = sig.ebx == 0x4B4D_564B && sig.ecx == 0x564B_4D56 && sig.edx == 0x0000_004D;
    if !ok {
        crate::println!(
            "kvm-detect: cpuid 0x40000000 -> eax={:#x} ebx={:#x} ecx={:#x} edx={:#x}",
            sig.eax,
            sig.ebx,
            sig.ecx,
            sig.edx
        );
    }
    ok
}

fn read_pvclock_time_info(va: u64) -> Option<(u64, bool)> {
    use core::ptr::{addr_of, read_unaligned, read_volatile};
    let ptr = va as *const PvclockVcpuTimeInfo;
    for _ in 0..5 {
        // SAFETY: va is a non-zero pvclock time-info VA published by
        // setup_kvm_pvclock_bsp/init_ap — the kernel high-VA alias of a
        // full owned frame, so it is mapped and large enough for the
        // struct. addr_of! avoids forming a reference into the
        // packed/concurrently-host-written layout, and read_volatile is
        // mandatory here because the host hypervisor mutates `version`
        // out from under us (the odd-then-equal check below detects an
        // in-flight update).
        let v_before = unsafe { read_volatile(addr_of!((*ptr).version)) };
        if v_before & 1 != 0 {
            super::pause();
            continue;
        }
        // SAFETY: same mapped, frame-sized, owned page as above;
        // read_unaligned tolerates the #[repr(C, packed)] layout, and
        // the surrounding version-stability check discards the snapshot
        // if the host wrote it mid-read.
        let info = unsafe { read_unaligned(ptr) };
        // SAFETY: re-reads `version` from the same mapped page via
        // addr_of! + read_volatile; the volatile read is required so the
        // compiler cannot fold it with v_before and miss a host update.
        let v_after = unsafe { read_volatile(addr_of!((*ptr).version)) };
        if v_before != v_after {
            super::pause();
            continue;
        }
        let tsc_now = rdtsc();
        let ts = info.tsc_timestamp;
        let tsc_to_system_mul = info.tsc_to_system_mul;
        let tsc_shift = info.tsc_shift;
        let system_time = info.system_time;
        let flags = info.flags;
        let mut delta = tsc_now.saturating_sub(ts);
        if tsc_shift >= 0 {
            delta <<= tsc_shift as u32;
        } else {
            delta >>= (-tsc_shift) as u32;
        }
        let scaled = (delta as u128).wrapping_mul(tsc_to_system_mul as u128) >> 32;
        let ns = (scaled as u64).wrapping_add(system_time);
        let stable = flags & 1 != 0;
        return Some((ns, stable));
    }
    None
}

fn read_pvclock_wall_clock(va: u64) -> Option<(u32, u32)> {
    use core::ptr::{addr_of, read_unaligned, read_volatile};
    let ptr = va as *const PvclockWallClock;
    for _ in 0..5 {
        // SAFETY: va is the non-zero PVCLOCK_WALL_CLOCK VA published by
        // setup_kvm_pvclock_bsp — the kernel high-VA alias of an owned,
        // mapped frame larger than this struct. addr_of! avoids a
        // reference into the packed, host-written page; read_volatile is
        // required because the host mutates `version` concurrently and
        // the odd-version / mismatch checks rely on observing each store.
        let v_before = unsafe { read_volatile(addr_of!((*ptr).version)) };
        if v_before & 1 != 0 {
            super::pause();
            continue;
        }
        // SAFETY: same mapped, frame-sized, owned page; read_unaligned
        // handles the #[repr(C, packed)] layout and the version check
        // below rejects the snapshot if the host updated it mid-read.
        let snap = unsafe { read_unaligned(ptr) };
        // SAFETY: re-reads `version` from the same page via addr_of! +
        // read_volatile so the compiler keeps it distinct from v_before
        // and a concurrent host update is observed.
        let v_after = unsafe { read_volatile(addr_of!((*ptr).version)) };
        if v_before != v_after {
            super::pause();
            continue;
        }
        return Some((snap.sec, snap.nsec));
    }
    None
}

fn tsc_hz_from_pvclock() -> Option<u64> {
    let va = PVCLOCK_TIME_INFO[0].load(Ordering::Relaxed);
    if va == 0 {
        return None;
    }
    let ptr = va as *const PvclockVcpuTimeInfo;
    // SAFETY: va is the BSP's PVCLOCK_TIME_INFO[0] entry, checked
    // non-zero just above — the kernel high-VA alias of the owned,
    // mapped frame published by setup_kvm_pvclock_bsp, sized well beyond
    // the struct. read_unaligned tolerates the #[repr(C, packed)]
    // layout. This runs once during init() on the BSP (KVM has just
    // populated the page with the scaling parameters), so no version
    // retry is needed for a one-shot calibration read.
    let info = unsafe { core::ptr::read_unaligned(ptr) };
    if info.tsc_to_system_mul == 0 {
        return None;
    }
    let one_sec_in_cycles = {
        let mul = info.tsc_to_system_mul as u64;
        let denom = if info.tsc_shift >= 0 {
            (mul << info.tsc_shift as u32) as u128
        } else {
            (mul >> (-info.tsc_shift) as u32) as u128
        };
        if denom == 0 {
            return None;
        }
        ((1u128 << 32) * 1_000_000_000u128 / denom) as u64
    };
    Some(one_sec_in_cycles)
}

fn tsc_hz_from_cpuid() -> u64 {
    if let Some(hz) = tsc_hz_from_leaf_15() {
        return hz;
    }
    if let Some(hz) = tsc_hz_from_leaf_16() {
        return hz;
    }
    FALLBACK_TSC_HZ
}

fn tsc_hz_from_leaf_15() -> Option<u64> {
    let max_leaf = __cpuid(0).eax;
    if max_leaf < 0x15 {
        return None;
    }
    let r = __cpuid(0x15);
    let den = r.eax as u64;
    let num = r.ebx as u64;
    let crystal = r.ecx as u64;
    if den == 0 || num == 0 || crystal == 0 {
        return None;
    }
    Some(crystal.saturating_mul(num) / den)
}

fn tsc_hz_from_leaf_16() -> Option<u64> {
    let max_leaf = __cpuid(0).eax;
    if max_leaf < 0x16 {
        return None;
    }
    let r = __cpuid(0x16);
    let mhz = r.eax as u64;
    if mhz == 0 {
        return None;
    }
    Some(mhz.saturating_mul(1_000_000))
}

#[inline]
fn cycles_to_nanos(cycles: u64, hz: u64) -> u64 {
    ((cycles as u128) * 1_000_000_000u128 / hz as u128) as u64
}

#[inline]
fn nanos_to_cycles(nanos: u64, hz: u64) -> u64 {
    ((nanos as u128) * (hz as u128) / 1_000_000_000u128) as u64
}
