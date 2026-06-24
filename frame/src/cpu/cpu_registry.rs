use crate::cpu::per_cpu::MAX_CPUS;
use crate::sync::SpinIrq;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApicId(pub u8);

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CpuIndex(u32);

impl CpuIndex {
    pub fn raw(self) -> u32 {
        self.0
    }
}

const UNMAPPED: u16 = u16::MAX;

struct CpuRegistry {
    apic_to_index: [u16; 256],
    index_to_apic: [u8; MAX_CPUS],
    count: u32,
}

impl CpuRegistry {
    const fn new() -> Self {
        Self {
            apic_to_index: [UNMAPPED; 256],
            index_to_apic: [0; MAX_CPUS],
            count: 0,
        }
    }

    fn register(&mut self, apic: ApicId) -> Option<CpuIndex> {
        let existing = self.apic_to_index[apic.0 as usize];
        if existing != UNMAPPED {
            return Some(CpuIndex(existing as u32));
        }
        if (self.count as usize) >= MAX_CPUS {
            return None;
        }
        let idx = self.count;
        self.apic_to_index[apic.0 as usize] = idx as u16;
        self.index_to_apic[idx as usize] = apic.0;
        self.count += 1;
        Some(CpuIndex(idx))
    }

    fn apic_for(&self, idx: CpuIndex) -> Option<ApicId> {
        if (idx.0 as usize) < (self.count as usize) {
            Some(ApicId(self.index_to_apic[idx.0 as usize]))
        } else {
            None
        }
    }

    fn index_for(&self, apic: ApicId) -> Option<CpuIndex> {
        match self.apic_to_index[apic.0 as usize] {
            UNMAPPED => None,
            v => Some(CpuIndex(v as u32)),
        }
    }
}

static CPU_REGISTRY: SpinIrq<CpuRegistry> = SpinIrq::new(CpuRegistry::new());

pub fn register_cpu(apic: ApicId) -> Option<CpuIndex> {
    CPU_REGISTRY.lock().register(apic)
}

pub fn apic_for_index(cpu_index: u32) -> Option<u8> {
    CPU_REGISTRY
        .lock()
        .apic_for(CpuIndex(cpu_index))
        .map(|a| a.0)
}

pub fn index_for_apic(apic: u8) -> Option<u32> {
    CPU_REGISTRY.lock().index_for(ApicId(apic)).map(|c| c.0)
}

pub fn selftest_sparse_mapping() -> bool {
    let mut reg = CpuRegistry::new();
    let inputs = [0u8, 2, 32, 64];
    for (expected, &apic) in inputs.iter().enumerate() {
        match reg.register(ApicId(apic)) {
            Some(idx) if idx.raw() as usize == expected => {}
            _ => return false,
        }
    }
    if reg.register(ApicId(2)) != Some(CpuIndex(1)) {
        return false;
    }
    if reg.count as usize != inputs.len() {
        return false;
    }
    for (expected_idx, &apic) in inputs.iter().enumerate() {
        if reg.index_for(ApicId(apic)) != Some(CpuIndex(expected_idx as u32)) {
            return false;
        }
        if reg.apic_for(CpuIndex(expected_idx as u32)) != Some(ApicId(apic)) {
            return false;
        }
    }
    if reg.index_for(ApicId(100)).is_some() {
        return false;
    }
    if reg.apic_for(CpuIndex(MAX_CPUS as u32)).is_some() {
        return false;
    }
    true
}
