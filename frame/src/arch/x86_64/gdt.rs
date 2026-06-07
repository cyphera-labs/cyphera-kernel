use spin::Once;
use x86_64::instructions::segmentation::{CS, DS, ES, FS, GS, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};

use crate::cpu::per_cpu::MAX_CPUS;

use super::tss::{populate_for, tss_static};

const GDT_SIZE: usize = 16;

#[derive(Copy, Clone)]
pub struct Selectors {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_code: SegmentSelector,
    pub user_data: SegmentSelector,
}

struct GdtState {
    gdt: GlobalDescriptorTable<GDT_SIZE>,
    sel: Selectors,
    tss_selectors: [SegmentSelector; MAX_CPUS],
}

static GDT: Once<GdtState> = Once::new();

pub fn init_for(cpu_id: u32) {
    let state = GDT.call_once(|| {
        for i in 0..(MAX_CPUS as u32) {
            populate_for(i);
        }

        let mut gdt = GlobalDescriptorTable::<GDT_SIZE>::empty();
        let kernel_code = gdt.append(Descriptor::kernel_code_segment());
        let kernel_data = gdt.append(Descriptor::kernel_data_segment());
        let user_data = gdt.append(Descriptor::user_data_segment());
        let user_code = gdt.append(Descriptor::user_code_segment());

        let mut tss_selectors = [SegmentSelector::NULL; MAX_CPUS];
        for (i, slot) in tss_selectors.iter_mut().enumerate() {
            *slot = gdt.append(Descriptor::tss_segment(tss_static(i as u32)));
        }

        GdtState {
            gdt,
            sel: Selectors {
                kernel_code,
                kernel_data,
                user_code,
                user_data,
            },
            tss_selectors,
        }
    });

    state.gdt.load();
    // SAFETY: `gdt.load()` just installed this exact GDT into this CPU's
    // GDTR, so every selector below indexes a present descriptor in the
    // live table. kernel_code/kernel_data are the selectors `gdt.append`
    // returned for the CS and data descriptors, so each matches its
    // descriptor type and DPL=0 (we are at CPL=0 during init). Every CPU's
    // TSS was filled by the `call_once` closure (BSP, single-threaded,
    // before any AP starts) before its descriptor was appended, so each
    // `tss_selectors[i]` points at a present 64-bit TSS descriptor. `cpu_id`
    // is the caller-supplied CPU index (BSP passes 0; the AP path in
    // `smp::ap_low_entry` passes its trampoline-bounded id); this scope does
    // not check the bound, but `tss_selectors[cpu_id as usize]` is a slice
    // index, so an out-of-range id panics rather than reading OOB. Each CPU
    // `LTR`s its own dedicated slot `tss_selectors[cpu_id]`, so no two CPUs
    // ever touch the same TSS busy bit; and `init_for` runs once per CPU, so
    // a CPU never re-`LTR`s its own already-busy descriptor (which would #GP).
    unsafe {
        CS::set_reg(state.sel.kernel_code);
        SS::set_reg(state.sel.kernel_data);
        DS::set_reg(state.sel.kernel_data);
        ES::set_reg(state.sel.kernel_data);
        FS::set_reg(state.sel.kernel_data);
        GS::set_reg(state.sel.kernel_data);
        load_tss(state.tss_selectors[cpu_id as usize]);
    }
}

pub fn init() {
    init_for(0);
}

pub fn selectors() -> &'static Selectors {
    &GDT.get().expect("gdt::init not called").sel
}
