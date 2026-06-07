use frame::mm::{
    VirtAddr,
    vm::{Perms, VmSpace},
};

use crate::sched;
use crate::stack_init::{AuxvInfo, build_user_stack};
use crate::vfs::{
    self, FsError,
    path::{self, Context},
};

const INIT_PATHS: &[&str] = &["/sbin/init", "/etc/init", "/bin/init", "/bin/sh"];

const USER_STACK_VADDR: u64 = 0x7fff_0000_0000;
const USER_STACK_PAGES: usize = 8;
const PAGE_SIZE: u64 = 4096;

pub fn exec_init() -> ! {
    let (path_str, init_inode) = locate_init();

    let size = init_inode.stat().size;
    if size == 0 {
        panic!("init exec: {path_str} is empty (size 0)");
    }
    let mut buf = alloc::vec![0u8; size as usize];
    match init_inode.read_at(0, &mut buf) {
        Ok(n) if n as u64 == size => {}
        Ok(n) => panic!("init exec: short read on {path_str}: expected {size} got {n}"),
        Err(e) => panic!("init exec: failed to read {path_str}: {e:?}"),
    }
    frame::println!("init exec: loaded {} bytes from {}", size, path_str);

    let mut vmspace = VmSpace::new_user().expect("init exec: failed to allocate user VmSpace");

    let loaded = match crate::elf::load_static(&buf, &mut vmspace) {
        Ok(l) => l,
        Err(e) => panic!("init exec: load_static({path_str}) failed: {e:?}"),
    };
    let user_entry = loaded.interp_entry.unwrap_or(loaded.entry);
    frame::println!(
        "init exec: ELF loaded; entry @ {:#x}, image_end @ {:#x}{}",
        loaded.entry,
        loaded.image_end,
        if loaded.interp_entry.is_some() {
            alloc::format!(" (dynamic; dispatched to interp @ {:#x})", user_entry)
        } else {
            alloc::string::String::new()
        },
    );

    vmspace
        .map_anon(
            VirtAddr::new(USER_STACK_VADDR),
            USER_STACK_PAGES,
            Perms::READ | Perms::WRITE | Perms::USER,
        )
        .expect("init exec: failed to map user stack");
    let stack_top = USER_STACK_VADDR + (USER_STACK_PAGES as u64) * PAGE_SIZE;

    let argv: &[&[u8]] = &[path_str.as_bytes()];
    let envp: &[&[u8]] = &[
        b"HOME=/root",
        b"TERM=linux",
        b"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
    ];
    let aux = AuxvInfo {
        phdr: loaded.phdr_va,
        phent: loaded.phent,
        phnum: loaded.phnum,
        entry: loaded.entry,
        interp_base: loaded.interp_base.unwrap_or(0),
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
        secure: false,
    };
    let rsp = match build_user_stack(&vmspace, stack_top, argv, envp, &aux) {
        Ok(rsp) => rsp,
        Err(e) => panic!("init exec: failed to build user stack: {e:?}"),
    };
    frame::println!(
        "init exec: user stack built; rsp @ {:#x} (argv={} envp={})",
        rsp,
        argv.len(),
        envp.len(),
    );

    let pid = sched::register_with_vmspace(Some(vmspace), user_entry, rsp, loaded.image_end);
    {
        use crate::process::{MapSegLabel, MapSegment, MapsLayout};
        use frame::mm::vm::Perms;
        let mut layout = MapsLayout::default();
        for (lo, hi, prot) in &loaded.segments {
            layout.segments.push(MapSegment {
                start: *lo,
                end: *hi,
                prot: *prot,
                label: MapSegLabel::Image,
            });
        }
        for (lo, hi, prot) in &loaded.interp_segments {
            layout.segments.push(MapSegment {
                start: *lo,
                end: *hi,
                prot: *prot,
                label: MapSegLabel::Interp,
            });
        }
        layout.segments.push(MapSegment {
            start: USER_STACK_VADDR,
            end: stack_top,
            prot: Perms::READ | Perms::WRITE | Perms::USER,
            label: MapSegLabel::Stack,
        });
        sched::set_maps_layout(pid, layout);
    }
    frame::println!(
        "init exec: registered PID {} with scheduler; entering scheduler loop",
        pid.0,
    );

    sched::enter_scheduler_bsp()
}

fn locate_init() -> (&'static str, alloc::sync::Arc<dyn vfs::Inode>) {
    let ctx = Context::current();
    for p in INIT_PATHS {
        match path::resolve(&ctx, &ctx.root, p) {
            Ok(inode) => return (p, inode),
            Err(FsError::NotFound) => continue,
            Err(e) => panic!("init exec: error resolving {p}: {e:?}"),
        }
    }
    panic!("init exec: no init binary found (tried {:?})", INIT_PATHS);
}
