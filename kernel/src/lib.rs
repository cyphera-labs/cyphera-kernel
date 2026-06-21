#![cfg_attr(not(host_test), no_std)]
#![forbid(unsafe_code)]
#![cfg_attr(host_test, allow(dead_code, unused_imports))]

extern crate alloc;

pub mod bpf;
pub mod errno;

#[cfg(host_test)]
pub mod vfs {
    pub mod path;
    pub mod pipe;
}
#[cfg(host_test)]
pub mod fs {
    pub mod ext4;
    pub mod tar;
}

#[cfg(host_test)]
pub mod futex;
#[cfg(host_test)]
#[path = "process_host.rs"]
pub mod process;
#[cfg(host_test)]
pub mod random;
#[cfg(host_test)]
#[path = "sched_host.rs"]
pub mod sched;
#[cfg(host_test)]
pub mod sched_runqueue;
#[cfg(host_test)]
pub mod timeout;
#[cfg(host_test)]
pub mod wait;

#[cfg(not(host_test))]
pub mod cgroup;
#[cfg(not(host_test))]
pub mod console;
#[cfg(not(host_test))]
pub mod drm;
#[cfg(not(host_test))]
pub mod elf;
#[cfg(not(host_test))]
pub mod fdtypes;
#[cfg(not(host_test))]
pub mod fs;
#[cfg(not(host_test))]
pub mod futex;
#[cfg(not(host_test))]
pub mod init_exec;
#[cfg(not(host_test))]
pub mod input;
#[cfg(not(host_test))]
pub mod io;
#[cfg(not(host_test))]
pub mod ipc;
#[cfg(not(host_test))]
pub mod klog;
#[cfg(not(host_test))]
pub mod mmap_fault;
#[cfg(not(host_test))]
pub mod net;
#[cfg(not(host_test))]
pub mod process;
#[cfg(not(host_test))]
pub mod ptrace;
#[cfg(not(host_test))]
pub mod pty;
#[cfg(not(host_test))]
pub mod random;
#[cfg(not(host_test))]
pub mod sched;
#[cfg(not(host_test))]
pub mod sched_runqueue;
#[cfg(not(host_test))]
pub mod seccomp;
#[cfg(not(host_test))]
pub mod security;
#[cfg(not(host_test))]
pub mod signal;
#[cfg(not(host_test))]
pub mod stack_init;
#[cfg(not(host_test))]
pub mod syscall;
#[cfg(not(host_test))]
pub mod timeout;
#[cfg(not(host_test))]
pub mod vfs;
#[cfg(not(host_test))]
pub mod wait;

#[cfg(not(host_test))]
pub fn init() {
    frame::io::uart::set_klog_sink(klog::push_bytes);

    virtio::init();
    random::init();
    cgroup::init();
    init_vfs();
    frame::mm::heap::expand_full();
    net::init();
    syscall::install();
    ptrace::install_trap_hook();
    frame::intr::lapic::register_tick_handler(sched::on_tick);

    frame::arch::x86_64::smp::set_ap_main(sched::ap_main);
    let apic_ids = frame::arch::x86_64::madt::parse_apic_ids(frame::boot::rsdp_paddr());
    if !apic_ids.is_empty() {
        frame::println!(
            "madt: bringing up {} APs (apic_ids = {:?})",
            apic_ids.len(),
            apic_ids
        );
    }
    frame::arch::x86_64::smp::bring_up(&apic_ids);

    net::start_pump_kthread();
}

#[cfg(not(host_test))]
fn init_vfs() {
    use alloc::sync::Arc;
    use vfs::{Inode, InodeKind};

    let root = fs::tmpfs::TmpfsInode::new_dir();

    let dev = fs::tmpfs::TmpfsInode::new_dir();
    dev.attach("null", fs::devfs::null()).expect("attach null");
    dev.attach("zero", fs::devfs::zero()).expect("attach zero");
    dev.attach("full", fs::devfs::full()).expect("attach full");
    dev.attach("random", fs::devfs::random())
        .expect("attach random");
    dev.attach("urandom", fs::devfs::urandom())
        .expect("attach urandom");
    dev.attach("console", fs::devfs::console())
        .expect("attach console");
    dev.attach("tty", fs::devfs::tty()).expect("attach tty");
    for n in 1..=6 {
        let name = alloc::format!("tty{n}");
        dev.attach(&name, fs::devfs::tty()).expect("attach tty[n]");
    }
    dev.attach("fb0", fs::devfs::fb0()).expect("attach fb0");
    if virtio::framebuffer_info().is_some() {
        let dri_dir = fs::tmpfs::TmpfsInode::new_dir();
        dri_dir.attach("card0", drm::card0()).expect("attach card0");
        let dri_dyn: Arc<dyn Inode> = dri_dir;
        dev.attach("dri", dri_dyn).expect("attach /dev/dri");
    }
    console::install_screen_sink();
    dev.attach("dsp", fs::devfs::dsp()).expect("attach dsp");
    if virtio::block_capacity_sectors().is_some() {
        dev.attach("vda", fs::devfs::vda()).expect("attach vda");
    }
    let input_dir = fs::tmpfs::TmpfsInode::new_dir();
    let input_count = virtio::input_count();
    for i in 0..input_count {
        let name = alloc::format!("event{i}");
        input_dir
            .attach(&name, fs::devfs::input_event(i))
            .expect("attach input event");
    }
    let input_dyn: Arc<dyn Inode> = input_dir;
    dev.attach("input", input_dyn).expect("attach /dev/input");
    let shm: Arc<dyn Inode> = fs::tmpfs::TmpfsInode::new_dir();
    dev.attach("shm", shm).expect("attach /dev/shm");
    let dev_dyn: Arc<dyn Inode> = dev;
    let dev_id = dev_dyn.inode_id();
    let dev_mount = dev_dyn.clone();
    root.attach("dev", dev_dyn).expect("attach /dev");

    let tmp = fs::tmpfs::TmpfsInode::new_dir();
    let tmp_dyn: Arc<dyn Inode> = tmp;
    let tmp_id = tmp_dyn.inode_id();
    let tmp_mount = tmp_dyn.clone();
    root.attach("tmp", tmp_dyn).expect("attach /tmp");

    let proc_root = fs::procfs::root();
    let proc_id = proc_root.inode_id();
    let proc_mount = proc_root.clone();
    root.attach("proc", proc_root).expect("attach /proc");

    let sys_root = fs::sysfs::root();
    let sys_id = sys_root.inode_id();
    let sys_mount = sys_root.clone();
    root.attach("sys", sys_root).expect("attach /sys");

    {
        let module_span: Option<(u64, u64)> = {
            let modules = frame::boot::modules();
            if let Some(m) = modules.first() {
                let span = (m.paddr, m.size);
                match frame::boot::module_bytes(m) {
                    Some(archive) => {
                        let root_dyn: Arc<dyn Inode> = root.clone();
                        match fs::tar::extract_into(&root_dyn, archive) {
                            Ok(count) => frame::println!(
                                "initrd: extracted {} entries from module[0] ({} KiB at {:#x})",
                                count,
                                m.size / 1024,
                                m.paddr,
                            ),
                            Err(e) => frame::println!(
                                "initrd: extract failed: {e:?} (continuing with synthetic root)"
                            ),
                        }
                    }
                    None => frame::println!(
                        "initrd: module[0] at {:#x} size {} KiB exceeds high-half map; skipping",
                        m.paddr,
                        m.size / 1024,
                    ),
                }
                Some(span)
            } else {
                frame::println!(
                    "initrd: no module supplied; root has synthetic /dev /proc /sys /tmp only"
                );
                None
            }
        };
        if let Some((paddr, size)) = module_span {
            let frames = frame::mm::frame_alloc::reclaim_module(paddr, size);
            if frames != 0 {
                frame::println!(
                    "initrd: reclaimed module frames ({} MiB) to the buddy allocator",
                    (frames * 4096) / (1024 * 1024),
                );
            }
        }
    }

    let _ = InodeKind::Directory;
    let root_dyn: Arc<dyn Inode> = root;
    let root_id = root_dyn.inode_id();
    vfs::set_root(root_dyn.clone());

    vfs::mount_install(
        "/",
        root_id,
        root_dyn,
        vfs::MountPropagation::Private,
        "rootfs",
        "tmpfs",
    );
    vfs::mount_install(
        "/dev",
        dev_id,
        dev_mount,
        vfs::MountPropagation::Private,
        "devtmpfs",
        "devtmpfs",
    );
    vfs::mount_install(
        "/tmp",
        tmp_id,
        tmp_mount,
        vfs::MountPropagation::Private,
        "tmpfs",
        "tmpfs",
    );
    vfs::mount_install(
        "/proc",
        proc_id,
        proc_mount,
        vfs::MountPropagation::Private,
        "proc",
        "proc",
    );
    vfs::mount_install(
        "/sys",
        sys_id,
        sys_mount,
        vfs::MountPropagation::Private,
        "sysfs",
        "sysfs",
    );

    frame::println!("vfs: root tmpfs mounted; /dev, /tmp, /proc, /sys populated");
}

#[cfg(not(host_test))]
pub fn boot_banner() {
    frame::println!("kernel services online (no unsafe code in this layer)");
}
