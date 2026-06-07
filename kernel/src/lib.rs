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
pub mod elf;
#[cfg(not(host_test))]
pub mod fdtypes;
#[cfg(not(host_test))]
pub mod fs;
#[cfg(not(host_test))]
pub mod futex;
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
pub mod sched;
#[cfg(not(host_test))]
pub mod init_exec;
#[cfg(not(host_test))]
pub mod sched_runqueue;
#[cfg(not(host_test))]
pub mod seccomp;
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
    cgroup::init();
    init_vfs();
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
    dev.attach("dsp", fs::devfs::dsp()).expect("attach dsp");
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
    root.attach("dev", dev_dyn).expect("attach /dev");

    let tmp = fs::tmpfs::TmpfsInode::new_dir();
    let tmp_dyn: Arc<dyn Inode> = tmp;
    root.attach("tmp", tmp_dyn).expect("attach /tmp");

    root.attach("proc", fs::procfs::root())
        .expect("attach /proc");

    root.attach("sys", fs::sysfs::root()).expect("attach /sys");

    {
        let modules = frame::boot::modules();
        if let Some(m) = modules.first() {
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
        } else {
            frame::println!(
                "initrd: no module supplied; root has synthetic /dev /proc /sys /tmp only"
            );
        }
    }

    let _ = InodeKind::Directory;
    let root_dyn: Arc<dyn Inode> = root;
    vfs::set_root(root_dyn);
    frame::println!("vfs: root tmpfs mounted; /dev, /tmp, /proc, /sys populated");
}

#[cfg(not(host_test))]
pub fn boot_banner() {
    frame::println!("kernel services online (no unsafe code in this layer)");
}
