extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use cyphera_kapi::{Errno, KResult};

use crate::vfs::{DirEntry, Inode, InodeKind, Stat};

const GPU_DEVICE_DIR: &str = "/sys/devices/platform/virtio-mmio.gpu";

pub fn root() -> Arc<dyn Inode> {
    let kernel = StaticDir::new(alloc::vec![Entry::file("ostype", "Linux\n")]);
    let class_net_children = build_class_net();
    let class_net = StaticDir::new(class_net_children);
    let mut class_children = alloc::vec![Entry::dir("net", class_net)];
    let block = StaticDir::new(build_block());
    let fs_dir = StaticDir::new(alloc::vec![(
        "cgroup".to_string(),
        Entry::Dir(crate::fs::cgroupfs::root()),
    )]);

    let mut devices_children: Vec<(String, Entry)> = Vec::new();
    let mut dev_char_children: Vec<(String, Entry)> = Vec::new();
    let mut bus_children: Vec<(String, Entry)> = Vec::new();

    if virtio::framebuffer_info().is_some() {
        let (platform_tree, drm_links, char_links) = build_drm_topology();
        devices_children.push(("platform".to_string(), Entry::Dir(platform_tree)));
        class_children.push(Entry::dir("drm", StaticDir::new(drm_links)));
        dev_char_children.extend(char_links);
        bus_children.push((
            "platform".to_string(),
            Entry::Dir(Arc::new(StaticDir::new(alloc::vec![Entry::dir(
                "devices",
                StaticDir::new(alloc::vec![Entry::symlink(
                    "virtio-mmio.gpu",
                    GPU_DEVICE_DIR,
                )]),
            )]))),
        ));
    }

    let input_count = virtio::input_count();
    if input_count > 0 {
        let (input_virtual, class_input, char_input) = build_input_topology(input_count);
        devices_children.push(("virtual".to_string(), Entry::Dir(input_virtual)));
        class_children.push(Entry::dir("input", StaticDir::new(class_input)));
        dev_char_children.extend(char_input);
    }

    let class = StaticDir::new(class_children);
    let devices = StaticDir::new(devices_children);
    let bus = StaticDir::new(bus_children);
    let dev_char = StaticDir::new(dev_char_children);
    let dev_dir = StaticDir::new(alloc::vec![Entry::dir("char", dev_char)]);

    Arc::new(StaticDir::new(alloc::vec![
        Entry::dir("kernel", kernel),
        Entry::dir("class", class),
        Entry::dir("block", block),
        Entry::dir("bus", bus),
        Entry::dir("devices", devices),
        Entry::dir("dev", dev_dir),
        Entry::dir("fs", fs_dir),
    ]))
}

type DrmTopology = (Arc<dyn Inode>, Vec<(String, Entry)>, Vec<(String, Entry)>);

fn build_drm_topology() -> DrmTopology {
    let card0_dir = alloc::format!("{GPU_DEVICE_DIR}/drm/card0");
    let render_dir = alloc::format!("{GPU_DEVICE_DIR}/drm/renderD128");

    let mut drm_node_children: Vec<(String, Entry)> = Vec::new();
    let mut class_drm: Vec<(String, Entry)> = Vec::new();
    let mut dev_char: Vec<(String, Entry)> = Vec::new();

    drm_node_children.push((
        "card0".to_string(),
        Entry::Dir(drm_node_dir("226:0\n", "card0")),
    ));
    class_drm.push(Entry::symlink("card0", &card0_dir));
    dev_char.push(Entry::symlink("226:0", &card0_dir));

    if virtio::gpu_virgl_enabled() {
        drm_node_children.push((
            "renderD128".to_string(),
            Entry::Dir(drm_node_dir("226:128\n", "renderD128")),
        ));
        class_drm.push(Entry::symlink("renderD128", &render_dir));
        dev_char.push(Entry::symlink("226:128", &render_dir));
    }

    let drm_dir = StaticDir::new(drm_node_children);

    let platform_uevent = "DRIVER=virtio-mmio\nMODALIAS=platform:virtio-mmio\n";
    let gpu_device = StaticDir::new(alloc::vec![
        Entry::symlink("subsystem", "/sys/bus/platform"),
        Entry::file("uevent", platform_uevent),
        Entry::dir("drm", drm_dir),
    ]);
    let platform = StaticDir::new(alloc::vec![(
        "virtio-mmio.gpu".to_string(),
        Entry::Dir(Arc::new(gpu_device)),
    )]);

    (Arc::new(platform), class_drm, dev_char)
}

fn drm_node_dir(dev_line: &'static str, node_name: &str) -> Arc<dyn Inode> {
    let uevent = alloc::format!("DEVNAME=dri/{node_name}\nMAJOR=226\n");
    Arc::new(StaticDir::new(alloc::vec![
        Entry::file("dev", dev_line),
        Entry::symlink("device", GPU_DEVICE_DIR),
        Entry::symlink("subsystem", "/sys/class/drm"),
        Entry::file_owned("uevent", uevent),
    ]))
}

type InputTopology = (Arc<dyn Inode>, Vec<(String, Entry)>, Vec<(String, Entry)>);

fn build_input_topology(count: usize) -> InputTopology {
    let mut virtual_children: Vec<(String, Entry)> = Vec::new();
    let mut class_input: Vec<(String, Entry)> = Vec::new();
    let mut dev_char: Vec<(String, Entry)> = Vec::new();

    for i in 0..count {
        let minor = 64 + i;

        let caps = StaticDir::new(alloc::vec![
            Entry::file("ev", "100003\n"),
            Entry::file(
                "key",
                "ffffffffffffffff ffffffffffffffff ffffffffffffffff fffffffffffffffe\n",
            ),
            Entry::file("rel", "0\n"),
            Entry::file("abs", "0\n"),
        ]);
        let id = StaticDir::new(alloc::vec![
            Entry::file("bustype", "0006\n"),
            Entry::file("vendor", "1af4\n"),
            Entry::file("product", "0001\n"),
            Entry::file("version", "0001\n"),
        ]);
        let event_node = StaticDir::new(alloc::vec![
            Entry::file_owned("dev", alloc::format!("13:{minor}\n")),
            Entry::node(
                "uevent",
                Arc::new(UeventNode {
                    content: alloc::format!("MAJOR=13\nMINOR={minor}\nDEVNAME=input/event{i}\n"),
                    devpath: alloc::format!("/devices/virtual/input/input{i}/event{i}"),
                    props: alloc::vec![
                        ("SUBSYSTEM".to_string(), "input".to_string()),
                        ("MAJOR".to_string(), "13".to_string()),
                        ("MINOR".to_string(), alloc::format!("{minor}")),
                        ("DEVNAME".to_string(), alloc::format!("input/event{i}")),
                    ],
                }),
            ),
            Entry::symlink("subsystem", "../../../../../class/input"),
            Entry::symlink("device", ".."),
        ]);
        let input_node = StaticDir::new(alloc::vec![
            Entry::file("name", "cyphera virtio keyboard\n"),
            Entry::node(
                "uevent",
                Arc::new(UeventNode {
                    content: "PRODUCT=6/1af4/1/1\nNAME=\"cyphera virtio keyboard\"\n".to_string(),
                    devpath: alloc::format!("/devices/virtual/input/input{i}"),
                    props: alloc::vec![("SUBSYSTEM".to_string(), "input".to_string())],
                }),
            ),
            Entry::symlink("subsystem", "../../../../class/input"),
            Entry::dir("id", id),
            Entry::dir("capabilities", caps),
            Entry::dir(&alloc::format!("event{i}"), event_node),
        ]);
        virtual_children.push((alloc::format!("input{i}"), Entry::Dir(Arc::new(input_node))));
        let event_rel = alloc::format!("../../devices/virtual/input/input{i}/event{i}");
        let input_rel = alloc::format!("../../devices/virtual/input/input{i}");
        class_input.push(Entry::symlink(&alloc::format!("event{i}"), &event_rel));
        class_input.push(Entry::symlink(&alloc::format!("input{i}"), &input_rel));
        dev_char.push(Entry::symlink(&alloc::format!("13:{minor}"), &event_rel));
    }

    let virtual_dir = StaticDir::new(alloc::vec![Entry::dir(
        "input",
        StaticDir::new(virtual_children),
    )]);
    (Arc::new(virtual_dir), class_input, dev_char)
}

fn build_class_net() -> Vec<(String, Entry)> {
    let mut out = Vec::new();
    let lo = StaticDir::new(alloc::vec![
        Entry::file("address", "00:00:00:00:00:00\n"),
        Entry::file("mtu", "65536\n"),
        Entry::file("operstate", "unknown\n"),
        Entry::file("type", "772\n"),
    ]);
    out.push(("lo".to_string(), Entry::Dir(Arc::new(lo))));

    if let Some(mac) = virtio::net_mac() {
        let s = alloc::format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );
        let eth0 = StaticDir::new(alloc::vec![
            Entry::file_owned("address", s),
            Entry::file("mtu", "1500\n"),
            Entry::file("operstate", "up\n"),
            Entry::file("type", "1\n"),
        ]);
        out.push(("eth0".to_string(), Entry::Dir(Arc::new(eth0))));
    }
    out
}

fn build_block() -> Vec<(String, Entry)> {
    let mut out = Vec::new();
    if let Some(sectors) = virtio::block_capacity_sectors() {
        let size = alloc::format!("{}\n", sectors);
        let queue = StaticDir::new(alloc::vec![
            Entry::file("logical_block_size", "512\n"),
            Entry::file("physical_block_size", "512\n"),
            Entry::file("hw_sector_size", "512\n"),
        ]);
        let vda = StaticDir::new(alloc::vec![
            Entry::file_owned("size", size),
            Entry::file("ro", "0\n"),
            Entry::file("removable", "0\n"),
            Entry::file("dev", "254:0\n"),
            Entry::dir("queue", queue),
        ]);
        out.push(("vda".to_string(), Entry::Dir(Arc::new(vda))));
    }
    out
}

enum Entry {
    File(StaticAttr),
    Dir(Arc<dyn Inode>),
    Node(Arc<dyn Inode>),
    Symlink(SymlinkAttr),
}

impl Entry {
    fn file(name: &'static str, body: &str) -> (String, Self) {
        (
            name.to_string(),
            Entry::File(StaticAttr::new(body.to_string())),
        )
    }
    fn file_owned(name: &str, body: String) -> (String, Self) {
        (name.to_string(), Entry::File(StaticAttr::new(body)))
    }
    fn node(name: &str, inode: Arc<dyn Inode>) -> (String, Self) {
        (name.to_string(), Entry::Node(inode))
    }
    fn dir(name: &str, dir: StaticDir) -> (String, Self) {
        (name.to_string(), Entry::Dir(Arc::new(dir)))
    }
    fn symlink(name: &str, target: &str) -> (String, Self) {
        (
            name.to_string(),
            Entry::Symlink(SymlinkAttr::new(target.to_string())),
        )
    }
}

struct StaticDir {
    entries: Vec<(String, Entry)>,
}

impl StaticDir {
    fn new(entries: Vec<(String, Entry)>) -> Self {
        Self { entries }
    }
}

impl Inode for StaticDir {
    fn kind(&self) -> InodeKind {
        InodeKind::Directory
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Directory, 0, 0o555)
    }
    fn lookup(&self, name: &str) -> KResult<Arc<dyn Inode>> {
        for (n, e) in &self.entries {
            if n == name {
                return Ok(match e {
                    Entry::File(a) => Arc::new(a.clone()),
                    Entry::Dir(d) => d.clone(),
                    Entry::Node(d) => d.clone(),
                    Entry::Symlink(s) => Arc::new(s.clone()),
                });
            }
        }
        Err(Errno::NOENT)
    }
    fn list(&self) -> KResult<Vec<DirEntry>> {
        Ok(self
            .entries
            .iter()
            .map(|(n, e)| DirEntry {
                name: n.clone(),
                kind: match e {
                    Entry::File(_) => InodeKind::Regular,
                    Entry::Dir(_) => InodeKind::Directory,
                    Entry::Node(_) => InodeKind::Regular,
                    Entry::Symlink(_) => InodeKind::Symlink,
                },
                inode_id: hash_str(n),
            })
            .collect())
    }
}

#[derive(Clone)]
struct StaticAttr {
    body: String,
}

impl StaticAttr {
    fn new(body: String) -> Self {
        Self { body }
    }
}

impl Inode for StaticAttr {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, self.body.len() as u64, 0o444)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<usize> {
        let src = self.body.as_bytes();
        if offset >= src.len() as u64 {
            return Ok(0);
        }
        let start = offset as usize;
        let n = (src.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&src[start..start + n]);
        Ok(n)
    }
}

#[derive(Clone)]
struct SymlinkAttr {
    target: String,
}

impl SymlinkAttr {
    fn new(target: String) -> Self {
        Self { target }
    }
}

impl Inode for SymlinkAttr {
    fn kind(&self) -> InodeKind {
        InodeKind::Symlink
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Symlink, self.target.len() as u64, 0o777)
    }
    fn read_link(&self) -> KResult<String> {
        Ok(self.target.clone())
    }
}

struct UeventNode {
    content: String,
    devpath: String,
    props: Vec<(String, String)>,
}

impl Inode for UeventNode {
    fn kind(&self) -> InodeKind {
        InodeKind::Regular
    }
    fn stat(&self) -> Stat {
        Stat::fresh(InodeKind::Regular, self.content.len() as u64, 0o644)
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> KResult<usize> {
        let src = self.content.as_bytes();
        if offset >= src.len() as u64 {
            return Ok(0);
        }
        let start = offset as usize;
        let n = (src.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&src[start..start + n]);
        Ok(n)
    }
    fn write_at(&self, _offset: u64, buf: &[u8]) -> KResult<usize> {
        let action = core::str::from_utf8(buf)
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("");
        if matches!(action, "add" | "change" | "remove" | "bind" | "online") {
            let props: Vec<(&str, &str)> = self
                .props
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            crate::net::netlink::emit_uevent(action, &self.devpath, &props);
        }
        Ok(buf.len())
    }
    fn truncate(&self, _len: u64) -> KResult<()> {
        Ok(())
    }
}

fn hash_str(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}
