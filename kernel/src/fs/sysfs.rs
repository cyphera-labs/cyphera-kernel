extern crate alloc;

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::vfs::{DirEntry, FsError, Inode, InodeKind, Stat};

pub fn root() -> Arc<dyn Inode> {
    let kernel = StaticDir::new(alloc::vec![Entry::file("ostype", "Linux\n")]);
    let class_net_children = build_class_net();
    let class_net = StaticDir::new(class_net_children);
    let class = StaticDir::new(alloc::vec![Entry::dir("net", class_net)]);
    let block = StaticDir::new(alloc::vec![]);
    let devices = StaticDir::new(alloc::vec![]);
    let fs_dir = StaticDir::new(alloc::vec![(
        "cgroup".to_string(),
        Entry::Dir(crate::fs::cgroupfs::root()),
    )]);
    Arc::new(StaticDir::new(alloc::vec![
        Entry::dir("kernel", kernel),
        Entry::dir("class", class),
        Entry::dir("block", block),
        Entry::dir("devices", devices),
        Entry::dir("fs", fs_dir),
    ]))
}

fn build_class_net() -> Vec<(alloc::string::String, Entry)> {
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
        let leaked: &'static str = alloc::boxed::Box::leak(s.into_boxed_str());
        let eth0 = StaticDir::new(alloc::vec![
            Entry::file_static("address", leaked),
            Entry::file("mtu", "1500\n"),
            Entry::file("operstate", "up\n"),
            Entry::file("type", "1\n"),
        ]);
        out.push(("eth0".to_string(), Entry::Dir(Arc::new(eth0))));
    }
    out
}

enum Entry {
    File(StaticAttr),
    Dir(Arc<dyn Inode>),
}

impl Entry {
    fn file(name: &'static str, body: &'static str) -> (alloc::string::String, Self) {
        (name.to_string(), Entry::File(StaticAttr::new(body)))
    }
    fn file_static(name: &'static str, body: &'static str) -> (alloc::string::String, Self) {
        (name.to_string(), Entry::File(StaticAttr::new(body)))
    }
    fn dir(name: &'static str, dir: StaticDir) -> (alloc::string::String, Self) {
        (name.to_string(), Entry::Dir(Arc::new(dir)))
    }
}

struct StaticDir {
    entries: Vec<(alloc::string::String, Entry)>,
}

impl StaticDir {
    fn new(entries: Vec<(alloc::string::String, Entry)>) -> Self {
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
    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>, FsError> {
        for (n, e) in &self.entries {
            if n == name {
                return Ok(match e {
                    Entry::File(a) => Arc::new(a.clone()),
                    Entry::Dir(d) => d.clone(),
                });
            }
        }
        Err(FsError::NotFound)
    }
    fn list(&self) -> Result<Vec<DirEntry>, FsError> {
        Ok(self
            .entries
            .iter()
            .map(|(n, e)| DirEntry {
                name: n.clone(),
                kind: match e {
                    Entry::File(_) => InodeKind::Regular,
                    Entry::Dir(_) => InodeKind::Directory,
                },
                inode_id: hash_str(n),
            })
            .collect())
    }
}

#[derive(Clone)]
struct StaticAttr {
    body: &'static str,
}

impl StaticAttr {
    fn new(body: &'static str) -> Self {
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
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
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

fn hash_str(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}
