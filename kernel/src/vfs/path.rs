use alloc::string::String;
use alloc::vec::Vec;

#[cfg(not(host_test))]
use alloc::sync::Arc;

#[cfg(not(host_test))]
use super::{Inode, InodeKind, MountEntry, MountInUseTag, MountPropagation, MountTable};

#[cfg(not(host_test))]
use cyphera_kapi::{Errno, KResult};

#[cfg(not(host_test))]
type ResolveWithMount = KResult<(Arc<dyn Inode>, Option<Arc<MountInUseTag>>)>;

#[cfg(not(host_test))]
pub struct Context {
    pub root: Arc<dyn Inode>,
    pub mounts: Arc<MountTable>,
}

#[cfg(not(host_test))]
impl Context {
    pub fn current() -> Self {
        let root =
            crate::core::with_current_fs_root(|r| r.clone()).unwrap_or_else(super::root_inode);
        let mounts = crate::core::with_current_mount_table(|m| m.clone())
            .flatten()
            .unwrap_or_else(super::global_mount_table);
        Self { root, mounts }
    }

    pub fn global() -> Self {
        Self {
            root: super::root_inode(),
            mounts: super::global_mount_table(),
        }
    }

    pub fn for_table(mounts: Arc<MountTable>) -> Self {
        Self {
            root: super::root_inode(),
            mounts,
        }
    }

    pub fn lookup_mount(&self, path: &str) -> Option<Arc<dyn Inode>> {
        self.mounts.lookup(path)
    }

    pub fn lookup_mount_full(&self, path: &str) -> Option<MountEntry> {
        self.mounts.snapshot_one(path)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install_mount(
        &self,
        target_path: &str,
        target_inode_id: u64,
        root: Arc<dyn Inode>,
        propagation: MountPropagation,
        source: &str,
        fstype: &str,
    ) {
        self.mounts.install(
            target_path,
            target_inode_id,
            root,
            propagation,
            source,
            fstype,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install_mount_propagating(
        &self,
        target_path: &str,
        target_inode_id: u64,
        root: Arc<dyn Inode>,
        propagation: MountPropagation,
        source: &str,
        fstype: &str,
    ) -> alloc::vec::Vec<alloc::string::String> {
        use alloc::string::String;

        let containing = self.containing_mount_with_proper_prefix(target_path);
        self.install_mount(
            target_path,
            target_inode_id,
            root.clone(),
            propagation.clone(),
            source,
            fstype,
        );

        let (containing_path, containing_entry) = match containing {
            Some(c) => c,
            None => return alloc::vec::Vec::new(),
        };

        let shared_pg = match containing_entry.propagation {
            MountPropagation::Shared(pg) => pg,
            _ => return alloc::vec::Vec::new(),
        };

        let suffix = if containing_path == "/" {
            String::from(target_path)
        } else {
            String::from(&target_path[containing_path.len()..])
        };

        let mut mirrored = alloc::vec::Vec::new();
        let peers = shared_pg.snapshot_members();
        let slaves = shared_pg.snapshot_slaves();

        for (peer_table, peer_path) in peers.iter() {
            if Arc::ptr_eq(peer_table, &self.mounts) && *peer_path == containing_path {
                continue;
            }
            let mirror_path = join_for_mirror(peer_path, &suffix);
            let peer_ctx = Context::for_table(peer_table.clone());
            if let Some(mirror_target_id) = peer_ctx.resolve_inode_id(&mirror_path) {
                peer_table.install(
                    &mirror_path,
                    mirror_target_id,
                    root.clone(),
                    propagation.clone(),
                    source,
                    fstype,
                );
                mirrored.push(mirror_path);
            }
        }
        for (slave_table, slave_path) in slaves.iter() {
            let mirror_path = join_for_mirror(slave_path, &suffix);
            let slave_ctx = Context::for_table(slave_table.clone());
            if let Some(mirror_target_id) = slave_ctx.resolve_inode_id(&mirror_path) {
                slave_table.install(
                    &mirror_path,
                    mirror_target_id,
                    root.clone(),
                    MountPropagation::Private,
                    source,
                    fstype,
                );
                mirrored.push(mirror_path);
            }
        }
        mirrored
    }

    pub fn remove_mount(&self, target_path: &str) -> Option<Arc<dyn Inode>> {
        self.mounts.remove(target_path)
    }

    pub fn remove_mount_propagating(&self, target_path: &str) -> Option<Arc<dyn Inode>> {
        use alloc::string::String;
        let containing = self.containing_mount_with_proper_prefix(target_path);
        let root = self.remove_mount(target_path)?;

        if let Some((containing_path, entry)) = containing {
            if let MountPropagation::Shared(pg) = entry.propagation {
                let suffix = if containing_path == "/" {
                    String::from(target_path)
                } else {
                    String::from(&target_path[containing_path.len()..])
                };
                for (peer_table, peer_path) in pg.snapshot_members().iter() {
                    if Arc::ptr_eq(peer_table, &self.mounts) && *peer_path == containing_path {
                        continue;
                    }
                    let mirror_path = join_for_mirror(peer_path, &suffix);
                    let _ = peer_table.remove(&mirror_path);
                }
                for (slave_table, slave_path) in pg.snapshot_slaves().iter() {
                    let mirror_path = join_for_mirror(slave_path, &suffix);
                    let _ = slave_table.remove(&mirror_path);
                }
            }
        }
        Some(root)
    }

    pub fn set_mount_propagation(&self, path: &str, new_prop: MountPropagation) -> bool {
        self.mounts.set_propagation(path, new_prop)
    }

    fn containing_mount_with_proper_prefix(
        &self,
        path: &str,
    ) -> Option<(alloc::string::String, MountEntry)> {
        self.mounts.proper_containing_mount_with_path(path)
    }

    fn resolve_inode_id(&self, path: &str) -> Option<u64> {
        match resolve(self, &self.root, path) {
            Ok(i) => Some(i.inode_id()),
            Err(_) => None,
        }
    }

    pub fn containing_mount(&self, path: &str) -> Option<MountEntry> {
        self.mounts.containing_mount(path)
    }

    pub fn collect_subtree(
        &self,
        prefix: &str,
    ) -> alloc::vec::Vec<(alloc::string::String, MountEntry)> {
        self.mounts.collect_subtree(prefix)
    }
}

#[cfg(not(host_test))]
pub fn resolve(ctx: &Context, start: &Arc<dyn Inode>, path: &str) -> KResult<Arc<dyn Inode>> {
    resolve_with_depth(ctx, start, "/", path, 0, true).map(|r| r.inode)
}

#[cfg(not(host_test))]
pub fn resolve_no_follow(
    ctx: &Context,
    start: &Arc<dyn Inode>,
    path: &str,
) -> KResult<Arc<dyn Inode>> {
    resolve_with_depth(ctx, start, "/", path, 0, false).map(|r| r.inode)
}

#[cfg(not(host_test))]
pub fn resolve_with_mount(ctx: &Context, start: &Arc<dyn Inode>, path: &str) -> ResolveWithMount {
    let r = resolve_with_depth(ctx, start, "/", path, 0, true)?;
    Ok((r.inode, r.mount_tag))
}

#[cfg(not(host_test))]
pub fn resolve_no_follow_with_mount(
    ctx: &Context,
    start: &Arc<dyn Inode>,
    path: &str,
) -> ResolveWithMount {
    let r = resolve_with_depth(ctx, start, "/", path, 0, false)?;
    Ok((r.inode, r.mount_tag))
}

#[cfg(not(host_test))]
struct ResolveResult {
    inode: Arc<dyn Inode>,
    mount_tag: Option<Arc<MountInUseTag>>,
}

#[cfg(not(host_test))]
const MAX_SYMLINK_DEPTH: u32 = 40;

#[cfg(not(host_test))]
fn join_canonical(base_canonical: &str, component: &str) -> alloc::string::String {
    use alloc::string::String;
    let mut s = String::with_capacity(base_canonical.len() + 1 + component.len());
    if base_canonical == "/" {
        s.push('/');
    } else {
        s.push_str(base_canonical);
        s.push('/');
    }
    s.push_str(component);
    s
}

#[cfg(not(host_test))]
fn join_for_mirror(peer_path: &str, suffix: &str) -> alloc::string::String {
    use alloc::string::String;
    if suffix.is_empty() {
        return String::from(peer_path);
    }
    if peer_path == "/" {
        return String::from(suffix);
    }
    let mut s = String::with_capacity(peer_path.len() + suffix.len());
    s.push_str(peer_path);
    s.push_str(suffix);
    s
}

#[cfg(not(host_test))]
fn resolve_with_depth(
    ctx: &Context,
    start: &Arc<dyn Inode>,
    start_canonical: &str,
    path: &str,
    depth: u32,
    follow_last: bool,
) -> KResult<ResolveResult> {
    use alloc::string::String;

    if depth > MAX_SYMLINK_DEPTH {
        return Err(Errno::INVAL);
    }
    let mut deepest_mount_tag: Option<Arc<MountInUseTag>> = None;
    let (mut current, mut canonical) = if path.starts_with('/') {
        (ctx.root.clone(), String::from("/"))
    } else {
        (start.clone(), String::from(start_canonical))
    };

    let components: Vec<&str> = path
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect();
    let last_idx = components.len();
    for (i, component) in components.iter().enumerate() {
        if *component == ".." {
            return Err(Errno::NOSYS);
        }
        let is_last = i + 1 == last_idx;
        let child = current.lookup(component)?;
        let child_canonical = join_canonical(&canonical, component);
        let (child, child_canonical) = match ctx.lookup_mount_full(&child_canonical) {
            Some(entry) => {
                deepest_mount_tag = Some(entry.in_use.clone());
                (entry.root.clone(), child_canonical)
            }
            None => (child, child_canonical),
        };
        let should_follow = if is_last { follow_last } else { true };
        let (next, next_canonical) = if should_follow && child.kind() == InodeKind::Symlink {
            if let Some(resolved) = child.magic_resolve() {
                (resolved, child_canonical)
            } else {
                let target = child.read_link()?;
                let target_canonical = if target.starts_with('/') {
                    normalize("/", &target)
                } else {
                    normalize(&canonical, &target)
                };
                let r =
                    resolve_with_depth(ctx, &ctx.root, "/", &target_canonical, depth + 1, true)?;
                if let Some(t) = r.mount_tag {
                    deepest_mount_tag = Some(t);
                }
                (r.inode, target_canonical)
            }
        } else {
            (child, child_canonical)
        };
        current = next;
        canonical = next_canonical;
    }
    let _ = canonical;
    Ok(ResolveResult {
        inode: current,
        mount_tag: deepest_mount_tag,
    })
}

#[cfg(not(host_test))]
pub fn resolve_parent<'a>(
    ctx: &Context,
    start: &Arc<dyn Inode>,
    path: &'a str,
) -> KResult<(Arc<dyn Inode>, &'a str)> {
    let trimmed = path.trim_end_matches('/');
    let split = trimmed.rfind('/');
    let (parent_path, leaf) = match split {
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => ("", trimmed),
    };
    if leaf.is_empty() {
        return Err(Errno::INVAL);
    }

    let parent = if parent_path.is_empty() && trimmed.starts_with('/') {
        ctx.root.clone()
    } else if parent_path.is_empty() {
        start.clone()
    } else {
        resolve(ctx, start, parent_path)?
    };

    if parent.kind() != InodeKind::Directory {
        return Err(Errno::NOTDIR);
    }

    Ok((parent, leaf))
}

pub fn normalize(cwd: &str, target: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if !target.starts_with('/') {
        for c in cwd.split('/').filter(|s| !s.is_empty()) {
            match c {
                "." => {}
                ".." => {
                    parts.pop();
                }
                _ => parts.push(c),
            }
        }
    }
    for c in target.split('/').filter(|s| !s.is_empty()) {
        match c {
            "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(c),
        }
    }
    if parts.is_empty() {
        return String::from("/");
    }
    let mut s = String::new();
    for p in parts {
        s.push('/');
        s.push_str(p);
    }
    s
}

#[cfg(host_test)]
#[cfg(test)]
mod host_tests {
    use super::normalize;
    use alloc::string::String;

    #[test]
    fn normalize_absolute_target_drops_cwd() {
        assert_eq!(normalize("/a/b", "/c/d"), "/c/d");
    }

    #[test]
    fn normalize_relative_target_walks_cwd() {
        assert_eq!(normalize("/a/b", "c/d"), "/a/b/c/d");
    }

    #[test]
    fn normalize_dot_components_skip() {
        assert_eq!(normalize("/", "./a/./b/."), "/a/b");
    }

    #[test]
    fn normalize_dotdot_pops() {
        assert_eq!(normalize("/a/b", "../c"), "/a/c");
    }

    #[test]
    fn normalize_dotdot_clamps_at_root() {
        assert_eq!(normalize("/", "../../../../foo"), "/foo");
    }

    #[test]
    fn normalize_only_dotdot_yields_root() {
        assert_eq!(normalize("/", ".."), "/");
        assert_eq!(normalize("/a/b", "../../.."), "/");
    }

    #[test]
    fn normalize_empty_inputs() {
        assert_eq!(normalize("", ""), "/");
        assert_eq!(normalize("", "/"), "/");
        assert_eq!(normalize("/", ""), "/");
    }

    #[test]
    fn normalize_trailing_slashes_collapsed() {
        assert_eq!(normalize("/", "/a/b///"), "/a/b");
        assert_eq!(normalize("/", "/a//b/"), "/a/b");
    }

    #[test]
    fn normalize_unsanitized_cwd_handled() {
        assert_eq!(normalize("/a/../b/./c", "leaf"), "/b/c/leaf");
        assert_eq!(normalize("../../etc", "passwd"), "/etc/passwd");
    }

    #[test]
    fn normalize_only_separators_in_cwd() {
        assert_eq!(normalize("////", "x"), "/x");
    }

    #[test]
    fn normalize_dotdot_inside_target_does_not_walk_into_cwd_segments() {
        assert_eq!(normalize("/a/b/c", "../../d"), "/a/d");
    }

    #[test]
    fn normalize_long_input_does_not_overflow() {
        let mut t = String::new();
        for _ in 0..1024 {
            t.push_str("../");
        }
        t.push_str("end");
        assert_eq!(normalize("/a/b/c/d", &t), "/end");
    }

    #[test]
    fn normalize_unicode_segments_preserved() {
        assert_eq!(normalize("/", "/α/β/γ"), "/α/β/γ");
    }
}
