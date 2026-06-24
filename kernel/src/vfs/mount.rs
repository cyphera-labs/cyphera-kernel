use alloc::string::String;
use alloc::sync::Arc;

use crate::errno::EINVAL;

pub const MS_RDONLY: u64 = 0x0001;
pub const MS_NOSUID: u64 = 0x0002;
pub const MS_NODEV: u64 = 0x0004;
pub const MS_NOEXEC: u64 = 0x0008;
pub const MOUNT_FLAG_MASK: u64 = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC;
pub const MS_BIND: u64 = 0x1000;
const MS_REC: u64 = 0x4000;
pub const MS_REMOUNT: u64 = 0x0020;
const MS_SHARED: u64 = 1 << 20;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SLAVE: u64 = 1 << 19;
const MS_UNBINDABLE: u64 = 1 << 17;
pub const MS_MOVE: u64 = 0x2000;
pub const PROPAGATION_MASK: u64 = MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE;

const MNT_FORCE: u64 = 1;
const MNT_DETACH: u64 = 2;
pub const MNT_EXPIRE: u64 = 4;
const UMOUNT_NOFOLLOW: u64 = 8;
const EBUSY: i64 = -16;

fn fresh_propagation(flags: u64) -> super::MountPropagation {
    if flags & MS_UNBINDABLE != 0 {
        super::MountPropagation::Unbindable
    } else if flags & MS_SHARED != 0 {
        super::MountPropagation::Shared(super::PeerGroup::new_empty())
    } else {
        super::MountPropagation::Private
    }
}

pub fn change_propagation(ctx: &super::path::Context, t_norm: &str, flags: u64) -> i64 {
    let mut targets: alloc::vec::Vec<String> = alloc::vec::Vec::new();
    if (flags & MS_REC) != 0 {
        for (suffix, _) in ctx.collect_subtree(t_norm) {
            let p = if suffix.is_empty() {
                String::from(t_norm)
            } else if t_norm == "/" {
                suffix
            } else {
                let mut s = String::from(t_norm);
                s.push_str(&suffix);
                s
            };
            targets.push(p);
        }
        if targets.is_empty() {
            targets.push(String::from(t_norm));
        }
    } else {
        targets.push(String::from(t_norm));
    }
    for p in targets.iter() {
        let existing = match ctx.lookup_mount_full(p) {
            Some(e) => e,
            None => continue,
        };
        let new_prop = if flags & MS_UNBINDABLE != 0 {
            super::MountPropagation::Unbindable
        } else if flags & MS_PRIVATE != 0 {
            super::MountPropagation::Private
        } else if flags & MS_SHARED != 0 {
            match existing.propagation.clone() {
                super::MountPropagation::Shared(g) => super::MountPropagation::Shared(g),
                _ => super::MountPropagation::Shared(super::PeerGroup::new_empty()),
            }
        } else if flags & MS_SLAVE != 0 {
            match existing.propagation.clone() {
                super::MountPropagation::Shared(g) => super::MountPropagation::Slave(g),
                other => other,
            }
        } else {
            existing.propagation.clone()
        };
        ctx.set_mount_propagation(p, new_prop);
    }
    0
}

pub fn move_mount(ctx: &super::path::Context, s_norm: &str, t_norm: &str) -> i64 {
    let entry = match ctx.lookup_mount_full(s_norm) {
        Some(e) => e,
        None => return EINVAL,
    };
    let tgt_inode = match super::path::resolve(ctx, &ctx.root, t_norm) {
        Ok(i) => i,
        Err(e) => return e.as_neg_i64(),
    };
    ctx.remove_mount(s_norm);
    let moved_flags = entry.in_use.flags();
    ctx.install_mount(
        t_norm,
        tgt_inode.inode_id(),
        entry.root,
        entry.propagation,
        &entry.source,
        &entry.fstype,
        moved_flags,
    );
    0
}

pub fn bind_mount(ctx: &super::path::Context, s_norm: &str, t_norm: &str, flags: u64) -> i64 {
    if let Some(containing) = ctx.containing_mount(s_norm) {
        if containing.propagation.is_unbindable() {
            return EINVAL;
        }
    }
    let src_inode = match super::path::resolve(ctx, &ctx.root, s_norm) {
        Ok(i) => i,
        Err(e) => return e.as_neg_i64(),
    };
    let tgt_inode = match super::path::resolve(ctx, &ctx.root, t_norm) {
        Ok(i) => i,
        Err(e) => return e.as_neg_i64(),
    };
    let src_entry = ctx
        .lookup_mount_full(s_norm)
        .or_else(|| ctx.containing_mount(s_norm));
    let explicit = flags & PROPAGATION_MASK;
    let bind_prop = if explicit != 0 {
        fresh_propagation(flags)
    } else {
        match src_entry.as_ref().map(|e| e.propagation.clone()) {
            Some(super::MountPropagation::Shared(g)) => super::MountPropagation::Shared(g),
            Some(super::MountPropagation::Slave(g)) => super::MountPropagation::Slave(g),
            _ => super::MountPropagation::Private,
        }
    };
    let bind_fstype = src_entry
        .as_ref()
        .map(|e| e.fstype.clone())
        .unwrap_or_else(|| String::from("none"));
    ctx.install_mount_propagating(
        t_norm,
        tgt_inode.inode_id(),
        src_inode,
        bind_prop,
        s_norm,
        &bind_fstype,
        flags & MOUNT_FLAG_MASK,
    );
    if (flags & MS_REC) != 0 {
        for (suffix, entry) in ctx.collect_subtree(s_norm) {
            if suffix.is_empty() {
                continue;
            }
            let mirror_path = if t_norm == "/" {
                suffix.clone()
            } else {
                let mut s = String::from(t_norm);
                s.push_str(&suffix);
                s
            };
            if let Ok(mirror_target_inode) = super::path::resolve(ctx, &ctx.root, &mirror_path) {
                let sub_flags = entry.in_use.flags();
                ctx.install_mount_propagating(
                    &mirror_path,
                    mirror_target_inode.inode_id(),
                    entry.root.clone(),
                    entry.propagation,
                    &entry.source,
                    &entry.fstype,
                    sub_flags,
                );
            }
        }
    }
    0
}

#[allow(clippy::too_many_arguments)]
pub fn install_new(
    ctx: &super::path::Context,
    normalized: &str,
    target_inode_id: u64,
    new_root: Arc<dyn super::Inode>,
    flags: u64,
    source: &str,
    fstype: &str,
) {
    let new_prop = fresh_propagation(flags);
    ctx.install_mount_propagating(
        normalized,
        target_inode_id,
        new_root,
        new_prop,
        source,
        fstype,
        flags & MOUNT_FLAG_MASK,
    );
}

pub fn do_umount(ctx: &super::path::Context, normalized: &str, flags: u64) -> i64 {
    if (flags & UMOUNT_NOFOLLOW) != 0 {
        if let Err(e) = super::path::resolve_no_follow(ctx, &ctx.root, normalized) {
            return e.as_neg_i64();
        }
    }

    let skip_busy_check = (flags & (MNT_DETACH | MNT_FORCE)) != 0;
    if !skip_busy_check {
        if let Some(entry) = ctx.lookup_mount_full(normalized) {
            if entry.in_use.refs() > 0 {
                return EBUSY;
            }
        }
    }

    if ctx.remove_mount_propagating(normalized).is_none() {
        return EINVAL;
    }
    0
}
