use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use frame::mm::{PhysFrame, Size4KiB, frame_alloc, read_from_frame, write_to_frame, zero_frame};
use frame::sync::SpinIrq;

const MAX_PAGES: usize = 1024;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    inode_id: u64,
    page_offset: u64,
}

struct Page {
    frame: PhysFrame<Size4KiB>,
    len: usize,
    pin_count: u32,
    dirty: bool,
}

struct State {
    map: BTreeMap<Key, Page>,
    lru: VecDeque<Key>,
}

static CACHE: SpinIrq<State> = SpinIrq::new(State {
    map: BTreeMap::new(),
    lru: VecDeque::new(),
});

pub fn lookup(inode_id: u64, page_offset: u64) -> Option<Vec<u8>> {
    let key = Key {
        inode_id,
        page_offset: page_offset & !0xfff,
    };
    let mut s = CACHE.lock();
    if !s.map.contains_key(&key) {
        return None;
    }
    s.lru.retain(|k| *k != key);
    s.lru.push_back(key);
    let page = s.map.get(&key)?;
    let len = page.len;
    let mut buf = alloc::vec![0u8; len];
    read_from_frame(page.frame, 0, &mut buf);
    Some(buf)
}

pub fn insert(inode_id: u64, page_offset: u64, data: &[u8]) {
    if data.is_empty() || data.len() > 4096 {
        return;
    }
    let frame = match frame_alloc::alloc_frame() {
        Some(f) => f,
        None => return,
    };
    zero_frame(frame);
    write_to_frame(frame, 0, data);

    let key = Key {
        inode_id,
        page_offset: page_offset & !0xfff,
    };
    let mut s = CACHE.lock();

    if let Some(old) = s.map.get(&key) {
        if old.pin_count > 0 {
            frame_alloc::free_frame(frame);
            return;
        }
    }

    if let Some(old) = s.map.remove(&key) {
        s.lru.retain(|k| *k != key);
        frame_alloc::free_frame(old.frame);
    }

    while s.map.len() >= MAX_PAGES {
        let mut victim = None;
        for &k in s.lru.iter() {
            if let Some(p) = s.map.get(&k) {
                if p.pin_count == 0 {
                    victim = Some(k);
                    break;
                }
            }
        }
        match victim {
            Some(v) => {
                s.lru.retain(|k| *k != v);
                if let Some(page) = s.map.remove(&v) {
                    frame_alloc::free_frame(page.frame);
                }
            }
            None => break,
        }
    }

    s.map.insert(
        key,
        Page {
            frame,
            len: data.len(),
            pin_count: 0,
            dirty: false,
        },
    );
    s.lru.push_back(key);
}

pub fn pin_or_load(
    inode_id: u64,
    page_offset: u64,
    inode: &dyn crate::vfs::Inode,
) -> Option<PhysFrame<Size4KiB>> {
    let key = Key {
        inode_id,
        page_offset: page_offset & !0xfff,
    };
    {
        let mut s = CACHE.lock();
        if s.map.contains_key(&key) {
            let frame = {
                let page = s.map.get_mut(&key).unwrap();
                page.pin_count = page.pin_count.saturating_add(1);
                page.frame
            };
            s.lru.retain(|k| *k != key);
            s.lru.push_back(key);
            return Some(frame);
        }
    }
    let mut buf = [0u8; 4096];
    let n = inode.read_at(key.page_offset, &mut buf).unwrap_or(0);
    let frame = frame_alloc::alloc_frame()?;
    zero_frame(frame);
    if n > 0 {
        write_to_frame(frame, 0, &buf[..n]);
    }
    let mut s = CACHE.lock();
    if s.map.contains_key(&key) {
        frame_alloc::free_frame(frame);
        let existing = {
            let page = s.map.get_mut(&key).unwrap();
            page.pin_count = page.pin_count.saturating_add(1);
            page.frame
        };
        s.lru.retain(|k| *k != key);
        s.lru.push_back(key);
        return Some(existing);
    }
    while s.map.len() >= MAX_PAGES {
        let mut victim = None;
        for &k in s.lru.iter() {
            if let Some(p) = s.map.get(&k) {
                if p.pin_count == 0 {
                    victim = Some(k);
                    break;
                }
            }
        }
        match victim {
            Some(k) => {
                s.lru.retain(|x| *x != k);
                if let Some(page) = s.map.remove(&k) {
                    frame_alloc::free_frame(page.frame);
                }
            }
            None => break,
        }
    }
    s.map.insert(
        key,
        Page {
            frame,
            len: n,
            pin_count: 1,
            dirty: false,
        },
    );
    s.lru.push_back(key);
    Some(frame)
}

pub fn pin(inode_id: u64, page_offset: u64) {
    let key = Key {
        inode_id,
        page_offset: page_offset & !0xfff,
    };
    let mut s = CACHE.lock();
    if let Some(page) = s.map.get_mut(&key) {
        page.pin_count = page.pin_count.saturating_add(1);
    }
}

pub fn unpin(inode_id: u64, page_offset: u64) {
    let key = Key {
        inode_id,
        page_offset: page_offset & !0xfff,
    };
    let mut s = CACHE.lock();
    if let Some(page) = s.map.get_mut(&key) {
        if page.pin_count > 0 {
            page.pin_count -= 1;
        }
    }
}

pub fn mark_dirty(inode_id: u64, page_offset: u64) {
    let key = Key {
        inode_id,
        page_offset: page_offset & !0xfff,
    };
    let mut s = CACHE.lock();
    if let Some(page) = s.map.get_mut(&key) {
        page.dirty = true;
    }
}

pub fn writeback(
    inode_id: u64,
    start: u64,
    end: u64,
    inode: &dyn crate::vfs::Inode,
) -> cyphera_kapi::KResult<usize> {
    let page_start = start & !0xfff;
    let page_end = end.saturating_add(0xfff) & !0xfff;
    let dirty: Vec<(u64, Vec<u8>)> = {
        let mut s = CACHE.lock();
        let keys: Vec<Key> = s
            .map
            .keys()
            .filter(|k| {
                k.inode_id == inode_id && k.page_offset >= page_start && k.page_offset < page_end
            })
            .copied()
            .collect();
        let mut out = Vec::new();
        for k in keys {
            let page = match s.map.get_mut(&k) {
                Some(p) => p,
                None => continue,
            };
            if !page.dirty {
                continue;
            }
            let mut buf = alloc::vec![0u8; page.len];
            read_from_frame(page.frame, 0, &mut buf);
            page.dirty = false;
            out.push((k.page_offset, buf));
        }
        out
    };
    let mut total = 0usize;
    for (offset, buf) in dirty {
        match inode.write_at(offset, &buf) {
            Ok(n) => total += n,
            Err(e) => {
                let key = Key {
                    inode_id,
                    page_offset: offset,
                };
                if let Some(page) = CACHE.lock().map.get_mut(&key) {
                    page.dirty = true;
                }
                return Err(e);
            }
        }
    }
    Ok(total)
}

pub fn invalidate_range(inode_id: u64, start: u64, end: u64) {
    let page_start = start & !0xfff;
    let page_end = end.saturating_add(0xfff) & !0xfff;
    let mut s = CACHE.lock();
    let mut victims = Vec::new();
    for (k, page) in s.map.iter() {
        if k.inode_id == inode_id
            && k.page_offset >= page_start
            && k.page_offset < page_end
            && page.pin_count == 0
        {
            victims.push(*k);
        }
    }
    for k in victims {
        if let Some(page) = s.map.remove(&k) {
            frame_alloc::free_frame(page.frame);
        }
        s.lru.retain(|x| *x != k);
    }
}

pub fn write_through(inode_id: u64, offset: u64, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let write_end = offset.saturating_add(data.len() as u64);
    let mut s = CACHE.lock();
    let mut evict = Vec::new();
    let mut po = offset & !0xfff;
    while po < write_end {
        let page_end = po.saturating_add(4096);
        let key = Key {
            inode_id,
            page_offset: po,
        };
        if let Some(page) = s.map.get_mut(&key) {
            if page.pin_count > 0 {
                let ov_lo = offset.max(po);
                let ov_hi = write_end.min(page_end);
                let in_page = (ov_lo - po) as usize;
                let src = (ov_lo - offset) as usize;
                let len = (ov_hi - ov_lo) as usize;
                write_to_frame(page.frame, in_page, &data[src..src + len]);
                let new_len = (ov_hi - po) as usize;
                if new_len > page.len {
                    page.len = new_len;
                }
            } else {
                evict.push(key);
            }
        }
        po = page_end;
    }
    for k in evict {
        if let Some(page) = s.map.remove(&k) {
            frame_alloc::free_frame(page.frame);
        }
        s.lru.retain(|x| *x != k);
    }
}

pub fn drop_inode(inode_id: u64) {
    let mut s = CACHE.lock();
    let victims: Vec<Key> = s
        .map
        .keys()
        .filter(|k| k.inode_id == inode_id)
        .copied()
        .collect();
    for k in victims {
        if let Some(page) = s.map.remove(&k) {
            frame_alloc::free_frame(page.frame);
        }
        s.lru.retain(|x| *x != k);
    }
}
