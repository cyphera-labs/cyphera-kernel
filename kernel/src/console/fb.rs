use frame::sync::SpinIrq;

use super::font::{self, CELL_H, CELL_W};

const FG: [u8; 4] = [0xff, 0xff, 0xff, 0xff];
const BG: [u8; 4] = [0x00, 0x00, 0x00, 0xff];

#[derive(Clone, Copy, PartialEq)]
enum Esc {
    None,
    Saw,
    Csi,
}

struct Screen {
    cols: usize,
    rows: usize,
    fb_w: usize,
    cx: usize,
    cy: usize,
    esc: Esc,
    ready: bool,
}

static SCREEN: SpinIrq<Screen> = SpinIrq::new(Screen {
    cols: 0,
    rows: 0,
    fb_w: 0,
    cx: 0,
    cy: 0,
    esc: Esc::None,
    ready: false,
});

fn ensure_ready(s: &mut Screen) -> bool {
    if s.ready {
        return true;
    }
    if let Some((_, _, w, h)) = virtio::framebuffer_info() {
        let (w, h) = (w as usize, h as usize);
        let cols = w / CELL_W;
        let rows = h / CELL_H;
        if cols > 0 && rows > 0 {
            s.fb_w = w;
            s.cols = cols;
            s.rows = rows;
            s.ready = true;
        }
    }
    s.ready
}

fn put_cell(s: &Screen, col: usize, row: usize, c: u8) {
    let g = font::glyph(c);
    let x0 = col * CELL_W;
    let y0 = row * CELL_H;
    for (dy, bits) in g.iter().enumerate() {
        let mut line = [0u8; CELL_W * 4];
        for x in 0..CELL_W {
            let px = if (bits >> (7 - x)) & 1 != 0 { FG } else { BG };
            line[x * 4..x * 4 + 4].copy_from_slice(&px);
        }
        let off = ((y0 + dy) * s.fb_w + x0) * 4;
        virtio::fb_write(off, &line);
    }
}

fn newline(s: &mut Screen) {
    s.cx = 0;
    if s.cy + 1 >= s.rows {
        virtio::fb_scroll_up(CELL_H);
        s.cy = s.rows - 1;
    } else {
        s.cy += 1;
    }
}

pub(crate) fn putbytes(bytes: &[u8]) {
    let mut s = match SCREEN.try_lock() {
        Some(g) => g,
        None => return,
    };
    if !ensure_ready(&mut s) {
        return;
    }
    let mut dirty = false;
    for &b in bytes {
        match s.esc {
            Esc::Saw => {
                s.esc = if b == b'[' { Esc::Csi } else { Esc::None };
                continue;
            }
            Esc::Csi => {
                if (0x40..=0x7e).contains(&b) {
                    s.esc = Esc::None;
                }
                continue;
            }
            Esc::None => {}
        }
        match b {
            0x1b => s.esc = Esc::Saw,
            b'\n' => {
                newline(&mut s);
                dirty = true;
            }
            b'\r' => s.cx = 0,
            0x08 | 0x7f if s.cx > 0 => {
                s.cx -= 1;
                let (cx, cy) = (s.cx, s.cy);
                put_cell(&s, cx, cy, b' ');
                dirty = true;
            }
            b'\t' => {
                let stop = ((s.cx / 8) + 1) * 8;
                while s.cx < stop && s.cx < s.cols {
                    let (cx, cy) = (s.cx, s.cy);
                    put_cell(&s, cx, cy, b' ');
                    s.cx += 1;
                }
                dirty = true;
            }
            0x20..=0x7e => {
                if s.cx >= s.cols {
                    newline(&mut s);
                }
                let (cx, cy) = (s.cx, s.cy);
                put_cell(&s, cx, cy, b);
                s.cx += 1;
                dirty = true;
            }
            _ => {}
        }
    }
    if dirty {
        let _ = virtio::gpu_flush();
    }
}
