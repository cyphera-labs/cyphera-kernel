#[cfg(not(host_test))]
use frame::sync::SpinIrq;

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u8; 64] {
    let init: [u32; 16] = [
        CONSTANTS[0],
        CONSTANTS[1],
        CONSTANTS[2],
        CONSTANTS[3],
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        key[5],
        key[6],
        key[7],
        counter,
        nonce[0],
        nonce[1],
        nonce[2],
    ];
    let mut s = init;
    for _ in 0..10 {
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[i].wrapping_add(init[i]).to_le_bytes());
    }
    out
}

const RESEED_BYTES: usize = 1 << 20;

struct Csprng {
    key: [u32; 8],
    seeded: bool,
    since_reseed: usize,
}

impl Csprng {
    const fn new() -> Self {
        Self {
            key: [0; 8],
            seeded: false,
            since_reseed: 0,
        }
    }

    #[cfg(not(host_test))]
    fn reseed(&mut self) {
        let mut seed = [0u8; 32];
        let _ = frame::cpu::hwrng::fill(&mut seed);
        let mut vbuf = [0u8; 32];
        if let Ok(n) = virtio::fill_random(&mut vbuf) {
            for i in 0..n.min(32) {
                seed[i] ^= vbuf[i];
            }
        }
        let tsc = frame::cpu::rdtsc().to_le_bytes();
        for i in 0..8 {
            seed[i] ^= tsc[i];
        }
        for i in 0..8 {
            let w = u32::from_le_bytes([
                seed[4 * i],
                seed[4 * i + 1],
                seed[4 * i + 2],
                seed[4 * i + 3],
            ]);
            self.key[i] ^= w;
        }
        self.seeded = true;
        self.since_reseed = 0;
    }

    fn fill(&mut self, out: &mut [u8]) {
        #[cfg(not(host_test))]
        if !self.seeded || self.since_reseed >= RESEED_BYTES {
            self.reseed();
        }
        let nonce = [0u32; 3];
        let b0 = block(&self.key, 0, &nonce);
        let mut next_key = [0u32; 8];
        for i in 0..8 {
            next_key[i] =
                u32::from_le_bytes([b0[4 * i], b0[4 * i + 1], b0[4 * i + 2], b0[4 * i + 3]]);
        }
        let mut produced = out.len().min(32);
        out[..produced].copy_from_slice(&b0[32..32 + produced]);
        let mut counter = 1u32;
        while produced < out.len() {
            let blk = block(&self.key, counter, &nonce);
            let take = (out.len() - produced).min(64);
            out[produced..produced + take].copy_from_slice(&blk[..take]);
            produced += take;
            counter = counter.wrapping_add(1);
        }
        self.key = next_key;
        self.since_reseed = self.since_reseed.saturating_add(out.len());
    }
}

#[cfg(not(host_test))]
static RNG: SpinIrq<Csprng> = SpinIrq::new(Csprng::new());

#[cfg(not(host_test))]
pub fn fill(buf: &mut [u8]) {
    RNG.lock().fill(buf);
}

#[cfg(not(host_test))]
pub fn init() {
    assert!(self_test(), "CSPRNG power-on self-test failed");
    RNG.lock().reseed();
}

pub fn self_test() -> bool {
    let mut s = [0u32; 16];
    s[0] = 0x1111_1111;
    s[1] = 0x0102_0304;
    s[2] = 0x9b8d_6f43;
    s[3] = 0x0123_4567;
    quarter_round(&mut s, 0, 1, 2, 3);
    if s[0] != 0xea2a_92f4 || s[1] != 0xcb1c_f8ce || s[2] != 0x4581_472e || s[3] != 0x5881_c4bb {
        return false;
    }
    let key: [u32; 8] = [
        0x0302_0100,
        0x0706_0504,
        0x0b0a_0908,
        0x0f0e_0d0c,
        0x1312_1110,
        0x1716_1514,
        0x1b1a_1918,
        0x1f1e_1d1c,
    ];
    let nonce: [u32; 3] = [0x0900_0000, 0x4a00_0000, 0x0000_0000];
    let expected: [u8; 64] = [
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71,
        0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4,
        0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9,
        0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8,
        0xa2, 0x50, 0x3c, 0x4e,
    ];
    block(&key, 1, &nonce) == expected
}

#[cfg(host_test)]
#[cfg(test)]
mod host_tests {
    use super::*;

    fn key_to_bytes(key: &[u32; 8]) -> [u8; 32] {
        let mut b = [0u8; 32];
        for i in 0..8 {
            b[i * 4..i * 4 + 4].copy_from_slice(&key[i].to_le_bytes());
        }
        b
    }

    fn nonce_to_bytes(nonce: &[u32; 3]) -> [u8; 12] {
        let mut b = [0u8; 12];
        for i in 0..3 {
            b[i * 4..i * 4 + 4].copy_from_slice(&nonce[i].to_le_bytes());
        }
        b
    }

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_key(state: &mut u64) -> [u32; 8] {
        let mut k = [0u32; 8];
        for w in k.iter_mut() {
            *w = splitmix64(state) as u32;
        }
        k
    }

    fn next_nonce(state: &mut u64) -> [u32; 3] {
        let mut n = [0u32; 3];
        for w in n.iter_mut() {
            *w = splitmix64(state) as u32;
        }
        n
    }

    fn oracle_keystream(key: &[u32; 8], nonce: &[u32; 3], blocks: usize) -> Vec<u8> {
        use chacha20::ChaCha20;
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        let mut cipher =
            ChaCha20::new_from_slices(&key_to_bytes(key), &nonce_to_bytes(nonce)).unwrap();
        let mut buf = vec![0u8; blocks * 64];
        cipher.apply_keystream(&mut buf);
        buf
    }

    fn erased_key(key: &[u32; 8]) -> [u32; 8] {
        let b0 = block(key, 0, &[0u32; 3]);
        let mut k = [0u32; 8];
        for i in 0..8 {
            k[i] = u32::from_le_bytes([b0[4 * i], b0[4 * i + 1], b0[4 * i + 2], b0[4 * i + 3]]);
        }
        k
    }

    fn expected_fill(key: &[u32; 8], len: usize) -> Vec<u8> {
        let nonce = [0u32; 3];
        let mut out = Vec::with_capacity(len + 64);
        let b0 = block(key, 0, &nonce);
        out.extend_from_slice(&b0[32..]);
        let mut ctr = 1u32;
        while out.len() < len {
            out.extend_from_slice(&block(key, ctr, &nonce));
            ctr = ctr.wrapping_add(1);
        }
        out.truncate(len);
        out
    }

    #[test]
    fn block_matches_independent_chacha20_over_randomized_inputs() {
        let mut s = 0x0123_4567_89AB_CDEFu64;
        const BLOCKS: usize = 64;
        for _ in 0..300 {
            let key = next_key(&mut s);
            let nonce = next_nonce(&mut s);
            let ks = oracle_keystream(&key, &nonce, BLOCKS);
            for ctr in 0..BLOCKS {
                assert_eq!(
                    &block(&key, ctr as u32, &nonce)[..],
                    &ks[ctr * 64..ctr * 64 + 64],
                    "block mismatch: key={key:?} nonce={nonce:?} counter={ctr}"
                );
            }
        }
    }

    #[test]
    fn fill_output_uses_pre_erasure_key_all_lengths() {
        let key = [0x1111_1111u32, 0x2222_2222, 3, 4, 5, 6, 7, 8];
        for &len in &[0usize, 1, 16, 31, 32, 33, 63, 64, 65, 96, 127, 128, 200] {
            let mut rng = Csprng {
                key,
                seeded: true,
                since_reseed: 0,
            };
            let mut out = vec![0u8; len];
            rng.fill(&mut out);
            assert_eq!(
                out,
                expected_fill(&key, len),
                "fill output wrong at len={len}"
            );
        }
    }

    #[test]
    fn fill_replaces_key_after_generation() {
        let key = [0x9ABC_DEF0u32, 1, 2, 3, 4, 5, 6, 7];
        let mut rng = Csprng {
            key,
            seeded: true,
            since_reseed: 0,
        };
        let mut out = [0u8; 40];
        rng.fill(&mut out);
        assert_eq!(
            rng.key,
            erased_key(&key),
            "key not replaced with block-0 first half"
        );
        assert_ne!(rng.key, key, "key unchanged after fill — erasure missing");
    }

    #[test]
    fn successive_fills_never_reuse_keystream() {
        let key = [0x5555_5555u32, 0xAAAA_AAAA, 1, 2, 3, 4, 5, 6];
        let mut rng = Csprng {
            key,
            seeded: true,
            since_reseed: 0,
        };
        let mut a = [0u8; 64];
        rng.fill(&mut a);
        let mut b = [0u8; 64];
        rng.fill(&mut b);
        assert_ne!(a, b, "keystream reused across draws — erasure broken");
        assert_eq!(
            &b[..],
            &expected_fill(&erased_key(&key), 64)[..],
            "draw 2 is not the keystream under the erased key"
        );
    }

    #[test]
    fn self_test_passes_on_host() {
        assert!(self_test());
    }
}
