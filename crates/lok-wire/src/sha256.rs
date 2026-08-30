//! SHA-256 and HMAC-SHA-256, in-tree.
//!
//! Why in-tree rather than `sha2`/`hmac`: the workspace is deliberately minimal-dep (see
//! `Cargo.toml`), the sensor image is meant to be auditable in an afternoon, and this is
//! the *only* symmetric primitive the wire format needs. It is a textbook implementation
//! checked against the published FIPS 180-4 and RFC 4231 vectors in the tests below — if
//! those pass, the construction is the standard one.
//!
//! This is **not** the signing primitive. Bundle signatures are ed25519 and land with the
//! control plane (Phase 2); do not grow this module into that.

pub const DIGEST_LEN: usize = 32;
const BLOCK_LEN: usize = 64;

#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Streaming SHA-256. Feed with [`update`](Sha256::update), finish with
/// [`finish`](Sha256::finish).
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; BLOCK_LEN],
    filled: usize,
    /// Total message length in bits, for the length suffix.
    bits: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 { state: H0, block: [0u8; BLOCK_LEN], filled: 0, bits: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.bits = self.bits.wrapping_add((data.len() as u64) * 8);
        while !data.is_empty() {
            let take = (BLOCK_LEN - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled == BLOCK_LEN {
                let block = self.block;
                self.compress(&block);
                self.filled = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; DIGEST_LEN] {
        let bits = self.bits;
        self.update(&[0x80]);
        // Pad with zeros until 8 bytes short of a block boundary, then the bit length.
        while self.filled != BLOCK_LEN - 8 {
            self.update(&[0x00]);
        }
        self.block[BLOCK_LEN - 8..].copy_from_slice(&bits.to_be_bytes());
        let block = self.block;
        self.compress(&block);

        let mut out = [0u8; DIGEST_LEN];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; BLOCK_LEN]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        for (s, v) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

/// One-shot SHA-256 over a sequence of parts (no allocation to concatenate them).
pub fn sha256(parts: &[&[u8]]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}

/// HMAC-SHA-256 (RFC 2104) over a sequence of message parts.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; DIGEST_LEN] {
    let mut k0 = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        k0[..DIGEST_LEN].copy_from_slice(&sha256(&[key]));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    for p in parts {
        inner.update(p);
    }
    let inner = inner.finish();

    sha256(&[&opad, &inner])
}

/// The first 8 bytes of an HMAC, as a big-endian `u64`. The wire tag: 64 bits is the size
/// budget the datagram has, and the threat is a middlebox forging *one* tag in real time,
/// not an offline attacker with unlimited attempts.
pub fn hmac_tag64(key: &[u8], parts: &[&[u8]]) -> u64 {
    let mac = hmac_sha256(key, parts);
    u64::from_be_bytes(mac[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// FIPS 180-4 published vectors, plus the multi-block case that exercises padding
    /// across a block boundary.
    #[test]
    fn sha256_matches_published_vectors() {
        assert_eq!(
            hex(&sha256(&[b""])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(&[b"abc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(&[b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"])),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // A million 'a' would be slow here; 1000 blocks is enough to exercise chaining.
        let long = vec![b'a'; 64 * 1000];
        assert_eq!(
            hex(&sha256(&[&long])),
            hex(&sha256(&[&long[..32_000], &long[32_000..]])),
            "streaming in parts must equal the one-shot digest"
        );
    }

    /// RFC 4231 test cases 1, 2 and 3 — including the case where the key is longer than a
    /// block and must be hashed down first (case 5's key shape).
    #[test]
    fn hmac_matches_rfc4231_vectors() {
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], &[b"Hi There"])),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", &[b"what do ya want for nothing?"])),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 20], &[&[0xdd; 50][..]])),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
        // RFC 4231 case 4: key longer than the 64-byte block, so it is hashed first.
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn parts_are_concatenated_not_hashed_separately() {
        assert_eq!(hmac_sha256(b"k", &[b"ab", b"c"]), hmac_sha256(b"k", &[b"abc"]));
        assert_ne!(hmac_sha256(b"k", &[b"ab", b"c"]), hmac_sha256(b"k", &[b"a", b"bc", b"x"]));
    }

    #[test]
    fn tag64_is_the_leading_eight_bytes() {
        let mac = hmac_sha256(b"k", &[b"m"]);
        assert_eq!(hmac_tag64(b"k", &[b"m"]), u64::from_be_bytes(mac[..8].try_into().unwrap()));
    }
}
