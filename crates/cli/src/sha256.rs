//! SHA-256, for the ruleset digests in the attestation.
//!
//! Hand-written, which needs justifying against the line D-08 draws. That line
//! is about *silent* failure: a hand-written parser can misread valid input and
//! nobody finds out. This is neither a parser nor a signer.
//!
//! * It handles no key material. D-09 keeps signing out of the tool entirely,
//!   so nothing here is a crypto trust boundary — a digest identifies an input,
//!   it does not attest to anything on its own.
//! * Its failure mode is loud. A wrong implementation disagrees with
//!   `sha256sum` on the first byte, and the FIPS 180-4 vectors below catch that
//!   before it ships. There is no "quietly means something else" outcome.
//! * The alternative costs five runtime crates on an artifact whose deployment
//!   story is a small auditable tree.
//!
//! If that trade ever looks wrong, `sha2` from RustCrypto is the drop-in and
//! the only thing to change is this file.

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

/// SHA-256 of a byte slice, as defined by FIPS 180-4.
pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut h = H0;

    // Padding: a 1 bit, then zeros, then the length in bits as a 64-bit
    // big-endian integer, to a multiple of 64 bytes.
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for block in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        for (dst, src) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *dst = dst.wrapping_add(src);
        }
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Lowercase hex, the form `sha256sum` prints.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap());
    }
    s
}

/// Convenience: hex digest of a string.
pub fn hex_digest(data: &str) -> String {
    hex(&digest(data.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 and the standard NIST examples. These are the reason a
    /// hand-written hash is defensible where a hand-written parser is not:
    /// there is an external authority to check against.
    #[test]
    fn matches_the_published_vectors() {
        let cases: &[(&str, &str)] = &[
            ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(hex_digest(input), *want, "input {input:?}");
        }
    }

    /// The million-a vector, which exercises the block loop and the length
    /// encoding rather than a single padded block.
    #[test]
    fn matches_the_long_vector() {
        let million = "a".repeat(1_000_000);
        assert_eq!(
            hex_digest(&million),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// Every padding boundary: one byte short of a block, exactly a block, and
    /// the case that forces a second padding block.
    #[test]
    fn padding_boundaries_are_handled() {
        for n in [54usize, 55, 56, 57, 63, 64, 65, 119, 120] {
            let input = "x".repeat(n);
            // Cross-check the length-dependent path against a known property:
            // the digest is 32 bytes and differs from its neighbours.
            let d = digest(input.as_bytes());
            assert_eq!(d.len(), 32);
            let other = digest("x".repeat(n + 1).as_bytes());
            assert_ne!(d, other, "length {n} collided with {}", n + 1);
        }
        // 56 bytes is the exact point where padding needs a second block.
        assert_eq!(
            hex_digest(&"a".repeat(56)),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
    }

    #[test]
    fn hex_is_lowercase_and_fixed_width() {
        let h = hex_digest("");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
