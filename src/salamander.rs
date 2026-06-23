//! Salamander UDP obfuscation (Hysteria-2 technique), applied to QUIC datagrams.
//!
//! Goal: break DPI pattern-matching of QUIC (the recognizable Initial-packet shape and the
//! SNI in its encrypted-with-a-well-known-key ClientHello) so a moderate-DPI network that
//! passes generic UDP lets our traffic through. It is **obfuscation, not encryption**: QUIC
//! underneath is already authenticated + encrypted, so this layer only needs to randomize the
//! bytes on the wire, not provide integrity.
//!
//! Construction (matches Hysteria's salamander):
//!   * per-packet `salt` = 8 random bytes,
//!   * `key = BLAKE2b-256(psk ‖ salt)` (32 bytes),
//!   * `out = salt ‖ (plain[i] ^ key[i % 32])` — repeating-key XOR, fresh key every packet.
//!     Overhead is the 8-byte salt; there is no auth tag.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

type Blake2b256 = Blake2b<U32>;

/// Random salt prepended to every obfuscated datagram.
pub const SALT_LEN: usize = 8;
/// Per-packet keystream length (BLAKE2b-256 output), cycled across the datagram.
const KEY_LEN: usize = 32;

/// Stateless obfuscator parameterised by the pre-shared key.
#[derive(Clone)]
pub struct Salamander {
    psk: Vec<u8>,
}

impl Salamander {
    pub fn new(psk: Vec<u8>) -> Self {
        Self { psk }
    }

    fn key(&self, salt: &[u8]) -> [u8; KEY_LEN] {
        let mut h = Blake2b256::new();
        h.update(&self.psk);
        h.update(salt);
        h.finalize().into()
    }

    /// Obfuscate `plain` into `out` (which must be at least `plain.len() + SALT_LEN`), using the
    /// caller-supplied random `salt`. Returns the number of bytes written.
    pub fn obfuscate(&self, plain: &[u8], salt: [u8; SALT_LEN], out: &mut [u8]) -> usize {
        out[..SALT_LEN].copy_from_slice(&salt);
        let key = self.key(&salt);
        for (i, &b) in plain.iter().enumerate() {
            out[SALT_LEN + i] = b ^ key[i % KEY_LEN];
        }
        SALT_LEN + plain.len()
    }

    /// Reverse `obfuscate` in place: `buf[..len]` is a salt-prefixed obfuscated datagram; the
    /// recovered plaintext is written to `buf[..len - SALT_LEN]`. Returns the plaintext length,
    /// or `None` if the datagram is too short to carry a salt.
    pub fn deobfuscate_in_place(&self, buf: &mut [u8], len: usize) -> Option<usize> {
        if len < SALT_LEN {
            return None;
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&buf[..SALT_LEN]);
        let key = self.key(&salt);
        let plain_len = len - SALT_LEN;
        // Forward pass: buf[i] only reads buf[SALT_LEN + i] (always ahead), so the left-shift
        // is safe in place.
        for i in 0..plain_len {
            buf[i] = buf[SALT_LEN + i] ^ key[i % KEY_LEN];
        }
        Some(plain_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_recovers_plaintext() {
        let s = Salamander::new(b"shared-psk".to_vec());
        let plain = b"the quic datagram bytes that DPI must not recognise".to_vec();
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];

        let mut obf = vec![0u8; plain.len() + SALT_LEN];
        let n = s.obfuscate(&plain, salt, &mut obf);
        assert_eq!(n, plain.len() + SALT_LEN);
        // The body must not appear in the clear.
        assert_ne!(&obf[SALT_LEN..], &plain[..]);

        let mut buf = obf.clone();
        let len = s.deobfuscate_in_place(&mut buf, n).unwrap();
        assert_eq!(len, plain.len());
        assert_eq!(&buf[..len], &plain[..]);
    }

    #[test]
    fn different_salt_yields_different_ciphertext() {
        let s = Salamander::new(b"k".to_vec());
        let plain = b"same plaintext".to_vec();
        let mut a = vec![0u8; plain.len() + SALT_LEN];
        let mut b = vec![0u8; plain.len() + SALT_LEN];
        s.obfuscate(&plain, [0u8; SALT_LEN], &mut a);
        s.obfuscate(&plain, [9u8; SALT_LEN], &mut b);
        assert_ne!(a[SALT_LEN..], b[SALT_LEN..]);
    }

    #[test]
    fn wrong_psk_does_not_recover() {
        let plain = b"secret-ish bytes".to_vec();
        let salt = [4u8; SALT_LEN];
        let mut obf = vec![0u8; plain.len() + SALT_LEN];
        Salamander::new(b"correct".to_vec()).obfuscate(&plain, salt, &mut obf);

        let mut buf = obf.clone();
        let len = Salamander::new(b"wrong".to_vec())
            .deobfuscate_in_place(&mut buf, obf.len())
            .unwrap();
        assert_ne!(&buf[..len], &plain[..]);
    }
}
