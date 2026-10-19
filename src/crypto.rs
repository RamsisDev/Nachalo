//! Thin wrappers over third-party primitives. No primitive is implemented here.
//!
//! What is checked, and what is not:
//! - ML-KEM-768 (`libcrux-ml-kem`, called from `handshake`) is the only one with machine-checked
//!   proofs, and only in part. Per libcrux's own status table, hax/F* prove panic freedom and
//!   functional correctness of the portable field arithmetic, NTT, compression and serialization,
//!   and of most of the AVX2 code, but not of the IND-CPA layer, the matrix code or the generic
//!   sampling and serialization, nor of the NEON code. Constant time is best effort, not proven:
//!   its compile-time check, `check-secret-independence`, is off here.
//! - ChaCha20-Poly1305, HKDF and SHA-2 (RustCrypto) and X25519 and ristretto255 (dalek) are
//!   tested by their authors, not formally verified. The published audits of RustCrypto's AEADs
//!   and of curve25519-dalek predate the versions used here.
//! - This crate checks HKDF against RFC 5869 and the whole handshake against `vectors/v0*.json`,
//!   which RustCrypto's `ml-kem` produced and libcrux reproduces byte for byte. Nothing here has
//!   been audited.

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
/// ML-KEM-768 encapsulation key and ciphertext sizes.
pub const EK_LEN: usize = 1184;
pub const CT_LEN: usize = 1088;

pub type Key = [u8; KEY_LEN];

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS random generator unavailable");
    out
}

/// HKDF-SHA256 (RFC 5869).
pub fn hkdf<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out.as_mut())
        .expect("HKDF output length is a compile-time constant within limits");
    out
}

/// ChaCha20-Poly1305 (RFC 8439) under a single-use key, so the nonce is all zeros and there is no
/// associated data: the key itself is bound to the transcript. Returns `ciphertext || tag`.
pub fn seal(key: &Key, plaintext: &[u8]) -> Vec<u8> {
    let mut out = plaintext.to_vec();
    let tag = ChaCha20Poly1305::new(&(*key).into())
        .encrypt_inout_detached(&[0; 12].into(), &[], out.as_mut_slice().into())
        .expect("payload length within ChaCha20-Poly1305 limits");
    out.extend_from_slice(&tag);
    out
}

/// The inverse of [`seal`]; `None` if the tag does not verify.
pub fn open(key: &Key, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let at = sealed.len().checked_sub(TAG_LEN)?;
    let (ciphertext, tag) = sealed.split_at(at);
    let tag: [u8; TAG_LEN] = tag.try_into().ok()?;
    let mut out = Zeroizing::new(ciphertext.to_vec());
    ChaCha20Poly1305::new(&(*key).into())
        .decrypt_inout_detached(&[0; 12].into(), &[], out.as_mut_slice().into(), &tag.into())
        .ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn hkdf_matches_rfc5869_case_1() {
        let okm = hkdf::<42>(
            &hex("000102030405060708090a0b0c"),
            &[0x0b; 22],
            &hex("f0f1f2f3f4f5f6f7f8f9"),
        );
        assert_eq!(
            okm.as_slice(),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )
        );
    }

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        let key = random::<KEY_LEN>();
        let sealed = seal(&key, b"hello");
        assert_eq!(sealed.len(), 5 + TAG_LEN);
        assert_ne!(&sealed[..5], b"hello");
        assert_eq!(
            open(&key, &sealed).as_deref().map(Vec::as_slice),
            Some(&b"hello"[..])
        );

        for at in [0, 4, 5, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[at] ^= 1;
            assert!(open(&key, &tampered).is_none(), "flip at {at}");
        }
        assert!(open(&random::<KEY_LEN>(), &sealed).is_none());
        assert!(open(&key, &sealed[..TAG_LEN - 1]).is_none());
        assert_eq!(open(&key, &seal(&key, b"")).map(|p| p.len()), Some(0));
    }
}
