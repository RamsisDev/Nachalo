//! CPace in the initiator-responder setting, suite CPACE-RISTR255-SHA512, exactly as in
//! draft-irtf-cfrg-cpace-21 (sections 6 to 8.3 and appendix A). The draft's test vectors for
//! this suite (appendix B.3) are checked below, so any other implementation of the draft
//! interoperates.
//!
//! Only what Nachalo needs is here: the generator, scalar sampling, the public share and the
//! intermediate session key ISK. K never leaves this module (draft section 10.3).

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

pub const DSI: &[u8] = b"CPaceRistretto255";
const DSI_ISK: &[u8] = b"CPaceRistretto255_ISK";
/// SHA-512 input block size.
const S_IN_BYTES: usize = 128;
pub const SHARE_LEN: usize = 32;
pub const ISK_LEN: usize = 64;

/// LEB128 length followed by the data.
pub fn prepend_len(out: &mut Vec<u8>, data: &[u8]) {
    let mut len = data.len();
    loop {
        let byte = (len & 0x7f) as u8;
        len >>= 7;
        if len == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
    out.extend_from_slice(data);
}

pub fn lv_cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        prepend_len(&mut out, part);
    }
    out
}

/// `len(prepend_len(data))` for data of `len` bytes.
fn prepended_len(len: usize) -> usize {
    let mut n = len;
    let mut bytes = 1;
    while n >= 0x80 {
        n >>= 7;
        bytes += 1;
    }
    bytes + len
}

/// `lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)`, padded so DSI and PRS fill the first block.
fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Zeroizing<Vec<u8>> {
    let len_zpad =
        S_IN_BYTES.saturating_sub(1 + prepended_len(prs.len()) + prepended_len(DSI.len()));
    Zeroizing::new(lv_cat(&[DSI, prs, &vec![0; len_zpad], ci, sid]))
}

/// The secret generator. Whoever learns it can test password guesses offline.
pub fn generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    let hash = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(&*generator_string(
        prs, ci, sid,
    ))));
    RistrettoPoint::from_uniform_bytes(&hash)
}

/// `G.sample_scalar()` from 32 uniform bytes: the bits above the 252nd are cleared.
pub fn scalar(mut bytes: [u8; 32]) -> Scalar {
    bytes[31] &= 0x0f;
    let y = Scalar::from_bytes_mod_order(bytes);
    zeroize::Zeroize::zeroize(&mut bytes);
    y
}

/// `G.scalar_mult(y, g)`: the public share.
pub fn share(y: &Scalar, generator: &RistrettoPoint) -> [u8; SHARE_LEN] {
    (generator * y).compress().to_bytes()
}

/// `transcript_ir(Ya, ADa, Yb, ADb)`.
pub fn transcript_ir(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
    let mut out = lv_cat(&[ya, ada]);
    out.extend(lv_cat(&[yb, adb]));
    out
}

/// `K = G.scalar_mult_vfy(y, theirs)`, then `ISK = H(lv_cat(DSI_ISK, sid, K) || transcript)`.
/// `None` where the draft aborts: `theirs` does not decode, or K is the neutral element.
pub fn isk(
    y: &Scalar,
    theirs: &[u8; SHARE_LEN],
    sid: &[u8],
    transcript: &[u8],
) -> Option<Zeroizing<[u8; ISK_LEN]>> {
    let point = CompressedRistretto(*theirs).decompress()?;
    let k = point * y;
    if k.is_identity() {
        return None;
    }
    let k = Zeroizing::new(k.compress().to_bytes());
    let mut prefix = Zeroizing::new(lv_cat(&[DSI_ISK, sid, &*k]));
    prefix.extend_from_slice(transcript);
    Some(Zeroizing::new(Sha512::digest(&*prefix).into()))
}

#[cfg(test)]
mod tests {
    //! Appendix B.3 of draft-irtf-cfrg-cpace-21, and the string functions of appendix A.

    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }

    fn array<const N: usize>(s: &str) -> [u8; N] {
        hex(s).try_into().unwrap()
    }

    const PRS: &[u8] = b"Password";
    const CI: &str = "0b415f696e69746961746f720b425f726573706f6e646572";
    const SID: &str = "7e4b4791d6a8ef019b936c79fb7f2c57";
    const YA: &str = "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08";
    const YB: &str = "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d";
    const SHARE_A: &str = "d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157";
    const SHARE_B: &str = "3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258";

    #[test]
    fn string_functions_match_appendix_a() {
        assert_eq!(lv_cat(&[b""]), hex("00"));
        assert_eq!(lv_cat(&[b"1234"]), hex("0431323334"));
        let long: Vec<u8> = (0..128).collect();
        assert_eq!(&lv_cat(&[&long])[..3], hex("800100"));
        assert_eq!(lv_cat(&[&long[..127]])[0], 0x7f);
        assert_eq!(
            lv_cat(&[b"1234", b"5", b"", b"678"]),
            hex("043132333401350003363738")
        );
        assert_eq!(
            transcript_ir(b"123", b"PartyA", b"234", b"PartyB"),
            hex("03313233065061727479410332333406506172747942")
        );
        for len in [0, 1, 127, 128, 16383, 16384] {
            let mut out = Vec::new();
            prepend_len(&mut out, &vec![0; len]);
            assert_eq!(prepended_len(len), out.len(), "len {len}");
        }
    }

    #[test]
    fn generator_matches_b_3_1() {
        let gen_str = generator_string(PRS, &hex(CI), &hex(SID));
        assert_eq!(
            *gen_str,
            hex("11435061636552697374726574746f3235350850617373776f726464
                 00000000000000000000000000000000000000000000000000000000
                 00000000000000000000000000000000000000000000000000000000
                 00000000000000000000000000000000000000000000000000000000
                 00000000000000000000000000000000180b415f696e69746961746f
                 720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f
                 2c57")
        );
        assert_eq!(
            Sha512::digest(&*gen_str).to_vec(),
            hex("da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288
                 b6663af06bf645c93cd1c51512307199c80e84908916d983b34af772
                 05f90851a657ee27")
        );
        assert_eq!(
            generator(PRS, &hex(CI), &hex(SID))
                .compress()
                .to_bytes()
                .to_vec(),
            hex("222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56")
        );
    }

    #[test]
    fn shares_and_isk_match_b_3_2_to_b_3_5() {
        let g = generator(PRS, &hex(CI), &hex(SID));
        let (ya, yb) = (scalar(array(YA)), scalar(array(YB)));
        let (share_a, share_b) = (share(&ya, &g), share(&yb, &g));
        assert_eq!(share_a, array(SHARE_A));
        assert_eq!(share_b, array(SHARE_B));

        let transcript = transcript_ir(&share_a, b"ADa", &share_b, b"ADb");
        assert_eq!(
            transcript,
            hex("20d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0e
                 ec482b915703414461203ea7e0b19560d7c0b0f5734f63b955286dfa
                 8232b5ebe63324e2d9e7433f725803414462")
        );
        let expected = hex("b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dc
             ae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c
             3fa2068af7900447");
        let at_a = isk(&ya, &share_b, &hex(SID), &transcript).unwrap();
        let at_b = isk(&yb, &share_a, &hex(SID), &transcript).unwrap();
        assert_eq!(at_a.to_vec(), expected);
        assert_eq!(at_b.to_vec(), expected);
    }

    #[test]
    fn invalid_shares_abort_as_in_b_3_11() {
        let s = scalar(array(
            "7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05",
        ));
        let valid: [u8; 32] =
            array("2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");
        let not_a_point: [u8; 32] =
            array("2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");
        let point = CompressedRistretto(valid).decompress().unwrap();
        assert_eq!(
            (point * s).compress().to_bytes().to_vec(),
            hex("7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e")
        );
        assert!(isk(&s, &valid, b"", b"").is_some());
        assert!(isk(&s, &not_a_point, b"", b"").is_none());
        assert!(isk(&s, &[0; 32], b"", b"").is_none());
    }
}
