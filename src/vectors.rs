//! Test vectors: one handshake per invitation mode with every random value fixed, written to
//! `vectors/v0*.json` with its inputs, intermediate values, messages and outputs, so another
//! implementation can check itself byte by byte. The intermediate values are recomputed here
//! from the messages, apart from the code that produced them.
//!
//! `NACHALO_WRITE_VECTORS=1 cargo test vectors` rewrites the files; otherwise they are checked.

use ml_kem::{Decapsulate, DecapsulationKey768};
use serde_json::{Value, json};
use sha2::{Digest, Sha512};
use x25519_dalek::StaticSecret;

use super::*;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/");
const WORDS: &str = "alpha cable echo forest orbit velvet";
const WORDS_A: &str = "alpha cable echo forest orbit";
const WORDS_B: &str = "velvet stone happy river";
/// Wall clock, for the appointment window and the physical token's expiry.
const AT: u64 = 1_900_000_000;
const NOW_UNIX: u64 = AT + 60;
const CONTEXT: &[u8] = b"nachalo test vectors";
const PAYLOAD_A: &[u8] = b"payload from the initiator";
const PAYLOAD_B: &[u8] = b"payload from the responder";
const EXPORT_LABEL: &[u8] = b"example";
const NOW: u64 = 1000;

/// Random-looking bytes anyone can reproduce: SHA-512 of a label, as many blocks as needed.
fn fixed<const N: usize>(label: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, chunk) in out.chunks_mut(64).enumerate() {
        let block = Sha512::digest(format!("Nachalo v0 test vector: {label} {i}"));
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
    out
}

fn h(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

fn generate(invitation: &Invitation, inputs: Value) -> Value {
    let ir = InitiatorRandom {
        sid: fixed("initiator sid"),
        cpace: fixed("initiator cpace"),
        x25519: fixed("initiator x25519"),
        ml_kem: fixed("initiator ml-kem"),
        nonce: fixed("initiator nonce"),
    };
    let rr = ResponderRandom {
        cpace: fixed("responder cpace"),
        x25519: fixed("responder x25519"),
        ml_kem: fixed("responder ml-kem"),
    };
    let random = json!({
        "initiator": {
            "sid": h(&ir.sid),
            "cpace_scalar": h(&ir.cpace),
            "x25519_secret": h(&ir.x25519),
            "ml_kem_seed_d_z": h(&ir.ml_kem),
            "commitment_nonce": h(&ir.nonce),
        },
        "responder": {
            "cpace_scalar": h(&rr.cpace),
            "x25519_secret": h(&rr.x25519),
            "ml_kem_m": h(&rr.ml_kem),
        },
    });
    let (ya, xa, dk) = (
        cpace::scalar(ir.cpace),
        StaticSecret::from(ir.x25519),
        DecapsulationKey768::from_seed(ir.ml_kem.into()),
    );

    let (mut a, msg1) = Initiator::start_with(invitation, PAYLOAD_A, NOW, ir).unwrap();
    let (b, msg2) = Responder::respond_with(invitation, &msg1, PAYLOAD_B, NOW, rr).unwrap();
    let (a, msg3) = a.finish(&msg2, NOW).unwrap();
    let b = b.finish(&msg3, NOW).unwrap();
    let safety_words = b.safety_words();
    let safety = b.safety;
    let a = a.verify(&safety_words, NOW).unwrap();
    let b = b.confirm(NOW).unwrap();
    assert_eq!(a.key(), b.key());
    assert_eq!((a.peer_payload(), b.peer_payload()), (PAYLOAD_B, PAYLOAD_A));

    // Recomputed from the messages and A's secrets.
    let sid = &msg1[..YA_AT];
    let (prs, ci) = (&invitation.prs, &invitation.channel);
    let generator = cpace::generator(prs, ci, sid);
    let yb: [u8; SHARE_LEN] = msg2[..XB_AT].try_into().unwrap();
    let transcript_ir = cpace::transcript_ir(
        &msg1[YA_AT..XA_AT],
        &msg1[XA_AT..],
        &yb,
        &msg2[XB_AT..SEALED_B_AT],
    );
    let isk = cpace::isk(&ya, &yb, sid, &transcript_ir).unwrap();
    let ss_x = xa.diffie_hellman(&public(&msg2[XB_AT..CT_AT]));
    let ss_kem = dk.decapsulate(msg2[CT_AT..SEALED_B_AT].try_into().unwrap());
    let ikm: [u8; IKM_LEN] = [&isk[..], &ss_x.as_bytes()[..], &ss_kem[..]]
        .concat()
        .try_into()
        .unwrap();
    let t1 = Transcript::new(&msg1);
    let (t_b, t_a) = (t1.with(&msg2[..SEALED_B_AT]), t1.with(&msg2));
    let t = t_a.with(&msg3);
    let nonce = fixed::<NONCE_LEN>("initiator nonce");
    assert_eq!(msg1[COMMIT_AT..EK_AT], commitment(&nonce, PAYLOAD_A));

    json!({
        "protocol": String::from_utf8_lossy(PROTOCOL),
        "cpace": "CPACE-RISTR255-SHA512, draft-irtf-cfrg-cpace-21, initiator-responder",
        "about": "Every random value is fixed. Feed the inputs and random values to both roles \
                  and compare every intermediate value, message and output. Byte strings are hex.",
        "inputs": inputs,
        "random": random,
        "intermediate": {
            "rendezvous": h(&invitation.rendezvous()),
            "cpace_prs": h(prs),
            "cpace_ci": h(ci),
            "cpace_generator": h(generator.compress().as_bytes()),
            "cpace_transcript_ir": h(&transcript_ir),
            "cpace_isk": h(&*isk),
            "x25519_shared": h(ss_x.as_bytes()),
            "ml_kem_shared": h(&ss_kem),
            "ikm": h(&ikm),
            "commitment": h(&msg1[COMMIT_AT..EK_AT]),
            "transcript_b": h(&t_b.hash()),
            "seal_key_b": h(&*key(&t_b, &ikm, LABEL_SEAL_B)),
            "transcript_a": h(&t_a.hash()),
            "seal_key_a": h(&*key(&t_a, &ikm, LABEL_SEAL_A)),
            "transcript": h(&t.hash()),
            "safety": h(&safety),
        },
        "messages": {
            "msg1": h(&msg1),
            "msg2": h(&msg2),
            "msg3": h(&msg3),
        },
        "outputs": {
            "key": h(a.key()),
            "transcript": h(a.transcript()),
            "safety_words": &*safety_words,
            "export_label": h(EXPORT_LABEL),
            "export": h(&*a.export(EXPORT_LABEL)),
        },
    })
}

fn live() -> Value {
    let inputs = json!({
        "words": WORDS,
        "context": h(CONTEXT),
        "payload_a": h(PAYLOAD_A),
        "payload_b": h(PAYLOAD_B),
    });
    generate(&Invitation::live(WORDS, CONTEXT).unwrap(), inputs)
}

fn appointment() -> Value {
    let inputs = json!({
        "words_a": WORDS_A,
        "words_b": WORDS_B,
        "at": AT,
        "now_unix": NOW_UNIX,
        "context": h(CONTEXT),
        "payload_a": h(PAYLOAD_A),
        "payload_b": h(PAYLOAD_B),
    });
    let invitation = Invitation::appointment(WORDS_A, WORDS_B, AT, CONTEXT, NOW_UNIX).unwrap();
    generate(&invitation, inputs)
}

fn token() -> Value {
    let mut token = [0u8; TOKEN_LEN];
    token[..TOKEN_SECRET_LEN].copy_from_slice(&fixed::<TOKEN_SECRET_LEN>("physical token secret"));
    token[TOKEN_SECRET_LEN..].copy_from_slice(&(AT + 3600).to_be_bytes());
    let inputs = json!({
        "words": WORDS,
        "token": h(&token),
        "now_unix": NOW_UNIX,
        "context": h(CONTEXT),
        "payload_a": h(PAYLOAD_A),
        "payload_b": h(PAYLOAD_B),
    });
    generate(
        &Invitation::physical_token(WORDS, &token, CONTEXT, NOW_UNIX).unwrap(),
        inputs,
    )
}

#[test]
fn vectors() {
    let modes = [
        ("v0.json", live as fn() -> Value),
        ("v0-appointment.json", appointment),
        ("v0-physical-token.json", token),
    ];
    for (file, generate) in modes {
        let path = format!("{DIR}{file}");
        let generated = generate();
        assert_eq!(
            generated,
            generate(),
            "{file}: the vectors are not deterministic"
        );
        if std::env::var_os("NACHALO_WRITE_VECTORS").is_some() {
            let text = serde_json::to_string_pretty(&generated).unwrap() + "\n";
            std::fs::write(&path, text).unwrap();
            continue;
        }
        let stored: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            stored, generated,
            "vectors/{file} is stale: an incompatible change needs a new protocol version"
        );
    }
}
