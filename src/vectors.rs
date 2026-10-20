//! Test vectors: one handshake per invitation mode with every random value fixed, written to
//! `vectors/v0*.json` with its inputs, intermediate values, messages and outputs, so another
//! implementation can check itself byte by byte. The intermediate values are recomputed here
//! from the messages, apart from the code that produced them.
//!
//! `vectors/v0-negative.json` holds messages and times that must be refused, each one change away
//! from those handshakes.
//!
//! `NACHALO_WRITE_VECTORS=1 cargo test vectors` rewrites the files; otherwise they are checked.

use std::ops::Range;

use libcrux_ml_kem::mlkem768;
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
const NOW: Clock = Clock {
    now: 1000,
    now_unix: NOW_UNIX,
};

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

fn initiator_random() -> InitiatorRandom {
    InitiatorRandom {
        sid: fixed("initiator sid"),
        cpace: fixed("initiator cpace"),
        x25519: fixed("initiator x25519"),
        ml_kem: fixed("initiator ml-kem"),
        nonce: fixed("initiator nonce"),
    }
}

fn responder_random() -> ResponderRandom {
    ResponderRandom {
        cpace: fixed("responder cpace"),
        x25519: fixed("responder x25519"),
        ml_kem: fixed("responder ml-kem"),
    }
}

fn generate(invitation: &Invitation, inputs: Value) -> Value {
    let (ir, rr) = (initiator_random(), responder_random());
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
        mlkem768::generate_key_pair(ir.ml_kem).into_parts().0,
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
    let ss_kem = mlkem768::decapsulate(&dk, &msg2[CT_AT..SEALED_B_AT].try_into().unwrap());
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
    generate(
        &Invitation::live(WORDS, CONTEXT, &Config::default()).unwrap(),
        inputs,
    )
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
    let invitation =
        Invitation::appointment(WORDS_A, WORDS_B, AT, CONTEXT, NOW_UNIX, &Config::default())
            .unwrap();
    generate(&invitation, inputs)
}

fn fixed_token() -> [u8; TOKEN_LEN] {
    let mut token = [0u8; TOKEN_LEN];
    token[..TOKEN_SECRET_LEN].copy_from_slice(&fixed::<TOKEN_SECRET_LEN>("physical token secret"));
    token[TOKEN_SECRET_LEN..].copy_from_slice(&(AT + 3600).to_be_bytes());
    token
}

fn token() -> Value {
    let token = fixed_token();
    let inputs = json!({
        "words": WORDS,
        "token": h(&token),
        "now_unix": NOW_UNIX,
        "context": h(CONTEXT),
        "payload_a": h(PAYLOAD_A),
        "payload_b": h(PAYLOAD_B),
    });
    generate(
        &Invitation::physical_token(WORDS, &token, CONTEXT, NOW_UNIX, &Config::default()).unwrap(),
        inputs,
    )
}

/// `msg` with `range` replaced by `bytes`.
fn edit(msg: &[u8], range: Range<usize>, bytes: &[u8]) -> Vec<u8> {
    let mut out = msg.to_vec();
    out.splice(range, bytes.iter().copied());
    out
}

fn negative() -> Value {
    // Decodes to no ristretto255 point: draft-irtf-cfrg-cpace-21, appendix B.3.11.
    let not_a_point =
        hex::decode("2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c").unwrap();
    let config = Config::default();
    let invitation = Invitation::live(WORDS, CONTEXT, &config).unwrap();
    let start = || Initiator::start_with(&invitation, PAYLOAD_A, NOW, initiator_random()).unwrap();
    let respond = |msg1: &[u8]| {
        Responder::respond_with(&invitation, msg1, PAYLOAD_B, NOW, responder_random())
    };
    let (_, msg1) = start();
    let (b, msg2) = respond(&msg1).unwrap();
    let (_, msg3) = start().0.finish(&msg2, NOW).unwrap();
    let mut other_payload = start().0;
    other_payload.payload = Zeroizing::new(b"not the committed payload".to_vec());
    let (_, broken) = other_payload.finish(&msg2, NOW).unwrap();
    let flip_last = |msg: &[u8]| edit(msg, msg.len() - 1..msg.len(), &[msg[msg.len() - 1] ^ 1]);

    let messages = [
        (
            "msg1 one byte short",
            "respond",
            msg1[..MSG1_LEN - 1].to_vec(),
        ),
        (
            "msg1 Ya not a point",
            "respond",
            edit(&msg1, YA_AT..XA_AT, &not_a_point),
        ),
        (
            "msg1 Ya the identity",
            "respond",
            edit(&msg1, YA_AT..XA_AT, &[0; 32]),
        ),
        (
            "msg1 Xa of low order",
            "respond",
            edit(&msg1, XA_AT..COMMIT_AT, &[0; 32]),
        ),
        // The first coefficient of ek becomes 4095, not reduced mod q = 3329.
        (
            "msg1 ek fails the FIPS 203 check",
            "respond",
            edit(&msg1, EK_AT..EK_AT + 2, &[0xff; 2]),
        ),
        (
            "msg2 one byte short",
            "finish_a",
            msg2[..msg2_len(0) - 1].to_vec(),
        ),
        (
            "msg2 Yb not a point",
            "finish_a",
            edit(&msg2, 0..XB_AT, &not_a_point),
        ),
        (
            "msg2 Xb of low order",
            "finish_a",
            edit(&msg2, XB_AT..CT_AT, &[0; 32]),
        ),
        ("msg2 tag flipped", "finish_a", flip_last(&msg2)),
        (
            "msg3 one byte short",
            "finish_b",
            msg3[..msg3_len(0) - 1].to_vec(),
        ),
        ("msg3 tag flipped", "finish_b", flip_last(&msg3)),
        (
            "msg3 opens to a payload msg1 did not commit to",
            "finish_b",
            broken,
        ),
    ];
    let mut cases: Vec<Value> = messages
        .into_iter()
        .map(|(name, step, msg)| {
            let error = match step {
                "respond" => respond(&msg).err(),
                "finish_a" => start().0.finish(&msg, NOW).err(),
                _ => b.finish(&msg, NOW).err(),
            };
            assert_eq!(error, Some(Error::Rejected), "{name}");
            json!({ "name": name, "mode": "live", "step": step, "message": h(&msg), "error": "rejected" })
        })
        .collect();

    let window = config.appointment_window.as_secs();
    for (name, now_unix) in [
        ("appointment before its window", AT - 1),
        ("appointment after its window", AT + window + 1),
    ] {
        let built = Invitation::appointment(WORDS_A, WORDS_B, AT, CONTEXT, now_unix, &config);
        assert_eq!(built.err(), Some(Error::Expired), "{name}");
        cases.push(json!({ "name": name, "mode": "appointment", "step": "invitation", "now_unix": now_unix, "error": "expired" }));
    }
    let now_unix = AT + 3601;
    let built = Invitation::physical_token(WORDS, &fixed_token(), CONTEXT, now_unix, &config);
    assert_eq!(built.err(), Some(Error::Expired));
    cases.push(json!({ "name": "physical token past its expiry", "mode": "physical-token", "step": "invitation", "now_unix": now_unix, "error": "expired" }));

    json!({
        "protocol": String::from_utf8_lossy(PROTOCOL),
        "about": "Each case must fail at its step. Message cases start from v0.json: `respond` is B \
                  answering the message with v0.json's responder random values, `finish_a` is A, \
                  started with v0.json's initiator random values, receiving it as msg2, and \
                  `finish_b` is B, after answering v0.json's msg1, receiving it as msg3. \
                  `invitation` cases build the invitation of v0-appointment.json or \
                  v0-physical-token.json at `now_unix`, with the default appointment_window of \
                  1800 seconds. Byte strings are hex.",
        "cases": cases,
    })
}

#[test]
fn vectors() {
    let modes = [
        ("v0.json", live as fn() -> Value),
        ("v0-appointment.json", appointment),
        ("v0-physical-token.json", token),
        ("v0-negative.json", negative),
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
