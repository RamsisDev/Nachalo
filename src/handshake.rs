//! Three-message handshake: CPace + X25519 + ML-KEM-768, with a payload each way.
//!
//! ```text
//! msg1 A->B | sid 16 | cpace Ya 32 | x25519 Xa 32 | commitment 32 | ml-kem key 1184 |
//! msg2 B->A | cpace Yb 32 | x25519 Xb 32 | ml-kem ciphertext 1088 | sealed payload_b |
//! msg3 A->B | sealed (nonce 32 | payload_a) |
//! ```
//!
//! The invitation's secret (its words, plus the token in that mode) is only the CPace password.
//! The rest of each CPace message is CPace's associated data, so ISK authenticates both messages
//! whole. The keys come from `ikm = ISK || ss_x25519 || ss_mlkem`, so breaking them needs all three.
//!
//! Each payload is sealed under a key from the transcript so far, and its tag is that side's key
//! confirmation. A failed `finish` leaves its state usable, so a third party's bogus answer
//! cannot kill a handshake; A takes at most [`MAX_ANSWERS`] wrong ones.
//!
//! Someone who has the words can still sit in the middle. The 4 safety words, derived from the
//! whole transcript, catch it: B shows them and A must type them. msg1 commits to a random nonce
//! that msg3 reveals, which keeps such a man in the middle from grinding either session until
//! both sides' words match: when it must fix its msg2 to A, A's nonce is still hidden.
//!
//! The context both sides pass joins the words in CPace's channel identifier, so different
//! applications or networks derive different keys and never complete the handshake. It never
//! travels on the wire.
//!
//! An [`Invitation`] holds what the words, and in the other modes the appointment time or the
//! physical token, turn into: the CPace password and channel identifier, the rendezvous id and
//! how long a step may stay pending. The messages are the same in every mode.

use curve25519_dalek::scalar::Scalar;
use ml_kem::{Decapsulate, DecapsulationKey768, EncapsulationKey768, KeyExport};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::cpace::{self, SHARE_LEN};
use crate::crypto::{self, CT_LEN, EK_LEN, KEY_LEN, Key, TAG_LEN};
use crate::words::{
    APPOINTMENT_WORDS_A, APPOINTMENT_WORDS_B, WORD_COUNT, normalize, spells, to_words,
};

/// Domain separation for everything Nachalo derives. Changes with every incompatible version.
pub const PROTOCOL: &[u8] = b"Nachalo v0";
/// A pending handshake step dies this many seconds after it started, on its own device's
/// clock. No time travels on the wire, so the two devices' clocks never need to agree.
pub const INVITE_TTL: u64 = 600;
/// Wrong msg2 an initiator takes before it gives up. Each one is an online guess at the words.
pub const MAX_ANSWERS: u8 = 64;
/// Largest payload either side may send.
pub const MAX_PAYLOAD: usize = 1024;
/// Two bytes per safety word, 11 bits used: 4 words, 44 bits. Someone in the middle who gets
/// B to answer `q` msg1 matches them with probability `q * 2^-44`.
pub const SAFETY_LEN: usize = 8;
pub const RENDEZVOUS_LEN: usize = 32;
/// Bytes of the words' hash the rendezvous id is derived from. Whoever watches that id learns at
/// most these 24 bits of the words, and each answer is still a single online guess at the
/// other 42.
const RENDEZVOUS_TAG_LEN: usize = 3;
/// The same for an appointment, from A's words only. Every appointment slot has its own ids, so
/// fewer bits keep unrelated invitations apart: whoever watches the id learns at most 16 of A's
/// 55 bits and nothing about B's 44.
const APPOINTMENT_TAG_LEN: usize = 2;
/// An appointment can be answered from its start time until this many seconds later, wall clock.
pub const APPOINTMENT_WINDOW: u64 = 1800;
/// A physical token: a 32-byte secret, then the last second it is valid as a big-endian Unix
/// time.
pub const TOKEN_LEN: usize = 40;
const TOKEN_SECRET_LEN: usize = 32;

const SID_LEN: usize = 16;
const DH_LEN: usize = 32;
const NONCE_LEN: usize = 32;

const YA_AT: usize = SID_LEN;
const XA_AT: usize = YA_AT + SHARE_LEN;
const COMMIT_AT: usize = XA_AT + DH_LEN;
const EK_AT: usize = COMMIT_AT + KEY_LEN;
pub const MSG1_LEN: usize = EK_AT + EK_LEN;

const XB_AT: usize = SHARE_LEN;
const CT_AT: usize = XB_AT + DH_LEN;
const SEALED_B_AT: usize = CT_AT + CT_LEN;

/// msg2 length for a responder payload of `payload` bytes.
pub const fn msg2_len(payload: usize) -> usize {
    SEALED_B_AT + payload + TAG_LEN
}

/// msg3 length for an initiator payload of `payload` bytes.
pub const fn msg3_len(payload: usize) -> usize {
    NONCE_LEN + payload + TAG_LEN
}

const LABEL_RENDEZVOUS_TAG: &[u8] = b"Nachalo v0 rendezvous tag";
const LABEL_RENDEZVOUS: &[u8] = b"Nachalo v0 rendezvous";
const LABEL_COMMIT: &[u8] = b"Nachalo v0 commit";
const LABEL_SEAL_B: &[u8] = b"Nachalo v0 seal b";
const LABEL_SEAL_A: &[u8] = b"Nachalo v0 seal a";
const LABEL_KEY: &[u8] = b"Nachalo v0 key";
const LABEL_SAFETY: &[u8] = b"Nachalo v0 safety";
const LABEL_EXPORT: &[u8] = b"Nachalo v0 export";
const LABEL_APPOINTMENT: &[u8] = b"Nachalo v0 appointment";
const LABEL_TOKEN: &[u8] = b"Nachalo v0 physical token";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Not the expected number of words from the list.
    BadWords,
    /// Past its deadline, out of answers, already finished, or outside the window of its
    /// appointment or physical token.
    Expired,
    /// More than [`MAX_PAYLOAD`] bytes.
    PayloadTooLarge,
    /// Malformed input or failed confirmation, with no further detail.
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// A: holds the words first, sends msg1 and msg3, types the safety words.
    Initiator,
    /// B: received the words, sends msg2, shows the safety words.
    Responder,
}

/// What both sides derive from the shared secret of one invitation, in one of three modes:
/// [`live`](Invitation::live), [`appointment`](Invitation::appointment) or
/// [`physical_token`](Invitation::physical_token). Both sides must build it from the same inputs.
pub struct Invitation {
    /// The CPace password.
    prs: Zeroizing<Vec<u8>>,
    /// The CPace channel identifier.
    channel: Vec<u8>,
    rendezvous: [u8; RENDEZVOUS_LEN],
    /// How long a step started from this invitation may stay pending.
    ttl: u64,
}

impl Invitation {
    /// Live first contact: A draws [`WORD_COUNT`] words and both sides take part within
    /// [`INVITE_TTL`].
    pub fn live(words: &str, context: &[u8]) -> Result<Self, Error> {
        let words = normalize(words, WORD_COUNT).ok_or(Error::BadWords)?;
        let tag =
            crypto::hkdf::<RENDEZVOUS_TAG_LEN>(context, words.as_bytes(), LABEL_RENDEZVOUS_TAG);
        Ok(Invitation {
            prs: Zeroizing::new(words.as_bytes().to_vec()),
            channel: cpace::lv_cat(&[PROTOCOL, context]),
            rendezvous: *crypto::hkdf(context, &*tag, LABEL_RENDEZVOUS),
            ttl: INVITE_TTL,
        })
    }

    /// First contact at an agreed time: A draws [`APPOINTMENT_WORDS_A`] words, B draws
    /// [`APPOINTMENT_WORDS_B`], and they swap them along with `at`, the Unix time in seconds
    /// when the appointment starts. Each side must build it, start and answer within
    /// [`APPOINTMENT_WINDOW`] seconds from `at` on `now_unix`, its wall clock, and the whole
    /// handshake, safety words included, must end by then. Invitations for another `at` never
    /// complete.
    pub fn appointment(
        words_a: &str,
        words_b: &str,
        at: u64,
        context: &[u8],
        now_unix: u64,
    ) -> Result<Self, Error> {
        let a = normalize(words_a, APPOINTMENT_WORDS_A).ok_or(Error::BadWords)?;
        let b = normalize(words_b, APPOINTMENT_WORDS_B).ok_or(Error::BadWords)?;
        let end = at.saturating_add(APPOINTMENT_WINDOW);
        if now_unix < at || now_unix > end {
            return Err(Error::Expired);
        }
        let channel = cpace::lv_cat(&[PROTOCOL, context, LABEL_APPOINTMENT, &at.to_be_bytes()]);
        let tag = crypto::hkdf::<APPOINTMENT_TAG_LEN>(&channel, a.as_bytes(), LABEL_RENDEZVOUS_TAG);
        Ok(Invitation {
            prs: Zeroizing::new(cpace::lv_cat(&[a.as_bytes(), b.as_bytes()])),
            rendezvous: *crypto::hkdf(&channel, &*tag, LABEL_RENDEZVOUS),
            channel,
            ttl: INVITE_TTL.min(end - now_unix),
        })
    }

    /// First contact through a physical token: bytes from [`new_physical_token`] that A hands B
    /// in person on something B's device reads, along with [`WORD_COUNT`] words A gives B another
    /// way. B starts the handshake and A answers. Each side must build it, start and answer by
    /// the expiry the token carries, on `now_unix`, its wall clock.
    pub fn physical_token(
        words: &str,
        token: &[u8; TOKEN_LEN],
        context: &[u8],
        now_unix: u64,
    ) -> Result<Self, Error> {
        let words = normalize(words, WORD_COUNT).ok_or(Error::BadWords)?;
        let expires =
            u64::from_be_bytes(token[TOKEN_SECRET_LEN..].try_into().expect("fixed layout"));
        if now_unix > expires {
            return Err(Error::Expired);
        }
        let channel = cpace::lv_cat(&[PROTOCOL, context, LABEL_TOKEN]);
        // The token's secret cannot be guessed, so the id comes from all of it.
        Ok(Invitation {
            prs: Zeroizing::new(cpace::lv_cat(&[words.as_bytes(), token])),
            rendezvous: *crypto::hkdf(&channel, token, LABEL_RENDEZVOUS),
            channel,
            ttl: INVITE_TTL.min(expires - now_unix),
        })
    }

    /// Public id where the side that starts leaves msg1 and the other looks for it, for the
    /// application to map onto its transport. Unrelated invitations may share it. Its bytes look
    /// random, but a live invitation has only 2^24 ids per context and an appointment 2^16 per
    /// context and start time, so whoever lists them all still recognizes one. The id of a physical
    /// token comes from its secret and cannot be listed.
    pub fn rendezvous(&self) -> [u8; RENDEZVOUS_LEN] {
        self.rendezvous
    }

    fn deadline(&self, now: u64) -> u64 {
        now.saturating_add(self.ttl)
    }
}

/// A new physical token for A to hand over, valid for `lifetime` seconds from `now_unix`. A keeps
/// it to build its own [`Invitation::physical_token`]; erase it once it expires.
pub fn new_physical_token(lifetime: u64, now_unix: u64) -> Zeroizing<[u8; TOKEN_LEN]> {
    let mut token = Zeroizing::new([0u8; TOKEN_LEN]);
    token[..TOKEN_SECRET_LEN]
        .copy_from_slice(&*Zeroizing::new(crypto::random::<TOKEN_SECRET_LEN>()));
    token[TOKEN_SECRET_LEN..].copy_from_slice(&now_unix.saturating_add(lifetime).to_be_bytes());
    token
}

/// Every random value of an initiator, drawn up front so test vectors can fix them.
pub(crate) struct InitiatorRandom {
    pub sid: [u8; SID_LEN],
    pub cpace: [u8; 32],
    pub x25519: [u8; DH_LEN],
    /// FIPS 203 key generation seed `d || z`.
    pub ml_kem: [u8; 64],
    pub nonce: [u8; NONCE_LEN],
}

impl InitiatorRandom {
    fn new() -> Self {
        Self {
            sid: crypto::random(),
            cpace: crypto::random(),
            x25519: crypto::random(),
            ml_kem: crypto::random(),
            nonce: crypto::random(),
        }
    }
}

impl Drop for InitiatorRandom {
    fn drop(&mut self) {
        self.cpace.zeroize();
        self.x25519.zeroize();
        self.ml_kem.zeroize();
        self.nonce.zeroize();
    }
}

pub(crate) struct ResponderRandom {
    pub cpace: [u8; 32],
    pub x25519: [u8; DH_LEN],
    /// FIPS 203 encapsulation randomness `m`.
    pub ml_kem: [u8; 32],
}

impl ResponderRandom {
    fn new() -> Self {
        Self {
            cpace: crypto::random(),
            x25519: crypto::random(),
            ml_kem: crypto::random(),
        }
    }
}

impl Drop for ResponderRandom {
    fn drop(&mut self) {
        self.cpace.zeroize();
        self.x25519.zeroize();
        self.ml_kem.zeroize();
    }
}

/// The messages so far, length-prefixed after [`PROTOCOL`]; its hash is the transcript hash.
#[derive(Clone)]
struct Transcript(Vec<u8>);

impl Transcript {
    fn new(msg1: &[u8]) -> Self {
        Self(cpace::lv_cat(&[PROTOCOL, msg1]))
    }

    fn with(&self, msg: &[u8]) -> Self {
        let mut next = self.clone();
        cpace::prepend_len(&mut next.0, msg);
        next
    }

    fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.0).into()
    }
}

const IKM_LEN: usize = cpace::ISK_LEN + 2 * KEY_LEN;
type Ikm = Zeroizing<[u8; IKM_LEN]>;

pub struct Initiator {
    y: Zeroizing<Scalar>,
    x: StaticSecret,
    dk: DecapsulationKey768,
    /// Committed to in msg1, revealed in msg3.
    nonce: Zeroizing<[u8; NONCE_LEN]>,
    payload: Zeroizing<Vec<u8>>,
    msg1: Vec<u8>,
    deadline: u64,
    answers: u8,
    finished: bool,
}

impl Initiator {
    /// Starts the handshake: send msg1 to [`Invitation::rendezvous`]. `now` is in seconds on a
    /// clock of this device only.
    pub fn start(
        invitation: &Invitation,
        payload: &[u8],
        now: u64,
    ) -> Result<(Initiator, Vec<u8>), Error> {
        Self::start_with(invitation, payload, now, InitiatorRandom::new())
    }

    pub(crate) fn start_with(
        invitation: &Invitation,
        payload: &[u8],
        now: u64,
        random: InitiatorRandom,
    ) -> Result<(Initiator, Vec<u8>), Error> {
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        let g = cpace::generator(&invitation.prs, &invitation.channel, &random.sid);
        let y = Zeroizing::new(cpace::scalar(random.cpace));
        let x = StaticSecret::from(random.x25519);
        let dk = DecapsulationKey768::from_seed(random.ml_kem.into());

        let mut msg1 = Vec::with_capacity(MSG1_LEN);
        msg1.extend_from_slice(&random.sid);
        msg1.extend_from_slice(&cpace::share(&y, &g));
        msg1.extend_from_slice(PublicKey::from(&x).as_bytes());
        msg1.extend_from_slice(&commitment(&random.nonce, payload));
        msg1.extend_from_slice(&dk.encapsulation_key().to_bytes());

        let initiator = Initiator {
            y,
            x,
            dk,
            nonce: Zeroizing::new(random.nonce),
            payload: Zeroizing::new(payload.to_vec()),
            msg1: msg1.clone(),
            deadline: invitation.deadline(now),
            answers: 0,
            finished: false,
        };
        Ok((initiator, msg1))
    }

    /// The last second this invitation, safety words included, may complete.
    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Completes the handshake with B's msg2: send msg3 to B, then have the user type the
    /// safety words B shows into [`Unconfirmed::verify`]. A wrong msg2 leaves this invitation
    /// usable until its deadline or [`MAX_ANSWERS`].
    pub fn finish(&mut self, msg2: &[u8], now: u64) -> Result<(Unconfirmed, Vec<u8>), Error> {
        if self.finished || self.answers >= MAX_ANSWERS || now > self.deadline() {
            return Err(Error::Expired);
        }
        let result = self.try_finish(msg2);
        match result {
            Ok(_) => self.finished = true,
            Err(_) => self.answers += 1,
        }
        result
    }

    fn try_finish(&self, msg2: &[u8]) -> Result<(Unconfirmed, Vec<u8>), Error> {
        if !(msg2_len(0)..=msg2_len(MAX_PAYLOAD)).contains(&msg2.len()) {
            return Err(Error::Rejected);
        }
        let (prefix, sealed_b) = msg2.split_at(SEALED_B_AT);
        let yb = prefix[..XB_AT].try_into().expect("fixed layout");
        let ss_x = contributory(self.x.diffie_hellman(&public(&prefix[XB_AT..CT_AT])))?;
        let ss_kem = Zeroizing::new(
            self.dk
                .decapsulate(prefix[CT_AT..].try_into().expect("fixed layout")),
        );
        let ikm = ikm(&self.y, yb, &self.msg1, prefix, &ss_x, &ss_kem)?;

        let transcript = Transcript::new(&self.msg1);
        let key_b = key(&transcript.with(prefix), &ikm, LABEL_SEAL_B);
        let payload_b = crypto::open(&key_b, sealed_b).ok_or(Error::Rejected)?;

        let transcript = transcript.with(msg2);
        let mut plaintext = Zeroizing::new(self.nonce.to_vec());
        plaintext.extend_from_slice(&self.payload);
        let msg3 = crypto::seal(&key(&transcript, &ikm, LABEL_SEAL_A), &plaintext);

        let unconfirmed = Unconfirmed::new(
            Role::Initiator,
            &transcript.with(&msg3),
            &ikm,
            payload_b,
            self.deadline(),
        );
        Ok((unconfirmed, msg3))
    }
}

pub struct Responder {
    ikm: Ikm,
    /// Up to the end of msg2.
    transcript: Transcript,
    /// A's commitment to the nonce and payload msg3 must carry.
    commitment: [u8; KEY_LEN],
    deadline: u64,
}

impl Responder {
    /// Answers `msg1` found at the rendezvous: send msg2 back to A. It carries no time, so an old
    /// invitation is answered too; that is harmless, since only A, holding the words, can
    /// complete it and A drops it after the TTL. Every msg1 answered is an online guess for
    /// whoever sent it, and one more chance for someone in the middle to match the safety words,
    /// so cap how many you answer per invitation; [`MAX_ANSWERS`] keeps that chance at 2^-38.
    pub fn respond(
        invitation: &Invitation,
        msg1: &[u8],
        payload: &[u8],
        now: u64,
    ) -> Result<(Responder, Vec<u8>), Error> {
        Self::respond_with(invitation, msg1, payload, now, ResponderRandom::new())
    }

    pub(crate) fn respond_with(
        invitation: &Invitation,
        msg1: &[u8],
        payload: &[u8],
        now: u64,
        random: ResponderRandom,
    ) -> Result<(Responder, Vec<u8>), Error> {
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::PayloadTooLarge);
        }
        let msg1: &[u8; MSG1_LEN] = msg1.try_into().map_err(|_| Error::Rejected)?;
        let ek = EncapsulationKey768::new(msg1[EK_AT..].try_into().expect("fixed layout"))
            .map_err(|_| Error::Rejected)?;
        let g = cpace::generator(&invitation.prs, &invitation.channel, &msg1[..YA_AT]);
        let y = Zeroizing::new(cpace::scalar(random.cpace));
        let x = StaticSecret::from(random.x25519);
        let ss_x = contributory(x.diffie_hellman(&public(&msg1[XA_AT..COMMIT_AT])))?;
        let (ct, ss_kem) = ek.encapsulate_deterministic(&random.ml_kem.into());
        let ss_kem = Zeroizing::new(ss_kem);

        let mut msg2 = Vec::with_capacity(msg2_len(payload.len()));
        msg2.extend_from_slice(&cpace::share(&y, &g));
        msg2.extend_from_slice(PublicKey::from(&x).as_bytes());
        msg2.extend_from_slice(&ct);
        let ya = msg1[YA_AT..XA_AT].try_into().expect("fixed layout");
        let ikm = ikm(&y, ya, msg1, &msg2, &ss_x, &ss_kem)?;

        let transcript = Transcript::new(msg1);
        let key_b = key(&transcript.with(&msg2), &ikm, LABEL_SEAL_B);
        msg2.extend(crypto::seal(&key_b, payload));

        let responder = Responder {
            ikm,
            transcript: transcript.with(&msg2),
            commitment: msg1[COMMIT_AT..EK_AT].try_into().expect("fixed layout"),
            deadline: invitation.deadline(now),
        };
        Ok((responder, msg2))
    }

    /// The last second this answer, safety words included, may complete.
    pub fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Completes the handshake with A's msg3: show the user [`Unconfirmed::safety_words`] to
    /// read out to A, and [`Unconfirmed::confirm`] once A says they matched. A forged msg3
    /// leaves this answer usable: it reveals nothing about the words.
    pub fn finish(&self, msg3: &[u8], now: u64) -> Result<Unconfirmed, Error> {
        if now > self.deadline() {
            return Err(Error::Expired);
        }
        if !(msg3_len(0)..=msg3_len(MAX_PAYLOAD)).contains(&msg3.len()) {
            return Err(Error::Rejected);
        }
        let plaintext = crypto::open(&key(&self.transcript, &self.ikm, LABEL_SEAL_A), msg3)
            .ok_or(Error::Rejected)?;
        let (nonce, payload_a) = plaintext.split_at(NONCE_LEN);
        if !bool::from(commitment(nonce, payload_a).ct_eq(&self.commitment)) {
            return Err(Error::Rejected);
        }
        Ok(Unconfirmed::new(
            Role::Responder,
            &self.transcript.with(msg3),
            &self.ikm,
            Zeroizing::new(payload_a.to_vec()),
            self.deadline(),
        ))
    }
}

/// A finished handshake whose safety words nobody has compared yet. Until they match, the
/// other side may be someone who had the words, so the peer's payload stays locked inside.
pub struct Unconfirmed {
    established: Established,
    safety: [u8; SAFETY_LEN],
    deadline: u64,
}

impl Unconfirmed {
    fn new(
        role: Role,
        transcript: &Transcript,
        ikm: &[u8; IKM_LEN],
        peer_payload: Zeroizing<Vec<u8>>,
        deadline: u64,
    ) -> Self {
        let th = transcript.hash();
        Unconfirmed {
            established: Established {
                role,
                key: crypto::hkdf(&th, ikm, LABEL_KEY),
                transcript: th,
                peer_payload,
            },
            safety: *crypto::hkdf(&th, ikm, LABEL_SAFETY),
            deadline,
        }
    }

    pub fn role(&self) -> Role {
        self.established.role
    }

    /// Four words, equal on both sides unless someone who had the invitation words sits in the
    /// middle. Not secret, but compare them over a channel where the two people recognize each
    /// other, such as in person or on a call. B shows them, A types them.
    pub fn safety_words(&self) -> Zeroizing<String> {
        to_words(&self.safety)
    }

    /// A: opens the session once the user types the safety words B shows, ignoring case and
    /// spacing. A mismatch, from a typo or from someone in the middle, leaves it pending until
    /// the deadline; tell the user to stop if the words really differ.
    pub fn verify(&self, typed: &str, now: u64) -> Result<Established, Error> {
        if now > self.deadline {
            return Err(Error::Expired);
        }
        if spells(typed, &self.safety) {
            Ok(self.established.clone())
        } else {
            Err(Error::Rejected)
        }
    }

    /// B: opens the session once A says the safety words matched.
    pub fn confirm(self, now: u64) -> Result<Established, Error> {
        if now > self.deadline {
            return Err(Error::Expired);
        }
        Ok(self.established)
    }
}

/// What both sides share once the safety words matched.
#[derive(Clone)]
pub struct Established {
    role: Role,
    key: Zeroizing<Key>,
    transcript: [u8; 32],
    peer_payload: Zeroizing<Vec<u8>>,
}

impl Established {
    pub fn role(&self) -> Role {
        self.role
    }

    /// The shared secret, equal on both sides. Feed it to a KDF or use [`Established::export`]
    /// rather than using it as a key directly.
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Hash of the whole handshake, equal on both sides; public, good for channel binding.
    pub fn transcript(&self) -> &[u8; 32] {
        &self.transcript
    }

    /// The payload the other side sent.
    pub fn peer_payload(&self) -> &[u8] {
        &self.peer_payload
    }

    /// An independent 32-byte key for `label`, equal on both sides.
    pub fn export(&self, label: &[u8]) -> Zeroizing<Key> {
        crypto::hkdf(
            &self.transcript,
            &*self.key,
            &cpace::lv_cat(&[LABEL_EXPORT, label]),
        )
    }
}

fn commitment(nonce: &[u8], payload: &[u8]) -> [u8; KEY_LEN] {
    Sha256::digest(cpace::lv_cat(&[LABEL_COMMIT, nonce, payload])).into()
}

fn key(transcript: &Transcript, ikm: &[u8; IKM_LEN], label: &[u8]) -> Zeroizing<Key> {
    crypto::hkdf(&transcript.hash(), ikm, label)
}

fn public(bytes: &[u8]) -> PublicKey {
    PublicKey::from(<[u8; DH_LEN]>::try_from(bytes).expect("fixed layout"))
}

fn contributory(ss: SharedSecret) -> Result<SharedSecret, Error> {
    ss.was_contributory().then_some(ss).ok_or(Error::Rejected)
}

/// `ISK || ss_x || ss_kem`, with ISK from CPace over msg1 and the `prefix` of msg2.
fn ikm(
    y: &Scalar,
    theirs: &[u8; SHARE_LEN],
    msg1: &[u8],
    prefix: &[u8],
    ss_x: &SharedSecret,
    ss_kem: &[u8],
) -> Result<Ikm, Error> {
    let transcript_ir = cpace::transcript_ir(
        &msg1[YA_AT..XA_AT],
        &msg1[XA_AT..],
        &prefix[..XB_AT],
        &prefix[XB_AT..],
    );
    let isk = cpace::isk(y, theirs, &msg1[..YA_AT], &transcript_ir).ok_or(Error::Rejected)?;
    let mut ikm = Zeroizing::new([0u8; IKM_LEN]);
    ikm[..cpace::ISK_LEN].copy_from_slice(&*isk);
    ikm[cpace::ISK_LEN..cpace::ISK_LEN + KEY_LEN].copy_from_slice(ss_x.as_bytes());
    ikm[cpace::ISK_LEN + KEY_LEN..].copy_from_slice(ss_kem);
    Ok(ikm)
}

#[cfg(test)]
#[path = "vectors.rs"]
mod vectors;

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS: &str = "alpha cable echo forest orbit velvet";
    const WRONG: &str = "alpha cable echo forest orbit zoo";
    const NOW: u64 = 1_800_000_000;
    const CTX: &[u8] = b"test context";
    const PA: &[u8] = b"payload from A";
    const PB: &[u8] = b"payload from B, a bit longer";

    fn live(words: &str) -> Invitation {
        Invitation::live(words, CTX).unwrap()
    }

    /// Runs a handshake, letting `tamper` change message `n` on the wire.
    fn run(
        words_b: &str,
        tamper: impl Fn(usize, &mut Vec<u8>),
    ) -> Result<(Unconfirmed, Unconfirmed), Error> {
        let (mut a, mut msg1) = Initiator::start(&live(WORDS), PA, NOW)?;
        tamper(1, &mut msg1);
        let (b, mut msg2) = Responder::respond(&live(words_b), &msg1, PB, NOW + 1)?;
        tamper(2, &mut msg2);
        let (a, mut msg3) = a.finish(&msg2, NOW + 2)?;
        tamper(3, &mut msg3);
        Ok((a, b.finish(&msg3, NOW + 3)?))
    }

    #[test]
    fn happy_path() {
        let (a, b) = run("  ALPHA cable\techo forest orbit  Velvet ", |_, _| {}).unwrap();
        assert_eq!((a.role(), b.role()), (Role::Initiator, Role::Responder));
        let shown = b.safety_words();
        assert_eq!(shown.split(' ').count(), 4);
        assert_eq!(
            a.verify("wrong words here", NOW).err(),
            Some(Error::Rejected)
        );
        let a = a.verify(&shown.to_uppercase(), NOW + 4).unwrap();
        let b = b.confirm(NOW + 4).unwrap();
        assert_eq!(a.key(), b.key());
        assert_eq!(a.transcript(), b.transcript());
        assert_eq!((a.peer_payload(), b.peer_payload()), (PB, PA));
        assert_eq!(*a.export(b"x"), *b.export(b"x"));
        assert_ne!(*a.export(b"x"), *a.export(b"y"));
        assert_ne!(&*a.export(b"x"), a.key());
    }

    #[test]
    fn message_lengths() {
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, NOW).unwrap();
        assert_eq!(msg1.len(), MSG1_LEN);
        assert_eq!(MSG1_LEN, 1296);
        let (_, msg2) = Responder::respond(&live(WORDS), &msg1, PB, NOW).unwrap();
        assert_eq!(msg2.len(), msg2_len(PB.len()));
        let (_, msg3) = a.finish(&msg2, NOW).unwrap();
        assert_eq!(msg3.len(), msg3_len(PA.len()));
    }

    #[test]
    fn empty_and_largest_payloads() {
        for (pa, pb) in [
            (&[][..], &[][..]),
            (&[7; MAX_PAYLOAD][..], &[9; MAX_PAYLOAD][..]),
        ] {
            let (mut a, msg1) = Initiator::start(&live(WORDS), pa, NOW).unwrap();
            let (b, msg2) = Responder::respond(&live(WORDS), &msg1, pb, NOW).unwrap();
            let (a, msg3) = a.finish(&msg2, NOW).unwrap();
            let b = b.finish(&msg3, NOW).unwrap();
            let a = a.verify(&b.safety_words(), NOW).unwrap();
            let b = b.confirm(NOW).unwrap();
            assert_eq!((a.peer_payload(), b.peer_payload()), (pb, pa));
        }
        let big = [0; MAX_PAYLOAD + 1];
        assert_eq!(
            Initiator::start(&live(WORDS), &big, NOW).err(),
            Some(Error::PayloadTooLarge)
        );
        let (_, msg1) = Initiator::start(&live(WORDS), PA, NOW).unwrap();
        assert_eq!(
            Responder::respond(&live(WORDS), &msg1, &big, NOW).err(),
            Some(Error::PayloadTooLarge)
        );
    }

    #[test]
    fn a_man_in_the_middle_with_the_words_shows_different_safety_words() {
        // M answers A as B and invites B as A, running two handshakes with the same words.
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, NOW).unwrap();
        let (m_as_b, msg2) = Responder::respond(&live(WORDS), &msg1, b"M", NOW).unwrap();
        let (a, msg3) = a.finish(&msg2, NOW).unwrap();
        let m_with_a = m_as_b.finish(&msg3, NOW).unwrap();

        let (mut m_as_a, msg1) = Initiator::start(&live(WORDS), b"M", NOW).unwrap();
        let (b, msg2) = Responder::respond(&live(WORDS), &msg1, PB, NOW).unwrap();
        let (m_with_b, msg3) = m_as_a.finish(&msg2, NOW).unwrap();
        let b = b.finish(&msg3, NOW).unwrap();

        assert_eq!(*a.safety_words(), *m_with_a.safety_words());
        assert_eq!(*b.safety_words(), *m_with_b.safety_words());
        assert_ne!(a.safety, b.safety);
        assert_eq!(
            a.verify(&b.safety_words(), NOW).err(),
            Some(Error::Rejected)
        );
    }

    #[test]
    fn msg3_must_open_the_commitment() {
        for swap_nonce in [true, false] {
            let (mut a, msg1) = Initiator::start(&live(WORDS), PA, NOW).unwrap();
            let (b, msg2) = Responder::respond(&live(WORDS), &msg1, PB, NOW).unwrap();
            // A grinding man in the middle swaps in another nonce, or payload, after msg2.
            if swap_nonce {
                a.nonce = Zeroizing::new([3; NONCE_LEN]);
            } else {
                a.payload = Zeroizing::new(b"other".to_vec());
            }
            let (_, msg3) = a.finish(&msg2, NOW).unwrap();
            assert_eq!(b.finish(&msg3, NOW).err(), Some(Error::Rejected));
        }
    }

    #[test]
    fn wrong_words_rejected() {
        assert_eq!(run(WRONG, |_, _| {}).err(), Some(Error::Rejected));
    }

    #[test]
    fn different_contexts_never_complete() {
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, NOW).unwrap();
        let (_, msg2) =
            Responder::respond(&Invitation::live(WORDS, b"other").unwrap(), &msg1, PB, NOW)
                .unwrap();
        assert_eq!(a.finish(&msg2, NOW).err(), Some(Error::Rejected));
        let (_, msg2) =
            Responder::respond(&Invitation::live(WORDS, b"").unwrap(), &msg1, PB, NOW).unwrap();
        assert_eq!(a.finish(&msg2, NOW).err(), Some(Error::Rejected));
    }

    #[test]
    fn bogus_answers_leave_both_sides_usable() {
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, NOW).unwrap();
        let (_, guess) = Responder::respond(&live(WRONG), &msg1, PB, NOW).unwrap();
        assert_eq!(a.finish(&guess, NOW).err(), Some(Error::Rejected));
        assert_eq!(a.finish(&[0; 2000], NOW).err(), Some(Error::Rejected));

        let (b, msg2) = Responder::respond(&live(WORDS), &msg1, PB, NOW).unwrap();
        let (a, msg3) = a.finish(&msg2, NOW).unwrap();
        let mut forged = msg3.clone();
        forged[0] ^= 1;
        assert_eq!(b.finish(&forged, NOW).err(), Some(Error::Rejected));
        let b = b.finish(&msg3, NOW).unwrap();
        assert_eq!(*a.safety_words(), *b.safety_words());
    }

    #[test]
    fn an_initiator_takes_max_answers_wrong_ones_then_finishes_once() {
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, NOW).unwrap();
        let (_, msg2) = Responder::respond(&live(WORDS), &msg1, PB, NOW).unwrap();
        let (_, guess) = Responder::respond(&live(WRONG), &msg1, PB, NOW).unwrap();
        for _ in 0..MAX_ANSWERS {
            assert_eq!(a.finish(&guess, NOW).err(), Some(Error::Rejected));
        }
        assert_eq!(a.finish(&msg2, NOW).err(), Some(Error::Expired));

        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, NOW).unwrap();
        let (_, msg2) = Responder::respond(&live(WORDS), &msg1, PB, NOW).unwrap();
        assert!(a.finish(&msg2, NOW).is_ok());
        assert_eq!(a.finish(&msg2, NOW).err(), Some(Error::Expired));
    }

    #[test]
    fn flipped_byte_in_any_field_rejected() {
        let msg1 = [0, YA_AT, XA_AT, COMMIT_AT, EK_AT, MSG1_LEN - 1];
        let msg2 = [0, XB_AT, CT_AT, SEALED_B_AT, msg2_len(PB.len()) - 1];
        let msg3 = [0, NONCE_LEN, msg3_len(PA.len()) - 1];
        for (msg, fields) in [(1, &msg1[..]), (2, &msg2), (3, &msg3)] {
            for &at in fields {
                let flip = |m: usize, buf: &mut Vec<u8>| {
                    if m == msg {
                        buf[at] ^= 1;
                    }
                };
                let res = run(WORDS, flip).err();
                assert_eq!(res, Some(Error::Rejected), "flip in msg{msg} at {at}");
            }
        }
    }

    #[test]
    fn invalid_shares_rejected() {
        let ranges = [
            (1, YA_AT..XA_AT),
            (1, XA_AT..COMMIT_AT),
            (2, 0..XB_AT),
            (2, XB_AT..CT_AT),
        ];
        for (msg, range) in ranges {
            let zero = |m: usize, buf: &mut Vec<u8>| {
                if m == msg {
                    buf[range.clone()].fill(0);
                }
            };
            let res = run(WORDS, zero).err();
            assert_eq!(res, Some(Error::Rejected), "msg{msg} {range:?}");
        }
    }

    #[test]
    fn wrong_length_rejected() {
        for (msg, change) in [(1, -1), (1, 1), (2, -1), (2, 1), (3, -1), (3, 1)] {
            let resize = |m: usize, buf: &mut Vec<u8>| {
                if m == msg {
                    buf.resize(buf.len().checked_add_signed(change).unwrap(), 0);
                }
            };
            assert_eq!(run(WORDS, resize).err(), Some(Error::Rejected), "msg{msg}");
        }
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, NOW).unwrap();
        let (b, _) = Responder::respond(&live(WORDS), &msg1, PB, NOW).unwrap();
        assert_eq!(a.finish(&[], NOW).err(), Some(Error::Rejected));
        assert_eq!(
            a.finish(&vec![0; msg2_len(MAX_PAYLOAD) + 1], NOW).err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            b.finish(&[0; NONCE_LEN + TAG_LEN - 1], NOW).err(),
            Some(Error::Rejected)
        );
    }

    #[test]
    fn each_side_expires_its_own_step_on_its_own_clock() {
        const B_CLOCK: u64 = 42;
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, NOW).unwrap();
        let (b, msg2) = Responder::respond(&live(WORDS), &msg1, PB, B_CLOCK).unwrap();
        assert_eq!(
            a.finish(&msg2, NOW + INVITE_TTL + 1).err(),
            Some(Error::Expired)
        );
        let (a, msg3) = a.finish(&msg2, NOW + INVITE_TTL).unwrap();
        assert_eq!(
            b.finish(&msg3, B_CLOCK + INVITE_TTL + 1).err(),
            Some(Error::Expired)
        );
        let b = b.finish(&msg3, B_CLOCK + INVITE_TTL).unwrap();
        let words = b.safety_words();
        assert_eq!(
            a.verify(&words, NOW + INVITE_TTL + 1).err(),
            Some(Error::Expired)
        );
        assert!(a.verify(&words, NOW + INVITE_TTL).is_ok());
        assert_eq!(
            b.confirm(B_CLOCK + INVITE_TTL + 1).err(),
            Some(Error::Expired)
        );
    }

    #[test]
    fn bad_words_rejected_up_front() {
        for words in ["my dog is called max now", "alpha", ""] {
            assert_eq!(Invitation::live(words, CTX).err(), Some(Error::BadWords));
        }
    }

    #[test]
    fn rendezvous_keeps_only_a_short_tag_of_the_normalized_words() {
        let id = live(WORDS).rendezvous();
        assert_eq!(
            live(" ALPHA cable echo forest orbit Velvet").rendezvous(),
            id
        );
        assert_ne!(live(WRONG).rendezvous(), id);
        assert_ne!(Invitation::live(WORDS, b"other").unwrap().rendezvous(), id);
        let tag = crypto::hkdf::<RENDEZVOUS_TAG_LEN>(CTX, WORDS.as_bytes(), LABEL_RENDEZVOUS_TAG);
        assert_eq!(*crypto::hkdf(CTX, &*tag, LABEL_RENDEZVOUS), id);
    }

    const WORDS_A: &str = "alpha cable echo forest orbit";
    const WORDS_B: &str = "velvet stone happy river";
    const AT: u64 = 1_900_000_000;

    fn appointment(words_b: &str, at: u64, now_unix: u64) -> Result<Invitation, Error> {
        Invitation::appointment(WORDS_A, words_b, at, CTX, now_unix)
    }

    /// Runs a handshake between two invitations; both clocks are passed as `NOW`.
    fn complete(a: &Invitation, b: &Invitation) -> Result<(Established, Established), Error> {
        let (mut ia, msg1) = Initiator::start(a, PA, NOW)?;
        let (rb, msg2) = Responder::respond(b, &msg1, PB, NOW)?;
        let (ua, msg3) = ia.finish(&msg2, NOW)?;
        let ub = rb.finish(&msg3, NOW)?;
        Ok((ua.verify(&ub.safety_words(), NOW)?, ub.confirm(NOW)?))
    }

    #[test]
    fn an_appointment_completes_within_its_window() {
        let a = appointment(WORDS_B, AT, AT).unwrap();
        let b = Invitation::appointment(
            " ALPHA cable echo forest orbit",
            WORDS_B,
            AT,
            CTX,
            AT + 1799,
        )
        .unwrap();
        assert_eq!(a.rendezvous(), b.rendezvous());
        let (a, b) = complete(&a, &b).unwrap();
        assert_eq!(a.key(), b.key());
        assert_eq!((a.peer_payload(), b.peer_payload()), (PB, PA));
    }

    #[test]
    fn an_appointment_outside_its_window_fails() {
        for now_unix in [0, AT - 1, AT + APPOINTMENT_WINDOW + 1, u64::MAX] {
            assert_eq!(
                appointment(WORDS_B, AT, now_unix).err(),
                Some(Error::Expired)
            );
        }
        assert!(appointment(WORDS_B, AT, AT + APPOINTMENT_WINDOW).is_ok());

        // A step started near the end dies with the window, not INVITE_TTL later.
        let late = appointment(WORDS_B, AT, AT + APPOINTMENT_WINDOW - 5).unwrap();
        let (mut a, msg1) = Initiator::start(&late, PA, NOW).unwrap();
        assert_eq!(a.deadline(), NOW + 5);
        let (b, msg2) = Responder::respond(&late, &msg1, PB, NOW).unwrap();
        assert_eq!(b.deadline(), NOW + 5);
        assert_eq!(a.finish(&msg2, NOW + 6).err(), Some(Error::Expired));
    }

    #[test]
    fn appointments_at_other_times_or_with_other_words_never_complete() {
        let a = appointment(WORDS_B, AT, AT).unwrap();
        let other_time = appointment(WORDS_B, AT + 60, AT + 60).unwrap();
        assert_ne!(a.rendezvous(), other_time.rendezvous());
        assert_eq!(complete(&a, &other_time).err(), Some(Error::Rejected));
        let wrong_b = appointment("velvet stone happy zoo", AT, AT).unwrap();
        assert_eq!(complete(&a, &wrong_b).err(), Some(Error::Rejected));
        // The same 9 words split differently are another password.
        let split = Invitation::appointment(
            "alpha cable echo forest",
            "orbit velvet stone happy",
            AT,
            CTX,
            AT,
        );
        assert_eq!(split.err(), Some(Error::BadWords));
        // A live invitation never meets an appointment, even with the same context.
        let live = live(WORDS);
        assert_eq!(complete(&live, &a).err(), Some(Error::Rejected));
    }

    #[test]
    fn the_appointment_rendezvous_reveals_nothing_about_b_words() {
        let id = appointment(WORDS_B, AT, AT).unwrap().rendezvous();
        assert_eq!(
            appointment("zoo zoo zoo zoo", AT, AT).unwrap().rendezvous(),
            id
        );
        let other_a = Invitation::appointment("alpha cable echo forest zoo", WORDS_B, AT, CTX, AT);
        assert_ne!(other_a.unwrap().rendezvous(), id);
        assert_eq!(
            appointment("velvet stone happy", AT, AT).err(),
            Some(Error::BadWords)
        );
    }

    #[test]
    fn a_physical_token_works_until_it_expires() {
        let token = new_physical_token(3600, AT);
        assert_eq!(&token[TOKEN_SECRET_LEN..], &(AT + 3600).to_be_bytes());
        let a = Invitation::physical_token(WORDS, &token, CTX, AT).unwrap();
        let b = Invitation::physical_token(WORDS, &token, CTX, AT + 3600).unwrap();
        assert_eq!(a.rendezvous(), b.rendezvous());
        // B read the token and starts; A only answers.
        let (b, a) = complete(&b, &a).unwrap();
        assert_eq!(a.key(), b.key());
        assert_eq!((b.peer_payload(), a.peer_payload()), (PB, PA));

        assert_eq!(
            Invitation::physical_token(WORDS, &token, CTX, AT + 3601).err(),
            Some(Error::Expired)
        );
        // A step started near expiry dies with the token.
        let late = Invitation::physical_token(WORDS, &token, CTX, AT + 3598).unwrap();
        assert_eq!(
            Initiator::start(&late, PA, NOW).unwrap().0.deadline(),
            NOW + 2
        );
    }

    #[test]
    fn a_physical_token_needs_the_words_too() {
        let token = new_physical_token(3600, AT);
        let a = Invitation::physical_token(WORDS, &token, CTX, AT).unwrap();
        let other_token =
            Invitation::physical_token(WORDS, &new_physical_token(3600, AT), CTX, AT).unwrap();
        assert_ne!(a.rendezvous(), other_token.rendezvous());
        assert_eq!(complete(&other_token, &a).err(), Some(Error::Rejected));
        let wrong_words = Invitation::physical_token(WRONG, &token, CTX, AT).unwrap();
        assert_eq!(a.rendezvous(), wrong_words.rendezvous());
        assert_eq!(complete(&wrong_words, &a).err(), Some(Error::Rejected));
        // A token whose expiry was rewritten is another token.
        let mut moved = *token;
        moved[TOKEN_LEN - 1] ^= 1;
        let moved = Invitation::physical_token(WORDS, &moved, CTX, AT).unwrap();
        assert_eq!(complete(&moved, &a).err(), Some(Error::Rejected));
        assert_eq!(
            Invitation::physical_token("alpha", &token, CTX, AT).err(),
            Some(Error::BadWords)
        );
    }
}
