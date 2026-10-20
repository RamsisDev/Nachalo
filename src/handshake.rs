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
//! cannot kill a handshake; A takes at most its configured `max_answers` wrong ones.
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
//! when on the wall clock it can be used. The messages are the same in every mode.

use std::ops::RangeInclusive;

use curve25519_dalek::scalar::Scalar;
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::config::Config;
use crate::cpace::{self, SHARE_LEN};
use crate::crypto::{self, CT_LEN, EK_LEN, KEY_LEN, Key, TAG_LEN};
use crate::words::{
    APPOINTMENT_WORDS_A, APPOINTMENT_WORDS_B, WORD_COUNT, normalize, spells, to_words,
};

/// Domain separation for everything Nachalo derives. Changes with every incompatible version.
pub const PROTOCOL: &[u8] = b"Nachalo v0";
/// Largest payload every receiver accepts, whatever its own `max_payload` for sending: it holds
/// an ML-KEM-1024 key plus an ML-DSA-65 key and signature, and the largest msg2 still fits a
/// 16 KiB transport block.
pub const PAYLOAD_CEILING: usize = 8192;
/// Two bytes per safety word, 11 bits used: 4 words, 44 bits. Someone in the middle who gets
/// B to answer `q` msg1 matches them with probability `q * 2^-44`.
pub const SAFETY_LEN: usize = 8;
/// Length of [`Invitation::rendezvous`].
pub const RENDEZVOUS_LEN: usize = 32;
/// Bytes of the words' hash the rendezvous id is derived from. Whoever watches that id learns at
/// most these 24 bits of the words, and each answer is still a single online guess at the
/// other 42.
const RENDEZVOUS_TAG_LEN: usize = 3;
/// The same for an appointment, from A's words only. Every appointment slot has its own ids, so
/// fewer bits keep unrelated invitations apart: whoever watches the id learns at most 16 of A's
/// 55 bits and nothing about B's 44.
const APPOINTMENT_TAG_LEN: usize = 2;
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
/// msg1 length, whatever the payload: it carries only a commitment to it.
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

/// Why a step failed. On purpose, a rejected message does not say which check it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Not the expected number of words from the list.
    BadWords,
    /// Past its deadline, out of answers, already finished, or outside the window of its
    /// appointment or physical token.
    Expired,
    /// More than this device's `max_payload` bytes.
    PayloadTooLarge,
    /// Malformed input or failed confirmation, with no further detail.
    Rejected,
    /// A setting outside its profile's range, or a token expiry past the end of time.
    OutOfRange,
    /// The OS random generator failed.
    Rng,
}

/// The two clocks every step reads.
#[derive(Clone, Copy, Debug)]
pub struct Clock {
    /// Monotonic seconds, for the per-step TTL: a clock of this device only, that keeps
    /// counting while it sleeps. Only differences on the same device matter.
    pub now: u64,
    /// Wall-clock Unix seconds, for the appointment window and the token's expiry.
    pub now_unix: u64,
}

/// When a pending step dies: `ttl` after it started on the monotonic clock or on the wall clock,
/// whichever comes first. The wall clock catches monotonic clocks that stop while the device
/// sleeps, or restart with it while the step is saved (see [`Initiator::to_bytes`]).
#[derive(Clone, Copy)]
struct Deadline {
    now: u64,
    unix: u64,
}

impl Deadline {
    fn passed(self, clock: Clock) -> bool {
        clock.now > self.now || clock.now_unix > self.unix
    }
}

/// Which side of the handshake a device played.
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
#[derive(Clone)]
pub struct Invitation {
    /// The CPace password.
    prs: Zeroizing<Vec<u8>>,
    /// The CPace channel identifier.
    channel: Vec<u8>,
    rendezvous: [u8; RENDEZVOUS_LEN],
    /// When, on the wall clock, a step may start or stay pending: always for live.
    valid_unix: RangeInclusive<u64>,
    config: Config,
}

impl Invitation {
    /// Live first contact: A draws [`WORD_COUNT`] words and both sides take part within
    /// `config`'s `invite_ttl`.
    pub fn live(words: &str, context: &[u8], config: &Config) -> Result<Self, Error> {
        let words = normalize(words, WORD_COUNT).ok_or(Error::BadWords)?;
        let tag =
            crypto::hkdf::<RENDEZVOUS_TAG_LEN>(context, words.as_bytes(), LABEL_RENDEZVOUS_TAG);
        Ok(Invitation {
            prs: Zeroizing::new(words.as_bytes().to_vec()),
            channel: cpace::lv_cat(&[PROTOCOL, context]),
            rendezvous: *crypto::hkdf(context, &*tag, LABEL_RENDEZVOUS),
            valid_unix: 0..=u64::MAX,
            config: *config,
        })
    }

    /// First contact at an agreed time: A draws [`APPOINTMENT_WORDS_A`] words, B draws
    /// [`APPOINTMENT_WORDS_B`], and they swap them along with `at`, the Unix time in seconds
    /// when the appointment starts. Each side builds it, starts and answers only within
    /// `config`'s `appointment_window` from `at` on its wall clock, and the whole handshake,
    /// safety words included, must end by then. Invitations for another `at` never complete.
    pub fn appointment(
        words_a: &str,
        words_b: &str,
        at: u64,
        context: &[u8],
        now_unix: u64,
        config: &Config,
    ) -> Result<Self, Error> {
        let a = normalize(words_a, APPOINTMENT_WORDS_A).ok_or(Error::BadWords)?;
        let b = normalize(words_b, APPOINTMENT_WORDS_B).ok_or(Error::BadWords)?;
        let valid_unix = at..=at.saturating_add(config.appointment_window.as_secs());
        if !valid_unix.contains(&now_unix) {
            return Err(Error::Expired);
        }
        let channel = cpace::lv_cat(&[PROTOCOL, context, LABEL_APPOINTMENT, &at.to_be_bytes()]);
        let tag = crypto::hkdf::<APPOINTMENT_TAG_LEN>(&channel, a.as_bytes(), LABEL_RENDEZVOUS_TAG);
        Ok(Invitation {
            prs: Zeroizing::new(cpace::lv_cat(&[a.as_bytes(), b.as_bytes()])),
            rendezvous: *crypto::hkdf(&channel, &*tag, LABEL_RENDEZVOUS),
            channel,
            valid_unix,
            config: *config,
        })
    }

    /// First contact through a physical token: bytes from [`new_physical_token`] that A hands B
    /// in person on something B's device reads, along with [`WORD_COUNT`] words A gives B another
    /// way. B starts the handshake and A answers. Each side builds it, starts and answers only
    /// until the expiry the token carries, on its wall clock.
    pub fn physical_token(
        words: &str,
        token: &[u8; TOKEN_LEN],
        context: &[u8],
        now_unix: u64,
        config: &Config,
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
            valid_unix: 0..=expires,
            config: *config,
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

    /// Checks the wall clock and gives a step started now its deadline: `invite_ttl` later, or
    /// the end of the window or token if that comes first.
    fn deadline(&self, clock: Clock) -> Result<Deadline, Error> {
        if !self.valid_unix.contains(&clock.now_unix) {
            return Err(Error::Expired);
        }
        let ttl = self
            .config
            .invite_ttl
            .as_secs()
            .min(self.valid_unix.end() - clock.now_unix);
        Ok(Deadline {
            now: clock.now.saturating_add(ttl),
            unix: clock.now_unix + ttl,
        })
    }
}

/// A new physical token for A to hand over, valid for `lifetime` seconds from `now_unix`, with no
/// upper bound. A keeps it to build its own [`Invitation::physical_token`]; erase it once it
/// expires.
pub fn new_physical_token(
    lifetime: u64,
    now_unix: u64,
) -> Result<Zeroizing<[u8; TOKEN_LEN]>, Error> {
    let expires = now_unix.checked_add(lifetime).ok_or(Error::OutOfRange)?;
    let mut token = Zeroizing::new([0u8; TOKEN_LEN]);
    crypto::fill(&mut token[..TOKEN_SECRET_LEN])?;
    token[TOKEN_SECRET_LEN..].copy_from_slice(&expires.to_be_bytes());
    Ok(token)
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
    fn new() -> Result<Self, Error> {
        Ok(Self {
            sid: crypto::random()?,
            cpace: crypto::random()?,
            x25519: crypto::random()?,
            ml_kem: crypto::random()?,
            nonce: crypto::random()?,
        })
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
    fn new() -> Result<Self, Error> {
        Ok(Self {
            cpace: crypto::random()?,
            x25519: crypto::random()?,
            ml_kem: crypto::random()?,
        })
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

/// A's pending handshake, from [`Initiator::start`] until msg2 arrives.
pub struct Initiator {
    y: Zeroizing<Scalar>,
    x: StaticSecret,
    dk: MlKem768PrivateKey,
    /// Committed to in msg1, revealed in msg3.
    nonce: Zeroizing<[u8; NONCE_LEN]>,
    payload: Zeroizing<Vec<u8>>,
    msg1: Vec<u8>,
    deadline: Deadline,
    answers: u16,
    max_answers: u16,
    finished: bool,
}

/// libcrux does not zeroize its keys on drop.
impl Drop for Initiator {
    fn drop(&mut self) {
        self.dk[..MlKem768PrivateKey::len()].zeroize();
    }
}

impl Initiator {
    /// Starts the handshake: send msg1 to [`Invitation::rendezvous`].
    pub fn start(
        invitation: &Invitation,
        payload: &[u8],
        clock: Clock,
    ) -> Result<(Initiator, Vec<u8>), Error> {
        Self::start_with(invitation, payload, clock, InitiatorRandom::new()?)
    }

    pub(crate) fn start_with(
        invitation: &Invitation,
        payload: &[u8],
        clock: Clock,
        random: InitiatorRandom,
    ) -> Result<(Initiator, Vec<u8>), Error> {
        let deadline = invitation.deadline(clock)?;
        if payload.len() > invitation.config.max_payload {
            return Err(Error::PayloadTooLarge);
        }
        let g = cpace::generator(&invitation.prs, &invitation.channel, &random.sid);
        let y = Zeroizing::new(cpace::scalar(random.cpace));
        let x = StaticSecret::from(random.x25519);
        let (dk, ek) = mlkem768::generate_key_pair(random.ml_kem).into_parts();

        let mut msg1 = Vec::with_capacity(MSG1_LEN);
        msg1.extend_from_slice(&random.sid);
        msg1.extend_from_slice(&cpace::share(&y, &g));
        msg1.extend_from_slice(PublicKey::from(&x).as_bytes());
        msg1.extend_from_slice(&commitment(&random.nonce, payload));
        msg1.extend_from_slice(ek.as_slice());

        let initiator = Initiator {
            y,
            x,
            dk,
            nonce: Zeroizing::new(random.nonce),
            payload: Zeroizing::new(payload.to_vec()),
            msg1: msg1.clone(),
            deadline,
            answers: 0,
            max_answers: invitation.config.max_answers,
            finished: false,
        };
        Ok((initiator, msg1))
    }

    /// The last second on the monotonic clock this invitation, safety words included, may
    /// complete.
    pub fn deadline(&self) -> u64 {
        self.deadline.now
    }

    /// Saves this pending step, so [`Initiator::from_bytes`] resumes it after the app is killed
    /// or the device restarts. Save it again after each [`finish`](Initiator::finish) that fails,
    /// since each counts against `max_answers`. `finish` gives the same msg3 for the same msg2,
    /// so the state saved before it also resumes the handshake after it.
    ///
    /// The state holds this side's secrets: whoever reads it can complete the handshake in its
    /// place. Store it encrypted, for example in the iOS Keychain or the Android Keystore, and
    /// erase it once the step ends. It starts with a version byte. A restart resets the
    /// monotonic clock, so a restored step dies by the wall clock: `ttl` after it started.
    /// The same holds for [`Responder::to_bytes`] and [`Listener::to_bytes`].
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = state(STATE_INITIATOR, 4096 + self.payload.len());
        out.extend_from_slice(&*Zeroizing::new(self.y.to_bytes()));
        out.extend_from_slice(&*Zeroizing::new(self.x.to_bytes()));
        out.extend_from_slice(self.dk.as_slice());
        out.extend_from_slice(&*self.nonce);
        out.extend_from_slice(&self.msg1);
        put_deadline(&mut out, self.deadline);
        out.extend_from_slice(&self.answers.to_be_bytes());
        out.extend_from_slice(&self.max_answers.to_be_bytes());
        out.push(u8::from(self.finished));
        put_bytes(&mut out, &self.payload);
        out
    }

    /// Restores a step saved with [`Initiator::to_bytes`]; [`Error::Rejected`] if `bytes` is
    /// not one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, STATE_INITIATOR)?;
        let y = Option::from(Scalar::from_canonical_bytes(r.array()?)).ok_or(Error::Rejected)?;
        let x = StaticSecret::from(r.array::<DH_LEN>()?);
        let dk = r.take(MlKem768PrivateKey::len())?;
        let nonce = Zeroizing::new(r.array()?);
        let msg1 = r.take(MSG1_LEN)?.to_vec();
        let deadline = r.deadline()?;
        let (answers, max_answers) = (r.u16()?, r.u16()?);
        let finished = match r.array()? {
            [0] => false,
            [1] => true,
            _ => return Err(Error::Rejected),
        };
        let payload = Zeroizing::new(r.bytes()?.to_vec());
        r.end()?;
        Ok(Initiator {
            y: Zeroizing::new(y),
            x,
            dk: dk.try_into().map_err(|_| Error::Rejected)?,
            nonce,
            payload,
            msg1,
            deadline,
            answers,
            max_answers,
            finished,
        })
    }

    /// Completes the handshake with B's msg2: send msg3 to B, then have the user type the
    /// safety words B shows into [`Unconfirmed::verify`]. A wrong msg2 leaves this invitation
    /// usable until its deadline or `max_answers`.
    pub fn finish(&mut self, msg2: &[u8], clock: Clock) -> Result<(Unconfirmed, Vec<u8>), Error> {
        if self.finished || self.answers >= self.max_answers || self.deadline.passed(clock) {
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
        if !(msg2_len(0)..=msg2_len(PAYLOAD_CEILING)).contains(&msg2.len()) {
            return Err(Error::Rejected);
        }
        let (prefix, sealed_b) = msg2.split_at(SEALED_B_AT);
        let yb = prefix[..XB_AT].try_into().expect("fixed layout");
        let ss_x = contributory(self.x.diffie_hellman(&public(&prefix[XB_AT..CT_AT])))?;
        let ct: MlKem768Ciphertext = prefix[CT_AT..].try_into().expect("fixed layout");
        let ss_kem = Zeroizing::new(mlkem768::decapsulate(&self.dk, &ct));
        let ikm = ikm(&self.y, yb, &self.msg1, prefix, &ss_x, &ss_kem[..])?;

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
            self.deadline,
        );
        Ok((unconfirmed, msg3))
    }
}

/// B's side of one invitation: answers each msg1 found at its rendezvous, up to the invitation's
/// `max_answers`. Keep one per invitation for as long as you watch its rendezvous.
pub struct Listener {
    invitation: Invitation,
    answers: u16,
}

impl Listener {
    /// A listener with its own copy of `invitation`, which has answered nothing yet.
    pub fn new(invitation: &Invitation) -> Self {
        Listener {
            invitation: invitation.clone(),
            answers: 0,
        }
    }

    /// Answers `msg1` found at the rendezvous: send msg2 back to A. It carries no time, so an old
    /// msg1 is answered too; that is harmless, since only A, holding the words, can complete it
    /// and A drops it after its TTL. Every msg1 answered is an online guess for whoever sent it,
    /// and one more chance for someone in the middle to match the safety words, so once
    /// `max_answers` were answered, or outside the invitation's window, this returns
    /// [`Error::Expired`].
    pub fn respond(
        &mut self,
        msg1: &[u8],
        payload: &[u8],
        clock: Clock,
    ) -> Result<(Responder, Vec<u8>), Error> {
        if self.answers >= self.invitation.config.max_answers {
            return Err(Error::Expired);
        }
        let answer = Responder::respond_with(
            &self.invitation,
            msg1,
            payload,
            clock,
            ResponderRandom::new()?,
        )?;
        self.answers += 1;
        Ok(answer)
    }

    /// Saves this listener, its copy of the invitation included, so [`Listener::from_bytes`]
    /// resumes it; save it again after each [`respond`](Listener::respond). As for
    /// [`Initiator::to_bytes`], store it encrypted: it holds the invitation's secret. Only
    /// listeners on one of the built-in [`Profile`](crate::Profile)s restore.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let i = &self.invitation;
        let mut out = state(STATE_LISTENER, 512 + i.prs.len() + i.channel.len());
        out.extend_from_slice(&self.answers.to_be_bytes());
        out.extend_from_slice(&i.rendezvous);
        out.extend_from_slice(&i.valid_unix.start().to_be_bytes());
        out.extend_from_slice(&i.valid_unix.end().to_be_bytes());
        out.extend_from_slice(&i.config.invite_ttl.as_secs().to_be_bytes());
        out.extend_from_slice(&i.config.max_answers.to_be_bytes());
        out.extend_from_slice(&(i.config.max_payload as u64).to_be_bytes());
        out.extend_from_slice(&i.config.appointment_window.as_secs().to_be_bytes());
        put_bytes(&mut out, i.config.profile().name.as_bytes());
        put_bytes(&mut out, &i.channel);
        put_bytes(&mut out, &i.prs);
        out
    }

    /// Restores a listener saved with [`Listener::to_bytes`]; [`Error::Rejected`] if `bytes` is
    /// not one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, STATE_LISTENER)?;
        let answers = r.u16()?;
        let rendezvous = r.array()?;
        let valid_unix = r.u64()?..=r.u64()?;
        let (invite_ttl, max_answers, max_payload) = (r.u64()?, r.u16()?, r.u64()?);
        let appointment_window = r.u64()?;
        let config = Config::restore(
            r.bytes()?,
            invite_ttl,
            max_answers,
            max_payload,
            appointment_window,
        )
        .map_err(|_| Error::Rejected)?;
        let channel = r.bytes()?.to_vec();
        let prs = Zeroizing::new(r.bytes()?.to_vec());
        r.end()?;
        let invitation = Invitation {
            prs,
            channel,
            rendezvous,
            valid_unix,
            config,
        };
        Ok(Listener {
            invitation,
            answers,
        })
    }
}

/// B's answer to one msg1, from [`Listener::respond`] until msg3 arrives.
pub struct Responder {
    ikm: Ikm,
    /// Up to the end of msg2.
    transcript: Transcript,
    /// A's commitment to the nonce and payload msg3 must carry.
    commitment: [u8; KEY_LEN],
    deadline: Deadline,
}

impl Responder {
    pub(crate) fn respond_with(
        invitation: &Invitation,
        msg1: &[u8],
        payload: &[u8],
        clock: Clock,
        random: ResponderRandom,
    ) -> Result<(Responder, Vec<u8>), Error> {
        let deadline = invitation.deadline(clock)?;
        if payload.len() > invitation.config.max_payload {
            return Err(Error::PayloadTooLarge);
        }
        let msg1: &[u8; MSG1_LEN] = msg1.try_into().map_err(|_| Error::Rejected)?;
        let ek: MlKem768PublicKey = msg1[EK_AT..].try_into().expect("fixed layout");
        if !mlkem768::validate_public_key(&ek) {
            return Err(Error::Rejected);
        }
        let g = cpace::generator(&invitation.prs, &invitation.channel, &msg1[..YA_AT]);
        let y = Zeroizing::new(cpace::scalar(random.cpace));
        let x = StaticSecret::from(random.x25519);
        let ss_x = contributory(x.diffie_hellman(&public(&msg1[XA_AT..COMMIT_AT])))?;
        let (ct, ss_kem) = mlkem768::encapsulate(&ek, random.ml_kem);
        let ss_kem = Zeroizing::new(ss_kem);

        let mut msg2 = Vec::with_capacity(msg2_len(payload.len()));
        msg2.extend_from_slice(&cpace::share(&y, &g));
        msg2.extend_from_slice(PublicKey::from(&x).as_bytes());
        msg2.extend_from_slice(ct.as_slice());
        let ya = msg1[YA_AT..XA_AT].try_into().expect("fixed layout");
        let ikm = ikm(&y, ya, msg1, &msg2, &ss_x, &ss_kem[..])?;

        let transcript = Transcript::new(msg1);
        let key_b = key(&transcript.with(&msg2), &ikm, LABEL_SEAL_B);
        msg2.extend(crypto::seal(&key_b, payload));

        let responder = Responder {
            ikm,
            transcript: transcript.with(&msg2),
            commitment: msg1[COMMIT_AT..EK_AT].try_into().expect("fixed layout"),
            deadline,
        };
        Ok((responder, msg2))
    }

    /// The last second on the monotonic clock this answer, safety words included, may complete.
    pub fn deadline(&self) -> u64 {
        self.deadline.now
    }

    /// Saves this answer, so [`Responder::from_bytes`] resumes it. As for
    /// [`Initiator::to_bytes`], store it encrypted and erase it once the step ends.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = state(STATE_RESPONDER, 256 + self.transcript.0.len());
        out.extend_from_slice(&*self.ikm);
        out.extend_from_slice(&self.commitment);
        put_deadline(&mut out, self.deadline);
        put_bytes(&mut out, &self.transcript.0);
        out
    }

    /// Restores an answer saved with [`Responder::to_bytes`]; [`Error::Rejected`] if `bytes` is
    /// not one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes, STATE_RESPONDER)?;
        let ikm = Zeroizing::new(r.array()?);
        let commitment = r.array()?;
        let deadline = r.deadline()?;
        let transcript = Transcript(r.bytes()?.to_vec());
        r.end()?;
        Ok(Responder {
            ikm,
            transcript,
            commitment,
            deadline,
        })
    }

    /// Completes the handshake with A's msg3: show the user [`Unconfirmed::safety_words`] to
    /// read out to A, and [`Unconfirmed::confirm`] once A says they matched. A forged msg3
    /// leaves this answer usable: it reveals nothing about the words.
    pub fn finish(&self, msg3: &[u8], clock: Clock) -> Result<Unconfirmed, Error> {
        if self.deadline.passed(clock) {
            return Err(Error::Expired);
        }
        if !(msg3_len(0)..=msg3_len(PAYLOAD_CEILING)).contains(&msg3.len()) {
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
            self.deadline,
        ))
    }
}

/// A finished handshake whose safety words nobody has compared yet. Until they match, the
/// other side may be someone who had the words, so the peer's payload stays locked inside.
pub struct Unconfirmed {
    established: Established,
    safety: [u8; SAFETY_LEN],
    deadline: Deadline,
}

impl Unconfirmed {
    fn new(
        role: Role,
        transcript: &Transcript,
        ikm: &[u8; IKM_LEN],
        peer_payload: Zeroizing<Vec<u8>>,
        deadline: Deadline,
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

    /// Which side this device played.
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
    pub fn verify(&self, typed: &str, clock: Clock) -> Result<Established, Error> {
        if self.deadline.passed(clock) {
            return Err(Error::Expired);
        }
        if spells(typed, &self.safety) {
            Ok(self.established.clone())
        } else {
            Err(Error::Rejected)
        }
    }

    /// B: opens the session once A says the safety words matched.
    pub fn confirm(self, clock: Clock) -> Result<Established, Error> {
        if self.deadline.passed(clock) {
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
    /// Which side this device played.
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

/// First byte of every saved state; changes whenever its layout does.
const STATE_VERSION: u8 = 0;
const STATE_INITIATOR: u8 = 1;
const STATE_RESPONDER: u8 = 2;
const STATE_LISTENER: u8 = 3;

/// Saved state: `STATE_VERSION || kind || fields`, integers big-endian, variable-length fields
/// prefixed with their length as 4 bytes. Reserved up front so no unzeroized copy is left behind.
fn state(kind: u8, capacity: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(2 + capacity));
    out.extend_from_slice(&[STATE_VERSION, kind]);
    out
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("fields are small")
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
}

fn put_deadline(out: &mut Vec<u8>, deadline: Deadline) {
    out.extend_from_slice(&deadline.now.to_be_bytes());
    out.extend_from_slice(&deadline.unix.to_be_bytes());
}

/// Reads saved state; every error is [`Error::Rejected`].
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], kind: u8) -> Result<Self, Error> {
        match bytes {
            [STATE_VERSION, k, rest @ ..] if *k == kind => Ok(Reader(rest)),
            _ => Err(Error::Rejected),
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let (head, rest) = self.0.split_at_checked(len).ok_or(Error::Rejected)?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u16(&mut self) -> Result<u16, Error> {
        self.array().map(u16::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, Error> {
        self.array().map(u64::from_be_bytes)
    }

    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let len = u32::from_be_bytes(self.array()?);
        self.take(usize::try_from(len).map_err(|_| Error::Rejected)?)
    }

    fn deadline(&mut self) -> Result<Deadline, Error> {
        Ok(Deadline {
            now: self.u64()?,
            unix: self.u64()?,
        })
    }

    fn end(self) -> Result<(), Error> {
        self.0.is_empty().then_some(()).ok_or(Error::Rejected)
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
    use std::ops::{Add, Sub};
    use std::time::Duration;

    use super::*;
    use proptest::prelude::*;

    use crate::config::{Bounded, Profile};

    const WORDS: &str = "alpha cable echo forest orbit velvet";
    const WRONG: &str = "alpha cable echo forest orbit zoo";
    const NOW: u64 = 1_800_000_000;
    const CTX: &[u8] = b"test context";
    const PA: &[u8] = b"payload from A";
    const PB: &[u8] = b"payload from B, a bit longer";
    const CFG: Config = Config::new(&Profile::INTERACTIVE);
    const TTL: u64 = 600;
    const MAX_ANSWERS: u16 = 64;
    const MAX_PAYLOAD: usize = 1024;
    const WINDOW: u64 = 1800;
    const PROFILES: [&Profile; 3] = [
        &Profile::INTERACTIVE,
        &Profile::PQ_MESSENGER,
        &Profile::NEARBY,
    ];

    /// `now` on the monotonic clock, with the wall clock at the start of the appointment.
    fn c(now: u64) -> Clock {
        Clock { now, now_unix: AT }
    }

    /// `now_unix` on the wall clock, with the monotonic clock at `NOW`.
    fn wall(now_unix: u64) -> Clock {
        Clock { now: NOW, now_unix }
    }

    fn live(words: &str) -> Invitation {
        Invitation::live(words, CTX, &CFG).unwrap()
    }

    fn respond(
        invitation: &Invitation,
        msg1: &[u8],
        payload: &[u8],
        clock: Clock,
    ) -> Result<(Responder, Vec<u8>), Error> {
        Listener::new(invitation).respond(msg1, payload, clock)
    }

    /// Runs a handshake, letting `tamper` change message `n` on the wire.
    fn run(
        words_b: &str,
        tamper: impl Fn(usize, &mut Vec<u8>),
    ) -> Result<(Unconfirmed, Unconfirmed), Error> {
        let (mut a, mut msg1) = Initiator::start(&live(WORDS), PA, c(NOW))?;
        tamper(1, &mut msg1);
        let (b, mut msg2) = respond(&live(words_b), &msg1, PB, c(NOW + 1))?;
        tamper(2, &mut msg2);
        let (a, mut msg3) = a.finish(&msg2, c(NOW + 2))?;
        tamper(3, &mut msg3);
        Ok((a, b.finish(&msg3, c(NOW + 3))?))
    }

    #[test]
    fn happy_path() {
        let (a, b) = run("  ALPHA cable\techo forest orbit  Velvet ", |_, _| {}).unwrap();
        assert_eq!((a.role(), b.role()), (Role::Initiator, Role::Responder));
        let shown = b.safety_words();
        assert_eq!(shown.split(' ').count(), 4);
        assert_eq!(
            a.verify("wrong words here", c(NOW)).err(),
            Some(Error::Rejected)
        );
        let a = a.verify(&shown.to_uppercase(), c(NOW + 4)).unwrap();
        let b = b.confirm(c(NOW + 4)).unwrap();
        assert_eq!(a.key(), b.key());
        assert_eq!(a.transcript(), b.transcript());
        assert_eq!((a.peer_payload(), b.peer_payload()), (PB, PA));
        assert_eq!(*a.export(b"x"), *b.export(b"x"));
        assert_ne!(*a.export(b"x"), *a.export(b"y"));
        assert_ne!(&*a.export(b"x"), a.key());
    }

    #[test]
    fn message_lengths() {
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, c(NOW)).unwrap();
        assert_eq!(msg1.len(), MSG1_LEN);
        assert_eq!(MSG1_LEN, 1296);
        let (_, msg2) = respond(&live(WORDS), &msg1, PB, c(NOW)).unwrap();
        assert_eq!(msg2.len(), msg2_len(PB.len()));
        let (_, msg3) = a.finish(&msg2, c(NOW)).unwrap();
        assert_eq!(msg3.len(), msg3_len(PA.len()));
        assert_eq!(msg2_len(PAYLOAD_CEILING), 9360);
    }

    #[test]
    fn empty_and_largest_payloads() {
        for (pa, pb) in [
            (&[][..], &[][..]),
            (&[7; MAX_PAYLOAD][..], &[9; MAX_PAYLOAD][..]),
        ] {
            let (mut a, msg1) = Initiator::start(&live(WORDS), pa, c(NOW)).unwrap();
            let (b, msg2) = respond(&live(WORDS), &msg1, pb, c(NOW)).unwrap();
            let (a, msg3) = a.finish(&msg2, c(NOW)).unwrap();
            let b = b.finish(&msg3, c(NOW)).unwrap();
            let a = a.verify(&b.safety_words(), c(NOW)).unwrap();
            let b = b.confirm(c(NOW)).unwrap();
            assert_eq!((a.peer_payload(), b.peer_payload()), (pb, pa));
        }
        let big = [0; MAX_PAYLOAD + 1];
        assert_eq!(
            Initiator::start(&live(WORDS), &big, c(NOW)).err(),
            Some(Error::PayloadTooLarge)
        );
        let (_, msg1) = Initiator::start(&live(WORDS), PA, c(NOW)).unwrap();
        assert_eq!(
            respond(&live(WORDS), &msg1, &big, c(NOW)).err(),
            Some(Error::PayloadTooLarge)
        );
    }

    #[test]
    fn every_receiver_accepts_up_to_the_ceiling() {
        let config = Config::new(&Profile::PQ_MESSENGER)
            .with_max_payload(PAYLOAD_CEILING)
            .unwrap();
        let large = Invitation::live(WORDS, CTX, &config).unwrap();
        let small = live(WORDS);
        let mut max = vec![7; PAYLOAD_CEILING];

        // A device that sends at most 1 KiB still receives the most the other may send.
        let (mut a, msg1) = Initiator::start(&large, &max, c(NOW)).unwrap();
        let (b, msg2) = respond(&small, &msg1, PB, c(NOW)).unwrap();
        let (_, msg3) = a.finish(&msg2, c(NOW)).unwrap();
        assert!(b.finish(&msg3, c(NOW)).is_ok());
        let (mut a, msg1) = Initiator::start(&small, PA, c(NOW)).unwrap();
        let (_, msg2) = respond(&large, &msg1, &max, c(NOW)).unwrap();
        assert!(a.finish(&msg2, c(NOW)).is_ok());

        // One byte more is refused before anything is sent.
        max.push(0);
        assert_eq!(
            Initiator::start(&large, &max, c(NOW)).err(),
            Some(Error::PayloadTooLarge)
        );
        assert_eq!(
            config.with_max_payload(PAYLOAD_CEILING + 1).err(),
            Some(Error::OutOfRange)
        );
    }

    #[test]
    fn a_man_in_the_middle_with_the_words_shows_different_safety_words() {
        // M answers A as B and invites B as A, running two handshakes with the same words.
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, c(NOW)).unwrap();
        let (m_as_b, msg2) = respond(&live(WORDS), &msg1, b"M", c(NOW)).unwrap();
        let (a, msg3) = a.finish(&msg2, c(NOW)).unwrap();
        let m_with_a = m_as_b.finish(&msg3, c(NOW)).unwrap();

        let (mut m_as_a, msg1) = Initiator::start(&live(WORDS), b"M", c(NOW)).unwrap();
        let (b, msg2) = respond(&live(WORDS), &msg1, PB, c(NOW)).unwrap();
        let (m_with_b, msg3) = m_as_a.finish(&msg2, c(NOW)).unwrap();
        let b = b.finish(&msg3, c(NOW)).unwrap();

        assert_eq!(*a.safety_words(), *m_with_a.safety_words());
        assert_eq!(*b.safety_words(), *m_with_b.safety_words());
        assert_ne!(a.safety, b.safety);
        assert_eq!(
            a.verify(&b.safety_words(), c(NOW)).err(),
            Some(Error::Rejected)
        );
    }

    #[test]
    fn msg3_must_open_the_commitment() {
        for swap_nonce in [true, false] {
            let (mut a, msg1) = Initiator::start(&live(WORDS), PA, c(NOW)).unwrap();
            let (b, msg2) = respond(&live(WORDS), &msg1, PB, c(NOW)).unwrap();
            // A grinding man in the middle swaps in another nonce, or payload, after msg2.
            if swap_nonce {
                a.nonce = Zeroizing::new([3; NONCE_LEN]);
            } else {
                a.payload = Zeroizing::new(b"other".to_vec());
            }
            let (_, msg3) = a.finish(&msg2, c(NOW)).unwrap();
            assert_eq!(b.finish(&msg3, c(NOW)).err(), Some(Error::Rejected));
        }
    }

    #[test]
    fn wrong_words_rejected() {
        assert_eq!(run(WRONG, |_, _| {}).err(), Some(Error::Rejected));
    }

    #[test]
    fn different_contexts_never_complete() {
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, c(NOW)).unwrap();
        let other = Invitation::live(WORDS, b"other", &CFG).unwrap();
        let (_, msg2) = respond(&other, &msg1, PB, c(NOW)).unwrap();
        assert_eq!(a.finish(&msg2, c(NOW)).err(), Some(Error::Rejected));
        let empty = Invitation::live(WORDS, b"", &CFG).unwrap();
        let (_, msg2) = respond(&empty, &msg1, PB, c(NOW)).unwrap();
        assert_eq!(a.finish(&msg2, c(NOW)).err(), Some(Error::Rejected));
    }

    #[test]
    fn bogus_answers_leave_both_sides_usable() {
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, c(NOW)).unwrap();
        let (_, guess) = respond(&live(WRONG), &msg1, PB, c(NOW)).unwrap();
        assert_eq!(a.finish(&guess, c(NOW)).err(), Some(Error::Rejected));
        assert_eq!(a.finish(&[0; 2000], c(NOW)).err(), Some(Error::Rejected));

        let (b, msg2) = respond(&live(WORDS), &msg1, PB, c(NOW)).unwrap();
        let (a, msg3) = a.finish(&msg2, c(NOW)).unwrap();
        let mut forged = msg3.clone();
        forged[0] ^= 1;
        assert_eq!(b.finish(&forged, c(NOW)).err(), Some(Error::Rejected));
        let b = b.finish(&msg3, c(NOW)).unwrap();
        assert_eq!(*a.safety_words(), *b.safety_words());
    }

    #[test]
    fn an_initiator_takes_max_answers_wrong_ones_then_finishes_once() {
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, c(NOW)).unwrap();
        let (_, msg2) = respond(&live(WORDS), &msg1, PB, c(NOW)).unwrap();
        let (_, guess) = respond(&live(WRONG), &msg1, PB, c(NOW)).unwrap();
        for _ in 0..MAX_ANSWERS {
            assert_eq!(a.finish(&guess, c(NOW)).err(), Some(Error::Rejected));
        }
        assert_eq!(a.finish(&msg2, c(NOW)).err(), Some(Error::Expired));

        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, c(NOW)).unwrap();
        let (_, msg2) = respond(&live(WORDS), &msg1, PB, c(NOW)).unwrap();
        assert!(a.finish(&msg2, c(NOW)).is_ok());
        assert_eq!(a.finish(&msg2, c(NOW)).err(), Some(Error::Expired));
    }

    #[test]
    fn a_listener_answers_max_answers_msg1_then_stops() {
        let invitation = live(WORDS);
        let mut listener = Listener::new(&invitation);
        let (_, msg1) = Initiator::start(&invitation, PA, c(NOW)).unwrap();
        // A malformed msg1 gets no answer, so it does not count.
        assert_eq!(
            listener.respond(&msg1[1..], PB, c(NOW)).err(),
            Some(Error::Rejected)
        );
        for _ in 0..MAX_ANSWERS {
            assert!(listener.respond(&msg1, PB, c(NOW)).is_ok());
        }
        assert_eq!(
            listener.respond(&msg1, PB, c(NOW)).err(),
            Some(Error::Expired)
        );
    }

    #[test]
    fn saved_steps_resume_with_their_counters() {
        let config = Config::new(&Profile::NEARBY).with_max_answers(2).unwrap();
        let invitation = Invitation::live(WORDS, CTX, &config).unwrap();
        let (a, msg1) = Initiator::start(&invitation, PA, c(NOW)).unwrap();
        let mut listener = Listener::from_bytes(&Listener::new(&invitation).to_bytes()).unwrap();
        let (b, msg2) = listener.respond(&msg1, PB, c(NOW)).unwrap();
        let (_, guess) = respond(&live(WRONG), &msg1, PB, c(NOW)).unwrap();

        let mut a = Initiator::from_bytes(&a.to_bytes()).unwrap();
        assert_eq!(a.finish(&guess, c(NOW)).err(), Some(Error::Rejected));
        let saved = a.to_bytes();
        let b = Responder::from_bytes(&b.to_bytes()).unwrap();
        let (ua, msg3) = a.finish(&msg2, c(NOW)).unwrap();
        // The state saved before finish gives the same msg3 again.
        let (_, again) = Initiator::from_bytes(&saved)
            .unwrap()
            .finish(&msg2, c(NOW))
            .unwrap();
        assert_eq!(msg3, again);
        let ub = b.finish(&msg3, c(NOW)).unwrap();
        assert!(ua.verify(&ub.safety_words(), c(NOW)).is_ok());

        // One wrong msg2 and one msg1 answered were saved: one more each, then Expired.
        let mut a = Initiator::from_bytes(&saved).unwrap();
        assert_eq!(a.finish(&guess, c(NOW)).err(), Some(Error::Rejected));
        assert_eq!(a.finish(&msg2, c(NOW)).err(), Some(Error::Expired));
        let mut listener = Listener::from_bytes(&listener.to_bytes()).unwrap();
        assert!(listener.respond(&msg1, PB, c(NOW)).is_ok());
        assert_eq!(
            listener.respond(&msg1, PB, c(NOW)).err(),
            Some(Error::Expired)
        );
    }

    #[test]
    fn a_restored_step_dies_by_the_wall_clock_after_a_restart() {
        let (a, msg1) = Initiator::start(&live(WORDS), PA, c(NOW)).unwrap();
        let (_, msg2) = respond(&live(WORDS), &msg1, PB, c(NOW)).unwrap();
        let saved = a.to_bytes();
        // The monotonic clock started over at 0.
        let restarted = |now_unix| Clock { now: 5, now_unix };
        let mut a = Initiator::from_bytes(&saved).unwrap();
        assert_eq!(
            a.finish(&msg2, restarted(AT + TTL + 1)).err(),
            Some(Error::Expired)
        );
        assert!(a.finish(&msg2, restarted(AT + TTL)).is_ok());
    }

    #[test]
    fn malformed_state_rejected() {
        let invitation = live(WORDS);
        let (a, msg1) = Initiator::start(&invitation, PA, c(NOW)).unwrap();
        let (b, _) = respond(&invitation, &msg1, PB, c(NOW)).unwrap();
        let states = [
            (a.to_bytes(), Initiator::from_bytes(&[]).err()),
            (b.to_bytes(), Responder::from_bytes(&[]).err()),
            (
                Listener::new(&invitation).to_bytes(),
                Listener::from_bytes(&[]).err(),
            ),
        ];
        // Restores and saves again.
        let resave = |kind: usize, bytes: &[u8]| match kind {
            0 => Initiator::from_bytes(bytes).map(|s| s.to_bytes()),
            1 => Responder::from_bytes(bytes).map(|s| s.to_bytes()),
            _ => Listener::from_bytes(bytes).map(|s| s.to_bytes()),
        };
        let parse = |kind, bytes: &[u8]| resave(kind, bytes).err();
        for (kind, (state, empty)) in states.iter().enumerate() {
            assert_eq!(*empty, Some(Error::Rejected));
            assert_eq!(resave(kind, state).unwrap(), *state);
            let mut longer = state.to_vec();
            longer.push(0);
            assert_eq!(parse(kind, &longer), Some(Error::Rejected));
            assert_eq!(
                parse(kind, &state[..state.len() - 1]),
                Some(Error::Rejected)
            );
            let mut version = state.to_vec();
            version[0] = STATE_VERSION + 1;
            assert_eq!(parse(kind, &version), Some(Error::Rejected));
            assert_eq!(parse((kind + 1) % 3, state), Some(Error::Rejected));
        }
    }

    proptest! {
        #[test]
        fn any_payload_up_to_the_ceiling_completes(
            pa in prop::collection::vec(any::<u8>(), 0..=PAYLOAD_CEILING),
            pb in prop::collection::vec(any::<u8>(), 0..=PAYLOAD_CEILING),
        ) {
            let config = Config::new(&Profile::PQ_MESSENGER)
                .with_max_payload(PAYLOAD_CEILING)
                .unwrap();
            let invitation = Invitation::live(WORDS, CTX, &config).unwrap();
            let (mut a, msg1) = Initiator::start(&invitation, &pa, c(NOW)).unwrap();
            let (b, msg2) = respond(&invitation, &msg1, &pb, c(NOW)).unwrap();
            let (a, msg3) = a.finish(&msg2, c(NOW)).unwrap();
            let b = b.finish(&msg3, c(NOW)).unwrap();
            let a = a.verify(&b.safety_words(), c(NOW)).unwrap();
            let b = b.confirm(c(NOW)).unwrap();
            prop_assert_eq!(a.key(), b.key());
            prop_assert_eq!((a.peer_payload(), b.peer_payload()), (&pb[..], &pa[..]));
        }

        #[test]
        fn any_altered_byte_rejected(msg in 1..=3usize, at: prop::sample::Index, xor in 1..=u8::MAX) {
            let alter = |m: usize, buf: &mut Vec<u8>| {
                if m == msg {
                    let at = at.index(buf.len());
                    buf[at] ^= xor;
                }
            };
            prop_assert_eq!(run(WORDS, alter).err(), Some(Error::Rejected));
        }
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
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, c(NOW)).unwrap();
        let (b, _) = respond(&live(WORDS), &msg1, PB, c(NOW)).unwrap();
        assert_eq!(a.finish(&[], c(NOW)).err(), Some(Error::Rejected));
        assert_eq!(
            a.finish(&vec![0; msg2_len(PAYLOAD_CEILING) + 1], c(NOW))
                .err(),
            Some(Error::Rejected)
        );
        assert_eq!(
            b.finish(&[0; NONCE_LEN + TAG_LEN - 1], c(NOW)).err(),
            Some(Error::Rejected)
        );
    }

    #[test]
    fn each_side_expires_its_own_step_on_its_own_clock() {
        const B_CLOCK: u64 = 42;
        let (mut a, msg1) = Initiator::start(&live(WORDS), PA, c(NOW)).unwrap();
        let (b, msg2) = respond(&live(WORDS), &msg1, PB, c(B_CLOCK)).unwrap();
        assert_eq!(
            a.finish(&msg2, c(NOW + TTL + 1)).err(),
            Some(Error::Expired)
        );
        let (a, msg3) = a.finish(&msg2, c(NOW + TTL)).unwrap();
        assert_eq!(
            b.finish(&msg3, c(B_CLOCK + TTL + 1)).err(),
            Some(Error::Expired)
        );
        let b = b.finish(&msg3, c(B_CLOCK + TTL)).unwrap();
        let words = b.safety_words();
        assert_eq!(
            a.verify(&words, c(NOW + TTL + 1)).err(),
            Some(Error::Expired)
        );
        assert!(a.verify(&words, c(NOW + TTL)).is_ok());
        assert_eq!(b.confirm(c(B_CLOCK + TTL + 1)).err(), Some(Error::Expired));
    }

    #[test]
    fn bad_words_rejected_up_front() {
        for words in ["my dog is called max now", "alpha", ""] {
            assert_eq!(
                Invitation::live(words, CTX, &CFG).err(),
                Some(Error::BadWords)
            );
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
        let other = Invitation::live(WORDS, b"other", &CFG).unwrap();
        assert_ne!(other.rendezvous(), id);
        let tag = crypto::hkdf::<RENDEZVOUS_TAG_LEN>(CTX, WORDS.as_bytes(), LABEL_RENDEZVOUS_TAG);
        assert_eq!(*crypto::hkdf(CTX, &*tag, LABEL_RENDEZVOUS), id);
    }

    /// Checks that `with` takes a setting's bounds and refuses one unit beyond them.
    fn check_range<T>(bounds: Bounded<T>, unit: T, with: impl Fn(T) -> Result<Config, Error>)
    where
        T: Copy + Default + PartialEq + Add<Output = T> + Sub<Output = T>,
    {
        for value in [bounds.min, bounds.default, bounds.max] {
            assert!(with(value).is_ok());
        }
        assert_eq!(with(bounds.max + unit).err(), Some(Error::OutOfRange));
        if bounds.min != T::default() {
            assert_eq!(with(bounds.min - unit).err(), Some(Error::OutOfRange));
        }
    }

    #[test]
    fn settings_stay_within_their_profile() {
        let second = Duration::from_secs(1);
        for profile in PROFILES {
            let config = Config::new(profile);
            check_range(profile.invite_ttl, second, |v| config.with_invite_ttl(v));
            check_range(profile.max_answers, 1, |v| config.with_max_answers(v));
            check_range(profile.max_payload, 1, |v| config.with_max_payload(v));
            check_range(profile.appointment_window, second, |v| {
                config.with_appointment_window(v)
            });
        }
        assert_eq!(CFG.guess_bound_log2(), -36);
        assert_eq!(Config::new(&Profile::NEARBY).guess_bound_log2(), -40);
        let custom = CFG.with_invite_ttl(Duration::from_secs(120)).unwrap();
        let (a, _) =
            Initiator::start(&Invitation::live(WORDS, CTX, &custom).unwrap(), PA, c(NOW)).unwrap();
        assert_eq!(a.deadline(), NOW + 120);
    }

    const WORDS_A: &str = "alpha cable echo forest orbit";
    const WORDS_B: &str = "velvet stone happy river";
    const AT: u64 = 1_900_000_000;
    const DAY: u64 = 24 * 3600;

    fn appointment(words_b: &str, at: u64, now_unix: u64) -> Result<Invitation, Error> {
        Invitation::appointment(WORDS_A, words_b, at, CTX, now_unix, &CFG)
    }

    fn token(words: &str, token: &[u8; TOKEN_LEN], now_unix: u64) -> Result<Invitation, Error> {
        Invitation::physical_token(words, token, CTX, now_unix, &CFG)
    }

    /// Runs a handshake between two invitations, every step at `clock`.
    fn complete(
        a: &Invitation,
        b: &Invitation,
        clock: Clock,
    ) -> Result<(Established, Established), Error> {
        let (mut ia, msg1) = Initiator::start(a, PA, clock)?;
        let (rb, msg2) = respond(b, &msg1, PB, clock)?;
        let (ua, msg3) = ia.finish(&msg2, clock)?;
        let ub = rb.finish(&msg3, clock)?;
        Ok((ua.verify(&ub.safety_words(), clock)?, ub.confirm(clock)?))
    }

    #[test]
    fn every_pair_of_profiles_completes_in_every_mode() {
        let secret = new_physical_token(3600, AT).unwrap();
        for pa in PROFILES {
            for pb in PROFILES {
                let pair = |config: &Config| {
                    [
                        Invitation::live(WORDS, CTX, config).unwrap(),
                        Invitation::appointment(WORDS_A, WORDS_B, AT, CTX, AT, config).unwrap(),
                        Invitation::physical_token(WORDS, &secret, CTX, AT, config).unwrap(),
                    ]
                };
                let (a, b) = (pair(&Config::new(pa)), pair(&Config::new(pb)));
                for (a, b) in a.iter().zip(&b) {
                    let (a, b) = complete(a, b, c(NOW)).unwrap();
                    assert_eq!(a.key(), b.key(), "{} with {}", pa.name, pb.name);
                }
            }
        }
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
            &CFG,
        )
        .unwrap();
        assert_eq!(a.rendezvous(), b.rendezvous());
        let (a, b) = complete(&a, &b, wall(AT + 1799)).unwrap();
        assert_eq!(a.key(), b.key());
        assert_eq!((a.peer_payload(), b.peer_payload()), (PB, PA));
    }

    #[test]
    fn an_appointment_outside_its_window_fails() {
        for now_unix in [0, AT - 1, AT + WINDOW + 1, u64::MAX] {
            assert_eq!(
                appointment(WORDS_B, AT, now_unix).err(),
                Some(Error::Expired)
            );
        }
        assert!(appointment(WORDS_B, AT, AT + WINDOW).is_ok());

        // A step started near the end dies with the window, not invite_ttl later.
        let late = appointment(WORDS_B, AT, AT + WINDOW - 5).unwrap();
        let (mut a, msg1) = Initiator::start(&late, PA, wall(AT + WINDOW - 5)).unwrap();
        assert_eq!(a.deadline(), NOW + 5);
        let (b, msg2) = respond(&late, &msg1, PB, wall(AT + WINDOW - 5)).unwrap();
        assert_eq!(b.deadline(), NOW + 5);
        let after = Clock {
            now: NOW + 6,
            now_unix: AT + WINDOW - 5,
        };
        assert_eq!(a.finish(&msg2, after).err(), Some(Error::Expired));
    }

    #[test]
    fn an_appointment_built_inside_its_window_stops_working_when_it_closes() {
        let invitation = appointment(WORDS_B, AT, AT).unwrap();
        let closed = wall(AT + WINDOW + 1);
        assert_eq!(
            Initiator::start(&invitation, PA, closed).err(),
            Some(Error::Expired)
        );
        let (mut a, msg1) = Initiator::start(&invitation, PA, wall(AT)).unwrap();
        assert_eq!(
            respond(&invitation, &msg1, PB, closed).err(),
            Some(Error::Expired)
        );
        // Three days later, with a monotonic clock that stopped while the device slept.
        let (b, msg2) = respond(&invitation, &msg1, PB, wall(AT)).unwrap();
        assert_eq!(
            a.finish(&msg2, wall(AT + 3 * DAY)).err(),
            Some(Error::Expired)
        );
        let (_, msg3) = a.finish(&msg2, wall(AT)).unwrap();
        assert_eq!(b.finish(&msg3, closed).err(), Some(Error::Expired));
    }

    #[test]
    fn appointments_at_other_times_or_with_other_words_never_complete() {
        let a = appointment(WORDS_B, AT, AT).unwrap();
        let other_time = appointment(WORDS_B, AT + 60, AT + 60).unwrap();
        assert_ne!(a.rendezvous(), other_time.rendezvous());
        assert_eq!(
            complete(&a, &other_time, wall(AT + 60)).err(),
            Some(Error::Rejected)
        );
        let wrong_b = appointment("velvet stone happy zoo", AT, AT).unwrap();
        assert_eq!(complete(&a, &wrong_b, c(NOW)).err(), Some(Error::Rejected));
        // The same 9 words split differently are another password.
        let split = Invitation::appointment(
            "alpha cable echo forest",
            "orbit velvet stone happy",
            AT,
            CTX,
            AT,
            &CFG,
        );
        assert_eq!(split.err(), Some(Error::BadWords));
        // A live invitation never meets an appointment, even with the same context.
        let live = live(WORDS);
        assert_eq!(complete(&live, &a, c(NOW)).err(), Some(Error::Rejected));
    }

    #[test]
    fn the_appointment_rendezvous_reveals_nothing_about_b_words() {
        let id = appointment(WORDS_B, AT, AT).unwrap().rendezvous();
        assert_eq!(
            appointment("zoo zoo zoo zoo", AT, AT).unwrap().rendezvous(),
            id
        );
        let other_a =
            Invitation::appointment("alpha cable echo forest zoo", WORDS_B, AT, CTX, AT, &CFG);
        assert_ne!(other_a.unwrap().rendezvous(), id);
        assert_eq!(
            appointment("velvet stone happy", AT, AT).err(),
            Some(Error::BadWords)
        );
    }

    #[test]
    fn a_physical_token_works_until_it_expires() {
        let secret = new_physical_token(3600, AT).unwrap();
        assert_eq!(&secret[TOKEN_SECRET_LEN..], &(AT + 3600).to_be_bytes());
        let a = token(WORDS, &secret, AT).unwrap();
        let b = token(WORDS, &secret, AT + 3600).unwrap();
        assert_eq!(a.rendezvous(), b.rendezvous());
        // B read the token and starts; A only answers.
        let (b, a) = complete(&b, &a, wall(AT + 3600)).unwrap();
        assert_eq!(a.key(), b.key());
        assert_eq!((b.peer_payload(), a.peer_payload()), (PB, PA));

        assert_eq!(token(WORDS, &secret, AT + 3601).err(), Some(Error::Expired));
        // A step started near expiry dies with the token.
        let late = token(WORDS, &secret, AT + 3598).unwrap();
        let (a, _) = Initiator::start(&late, PA, wall(AT + 3598)).unwrap();
        assert_eq!(a.deadline(), NOW + 2);
    }

    #[test]
    fn a_physical_token_lives_exactly_its_lifetime() {
        let secret = new_physical_token(90 * DAY, AT).unwrap();
        let invitation = token(WORDS, &secret, AT).unwrap();
        // Kept in memory since day 0, it still completes on day 89...
        assert!(complete(&invitation, &invitation, wall(AT + 89 * DAY)).is_ok());
        // ...and no longer once the token has expired.
        assert_eq!(
            complete(&invitation, &invitation, wall(AT + 90 * DAY + 1)).err(),
            Some(Error::Expired)
        );
        assert!(new_physical_token(u64::MAX - AT, AT).is_ok());
        assert_eq!(
            new_physical_token(u64::MAX, AT).err(),
            Some(Error::OutOfRange)
        );
    }

    #[test]
    fn a_physical_token_needs_the_words_too() {
        let secret = new_physical_token(3600, AT).unwrap();
        let a = token(WORDS, &secret, AT).unwrap();
        let other_token = token(WORDS, &new_physical_token(3600, AT).unwrap(), AT).unwrap();
        assert_ne!(a.rendezvous(), other_token.rendezvous());
        assert_eq!(
            complete(&other_token, &a, c(NOW)).err(),
            Some(Error::Rejected)
        );
        let wrong_words = token(WRONG, &secret, AT).unwrap();
        assert_eq!(a.rendezvous(), wrong_words.rendezvous());
        assert_eq!(
            complete(&wrong_words, &a, c(NOW)).err(),
            Some(Error::Rejected)
        );
        // A token whose expiry was rewritten is another token.
        let mut moved = *secret;
        moved[TOKEN_LEN - 1] ^= 1;
        let moved = token(WORDS, &moved, AT).unwrap();
        assert_eq!(complete(&moved, &a, c(NOW)).err(), Some(Error::Rejected));
        assert_eq!(token("alpha", &secret, AT).err(), Some(Error::BadWords));
    }
}
