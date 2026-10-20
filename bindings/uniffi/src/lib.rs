//! Kotlin, Swift and Go bindings for [Nachalo](https://github.com/RamsisDev/Nachalo), through
//! UniFFI. Each item converts types and calls the `nachalo` crate, which documents the behavior.
//!
//! Secrets that cross into the foreign language (words, tokens, payloads, keys, exports) become
//! its own strings and byte arrays, which Rust's zeroizing does not reach: wipe them there if the
//! platform allows it. The objects wipe what they hold once released: call `close()` (Kotlin),
//! drop the last reference (Swift) or call `Destroy()` (Go) as soon as a step is done.

use std::sync::{Arc, Mutex};
use std::time::Duration;

uniffi::setup_scaffolding!("nachalo");

/// Why a step failed. On purpose, a rejected message does not say which check it failed.
#[derive(Debug, PartialEq, Eq, uniffi::Error)]
pub enum NachaloError {
    /// Not the expected number of words from the list.
    BadWords,
    /// Past its deadline, out of answers, already finished or confirmed, or outside the window
    /// of its appointment or physical token.
    Expired,
    /// More than this device's `max_payload` bytes.
    PayloadTooLarge,
    /// Malformed input or failed confirmation, with no further detail.
    Rejected,
    /// A setting outside its profile's range, or a token expiry past the end of time.
    OutOfRange,
    /// The OS random generator failed.
    Rng,
    /// A failure this version of the bindings does not know.
    Other,
}

impl std::fmt::Display for NachaloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for NachaloError {}

impl From<nachalo::Error> for NachaloError {
    fn from(error: nachalo::Error) -> Self {
        match error {
            nachalo::Error::BadWords => Self::BadWords,
            nachalo::Error::Expired => Self::Expired,
            nachalo::Error::PayloadTooLarge => Self::PayloadTooLarge,
            nachalo::Error::Rejected => Self::Rejected,
            nachalo::Error::OutOfRange => Self::OutOfRange,
            nachalo::Error::Rng => Self::Rng,
            _ => Self::Other,
        }
    }
}

type Result<T> = std::result::Result<T, NachaloError>;

/// Largest payload every receiver accepts.
#[uniffi::export]
pub fn payload_ceiling() -> u32 {
    nachalo::PAYLOAD_CEILING as u32
}

/// msg1 length, whatever the payload.
#[uniffi::export]
pub fn msg1_len() -> u32 {
    nachalo::MSG1_LEN as u32
}

/// msg2 length for a responder payload of `payload` bytes.
#[uniffi::export]
pub fn msg2_len(payload: u32) -> u32 {
    nachalo::msg2_len(payload as usize) as u32
}

/// msg3 length for an initiator payload of `payload` bytes.
#[uniffi::export]
pub fn msg3_len(payload: u32) -> u32 {
    nachalo::msg3_len(payload as usize) as u32
}

/// Length of `Invitation.rendezvous`.
#[uniffi::export]
pub fn rendezvous_len() -> u32 {
    nachalo::RENDEZVOUS_LEN as u32
}

/// Length of a physical token.
#[uniffi::export]
pub fn token_len() -> u32 {
    nachalo::TOKEN_LEN as u32
}

/// Words of a live or physical-token invitation.
#[uniffi::export]
pub fn word_count() -> u32 {
    nachalo::WORD_COUNT as u32
}

/// Words A draws for an appointment.
#[uniffi::export]
pub fn appointment_words_a() -> u32 {
    nachalo::APPOINTMENT_WORDS_A as u32
}

/// Words B draws for an appointment.
#[uniffi::export]
pub fn appointment_words_b() -> u32 {
    nachalo::APPOINTMENT_WORDS_B as u32
}

/// `count` random words from the list, separated by spaces. Secret: the returned string is not
/// zeroized.
#[uniffi::export]
pub fn words(count: u32) -> Result<String> {
    Ok(nachalo::words(count as usize)?.to_string())
}

/// A new physical token, valid for `lifetime` seconds from `now_unix`. Secret: the returned bytes
/// are not zeroized; erase them once the token expires.
#[uniffi::export]
pub fn new_physical_token(lifetime: u64, now_unix: u64) -> Result<Vec<u8>> {
    Ok(nachalo::new_physical_token(lifetime, now_unix)?.to_vec())
}

/// A named set of defaults and allowed ranges. Profiles are local: devices on different profiles
/// interoperate.
#[derive(uniffi::Enum)]
pub enum Profile {
    /// Chat or call, both online. The default.
    Interactive,
    /// Payloads up to the ceiling, for post-quantum keys and signatures.
    PqMessenger,
    /// QR, Bluetooth or LAN, side by side: short TTL, few answers.
    Nearby,
}

/// This device's limits: a profile and the values chosen within its ranges.
#[derive(uniffi::Object)]
pub struct Config(nachalo::Config);

#[uniffi::export]
impl Config {
    /// Every value at the profile's default.
    #[uniffi::constructor]
    pub fn new(profile: Profile) -> Self {
        Config(nachalo::Config::new(match profile {
            Profile::Interactive => &nachalo::Profile::INTERACTIVE,
            Profile::PqMessenger => &nachalo::Profile::PQ_MESSENGER,
            Profile::Nearby => &nachalo::Profile::NEARBY,
        }))
    }

    /// How long each pending step lives, in seconds.
    pub fn with_invite_ttl(&self, seconds: u64) -> Result<Arc<Config>> {
        Ok(Arc::new(Config(
            self.0.with_invite_ttl(Duration::from_secs(seconds))?,
        )))
    }

    /// Wrong msg2 taken as initiator, and msg1 answered as responder, per invitation.
    pub fn with_max_answers(&self, answers: u16) -> Result<Arc<Config>> {
        Ok(Arc::new(Config(self.0.with_max_answers(answers)?)))
    }

    /// Largest payload this device sends, in bytes.
    pub fn with_max_payload(&self, bytes: u32) -> Result<Arc<Config>> {
        Ok(Arc::new(Config(self.0.with_max_payload(bytes as usize)?)))
    }

    /// How long after its start time an appointment works, in seconds.
    pub fn with_appointment_window(&self, seconds: u64) -> Result<Arc<Config>> {
        Ok(Arc::new(Config(
            self.0
                .with_appointment_window(Duration::from_secs(seconds))?,
        )))
    }
}

/// The two clocks every step reads.
#[derive(Clone, Copy, uniffi::Record)]
pub struct Clock {
    /// Monotonic seconds that keep counting while the device sleeps.
    pub now: u64,
    /// Wall-clock Unix seconds.
    pub now_unix: u64,
}

impl From<Clock> for nachalo::Clock {
    fn from(clock: Clock) -> Self {
        nachalo::Clock {
            now: clock.now,
            now_unix: clock.now_unix,
        }
    }
}

/// Which side of the handshake a device played.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Role {
    /// A: sends msg1 and msg3, types the safety words.
    Initiator,
    /// B: sends msg2, shows the safety words.
    Responder,
}

impl From<nachalo::Role> for Role {
    fn from(role: nachalo::Role) -> Self {
        match role {
            nachalo::Role::Initiator => Role::Initiator,
            nachalo::Role::Responder => Role::Responder,
        }
    }
}

/// What both sides derive from the shared secret of one invitation. Holds the secret: release it
/// once both steps are done.
#[derive(uniffi::Object)]
pub struct Invitation(nachalo::Invitation);

#[uniffi::export]
impl Invitation {
    /// Live first contact from `word_count()` words.
    #[uniffi::constructor]
    pub fn live(words: String, context: Vec<u8>, config: Arc<Config>) -> Result<Self> {
        Ok(Invitation(nachalo::Invitation::live(
            &words, &context, &config.0,
        )?))
    }

    /// First contact at the Unix time `at`, from A's and B's words.
    #[uniffi::constructor]
    pub fn appointment(
        words_a: String,
        words_b: String,
        at: u64,
        context: Vec<u8>,
        now_unix: u64,
        config: Arc<Config>,
    ) -> Result<Self> {
        Ok(Invitation(nachalo::Invitation::appointment(
            &words_a, &words_b, at, &context, now_unix, &config.0,
        )?))
    }

    /// First contact through a physical token of `token_len()` bytes, `Rejected` otherwise.
    #[uniffi::constructor]
    pub fn physical_token(
        words: String,
        token: Vec<u8>,
        context: Vec<u8>,
        now_unix: u64,
        config: Arc<Config>,
    ) -> Result<Self> {
        let token = token
            .as_slice()
            .try_into()
            .map_err(|_| NachaloError::Rejected)?;
        Ok(Invitation(nachalo::Invitation::physical_token(
            &words, token, &context, now_unix, &config.0,
        )?))
    }

    /// Public id where the side that starts leaves msg1 and the other looks for it.
    pub fn rendezvous(&self) -> Vec<u8> {
        self.0.rendezvous().to_vec()
    }
}

/// A's pending handshake, from `start` until msg2 arrives. Holds secrets: release it once done.
#[derive(uniffi::Object)]
pub struct Initiator {
    state: Mutex<nachalo::Initiator>,
    msg1: Vec<u8>,
}

#[uniffi::export]
impl Initiator {
    /// Starts the handshake: send `msg1()` to the invitation's rendezvous. `payload` is secret
    /// until the safety words match.
    #[uniffi::constructor]
    pub fn start(invitation: Arc<Invitation>, payload: Vec<u8>, clock: Clock) -> Result<Self> {
        let (state, msg1) = nachalo::Initiator::start(&invitation.0, &payload, clock.into())?;
        Ok(Initiator {
            state: Mutex::new(state),
            msg1,
        })
    }

    /// The first message, to send to the rendezvous.
    pub fn msg1(&self) -> Vec<u8> {
        self.msg1.clone()
    }

    /// The last second on the monotonic clock this invitation may complete.
    pub fn deadline(&self) -> u64 {
        self.state.lock().unwrap().deadline()
    }

    /// Completes the handshake with B's msg2: send msg3 to B. A wrong msg2 leaves this
    /// initiator usable; once one succeeded, `Expired`.
    pub fn finish(&self, msg2: Vec<u8>, clock: Clock) -> Result<Finished> {
        let (unconfirmed, msg3) = self.state.lock().unwrap().finish(&msg2, clock.into())?;
        Ok(Finished {
            unconfirmed: Arc::new(unconfirmed.into()),
            msg3,
        })
    }
}

/// What `Initiator.finish` returns.
#[derive(uniffi::Record)]
pub struct Finished {
    /// The handshake, until the safety words are compared.
    pub unconfirmed: Arc<Unconfirmed>,
    /// The third message, to send to B.
    pub msg3: Vec<u8>,
}

/// B's side of one invitation: answers each msg1 found at its rendezvous, up to the config's
/// `max_answers`. Keep one per invitation. Holds the invitation's secret: release it once done.
#[derive(uniffi::Object)]
pub struct Listener(Mutex<nachalo::Listener>);

#[uniffi::export]
impl Listener {
    /// A listener with its own copy of `invitation`, which has answered nothing yet.
    #[uniffi::constructor]
    pub fn new(invitation: Arc<Invitation>) -> Self {
        Listener(Mutex::new(nachalo::Listener::new(&invitation.0)))
    }

    /// Answers `msg1`: send msg2 back to A. `payload` is secret until the safety words match.
    pub fn respond(&self, msg1: Vec<u8>, payload: Vec<u8>, clock: Clock) -> Result<Answer> {
        let (responder, msg2) = self
            .0
            .lock()
            .unwrap()
            .respond(&msg1, &payload, clock.into())?;
        Ok(Answer {
            responder: Arc::new(Responder(responder)),
            msg2,
        })
    }
}

/// What `Listener.respond` returns.
#[derive(uniffi::Record)]
pub struct Answer {
    /// The pending answer, until msg3 arrives.
    pub responder: Arc<Responder>,
    /// The second message, to send back to A.
    pub msg2: Vec<u8>,
}

/// B's answer to one msg1, until msg3 arrives. Holds secrets: release it once done.
#[derive(uniffi::Object)]
pub struct Responder(nachalo::Responder);

#[uniffi::export]
impl Responder {
    /// The last second on the monotonic clock this answer may complete.
    pub fn deadline(&self) -> u64 {
        self.0.deadline()
    }

    /// Completes the handshake with A's msg3. A forged msg3 leaves this answer usable.
    pub fn finish(&self, msg3: Vec<u8>, clock: Clock) -> Result<Arc<Unconfirmed>> {
        Ok(Arc::new(self.0.finish(&msg3, clock.into())?.into()))
    }
}

/// A finished handshake whose safety words nobody has compared yet. Holds the key: release it
/// once done.
#[derive(uniffi::Object)]
pub struct Unconfirmed {
    role: Role,
    /// `None` once `confirm` consumed it.
    state: Mutex<Option<nachalo::Unconfirmed>>,
}

impl From<nachalo::Unconfirmed> for Unconfirmed {
    fn from(unconfirmed: nachalo::Unconfirmed) -> Self {
        Unconfirmed {
            role: unconfirmed.role().into(),
            state: Mutex::new(Some(unconfirmed)),
        }
    }
}

#[uniffi::export]
impl Unconfirmed {
    /// Which side this device played.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Four words, equal on both sides unless someone sits in the middle. B shows them, A types
    /// them. `Expired` once confirmed.
    pub fn safety_words(&self) -> Result<String> {
        let state = self.state.lock().unwrap();
        Ok(state
            .as_ref()
            .ok_or(NachaloError::Expired)?
            .safety_words()
            .to_string())
    }

    /// A: opens the session once the user types the safety words B shows. A mismatch leaves it
    /// pending until the deadline.
    pub fn verify(&self, typed: String, clock: Clock) -> Result<Arc<Established>> {
        let state = self.state.lock().unwrap();
        let unconfirmed = state.as_ref().ok_or(NachaloError::Expired)?;
        Ok(Arc::new(Established(
            unconfirmed.verify(&typed, clock.into())?,
        )))
    }

    /// B: opens the session once A says the safety words matched. Consumes this object, as in
    /// Rust: any later call returns `Expired`.
    pub fn confirm(&self, clock: Clock) -> Result<Arc<Established>> {
        let unconfirmed = self.state.lock().unwrap().take();
        let unconfirmed = unconfirmed.ok_or(NachaloError::Expired)?;
        Ok(Arc::new(Established(unconfirmed.confirm(clock.into())?)))
    }
}

/// What both sides share once the safety words matched. Holds the key: release it once done.
#[derive(uniffi::Object)]
pub struct Established(nachalo::Established);

#[uniffi::export]
impl Established {
    /// Which side this device played.
    pub fn role(&self) -> Role {
        self.0.role().into()
    }

    /// The shared secret, 32 bytes, equal on both sides. Secret: the returned bytes are not
    /// zeroized; prefer `export`.
    pub fn key(&self) -> Vec<u8> {
        self.0.key().to_vec()
    }

    /// Hash of the whole handshake, equal on both sides; public, good for channel binding.
    pub fn transcript(&self) -> Vec<u8> {
        self.0.transcript().to_vec()
    }

    /// The payload the other side sent. The returned bytes are not zeroized.
    pub fn peer_payload(&self) -> Vec<u8> {
        self.0.peer_payload().to_vec()
    }

    /// An independent 32-byte key for `label`, equal on both sides. Secret: the returned bytes
    /// are not zeroized.
    pub fn export(&self, label: Vec<u8>) -> Vec<u8> {
        self.0.export(&label).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS: &str = "alpha cable echo forest orbit velvet";
    const WRONG: &str = "alpha cable echo forest orbit zoo";
    const CLOCK: Clock = Clock {
        now: 0,
        now_unix: 1_900_000_000,
    };

    fn live(words: &str) -> Arc<Invitation> {
        let config = Arc::new(Config::new(Profile::Interactive));
        Arc::new(Invitation::live(words.into(), b"test".to_vec(), config).unwrap())
    }

    #[test]
    fn every_error_maps_to_its_variant() {
        use nachalo::Error as E;
        for (core, ours) in [
            (E::BadWords, NachaloError::BadWords),
            (E::Expired, NachaloError::Expired),
            (E::PayloadTooLarge, NachaloError::PayloadTooLarge),
            (E::Rejected, NachaloError::Rejected),
            (E::OutOfRange, NachaloError::OutOfRange),
            (E::Rng, NachaloError::Rng),
        ] {
            assert_eq!(NachaloError::from(core), ours);
        }
        assert_eq!(words(5).err(), None);
        assert_eq!(words(3).unwrap().split(' ').count(), 3);
        let bad = Invitation::live(
            "one two".into(),
            vec![],
            Arc::new(Config::new(Profile::Nearby)),
        );
        assert_eq!(bad.err(), Some(NachaloError::BadWords));
        let config = Config::new(Profile::Nearby);
        assert_eq!(
            config.with_max_answers(1000).err(),
            Some(NachaloError::OutOfRange)
        );
        assert_eq!(
            new_physical_token(u64::MAX, 1).err(),
            Some(NachaloError::OutOfRange)
        );
    }

    #[test]
    fn a_live_handshake_runs_through_the_bindings() {
        let invitation = live(WORDS);
        assert_eq!(invitation.rendezvous().len() as u32, rendezvous_len());
        let a = Initiator::start(invitation.clone(), b"A".to_vec(), CLOCK).unwrap();
        assert_eq!(a.msg1().len() as u32, msg1_len());
        let listener = Listener::new(live(WORDS));
        let answer = listener.respond(a.msg1(), b"B".to_vec(), CLOCK).unwrap();
        assert_eq!(answer.msg2.len() as u32, msg2_len(1));

        // A bogus msg2 leaves A usable.
        let guess = Listener::new(live(WRONG))
            .respond(a.msg1(), b"B".to_vec(), CLOCK)
            .unwrap();
        assert_eq!(
            a.finish(guess.msg2, CLOCK).err(),
            Some(NachaloError::Rejected)
        );

        let finished = a.finish(answer.msg2.clone(), CLOCK).unwrap();
        assert_eq!(
            a.finish(answer.msg2, CLOCK).err(),
            Some(NachaloError::Expired)
        );
        let b = answer.responder.finish(finished.msg3, CLOCK).unwrap();
        let shown = b.safety_words().unwrap();
        let a = finished.unconfirmed.verify(shown, CLOCK).unwrap();
        let established_b = b.confirm(CLOCK).unwrap();

        // confirm consumed b.
        assert_eq!(b.confirm(CLOCK).err(), Some(NachaloError::Expired));
        assert_eq!(b.safety_words().err(), Some(NachaloError::Expired));
        assert_eq!(b.role(), Role::Responder);

        assert_eq!(a.key(), established_b.key());
        assert_eq!(a.export(b"x".to_vec()), established_b.export(b"x".to_vec()));
        assert_eq!(
            (a.peer_payload(), established_b.peer_payload()),
            (b"B".to_vec(), b"A".to_vec())
        );
        assert_eq!(a.role(), Role::Initiator);
    }

    #[test]
    fn a_token_of_the_wrong_length_is_rejected() {
        let token = new_physical_token(3600, CLOCK.now_unix).unwrap();
        assert_eq!(token.len() as u32, token_len());
        let config = Arc::new(Config::new(Profile::Interactive));
        let build = |token: Vec<u8>| {
            Invitation::physical_token(WORDS.into(), token, vec![], CLOCK.now_unix, config.clone())
        };
        assert!(build(token.clone()).is_ok());
        assert_eq!(
            build(token[1..].to_vec()).err(),
            Some(NachaloError::Rejected)
        );
    }
}
