//! TypeScript and JavaScript bindings for [Nachalo](https://github.com/RamsisDev/Nachalo), through
//! wasm-bindgen. Each item converts types and calls the `nachalo` crate, which documents the
//! behavior.
//!
//! Secrets that cross into JavaScript (words, tokens, payloads, keys, exports) become its own
//! strings and `Uint8Array`s, which Rust's zeroizing does not reach, and neither does the copy of
//! each argument in WebAssembly memory. The objects wipe what they hold once released: call
//! `free()` (or use `using`) as soon as a step is done.

use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;

type Result<T> = std::result::Result<T, JsValue>;

#[wasm_bindgen(typescript_custom_section)]
const ERROR_KIND: &str = r#"
/**
 * Every fallible call throws an `Error` named "NachaloError" whose `message` is one of these.
 * On purpose, "Rejected" does not say which check failed; "Other" is a failure this version of
 * the bindings does not know.
 */
export type NachaloErrorKind =
  "BadWords" | "Expired" | "PayloadTooLarge" | "Rejected" | "OutOfRange" | "Rng" | "Other";
"#;

fn kind(error: nachalo::Error) -> &'static str {
    match error {
        nachalo::Error::BadWords => "BadWords",
        nachalo::Error::Expired => "Expired",
        nachalo::Error::PayloadTooLarge => "PayloadTooLarge",
        nachalo::Error::Rejected => "Rejected",
        nachalo::Error::OutOfRange => "OutOfRange",
        nachalo::Error::Rng => "Rng",
        _ => "Other",
    }
}

fn error(error: nachalo::Error) -> JsValue {
    let thrown = js_sys::Error::new(kind(error));
    thrown.set_name("NachaloError");
    thrown.into()
}

/// A pair returned to JavaScript as a two-element array.
fn pair(first: impl Into<JsValue>, bytes: &[u8]) -> Array {
    Array::of2(&first.into(), &Uint8Array::from(bytes))
}

/// Largest payload every receiver accepts.
#[wasm_bindgen(js_name = payloadCeiling)]
pub fn payload_ceiling() -> usize {
    nachalo::PAYLOAD_CEILING
}

/// msg1 length, whatever the payload.
#[wasm_bindgen(js_name = msg1Len)]
pub fn msg1_len() -> usize {
    nachalo::MSG1_LEN
}

/// msg2 length for a responder payload of `payload` bytes.
#[wasm_bindgen(js_name = msg2Len)]
pub fn msg2_len(payload: usize) -> usize {
    nachalo::msg2_len(payload)
}

/// msg3 length for an initiator payload of `payload` bytes.
#[wasm_bindgen(js_name = msg3Len)]
pub fn msg3_len(payload: usize) -> usize {
    nachalo::msg3_len(payload)
}

/// Length of `Invitation.rendezvous()`.
#[wasm_bindgen(js_name = rendezvousLen)]
pub fn rendezvous_len() -> usize {
    nachalo::RENDEZVOUS_LEN
}

/// Length of a physical token.
#[wasm_bindgen(js_name = tokenLen)]
pub fn token_len() -> usize {
    nachalo::TOKEN_LEN
}

/// Words of a live or physical-token invitation.
#[wasm_bindgen(js_name = wordCount)]
pub fn word_count() -> usize {
    nachalo::WORD_COUNT
}

/// Words A draws for an appointment.
#[wasm_bindgen(js_name = appointmentWordsA)]
pub fn appointment_words_a() -> usize {
    nachalo::APPOINTMENT_WORDS_A
}

/// Words B draws for an appointment.
#[wasm_bindgen(js_name = appointmentWordsB)]
pub fn appointment_words_b() -> usize {
    nachalo::APPOINTMENT_WORDS_B
}

/// `count` random words from the list, separated by spaces. Secret: the returned string is not
/// zeroized.
#[wasm_bindgen]
pub fn words(count: usize) -> Result<String> {
    Ok(nachalo::words(count).map_err(error)?.to_string())
}

/// A new physical token, valid for `lifetime` seconds from `nowUnix`. Secret: the returned bytes
/// are not zeroized; erase them once the token expires.
#[wasm_bindgen(js_name = newPhysicalToken)]
pub fn new_physical_token(
    lifetime: u64,
    #[wasm_bindgen(js_name = nowUnix)] now_unix: u64,
) -> Result<Vec<u8>> {
    Ok(nachalo::new_physical_token(lifetime, now_unix)
        .map_err(error)?
        .to_vec())
}

/// A named set of defaults and allowed ranges. Profiles are local: devices on different profiles
/// interoperate.
#[wasm_bindgen]
pub enum Profile {
    /// Chat or call, both online. The default.
    Interactive,
    /// Payloads up to the ceiling, for post-quantum keys and signatures.
    PqMessenger,
    /// QR, Bluetooth or LAN, side by side: short TTL, few answers.
    Nearby,
}

/// This device's limits: a profile and the values chosen within its ranges.
#[wasm_bindgen]
pub struct Config(nachalo::Config);

#[wasm_bindgen]
impl Config {
    /// Every value at the profile's default.
    #[wasm_bindgen(constructor)]
    pub fn new(profile: Profile) -> Config {
        Config(nachalo::Config::new(match profile {
            Profile::Interactive => &nachalo::Profile::INTERACTIVE,
            Profile::PqMessenger => &nachalo::Profile::PQ_MESSENGER,
            Profile::Nearby => &nachalo::Profile::NEARBY,
        }))
    }

    /// How long each pending step lives, in seconds.
    #[wasm_bindgen(js_name = withInviteTtl)]
    pub fn with_invite_ttl(&self, seconds: u64) -> Result<Config> {
        let ttl = std::time::Duration::from_secs(seconds);
        Ok(Config(self.0.with_invite_ttl(ttl).map_err(error)?))
    }

    /// Wrong msg2 taken as initiator, and msg1 answered as responder, per invitation.
    #[wasm_bindgen(js_name = withMaxAnswers)]
    pub fn with_max_answers(&self, answers: u16) -> Result<Config> {
        Ok(Config(self.0.with_max_answers(answers).map_err(error)?))
    }

    /// Largest payload this device sends, in bytes.
    #[wasm_bindgen(js_name = withMaxPayload)]
    pub fn with_max_payload(&self, bytes: usize) -> Result<Config> {
        Ok(Config(self.0.with_max_payload(bytes).map_err(error)?))
    }

    /// How long after its start time an appointment works, in seconds.
    #[wasm_bindgen(js_name = withAppointmentWindow)]
    pub fn with_appointment_window(&self, seconds: u64) -> Result<Config> {
        let window = std::time::Duration::from_secs(seconds);
        Ok(Config(
            self.0.with_appointment_window(window).map_err(error)?,
        ))
    }
}

/// The two clocks every step reads.
#[wasm_bindgen]
#[derive(Clone, Copy)]
pub struct Clock {
    /// Monotonic seconds that keep counting while the device sleeps.
    pub now: u64,
    /// Wall-clock Unix seconds.
    #[wasm_bindgen(js_name = nowUnix)]
    pub now_unix: u64,
}

#[wasm_bindgen]
impl Clock {
    /// A clock reading.
    #[wasm_bindgen(constructor)]
    pub fn new(now: u64, #[wasm_bindgen(js_name = nowUnix)] now_unix: u64) -> Clock {
        Clock { now, now_unix }
    }
}

impl From<&Clock> for nachalo::Clock {
    fn from(clock: &Clock) -> Self {
        nachalo::Clock {
            now: clock.now,
            now_unix: clock.now_unix,
        }
    }
}

/// Which side of the handshake a device played.
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// What both sides derive from the shared secret of one invitation. Holds the secret: free it
/// once both steps are done.
#[wasm_bindgen]
pub struct Invitation(nachalo::Invitation);

#[wasm_bindgen]
impl Invitation {
    /// Live first contact from `wordCount()` words.
    pub fn live(words: &str, context: &[u8], config: &Config) -> Result<Invitation> {
        let invitation = nachalo::Invitation::live(words, context, &config.0).map_err(error)?;
        Ok(Invitation(invitation))
    }

    /// First contact at the Unix time `at`, from A's and B's words.
    pub fn appointment(
        #[wasm_bindgen(js_name = wordsA)] words_a: &str,
        #[wasm_bindgen(js_name = wordsB)] words_b: &str,
        at: u64,
        context: &[u8],
        #[wasm_bindgen(js_name = nowUnix)] now_unix: u64,
        config: &Config,
    ) -> Result<Invitation> {
        let invitation =
            nachalo::Invitation::appointment(words_a, words_b, at, context, now_unix, &config.0)
                .map_err(error)?;
        Ok(Invitation(invitation))
    }

    /// First contact through a physical token of `tokenLen()` bytes, "Rejected" otherwise.
    #[wasm_bindgen(js_name = physicalToken)]
    pub fn physical_token(
        words: &str,
        token: &[u8],
        context: &[u8],
        #[wasm_bindgen(js_name = nowUnix)] now_unix: u64,
        config: &Config,
    ) -> Result<Invitation> {
        let token = token
            .try_into()
            .map_err(|_| error(nachalo::Error::Rejected))?;
        let invitation =
            nachalo::Invitation::physical_token(words, token, context, now_unix, &config.0)
                .map_err(error)?;
        Ok(Invitation(invitation))
    }

    /// Public id where the side that starts leaves msg1 and the other looks for it.
    pub fn rendezvous(&self) -> Vec<u8> {
        self.0.rendezvous().to_vec()
    }
}

/// A's pending handshake, from `start` until msg2 arrives. Holds secrets: free it once done.
#[wasm_bindgen]
pub struct Initiator(nachalo::Initiator);

#[wasm_bindgen]
impl Initiator {
    /// Starts the handshake: send msg1 to the invitation's rendezvous. `payload` is secret until
    /// the safety words match.
    #[wasm_bindgen(unchecked_return_type = "[Initiator, Uint8Array]")]
    pub fn start(invitation: &Invitation, payload: &[u8], clock: &Clock) -> Result<Array> {
        let (initiator, msg1) =
            nachalo::Initiator::start(&invitation.0, payload, clock.into()).map_err(error)?;
        Ok(pair(Initiator(initiator), &msg1))
    }

    /// The last second on the monotonic clock this invitation may complete.
    pub fn deadline(&self) -> u64 {
        self.0.deadline()
    }

    /// Completes the handshake with B's msg2: send msg3 to B. A wrong msg2 leaves this
    /// initiator usable; once one succeeded, "Expired".
    #[wasm_bindgen(unchecked_return_type = "[Unconfirmed, Uint8Array]")]
    pub fn finish(&mut self, msg2: &[u8], clock: &Clock) -> Result<Array> {
        let (unconfirmed, msg3) = self.0.finish(msg2, clock.into()).map_err(error)?;
        Ok(pair(Unconfirmed(unconfirmed), &msg3))
    }
}

/// B's side of one invitation: answers each msg1 found at its rendezvous, up to the config's
/// `maxAnswers`. Keep one per invitation. Holds the invitation's secret: free it once done.
#[wasm_bindgen]
pub struct Listener(nachalo::Listener);

#[wasm_bindgen]
impl Listener {
    /// A listener with its own copy of `invitation`, which has answered nothing yet.
    #[wasm_bindgen(constructor)]
    pub fn new(invitation: &Invitation) -> Listener {
        Listener(nachalo::Listener::new(&invitation.0))
    }

    /// Answers `msg1`: send msg2 back to A. `payload` is secret until the safety words match.
    #[wasm_bindgen(unchecked_return_type = "[Responder, Uint8Array]")]
    pub fn respond(&mut self, msg1: &[u8], payload: &[u8], clock: &Clock) -> Result<Array> {
        let (responder, msg2) = self.0.respond(msg1, payload, clock.into()).map_err(error)?;
        Ok(pair(Responder(responder), &msg2))
    }
}

/// B's answer to one msg1, until msg3 arrives. Holds secrets: free it once done.
#[wasm_bindgen]
pub struct Responder(nachalo::Responder);

#[wasm_bindgen]
impl Responder {
    /// The last second on the monotonic clock this answer may complete.
    pub fn deadline(&self) -> u64 {
        self.0.deadline()
    }

    /// Completes the handshake with A's msg3. A forged msg3 leaves this answer usable.
    pub fn finish(&self, msg3: &[u8], clock: &Clock) -> Result<Unconfirmed> {
        Ok(Unconfirmed(
            self.0.finish(msg3, clock.into()).map_err(error)?,
        ))
    }
}

/// A finished handshake whose safety words nobody has compared yet. Holds the key: free it once
/// done.
#[wasm_bindgen]
pub struct Unconfirmed(nachalo::Unconfirmed);

#[wasm_bindgen]
impl Unconfirmed {
    /// Which side this device played.
    pub fn role(&self) -> Role {
        self.0.role().into()
    }

    /// Four words, equal on both sides unless someone sits in the middle. B shows them, A types
    /// them.
    #[wasm_bindgen(js_name = safetyWords)]
    pub fn safety_words(&self) -> String {
        self.0.safety_words().to_string()
    }

    /// A: opens the session once the user types the safety words B shows. A mismatch leaves it
    /// pending until the deadline.
    pub fn verify(&self, typed: &str, clock: &Clock) -> Result<Established> {
        Ok(Established(
            self.0.verify(typed, clock.into()).map_err(error)?,
        ))
    }

    /// B: opens the session once A says the safety words matched. Consumes this object, as in
    /// Rust, even when it throws.
    pub fn confirm(self, clock: &Clock) -> Result<Established> {
        Ok(Established(self.0.confirm(clock.into()).map_err(error)?))
    }
}

/// What both sides share once the safety words matched. Holds the key: free it once done.
#[wasm_bindgen]
pub struct Established(nachalo::Established);

#[wasm_bindgen]
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
    #[wasm_bindgen(js_name = peerPayload)]
    pub fn peer_payload(&self) -> Vec<u8> {
        self.0.peer_payload().to_vec()
    }

    /// An independent 32-byte key for `label`, equal on both sides. Secret: the returned bytes
    /// are not zeroized.
    pub fn export(&self, label: &[u8]) -> Vec<u8> {
        self.0.export(label).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_has_its_own_kind() {
        use nachalo::Error as E;
        let kinds = [
            E::BadWords,
            E::Expired,
            E::PayloadTooLarge,
            E::Rejected,
            E::OutOfRange,
            E::Rng,
        ]
        .map(kind);
        assert_eq!(
            kinds,
            [
                "BadWords",
                "Expired",
                "PayloadTooLarge",
                "Rejected",
                "OutOfRange",
                "Rng"
            ]
        );
    }
}
