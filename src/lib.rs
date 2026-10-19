//! Nachalo: first contact between two people who share nothing but 6 words.
//!
//! A draws 6 [`words`] and gives them to B outside the system. In three messages
//! ([`Initiator`] and [`Responder`]) both reach a shared key and swap one opaque payload each
//! way, such as the first key of a ratchet or the read capability of a channel. B then shows 4
//! safety words that A types, so even someone who intercepted the 6 words cannot sit in the
//! middle unnoticed.
//!
//! The library is sans-IO: messages are byte strings the application carries however it likes
//! (to the [`rendezvous`] id), and time is passed in. The handshake combines CPace
//! (draft-irtf-cfrg-cpace, CPACE-RISTR255-SHA512), X25519 and ML-KEM-768, so breaking it needs
//! all three, quantum computers included. The byte-level specification is `spec/nachalo.md`.
//!
//! Time is passed in as seconds and only differences on the same device matter: no time
//! travels on the wire and no two clocks are compared. Pass a monotonic clock that keeps counting
//! while the device sleeps, never the wall clock.
//!
//! ```
//! use nachalo::{Initiator, Responder, rendezvous, words};
//! # fn main() -> Result<(), nachalo::Error> {
//! # let now = 0;
//! let context = b"my-app v1";
//! let words = words(); // A gives these to B outside the system
//!
//! // A posts msg1 at rendezvous(&words, context)
//! let (mut a, msg1) = Initiator::start(&words, context, b"A's payload", now)?;
//! // B finds it there and answers
//! let (b, msg2) = Responder::respond(&words, context, &msg1, b"B's payload", now)?;
//! let (a, msg3) = a.finish(&msg2, now)?;
//! let b = b.finish(&msg3, now)?;
//!
//! // B shows b.safety_words(); A's user types them
//! # let typed_by_a = b.safety_words();
//! let a = a.verify(&typed_by_a, now)?;
//! let b = b.confirm(now)?; // once A says they matched
//! assert_eq!(a.key(), b.key());
//! assert_eq!(a.peer_payload(), b"B's payload");
//! # assert_eq!(rendezvous(&words, context)?.len(), 32);
//! # Ok(())
//! # }
//! ```

mod cpace;
mod crypto;
mod handshake;
mod words;

pub use crypto::Key;
pub(crate) use crypto::random;
pub use handshake::{
    Error, Established, INVITE_TTL, Initiator, MAX_ANSWERS, MAX_PAYLOAD, MSG1_LEN, PROTOCOL,
    RENDEZVOUS_LEN, Responder, Role, SAFETY_LEN, Unconfirmed, msg2_len, msg3_len, rendezvous,
};
pub use words::{WORD_COUNT, words};
