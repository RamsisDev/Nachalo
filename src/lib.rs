//! Reference implementation of Nachalo, a protocol for first contact between two people who share
//! nothing but a few words.
//!
//! Each side builds the same [`Invitation`] from what the two people swapped outside the system,
//! in one of three modes:
//!
//! - [`Invitation::live`]: A draws 6 [`words`] and both devices take part within minutes;
//! - [`Invitation::appointment`]: A draws 5 words, B draws 4, and they agree on a time; the
//!   invitation only works for a window from then, 30 minutes by default;
//! - [`Invitation::physical_token`]: A hands B in person a [`new_physical_token`], which B's
//!   device reads, and gives B 6 words.
//!
//! In three messages ([`Initiator`], and [`Listener`] on the other side) both reach a shared key and swap one
//! opaque payload each way, such as the first key of a ratchet or the read capability of a
//! channel. B then shows 4 safety words that A types, so even someone who intercepted the words
//! cannot sit in the middle unnoticed.
//!
//! The crate is sans-IO: messages are byte strings the application carries however it likes
//! (to [`Invitation::rendezvous`]), and time is passed in. The handshake combines CPace
//! (draft-irtf-cfrg-cpace, CPACE-RISTR255-SHA512), X25519 and ML-KEM-768, so breaking it needs
//! all three, quantum computers included. The protocol is defined by its specification,
//! `spec/nachalo.md` in the repository, not by this crate.
//!
//! Every step takes a [`Clock`]: `now`, monotonic seconds that keep counting while the device
//! sleeps, and `now_unix`, the wall clock. Each step's TTL runs on both, and the window of an
//! appointment or physical token on the wall clock. No time travels on the wire and no two
//! devices' clocks are compared.
//!
//! A pending step survives the app being killed: [`Initiator`], [`Responder`] and [`Listener`]
//! save to bytes with `to_bytes` and restore with `from_bytes`. The bytes hold secrets, so store
//! them encrypted (see [`Initiator::to_bytes`]).
//!
//! The limits (TTL, answers, payload size, appointment window) are local: each device picks a
//! [`Config`] from a [`Profile`], and devices with different ones still interoperate. Every
//! receiver accepts payloads up to [`PAYLOAD_CEILING`].
//!
//! ```
//! use nachalo::{Clock, Config, Initiator, Invitation, Listener, words};
//! # fn main() -> Result<(), nachalo::Error> {
//! # let clock = Clock { now: 0, now_unix: 1_900_000_000 };
//! let context = b"my-app v1";
//! let words = words(6)?; // A gives these to B outside the protocol
//! let invitation = Invitation::live(&words, context, &Config::default())?; // both sides build it
//!
//! // A posts msg1 at invitation.rendezvous()
//! let (mut a, msg1) = Initiator::start(&invitation, b"A's payload", clock)?;
//! // B listens there and answers
//! let (b, msg2) = Listener::new(&invitation).respond(&msg1, b"B's payload", clock)?;
//! let (a, msg3) = a.finish(&msg2, clock)?;
//! let b = b.finish(&msg3, clock)?;
//!
//! // B shows b.safety_words(); A's user types them
//! # let typed_by_a = b.safety_words();
//! let a = a.verify(&typed_by_a, clock)?;
//! let b = b.confirm(clock)?; // once A says they matched
//! assert_eq!(a.key(), b.key());
//! assert_eq!(a.peer_payload(), b"B's payload");
//! # assert_eq!(invitation.rendezvous().len(), 32);
//! # Ok(())
//! # }
//! ```

mod config;
mod cpace;
mod crypto;
mod handshake;
mod words;

pub use config::{Bounded, Config, Profile};
pub use crypto::Key;
pub use handshake::{
    Clock, Error, Established, Initiator, Invitation, Listener, MSG1_LEN, PAYLOAD_CEILING,
    PROTOCOL, RENDEZVOUS_LEN, Responder, Role, SAFETY_LEN, TOKEN_LEN, Unconfirmed, msg2_len,
    msg3_len, new_physical_token,
};
pub use words::{APPOINTMENT_WORDS_A, APPOINTMENT_WORDS_B, WORD_COUNT, words};

/// Runs the examples of the README and `docs/` as doctests, so they stay in sync with the crate.
#[cfg(doctest)]
mod docs {
    #[doc = include_str!("../README.md")]
    struct Readme;
    #[doc = include_str!("../docs/live.md")]
    struct Live;
    #[doc = include_str!("../docs/appointment.md")]
    struct Appointment;
    #[doc = include_str!("../docs/physical-token.md")]
    struct PhysicalToken;
}
