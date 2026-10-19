//! Reference implementation of Nachalo, a protocol for first contact between two people who share
//! nothing but a few words.
//!
//! Each side builds the same [`Invitation`] from what the two people swapped outside the system,
//! in one of three modes:
//!
//! - [`Invitation::live`]: A draws 6 [`words`] and both devices take part within minutes;
//! - [`Invitation::appointment`]: A draws 5 words, B draws 4, and they agree on a time; the
//!   invitation only works for 30 minutes from then;
//! - [`Invitation::physical_token`]: A hands B in person a [`new_physical_token`], which B's
//!   device reads, and gives B 6 words.
//!
//! In three messages ([`Initiator`] and [`Responder`]) both reach a shared key and swap one
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
//! Handshake steps take `now` in seconds and only differences on the same device matter: no time
//! travels on the wire and no two clocks are compared. Pass a monotonic clock that keeps counting
//! while the device sleeps, never the wall clock. Only building an appointment or physical-token
//! invitation reads the wall clock, to check its window.
//!
//! ```
//! use nachalo::{Initiator, Invitation, Responder, words};
//! # fn main() -> Result<(), nachalo::Error> {
//! # let now = 0;
//! let context = b"my-app v1";
//! let words = words(6); // A gives these to B outside the protocol
//! let invitation = Invitation::live(&words, context)?; // both sides build it
//!
//! // A posts msg1 at invitation.rendezvous()
//! let (mut a, msg1) = Initiator::start(&invitation, b"A's payload", now)?;
//! // B finds it there and answers
//! let (b, msg2) = Responder::respond(&invitation, &msg1, b"B's payload", now)?;
//! let (a, msg3) = a.finish(&msg2, now)?;
//! let b = b.finish(&msg3, now)?;
//!
//! // B shows b.safety_words(); A's user types them
//! # let typed_by_a = b.safety_words();
//! let a = a.verify(&typed_by_a, now)?;
//! let b = b.confirm(now)?; // once A says they matched
//! assert_eq!(a.key(), b.key());
//! assert_eq!(a.peer_payload(), b"B's payload");
//! # assert_eq!(invitation.rendezvous().len(), 32);
//! # Ok(())
//! # }
//! ```

mod cpace;
mod crypto;
mod handshake;
mod words;

pub use crypto::Key;
pub use handshake::{
    APPOINTMENT_WINDOW, Error, Established, INVITE_TTL, Initiator, Invitation, MAX_ANSWERS,
    MAX_PAYLOAD, MSG1_LEN, PROTOCOL, RENDEZVOUS_LEN, Responder, Role, SAFETY_LEN, TOKEN_LEN,
    Unconfirmed, msg2_len, msg3_len, new_physical_token,
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
