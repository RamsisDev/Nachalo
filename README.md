![Nachalo](assets/Nachalo.png)

Nachalo is a protocol for first contact between two people who share nothing but a few words.
From those words alone, their two devices agree on a shared key, exchange one payload each way,
and let the people detect anyone sitting in the middle.

This repository holds the protocol: [its specification](spec/nachalo.md), which defines it, and
[test vectors](vectors/), which let any implementation check itself byte by byte. It also holds a
reference implementation in Rust. Nachalo defines three messages and what each side computes;
carrying the messages, keeping time and everything the people see belong to the application.

## How it works

1. **Invitation.** The two people set one up outside the protocol: spoken, written down, or over
   another app. It comes in three modes:
   - **live**: A draws 6 random words and gives them to B; both devices take part within minutes;
   - **appointment**: A draws 5 words and B draws 4, they swap them and agree on a start time; the
     invitation works for 30 minutes from then and never again;
   - **physical token**: A hands B in person a token holding a random secret and an expiry, which
     B's device reads, and gives B 6 words; B's device starts and A's only has to answer.
2. **Handshake.** The two devices exchange three messages. They agree on a key and each receives
   the other's payload, such as the first key of a ratchet or the read capability of a channel.
3. **Safety words.** B's device shows 4 safety words, and A types them into A's device. If they
   match, nobody who intercepted the words sat in the middle.

The handshake combines CPace ([draft-irtf-cfrg-cpace], suite CPACE-RISTR255-SHA512), X25519 and
ML-KEM-768. Breaking the key requires breaking all three.

## Security properties

| Property | Guarantee |
| --- | --- |
| Guessing the words | Online only: each guess needs a live exchange with a victim, and answers per invitation are capped. An appointment is only valid for its 30 minutes; a physical-token invitation needs the token. |
| Key secrecy | Holds against a passive attacker with a future quantum computer (ML-KEM-768). |
| Man in the middle who knows the words | Detected by the safety words with probability at least 1 - 2^-38 per attempt. |
| Forward secrecy | Every key is ephemeral; learning the words afterwards does not reveal the key. |
| Metadata | No identifiers, accounts or timestamps on the wire. Message lengths reveal payload lengths. |

Someone who knows the words (and the token, in physical-token mode) learns both payloads before
the safety words are compared. If the safety words do not match, the application must discard
everything the handshake carried and start over with new words. Section 11 of the specification
covers the full threat model.

## Status

Draft, version `v0`. The wire format may still change; the first stable version will be `v1`.
Neither the protocol nor the reference implementation has been audited or formally verified.
**Do not rely on it for real protection yet.**

## Reference implementation

The Rust crate in this repository implements the specification and generates the test vectors.
Its CPace layer also passes the test vectors of [draft-irtf-cfrg-cpace]. It is sans-IO: it takes
bytes in and returns bytes out, and never sends messages, runs a server or stores anything.

```toml
[dependencies]
nachalo = { git = "https://github.com/RamsisDev/Nachalo" }
```

Requires Rust 1.88 or later. The crate contains no `unsafe` code.

```rust
use nachalo::{Initiator, Invitation, Responder, words};

let context = b"my-app v1";
let words = words(6); // A gives these to B outside the protocol
let invitation = Invitation::live(&words, context)?; // both sides build it
// or Invitation::appointment(&words_a, &words_b, at, context, now_unix)?
// or Invitation::physical_token(&words, &token, context, now_unix)?

// A posts msg1 at invitation.rendezvous()
let (mut a, msg1) = Initiator::start(&invitation, b"A's payload", now)?;
// B finds it there and answers
let (b, msg2) = Responder::respond(&invitation, &msg1, b"B's payload", now)?;
let (a, msg3) = a.finish(&msg2, now)?;
let b = b.finish(&msg3, now)?;

// B shows b.safety_words(); A's user types them
let a = a.verify(&typed_by_a, now)?;
let b = b.confirm(now)?; // once A says they matched
assert_eq!(a.key(), b.key());
assert_eq!(a.peer_payload(), b"B's payload");
```

The application provides:

- **Transport.** The initiator posts msg1 at the 32-byte `rendezvous` id; the application decides
  where msg2 and msg3 travel.
- **Clock.** `now` is in seconds, from a monotonic clock that keeps counting while the device
  sleeps. Each pending step expires after 10 minutes on its own device, or sooner at the end of an
  appointment or when a token expires. Building an appointment or physical-token invitation also
  takes `now_unix`, the wall clock, to check its window.
- **The physical token.** `new_physical_token(lifetime, now_unix)` returns the 40 bytes to hand
  over; A keeps a copy and erases it once it expires.
- **A cap on answers.** B should answer at most `MAX_ANSWERS` msg1 per invitation. The initiator
  enforces its own cap.
- **The user interface** for entering the words and comparing the safety words.

```bash
cargo test                                  # unit tests, CPace draft vectors, Nachalo vectors
NACHALO_WRITE_VECTORS=1 cargo test vectors  # rewrite vectors/ after a deliberate change
```

## Roadmap

- Formal model of v0 (ProVerif or Tamarin).
- More test vectors: rejections and edge cases.
- Reference implementation: serializable pending state, for mobile apps the OS kills
  mid-handshake, and bindings from the same core (a C ABI, UniFFI for Swift and Kotlin, WASM).

## License

The specification is licensed under [CC BY 4.0](spec/LICENSE). The code is licensed under either
[Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

[draft-irtf-cfrg-cpace]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/
