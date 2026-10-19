![Nachalo](assets/Nachalo.png)

Nachalo is a Rust library for first contact between two devices whose users share nothing but 6
words. From those words alone, the two devices agree on a shared key, exchange one payload each
way, and let the users detect anyone sitting in the middle.

It is a library and nothing more. It does not send messages, run a server, store anything, or
show a user interface. It takes bytes in and returns bytes out; the application carries the
messages over its own transport and owns everything the user sees.

## How it works

1. **Invitation.** A's device draws 6 random words, and A gives them to B by any other means:
   spoken, written down, or over another app.
2. **Handshake.** The two devices exchange three messages. They agree on a key and each receives
   the other's payload, such as the first key of a ratchet or the read capability of a channel.
3. **Safety words.** B's device shows 4 safety words, and A types them into A's device. If they
   match, nobody who intercepted the 6 words sat in the middle.

The handshake combines CPace ([draft-irtf-cfrg-cpace], suite CPACE-RISTR255-SHA512), X25519 and
ML-KEM-768. Breaking the key requires breaking all three.

## Security properties

| Property | Guarantee |
| --- | --- |
| Guessing the words | Online only: each guess needs a live exchange with a victim, and answers per invitation are capped. |
| Key secrecy | Holds against a passive attacker with a future quantum computer (ML-KEM-768). |
| Man in the middle who knows the words | Detected by the safety words with probability at least 1 - 2^-38 per attempt. |
| Forward secrecy | Every key is ephemeral; learning the words afterwards does not reveal the key. |
| Metadata | No identifiers, accounts or timestamps on the wire. Message lengths reveal payload lengths. |

Someone who knows the 6 words learns both payloads before the safety words are compared. If the
safety words do not match, the application must discard everything the handshake carried and
start over with new words. The [specification](spec/nachalo.md) (section 11) covers the full
threat model.

## Status

Draft, version `v0`. The wire format may still change. The code has not been audited and the
protocol has not been formally verified. **Do not rely on it for real protection yet.**

## Installation

```toml
[dependencies]
nachalo = { git = "https://github.com/RamsisDev/Nachalo" }
```

Requires Rust 1.88 or later. The crate contains no `unsafe` code.

## Usage

```rust
use nachalo::{Initiator, Responder, rendezvous, words};

let context = b"my-app v1";
let words = words(); // A gives these to B outside the system

// A posts msg1 at rendezvous(&words, context)
let (mut a, msg1) = Initiator::start(&words, context, b"A's payload", now)?;
// B finds it there and answers
let (b, msg2) = Responder::respond(&words, context, &msg1, b"B's payload", now)?;
let (a, msg3) = a.finish(&msg2, now)?;
let b = b.finish(&msg3, now)?;

// B shows b.safety_words(); A's user types them
let a = a.verify(&typed_by_a, now)?;
let b = b.confirm(now)?; // once A says they matched
assert_eq!(a.key(), b.key());
assert_eq!(a.peer_payload(), b"B's payload");
```

The application provides:

- **Transport.** A posts msg1 at the 32-byte `rendezvous` id; the application decides where msg2
  and msg3 travel.
- **Clock.** `now` is in seconds, from a monotonic clock that keeps counting while the device
  sleeps. Each pending step expires after 10 minutes on its own device.
- **A cap on answers.** B should answer at most `MAX_ANSWERS` msg1 per invitation. The initiator
  enforces its own cap.
- **The user interface** for entering the words and comparing the safety words.

## Specification and test vectors

Nachalo is defined by [its specification](spec/nachalo.md); this crate is the reference
implementation. [`vectors/v0.json`](vectors/v0.json) records a full handshake with every random
value fixed, so an implementation in any language can check itself byte by byte. The CPace layer
also passes the test vectors of [draft-irtf-cfrg-cpace].

## Development

```bash
cargo test                                  # unit tests, CPace draft vectors, Nachalo vectors
NACHALO_WRITE_VECTORS=1 cargo test vectors  # rewrite vectors/v0.json after a deliberate change
```

## Roadmap

- Formal model of v0 (ProVerif or Tamarin).
- Serializable pending state, for mobile apps the OS kills mid-handshake.
- Bindings from the same core: a C ABI (and Go through it), UniFFI for Swift and Kotlin, WASM.
- More test vectors: rejections and edge cases.

## License

The code is licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your
option. The specification is licensed under [CC BY 4.0](spec/LICENSE).

[draft-irtf-cfrg-cpace]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/
