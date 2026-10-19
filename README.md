# Nachalo

First contact between two people who share nothing but 6 words.

A draws 6 random words and gives them to B outside the system. In three messages, the two devices
agree on a shared key and swap one payload each way, such as a ratchet's first key or a channel's
read capability. Then B shows 3 safety words that A types, so even someone who intercepted the 6
words cannot sit in the middle unnoticed.

- **CPace + X25519 + ML-KEM-768:** only online guesses at the words, and a key that a recorded
  transcript does not give away, quantum computers included.
- **Safety words:** a man in the middle who knows the words is caught with probability
  1 - 2^-33 per attempt.
- **Sans-IO:** messages are byte strings you carry over any transport. No identifiers, accounts or
  clocks on the wire.

## A protocol first

Nachalo is defined by [its specification](spec/nachalo.md), not by this code. The Rust crate is
the reference implementation, and [`vectors/v0.json`](vectors/v0.json) records a full handshake
with every random value fixed, so an implementation in any language can check itself byte by
byte. The CPace layer follows
[draft-irtf-cfrg-cpace](https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/) (suite
CPACE-RISTR255-SHA512) and passes that draft's own test vectors.

## Status

Draft, version `v0`: the wire format may still change. Not audited. The symbolic model of the
earlier Janus Knot handshake does not cover this version yet, so no security property here is
formally established. Do not rely on it for real protection yet.

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

## Development

```bash
cargo test                                  # unit tests, CPace draft vectors, Nachalo vectors
NACHALO_WRITE_VECTORS=1 cargo test vectors  # rewrite vectors/v0.json after a deliberate change
```

## Roadmap

- Formal model of v0 (ProVerif or Tamarin).
- Serializable pending state, for mobile apps the OS kills mid-handshake.
- Bindings from this same core: a C ABI (and Go through it), UniFFI for Swift and Kotlin, WASM.
- More test vectors: rejections and edge cases.

## License

The code is licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your
option. The specification is licensed under [CC BY 4.0](spec/LICENSE). Use it for anything; keep
the copyright notice and credit the project.
