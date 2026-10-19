![Nachalo](assets/Nachalo.png)

# Nachalo

[![CI](https://github.com/RamsisDev/Nachalo/actions/workflows/ci.yml/badge.svg)](https://github.com/RamsisDev/Nachalo/actions/workflows/ci.yml)
[![Spec: CC BY 4.0](https://img.shields.io/badge/spec-CC%20BY%204.0-blue)](spec/LICENSE)
[![Code: MIT OR Apache-2.0](https://img.shields.io/badge/code-MIT%20OR%20Apache--2.0-blue)](#license)
![Status: draft v0](https://img.shields.io/badge/status-draft%20v0-orange)

**First contact between two people who share nothing but a few words.**

Nachalo ("beginning") is an open protocol for that first moment. From a few words alone, two
devices agree on a shared key, exchange one payload each way, and let the people detect anyone
sitting in the middle. No accounts, no servers of its own, no identifiers on the wire, and a key
that stays secret against a future quantum computer.

> [!WARNING]
> Nachalo is a draft (`v0`). The wire format may still change, and neither the protocol nor the
> reference implementation has been audited or formally verified. **Do not rely on it for real
> protection yet.**

## Why

Two people who want to talk privately have to bootstrap trust somehow. Exchanging public keys or
scanning QR codes works when they are side by side; reading out fingerprints is tedious and
easy to skip. Nachalo starts from something people can actually pass along: a few random words,
spoken, written down or sent over another app. From those words it produces what a secure
messenger, a file-sharing app or a peer-to-peer network needs to start: a shared key and one
authenticated payload each way, such as the first key of a ratchet or the read capability of a
channel.

## How it works

1. **Invitation.** The two people set one up outside the protocol, in one of three modes.
2. **Handshake.** The two devices exchange three messages over any transport. They agree on a key
   and each receives the other's payload.
3. **Safety words.** One device shows 4 words, and the other person types them. If they match,
   nobody who intercepted the invitation sat in the middle.

| Mode | The people swap | They connect | Read more |
| --- | --- | --- | --- |
| **Live** | 6 words | Within minutes | [docs/live.md](docs/live.md) |
| **Appointment** | 5 words one way, 4 the other, and a start time | In a window at that time (30 minutes by default), then never again | [docs/appointment.md](docs/appointment.md) |
| **Physical token** | A token handed over in person, and 6 words | Any time before the token expires | [docs/physical-token.md](docs/physical-token.md) |

The handshake combines CPace ([draft-irtf-cfrg-cpace], suite CPACE-RISTR255-SHA512), X25519 and
ML-KEM-768. Breaking the key requires breaking all three. [The handshake](docs/handshake.md)
explains the messages, the payloads and the safety words, and [docs/](docs/README.md) helps you
choose a mode.

## Security properties

| Property | Guarantee |
| --- | --- |
| Guessing the words | Online only: each guess needs a live exchange with a victim, and answers per invitation are capped. An appointment is only valid during its window; a physical-token invitation needs the token. |
| Key secrecy | Holds against a passive attacker with a future quantum computer (ML-KEM-768). |
| Man in the middle who knows the words | Detected by the safety words with probability at least 1 - 2^-38 per attempt, with the default limits. |
| Forward secrecy | Every key is ephemeral; learning the words afterwards does not reveal the key. |
| Metadata | No identifiers, accounts or timestamps on the wire. Message lengths reveal payload lengths. |

Someone who knows the whole invitation learns both payloads before the safety words are compared.
If the safety words do not match, the application must discard everything the handshake carried
and start over with new words. [Section 11 of the specification](spec/nachalo.md#11-security-considerations)
covers the full threat model.

## What is in this repository

| Path | What it is |
| --- | --- |
| [`spec/nachalo.md`](spec/nachalo.md) | The specification. It defines the protocol, byte by byte. |
| [`vectors/`](vectors/) | Test vectors: one full handshake per mode, with every random value fixed. |
| [`docs/`](docs/README.md) | A guide to the protocol and each invitation mode. |
| [`src/`](src/) | The reference implementation, a Rust crate. |

Nachalo is a protocol, not a library. Anyone can implement it from the specification and check
their implementation against the test vectors. Where the reference implementation and the
specification differ, the specification wins.

## Reference implementation

The Rust crate in this repository implements the specification and generates the test vectors.
Its CPace layer also passes the test vectors of [draft-irtf-cfrg-cpace]. It is sans-IO: it takes
bytes in and returns bytes out, and never sends messages, runs a server or stores anything. It
contains no `unsafe` code and requires Rust 1.88 or later.

```toml
[dependencies]
nachalo = { git = "https://github.com/RamsisDev/Nachalo" }
```

A live first contact, with both sides in one process:

```rust
use nachalo::{Clock, Config, Initiator, Invitation, Listener, words};

fn main() -> Result<(), nachalo::Error> {
    let context = b"my-app v1"; // equal on both sides, never sent
    let config = Config::default(); // local limits; each side may pick its own
    // Each device's monotonic seconds and wall-clock Unix seconds, read before every step.
    let clock = Clock { now: 0, now_unix: 1_900_000_000 };

    let words = words(6); // A's device draws them, and A gives them to B
    let invitation = Invitation::live(&words, context, &config)?; // both sides build it

    // A posts msg1 at invitation.rendezvous(); B listens there and answers.
    let (mut a, msg1) = Initiator::start(&invitation, b"A's payload", clock)?;
    let mut listener = Listener::new(&invitation);
    let (b, msg2) = listener.respond(&msg1, b"B's payload", clock)?;
    let (a, msg3) = a.finish(&msg2, clock)?;
    let b = b.finish(&msg3, clock)?;

    // B reads out b.safety_words(), A types them, and B confirms once A says they matched.
    let a = a.verify(&b.safety_words(), clock)?;
    let b = b.confirm(clock)?;

    assert_eq!(a.key(), b.key());
    assert_eq!(a.peer_payload(), b"B's payload");
    Ok(())
}
```

The other modes only change how the invitation is built:
`Invitation::appointment(words_a, words_b, at, context, now_unix, &config)` and
`Invitation::physical_token(words, token, context, now_unix, &config)`. Each page in
[docs/](docs/README.md) has a full example.

The application provides:

- **Transport.** The initiator posts msg1 at the 32-byte `rendezvous` id; the application decides
  where msg2 and msg3 travel.
- **Clocks.** Every step takes a `Clock`: `now`, seconds from a monotonic clock that keeps
  counting while the device sleeps, and `now_unix`, the wall clock. Each pending step expires
  after its `invite_ttl` (10 minutes by default) on its own device, or sooner at the end of an
  appointment or when a token expires; the wall clock is checked at every step.
- **Limits.** `Config::new(&Profile::INTERACTIVE)` (the default), `PQ_MESSENGER` (payloads up to
  8 KiB, for post-quantum keys and signatures) or `NEARBY` (short TTL, few answers), each tunable
  within its ranges. Limits are local, so devices with different ones still connect, and every
  receiver accepts payloads up to `PAYLOAD_CEILING` (8 KiB).
- **The physical token.** `new_physical_token(lifetime, now_unix)` returns the 40 bytes to hand
  over; the maker keeps a copy and erases it once it expires.
- **One `Listener` per invitation** on the responder, which stops after `max_answers` msg1. The
  initiator enforces its own cap.
- **The user interface** for entering the words and comparing the safety words.

## Development

```bash
cargo test                                  # unit tests, CPace draft vectors, Nachalo vectors, doc examples
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
NACHALO_WRITE_VECTORS=1 cargo test vectors  # rewrite vectors/ after a deliberate change
```

The code examples in this README and in `docs/` are compiled and run by `cargo test`.

## Contributing

Issues and pull requests are welcome, from typo fixes to independent implementations.

- **Protocol changes start in the specification.** Open an issue describing the problem first;
  a change to `spec/nachalo.md` usually means new test vectors and a change to the reference
  implementation in the same pull request.
- **Code changes** must pass `cargo fmt`, `cargo clippy` and `cargo test`, as CI checks.
- **Implementations in other languages** are especially welcome. Tell us about yours in an issue,
  and report anything in the specification that was unclear or ambiguous.

By contributing, you agree that your contributions are licensed as described below.

## Reporting a vulnerability

Please do not open a public issue for a security problem in the protocol or the implementation.
Report it privately through
[GitHub's private vulnerability reporting](https://github.com/RamsisDev/Nachalo/security/advisories/new).

## Roadmap

- Formal model of v0 (ProVerif or Tamarin).
- More test vectors: rejections and edge cases.
- Reference implementation: serializable pending state, for mobile apps the OS kills
  mid-handshake, and bindings from the same core (a C ABI, UniFFI for Swift and Kotlin, WASM).

## License

The specification and the documentation are licensed under [CC BY 4.0](spec/LICENSE). The code
is licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

[draft-irtf-cfrg-cpace]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/
