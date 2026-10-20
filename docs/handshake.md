# The handshake

Every Nachalo first contact has the same shape, whatever the invitation mode:

1. **Invitation.** The two people swap a few words (and, depending on the mode, a start time or
   a physical token) outside the protocol. Each device turns them into the same `Invitation`.
2. **Handshake.** The two devices exchange three messages. They agree on a key and each receives
   the other's payload.
3. **Safety words.** One device shows 4 words, the other person types them. If they match,
   nobody sat in the middle.

The three modes differ only in step 1: what the people swap, who starts, and how long the
invitation stays usable. Steps 2 and 3 are identical in every mode, and this page describes
them. For step 1, see [live](live.md), [appointment](appointment.md) and
[physical token](physical-token.md).

## Roles

The protocol has two roles:

| Role | Sends | Safety words |
| --- | --- | --- |
| **Initiator** (A) | msg1, msg3 | types the words the responder shows |
| **Responder** (B) | msg2 | shows the words, confirms once A says they matched |

In the live and appointment modes, the person who drew the first words is the initiator. In the
physical-token mode it is the other way round: the person who *received* the token starts.

## Messages

```mermaid
sequenceDiagram
    participant A as Initiator (A)
    participant R as Rendezvous id
    participant B as Responder (B)
    A->>R: msg1 (1296 bytes): CPace share, X25519 key, commitment, ML-KEM key
    R->>B: B finds msg1 there
    B->>A: msg2 (1168 + payload_b bytes): CPace share, X25519 key, ML-KEM ciphertext, sealed payload_b
    A->>B: msg3 (48 + payload_a bytes): sealed nonce and payload_a
    Note over A,B: both derive key and 4 safety words
    B-->>A: B reads out the safety words (in person or on a call)
    Note over A: A types them; the device checks them
    A-->>B: "They match"
    Note over B: B confirms
```

- **msg1** goes to the invitation's 32-byte **rendezvous id**, a public id both devices compute
  from the invitation. The application maps it onto its transport: a mailbox queue, a storage
  address, a pub/sub topic. Unrelated invitations may share an id, so B answers every msg1 it
  finds there, up to a cap.
- **msg2** and **msg3** travel wherever the application decides, for example to an id derived
  from the previous message.
- Nothing on the wire identifies either person: no accounts, no ids, no timestamps.

What each message contains, byte by byte, is in [section 7 of the specification](../spec/nachalo.md#7-messages).

## Three key exchanges in one

The key both sides end up with comes from three shared secrets at once:

- **CPace** (a PAKE, [draft-irtf-cfrg-cpace], suite CPACE-RISTR255-SHA512), keyed by the
  invitation. Only someone who knows the invitation can complete it, and every guess at the words
  needs a live exchange with a victim: a recorded handshake does not let anyone test guesses
  offline.
- **X25519**, an ephemeral Diffie-Hellman exchange.
- **ML-KEM-768**, a post-quantum key encapsulation, so a recording made today stays secret
  against a quantum computer tomorrow.

Breaking the key requires breaking all three.

## Payloads

Each side sends one opaque payload, possibly empty: the first public key of a ratchet, the read
capability of a channel, a long-term identity key. Nachalo does not look inside it. Each device
limits what it sends with its own `max_payload` (1 KiB by default, up to 8 KiB in the
`PQ_MESSENGER` profile), and every device accepts payloads up to 8 KiB, so two devices with
different limits still connect.

Payloads are confidential against anyone who does not know the invitation. They are only
*authenticated* once the safety words match: until then, the other side might be someone who
learned the words. The reference implementation keeps the peer's payload locked inside the
`Unconfirmed` state until the safety words are checked.

## Safety words

CPace proves that the other device knows the invitation, not that nobody else does. An attacker
who learned the words (say, by reading the message they were sent in) can run one handshake with
A posing as B and another with B posing as A. Both complete.

The safety words catch that. They are 4 words (44 bits) derived from the whole transcript, so the
two sessions of a man in the middle show different words, except by chance. A commits to a
random nonce in msg1 and reveals it only in msg3, so the attacker cannot steer the words toward a
collision. With B answering at most `max_answers` msg1 per invitation, an attacker goes unnoticed
with probability at most `max_answers / 2^44`: 2^-38 with the default of 64.

The safety words are not secret, but they must be compared over a channel where the two people
recognize each other: face to face, on a voice or video call. Comparing them over the same channel
the invitation went through proves nothing.

The comparison goes one way on purpose:

1. B's device shows the words, and B reads them out.
2. A types them. A's device accepts them only if they match its own. A typo leaves the session
   pending, so A can try again until the deadline.
3. A tells B they matched, and B confirms.

If the words really differ, someone sat in the middle. Both sides must **discard everything the
handshake carried**, treat both payloads as known to the attacker, and start over with new words.

## Time and limits

Every limit is local: each device picks its own, they never travel on the wire, and two devices
with different limits still connect. The reference implementation groups them in profiles with
allowed ranges (`Config::new(&Profile::...)`).

| Limit | Default (`INTERACTIVE`) | What happens |
| --- | --- | --- |
| `invite_ttl`, pending step lifetime | 10 minutes, or less at the end of an appointment or before a token expires | Each side's step expires on its own device's clock. Safety words included, the whole handshake must finish by then. |
| `max_answers`, wrong msg2 per initiator | 64 | A gives up on the invitation. Each wrong msg2 is someone's online guess at the words. |
| `max_answers`, msg1 answered per responder | 64 | Enforced by the `Listener`. Bounds online guessing against B and the man-in-the-middle chance above. |
| `max_payload`, payload sent | 1 KiB | Larger payloads are refused before anything is sent. Every receiver accepts up to 8 KiB. |
| `appointment_window` | 30 minutes | See [appointment](appointment.md). |

| Profile | For | Differs from `INTERACTIVE` |
| --- | --- | --- |
| `INTERACTIVE` | Chat or call, both online | |
| `PQ_MESSENGER` | First key of a post-quantum ratchet plus an identity | Sends 4 KiB by default, up to 8 KiB |
| `NEARBY` | QR, Bluetooth or LAN, side by side | 2-minute TTL, 4 answers (2^-40 per side), payload up to 8 KiB |

Every step takes two clocks. `now` is in seconds from a **monotonic clock that keeps counting
while the device sleeps**, for the step's TTL; only differences on the same device matter, so the
two devices' clocks never need to agree. `now_unix` is the wall clock. The TTL runs on it too, so
a step saved with `to_bytes` and restored after a restart, which resets the monotonic clock,
still expires on time. The appointment and physical-token modes check it at every step, so an
invitation kept in memory stops working when its window closes or its token expires.

## What the application provides

Nachalo is sans-IO: it takes bytes in and returns bytes out. The application provides:

- **the transport** for the three messages, starting from the rendezvous id;
- **the clocks**, monotonic for each step's TTL and wall clock for time-bound invitations;
- **its limits**, a `Config`, and one `Listener` per invitation on the responder;
- **the user interface** to enter words and compare safety words;
- **what to do with the result**: derive its own keys with `Established::export(label)`, use
  `Established::transcript()` for channel binding, and treat the peer's payload as authenticated.

## What Nachalo does not do

- It does not hide that a handshake happened: message lengths reveal payload lengths, and the
  public keys can be recognized. Pad payloads and wrap messages in fixed-size frames if that
  matters.
- It does not authenticate people. It authenticates one session, through the invitation and the
  safety words. Long-term identity is built on top, for example by sending identity keys as
  payloads.
- It does not cover groups, or two devices that are never online within `invite_ttl` of each
  other.

The full threat model is in [section 11 of the specification](../spec/nachalo.md#11-security-considerations).

[draft-irtf-cfrg-cpace]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/
