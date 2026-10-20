# Physical-token mode

The two people meet in person once, and connect later. One of them hands the other a token: a
random secret with an expiry, on anything the other's device can read, such as a QR code, an NFC
tag or a printed card. Any time before it expires, the person who received it starts the
handshake.

## At a glance

| | |
| --- | --- |
| People swap | A 40-byte token, handed over in person, and 6 words, given another way |
| Initiator | The person who **received** the token |
| Responder | The person who **made** it, whose device watches the rendezvous id |
| Usable | Until the expiry written in the token, chosen by its maker |
| Wall clock | Checked when each device builds the invitation and at every step |
| Guessing, per side | At most 2^-60 if the token is read by an attacker; negligible if only the words leak |

Unlike the other two modes, the person who set up the invitation does **not** start it. The token
holder decides when to connect, and the maker's device only has to answer.

## How it goes

```mermaid
sequenceDiagram
    actor Alice as Alice (made the token, responder)
    actor Bob as Bob (holds the token, initiator)
    Note over Alice,Bob: In person
    Note over Alice: The device makes a token valid for a week
    Alice-->>Bob: Shows the token as a QR code; Bob's device scans it
    Alice-->>Bob: 6 words, another way (spoken, on paper, any app)
    Note over Alice: The device watches the token's rendezvous id
    Note over Alice,Bob: Days later, before the token expires
    Note over Bob: Builds the invitation, posts msg1 at the rendezvous id
    Bob->>Alice: msg1, found at the rendezvous id
    Alice->>Bob: msg2
    Bob->>Alice: msg3
    Alice-->>Bob: Reads out the 4 safety words (on a call)
    Note over Bob: Types them: they match
    Bob-->>Alice: "They match"
    Note over Alice: Confirms
```

1. Alice's device makes a token with `new_physical_token(lifetime, now_unix)`: 32 random bytes
   followed by the expiry, as an 8-byte big-endian Unix time. It keeps a copy. An expiry past the
   end of `u64` is rejected with `OutOfRange`.
2. Alice hands Bob the token in person, on something Bob's device can read. How the 40 bytes are
   encoded (QR code, NFC, base32 on a card) is up to the application.
3. Alice also gives Bob 6 words drawn with `words(6)`, preferably another way than the token.
4. Alice's device watches the token's rendezvous id until the token expires.
5. Whenever Bob is ready, before the expiry, Bob's device builds the invitation and posts msg1 at
   the rendezvous id. Alice's device finds it, builds the same invitation and answers.
6. Alice's device shows the safety words. Alice reads them out, Bob types them, and both sides
   open the session.

Only the moment of starting is free. Once Bob starts, the rest follows the usual limit: Alice's
device must answer, and both people must compare the safety words, within `invite_ttl` (10
minutes by default). So Bob
should start when Alice can be reached, for example at the beginning of a call.

## Example

```rust
use nachalo::{Clock, Config, Initiator, Invitation, Listener, TOKEN_LEN, new_physical_token, words};

fn main() -> Result<(), nachalo::Error> {
    let context = b"my-app v1";
    let config = Config::default();

    // In person: Alice's device makes a token valid for a week, and draws the words.
    let made_at = 1_900_000_000; // Alice's wall clock, Unix seconds
    let token = new_physical_token(7 * 24 * 3600, made_at)?;
    let alice_words = words(6)?;

    // Alice's device builds its invitation now and listens at its rendezvous id until expiry.
    let alice_invitation = Invitation::physical_token(&alice_words, &token, context, made_at, &config)?;
    let mut alice_listener = Listener::new(&alice_invitation);

    // Bob's device reads the token (say, from a QR code) and Bob types the words.
    let token_read_by_bob: [u8; TOKEN_LEN] = *token;
    let bob_typed = alice_words.clone();

    // Three days later, Bob starts: Bob is the initiator. Each device passes its own clocks.
    let clock = Clock { now: 0, now_unix: made_at + 3 * 24 * 3600 };
    let bob_invitation =
        Invitation::physical_token(&bob_typed, &token_read_by_bob, context, clock.now_unix, &config)?;
    assert_eq!(alice_invitation.rendezvous(), bob_invitation.rendezvous());
    let (mut bob, msg1) = Initiator::start(&bob_invitation, b"Bob's payload", clock)?;

    // Alice's listener finds msg1 and answers.
    let (alice, msg2) = alice_listener.respond(&msg1, b"Alice's payload", clock)?;

    let (bob, msg3) = bob.finish(&msg2, clock)?;
    let alice = alice.finish(&msg3, clock)?;

    // Alice reads out the safety words, Bob types them, then Alice confirms.
    let bob = bob.verify(&alice.safety_words(), clock)?;
    let alice = alice.confirm(clock)?;
    assert_eq!(alice.key(), bob.key());
    assert_eq!(alice.peer_payload(), b"Bob's payload");

    // Once the token has expired, nobody can build or use the invitation.
    let expired = Clock { now: 0, now_unix: made_at + 8 * 24 * 3600 };
    let restarted = Initiator::start(&bob_invitation, b"Bob's payload", expired);
    assert_eq!(restarted.err(), Some(nachalo::Error::Expired));
    Ok(())
}
```

## How the invitation is derived

```text
token      = random(32) || be64(expires)                    40 bytes
PRS        = lv_cat(words, token)
CI         = lv_cat("Nachalo v0", context, "Nachalo v0 physical token")
rendezvous = HKDF(salt = CI, ikm = token, info = "Nachalo v0 rendezvous", 32)
ttl        = min(invite_ttl, expires - now_unix)              when each step starts
```

A device refuses to build the invitation, start a step from it or continue a pending one once
`now_unix > expires`, so the token lives exactly the lifetime it was made with, even if the
invitation stays in memory for weeks. The rendezvous id comes from the token's
256-bit secret, so nobody without the token can find the id or recognize it. The expiry is part
of the password, so a token whose expiry was rewritten is a different token and never completes.
See [section 6.3 of the specification](../spec/nachalo.md#63-physical-token).

## Why a token and words

The token and the words protect against different leaks:

- **Someone photographs or copies the token.** They still need the 6 words, and must guess them
  online, one live exchange at a time.
- **Someone reads the message with the words.** Without the token, they cannot even find the
  rendezvous id, let alone complete a handshake: its secret is 256 bits.

For this to hold, the words should not travel with the token: do not print them on the same card
or put them in the same QR code.

## Security

| Attacker | Outcome |
| --- | --- |
| Watches the network | Learns nothing about the key, even with a future quantum computer. Cannot tell which rendezvous id belongs to the token. |
| Read the token | Must guess the 66 bits of the words online, at most `max_answers` (64 by default) guesses per side: at most 2^-60. |
| Learned the words, not the token | Cannot find or complete the invitation: negligible. |
| Has both and sits in the middle | Completes both handshakes and learns both payloads, but the safety words differ, except with probability at most 2^-38. |

## Pitfalls

- **Roles are reversed.** The token's holder calls `Initiator::start`; the token's maker calls
  `Listener::respond`, shows the safety words and confirms.
- **Keep the words away from the token,** or one leak gives away both.
- **The maker keeps a copy of the token** to build its own invitation, and erases it once it
  expires or the handshake succeeds.
- **The maker's device must watch the rendezvous id** until the expiry, through one `Listener`,
  which stops after `max_answers` msg1.
- **Pick a lifetime that fits.** It has no upper bound: a longer one gives the holder more
  freedom, and an attacker who copied the token more time to try, still one online guess at a
  time. Profiles suggest 24 hours.

## When to use another mode

- Both people are available right now: [live](live.md) is simpler.
- They will not meet in person, but can agree on a time: use an [appointment](appointment.md).
