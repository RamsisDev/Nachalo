# Nachalo v0

**Status:** draft. Not audited, not formally verified. Version `v0` may still change without
notice; the first stable version will be `v1`.

**License:** this document is licensed under [CC BY 4.0](LICENSE).

## 1. Introduction

Nachalo ("beginning") is a three-message handshake for first contact between two people who
share nothing but a few words. The two people set up an invitation outside the system (spoken,
written down or over another app) in one of three modes (section 6):

- **live**: A draws 6 random words and gives them to B; both devices take part within minutes;
- **appointment**: A draws 5 words and B draws 4, they swap them and agree on a start time; the
  invitation works for a window from then (30 minutes by default) and never again;
- **physical token**: A hands B in person a token holding a random secret and an expiry, which
  B's device reads, and gives B 6 words.

With that alone, the two devices:

- agree on a shared key that a network attacker cannot learn, even with a quantum computer later
  (CPace + X25519 + ML-KEM-768);
- swap one opaque payload each way, such as the first public key of a ratchet or the read
  capability of a channel;
- catch an attacker who learned the words and sits in the middle: B shows 4 safety words and A
  types them.

Nachalo is a protocol, not a library. This document defines it, and `vectors/` lets any
implementation check itself byte by byte. The Rust crate in the same repository is a reference
implementation; where it and this document differ, this document wins.

### 1.1. Goals

- Only online guesses at the words: every guess costs the attacker one live exchange with a
  victim, and victims cap how many they take.
- Key secrecy against a passive attacker with a future quantum computer.
- Detection of an active attacker who knows the words, with probability at least 1 - 2^-38 per
  attempt with the recommended limits (section 11.3).
- No identifiers, accounts, or clocks on the wire. Messages are byte strings that the application
  carries over any transport.

### 1.2. Non-goals

- Hiding that a handshake took place, or the payload lengths. Applications that care pad their
  payloads and wrap the messages in their own fixed-size frames.
- Long-term identity. Nachalo authenticates a session with the words and the safety words, not a
  person. Applications build identity on top, for example by sending long-term keys as payloads.
- Group first contact.
- Fully asynchronous first contact. Both devices take part within `invite_ttl` (10 minutes by
  default) of each other, at a time the people agreed on (appointment) or while the physical token is valid.
  Section 11.7 discusses this.

## 2. Notation

- `a || b`: concatenation of byte strings.
- `len(a)`: length of `a` in bytes.
- `a[i..j]`: bytes `i` (included) to `j` (excluded) of `a`.
- `prepend_len(a)` and `lv_cat(a, b, ...)`: length-value encoding from
  [CPACE] appendix A.1: the length as LEB128, then the bytes. `lv_cat(a, b) = prepend_len(a) ||
  prepend_len(b)`.
- `SHA256(m)`: SHA-256 [FIPS180-4].
- `HKDF(salt, ikm, info, L)`: HKDF-SHA256 [RFC5869], extract then expand to `L` bytes.
- `Seal(k, p)`: ChaCha20-Poly1305 [RFC8439] encryption of `p` under key `k`, nonce 12 zero bytes,
  empty associated data; returns `ciphertext || tag` (`len(p) + 16` bytes). Every key is used for
  exactly one `Seal`.
- `Open(k, c)`: the inverse of `Seal`; fails if the tag does not verify.
- `X25519(k, u)`: [RFC7748].
- `ML-KEM-768.KeyGen_internal(d, z)`, `ML-KEM-768.Encaps_internal(ek, m)`,
  `ML-KEM-768.Decaps(dk, c)`: [FIPS203].
- `random(n)`: `n` bytes from a cryptographically secure random generator.
- Byte strings in quotes are ASCII, without terminator: `"Nachalo v0"` is 10 bytes.

## 3. Parameters

| Name | Value | Meaning |
| --- | --- | --- |
| `PROTOCOL` | `"Nachalo v0"` | Domain separation; changes with every incompatible version |
| `PAYLOAD_CEILING` | 8192 bytes | Largest payload every receiver accepts |
| `WORD_COUNT` | 6 | Words of a live or physical-token invitation, 66 bits |
| `APPOINTMENT_WORDS_A` | 5 | Words A draws for an appointment, 55 bits |
| `APPOINTMENT_WORDS_B` | 4 | Words B draws for an appointment, 44 bits |
| `TOKEN_LEN` | 40 bytes | Physical token: 32-byte secret, 8-byte expiry |
| `SAFETY_LEN` | 8 bytes | Safety words: 4 words, 44 bits |

`PAYLOAD_CEILING` fits the heaviest realistic first payload, an ML-KEM-1024 key (1568 bytes) plus
an ML-DSA-65 public key and signature (5261 bytes); the largest msg2, 9360 bytes, still fits a
single 16 384-byte block of transports such as SimpleX SMP; and it bounds the memory an attacker
can make a device allocate per message.

### 3.1. Local parameters

Each device also picks these limits for itself. They never travel on the wire and never enter
`CI`, so devices with different values interoperate: each one only bounds its own exposure, and a
mismatch never leaves a handshake half finished.

| Name | Recommended default | Bounds | If the two sides differ |
| --- | --- | --- | --- |
| `invite_ttl` | 600 seconds | How long each pending step lives on this device | Each side expires on its own clock |
| `max_answers` | 64 | Wrong msg2 this device takes as initiator, and msg1 it answers as responder, per invitation | Each side caps its own exposure; section 11 gives the bounds as functions of it |
| `max_payload` | 1024 bytes, at most `PAYLOAD_CEILING` | Bytes this device sends | Harmless: every receiver accepts up to `PAYLOAD_CEILING` |
| `appointment_window` | 1800 seconds | When this device builds and answers an appointment | The device outside its window never answers; the other side times out |

The lifetime of a physical token is not a local parameter: whoever makes the token chooses it, and
it travels inside the token. Implementations may offer named sets of these values for different
applications; the reference implementation calls them profiles.

CPace suite: **CPACE-RISTR255-SHA512** from [CPACE], in the initiator-responder setting
(`transcript_ir`). Its public shares are 32 bytes and its `ISK` is 64 bytes.

Labels, used as HKDF `info` or inside hashes:

| Label | Bytes |
| --- | --- |
| `L_RV_TAG` | `"Nachalo v0 rendezvous tag"` |
| `L_RV` | `"Nachalo v0 rendezvous"` |
| `L_COMMIT` | `"Nachalo v0 commit"` |
| `L_SEAL_B` | `"Nachalo v0 seal b"` |
| `L_SEAL_A` | `"Nachalo v0 seal a"` |
| `L_KEY` | `"Nachalo v0 key"` |
| `L_SAFETY` | `"Nachalo v0 safety"` |
| `L_EXPORT` | `"Nachalo v0 export"` |
| `L_APPOINTMENT` | `"Nachalo v0 appointment"` |
| `L_TOKEN` | `"Nachalo v0 physical token"` |

## 4. Inputs

- The invitation: the words of its mode (section 5), plus the start time `at` of an appointment
  or the `token` of a physical-token invitation (section 6).
- `context`: a byte string the application chooses, equal on both sides, such as the name and
  version of the application and of the network it runs on. It never travels on the wire.
  Devices with different contexts never complete a handshake.
- `payload_a`, `payload_b`: possibly empty, from A and B, each up to its sender's `max_payload`.
- `now`: seconds on a clock of the device itself, for each step's `ttl`. Only differences on one
  device matter. It should be a monotonic clock that keeps counting while the device sleeps, never
  the wall clock, which the network can move.
- `now_unix`: the device's wall clock, in seconds since the Unix epoch. Appointment and
  physical-token invitations check it when the invitation is built and whenever a step starts or
  continues (section 6).

In what follows, A is the initiator, which sends msg1 and msg3, and B the responder. In the live
and appointment modes A is the person who drew the first words; in the physical-token mode the
roles are swapped: the person who received the token starts the handshake, and the person who
made it answers.

## 5. Words

### 5.1. Word list

The BIP-39 English list [BIP39]: 2048 words, all lowercase ASCII, at most 8 letters. Its UTF-8
file with one word per line and `\n` endings has SHA-256
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`. Word `i` is line `i`,
counting from 0.

### 5.2. Bytes to words

`to_words(b)` takes `b` two bytes at a time. Each pair, read as a big-endian 16-bit integer,
gives the word at index `pair & 0x7ff`. The words are joined by single spaces (0x20).

### 5.3. Invitation words

`n` invitation words are `to_words(random(2n))`, `11n` bits. A live or physical-token invitation
has `WORD_COUNT` words, drawn by the person who sets it up. An appointment has two groups:
`APPOINTMENT_WORDS_A` drawn by A and `APPOINTMENT_WORDS_B` drawn by B. People must never choose
the words themselves, since chosen words are far easier to guess.

### 5.4. Normalization

Before any use, words typed by a person are normalized: lowercase, split on whitespace, rejoined
with single spaces. The result must be exactly the number of words of its group, all from the
list; otherwise the input is rejected. Section 6 turns the normalized words, as bytes, into
`PRS`, the CPace password.

### 5.5. Comparing safety words

Typed safety words match when, lowercased and split on whitespace, they equal the 4 words of
`to_words(safety)` in order.

## 6. Invitations

An invitation gives both devices four values: `PRS`, the CPace password; `CI`, the CPace channel
identifier; `rendezvous`, a public 32-byte id; and its window, the wall-clock times it can be used,
ending at `expires`, unbounded for a live invitation. Both sides compute them from the same inputs;
the handshake (section 7) is the same in every mode.

Whenever a step starts (sections 7.1 and 7.2), a device checks the window on its wall clock and
gives the step its `ttl`:

```text
if now_unix is outside the window: stop
ttl = min(invite_ttl, expires - now_unix)          just invite_ttl for live
```

A pending step then dies at `deadline = now + ttl` on the monotonic clock, or once
`now_unix > expires`, whichever comes first. Checking the wall clock at every step, not only when
the invitation is built, keeps an invitation held in memory from outliving its window, and keeps a
long-lived token valid exactly until its expiry, even on a monotonic clock that stops while the
device is suspended.

The two devices must find each other's messages without any identifier. A posts msg1 at
`rendezvous` and B looks for it there. The application maps the 32-byte id onto its transport: a
mailbox queue, a storage address, a topic, truncating it if needed. Unrelated invitations
sometimes share an id: B answers every msg1 it finds there, up to a cap (section 10). Replies
(msg2, msg3) travel wherever the application decides, for example to an id derived from the
previous message. This specification leaves that to the application.

### 6.1. Live

With `words` the normalized 6 words:

```text
PRS = words
CI  = lv_cat(PROTOCOL, context)
tag = HKDF(salt = context, ikm = PRS, info = L_RV_TAG, 3)
rendezvous = HKDF(salt = context, ikm = tag, info = L_RV, 32)
window = unbounded
```

Since only 24 bits of the words go into the id, anyone watching it learns at most those 24 bits.

### 6.2. Appointment

A draws 5 words, `words_a`, and B draws 4, `words_b`. The two people swap them, along with `at`:
the agreed start time, as seconds since the Unix epoch, which both devices must pass identically
(applications should round it to the minute). With `words_a` and `words_b` normalized and
`be64(x)` the 8-byte big-endian encoding of `x`:

```text
expires = at + appointment_window
PRS = lv_cat(words_a, words_b)
CI  = lv_cat(PROTOCOL, context, L_APPOINTMENT, be64(at))
tag = HKDF(salt = CI, ikm = words_a, info = L_RV_TAG, 2)
rendezvous = HKDF(salt = CI, ikm = tag, info = L_RV, 32)
window = at <= now_unix <= expires
```

A device rejects the invitation, and every step from it, outside the window. Because `ttl` stops
at `expires`, the whole handshake, safety words included, must end within the window. After that,
the invitation is useless twice over: no device builds or answers it, and since `at` is part of
`CI`, messages from one appointment never complete with an invitation for another time, even with
the same words. `appointment_window` is a local parameter, not part of `CI`.

Only `words_a` go into the rendezvous id, through 16 bits, so watching the id reveals nothing
about `words_b`. Each start time has its own ids, so 16 bits are enough to keep unrelated
invitations apart.

### 6.3. Physical token

A, the person setting up the invitation, makes a physical token: these bytes, on something A
hands B in person and B's device can read:

```text
token = random(32) || be64(now_unix + lifetime)        TOKEN_LEN bytes
```

A also gives B 6 words another way. A keeps a copy of the token to build its own invitation, and
erases it once it expires. The last 8 bytes, `expires`, are the last second the token is valid.
With `words` the normalized 6 words:

```text
PRS = lv_cat(words, token)
CI  = lv_cat(PROTOCOL, context, L_TOKEN)
rendezvous = HKDF(salt = CI, ikm = token, info = L_RV, 32)
window = now_unix <= expires
```

A device rejects the invitation, and every step from it, once `now_unix > expires`. The lifetime
has no upper bound: the token's secret cannot be guessed, and even with the token an attacker
still needs the words. A device only checks that `now_unix + lifetime` fits in 64 bits when it
makes a token. B, who received the token, is the
initiator: it posts msg1 at the rendezvous and A only has to look there and answer. The rendezvous
id comes from the 32-byte secret, so nobody without the token can find or recognize it. The expiry
is part of `PRS`, so a token whose expiry was rewritten is another token and never completes.

## 7. Messages

```text
msg1 A->B | sid 16 | Ya 32 | Xa 32 | commitment 32 | ek 1184 |               1296 bytes
msg2 B->A | Yb 32 | Xb 32 | ct 1088 | sealed_b (len(payload_b) + 16) |     1168 + len(payload_b)
msg3 A->B | sealed_a (32 + len(payload_a) + 16) |                          48 + len(payload_a)
```

The lengths of msg2 and msg3 reveal the payload lengths. Receivers reject any message whose
length is not one of the lengths allowed for payloads from 0 to `PAYLOAD_CEILING` bytes. A
receiver never applies its own `max_payload` to the peer.

Shared definitions:

```text
T(m1, ..., mk) = SHA256(lv_cat(PROTOCOL, m1, ..., mk))   transcript hash
ikm = ISK || ss_x || ss_kem                          128 bytes
```

### 7.1. A: msg1

1. Build the invitation and check its window (section 6). Reject payloads over `max_payload`.
2. Draw:
   - `sid = random(16)`;
   - `ya`: CPace `sample_scalar()`, from `random(32)` with the top 4 bits of the last byte cleared,
     read little-endian;
   - `xa = random(32)`, an X25519 private key;
   - `(d, z) = random(32), random(32)` and `(ek, dk) = ML-KEM-768.KeyGen_internal(d, z)`;
   - `nonce = random(32)`.
3. `g = calculate_generator(SHA-512, PRS, CI, sid)` for ristretto255 ([CPACE] section 8.3).
4. `Ya = scalar_mult(ya, g)`, `Xa = X25519(xa, 9)`.
5. `commitment = SHA256(lv_cat(L_COMMIT, nonce, payload_a))`.
6. `msg1 = sid || Ya || Xa || commitment || ek`. Send it to the rendezvous id. Record the
   deadline (section 6) and `answers = 0`.

### 7.2. B: msg2

1. Build the invitation and check its window. If B has already answered `max_answers` msg1 for
   this invitation, stop. Reject payloads over `max_payload`. Reject msg1 unless it is exactly
   1296 bytes, and unless `ek` passes the FIPS 203 encapsulation key check.
2. Draw `yb` (as `ya`), `xb = random(32)` and `m = random(32)`.
3. `g = calculate_generator(SHA-512, PRS, CI, sid)`, `Yb = scalar_mult(yb, g)`,
   `Xb = X25519(xb, 9)`.
4. `ss_x = X25519(xb, Xa)`. Reject if it is all zeros.
5. `(ct, ss_kem) = ML-KEM-768.Encaps_internal(ek, m)`.
6. CPace, with associated data the rest of each CPace message:
   - `ADa = Xa || commitment || ek` (msg1 from byte 48 on);
   - `ADb = Xb || ct`;
   - `K = scalar_mult_vfy(yb, Ya)`; reject if `Ya` does not decode or `K` is the identity;
   - `ISK = SHA-512(lv_cat("CPaceRistretto255_ISK", sid, K) || transcript_ir(Ya, ADa, Yb, ADb))`.
7. `prefix = Yb || Xb || ct`, `key_b = HKDF(T(msg1, prefix), ikm, L_SEAL_B, 32)`.
8. `msg2 = prefix || Seal(key_b, payload_b)`. Send it to A. Keep `ikm`, msg1, msg2 and
   `commitment`, record the deadline, and count one more msg1 answered.

Every random value is drawn fresh for each msg1 answered.

### 7.3. A: msg3

On each candidate msg2:

1. If A has already finished, `answers >= max_answers`, or the deadline has passed (section 6),
   the invitation is dead: stop.
2. Check the length. Split msg2 into `Yb`, `Xb`, `ct` and `sealed_b`.
3. Compute `ISK` as B did, with `K = scalar_mult_vfy(ya, Yb)`, rejecting the same cases.
4. `ss_x = X25519(xa, Xb)`, rejected if all zeros. `ss_kem = ML-KEM-768.Decaps(dk, ct)`.
5. `payload_b = Open(HKDF(T(msg1, prefix), ikm, L_SEAL_B, 32), sealed_b)`.
6. If any step failed, increment `answers` and keep waiting: a wrong msg2 is someone's guess at
   the words, or noise, and must not end the invitation.
7. Otherwise `key_a = HKDF(T(msg1, msg2), ikm, L_SEAL_A, 32)`,
   `msg3 = Seal(key_a, nonce || payload_a)`. Send it to B. A has finished; go to section 8.

### 7.4. B: finishing

On each candidate msg3:

1. If the deadline has passed, stop.
2. Check the length. `nonce || payload_a = Open(HKDF(T(msg1, msg2), ikm, L_SEAL_A, 32), msg3)`.
3. Check, in constant time, that `SHA256(lv_cat(L_COMMIT, nonce, payload_a)) = commitment`.
4. If a step failed, keep waiting: a forged msg3 reveals nothing about the words. Otherwise go to
   section 8.

## 8. Key schedule and confirmation

Both sides compute:

```text
th     = T(msg1, msg2, msg3)
key    = HKDF(th, ikm, L_KEY, 32)
safety = HKDF(th, ikm, L_SAFETY, 8)
```

The handshake is not done yet. B shows `to_words(safety)`, 4 words. The two people compare them
over a channel where they recognize each other, such as in person or on a call; the words are not
secret. A types the words B reads out, and A's device accepts them only if they match its own
(section 5.5). B's user confirms once A says they matched.

Until then, an implementation:

- must not release the peer's payload or `key` to the application;
- keeps the session pending until its deadline; a typo leaves it pending, so the user
  can try again. If the words really differ, someone sat in the middle: abort, and treat both
  payloads as known to the attacker.

Once confirmed, both sides hold `key`, `th` (public, useful for channel binding) and the peer's
payload. Applications derive their own keys with:

```text
export(label) = HKDF(th, key, lv_cat(L_EXPORT, label), 32)
```

## 9. Payloads

Payloads are opaque to Nachalo. They are confidential against anyone without the words, and
authenticated once the safety words match. Typical payloads:

- **A ratchet:** each side's first ratchet public key, so both can send as soon as the safety words
  match.
- **Pigeonhole [PIGEONHOLE]:** each side's BACAP read capability, so each can read what the other
  writes. This plays the role of the voucher token exchange, authenticated by a PAKE instead of a
  token.

A man in the middle who knows the words learns both payloads before the safety words are compared.
Payloads must therefore be safe to discard: if the safety words differ, the application drops
everything the handshake carried (for example, abandons the channels whose read capabilities were
sent) and starts over with new words.

## 10. Limits

- A takes at most `max_answers` wrong msg2 per invitation.
- B answers every msg1 at the rendezvous, since unrelated invitations can share it and B cannot
  tell its peer's apart before the handshake ends. Each answer is one online guess for whoever
  sent that msg1, so B must answer at most `max_answers` msg1 per invitation; the reference
  implementation enforces it. The same cap bounds a man in the middle's chance of matching the
  safety words (section 11.3).
- Each pending step dies `ttl` after it started, on its own device's clock: `invite_ttl`, or less
  near the end of an appointment window or before a token expires. No time travels on the wire,
  so the two clocks never need to agree; the appointment and physical-token modes also check the
  wall clock whenever a step starts or continues.

## 11. Security considerations

### 11.1. Threat model

The attacker controls the network: it reads, drops, delays, replays, and forges messages, and it
can run as many sessions as it likes. It may later have a quantum computer. It may also learn the
invitation words, or read the physical token, for example by reading the message they were sent
in. It does not control the channel where the safety words are compared: the two people recognize
each other there.

### 11.2. Guessing the words

CPace [CPACE] makes every guess an online one: a transcript, passive or from a failed active
session, does not let an attacker test guesses offline. The only offline test is the rendezvous id,
and it depends on a few bits only; Magic Wormhole [WORMHOLE] keeps its short code out of its
channel id for the same reason, since with 16 bits its server could invert the hash. An attacker
that answers A's msg1 gets one guess per msg2, and A takes at most `max_answers`; the same holds
for msg1 sent to B, with B's cap. Per side and per invitation, an attacker breaks it with
probability at most `max_answers / 2^r`, where `r` is what the rendezvous leaves of the secret.
With the recommended `max_answers = 64`:

| Mode | Secret | Rendezvous reveals | `r` | Per side, `max_answers = 64` |
| --- | --- | --- | --- | --- |
| Live | 66 bits | 24 bits | 42 | 2^-36 |
| Appointment | 99 bits: A 55, B 44 | 16 bits of A's | 83 | 2^-77 |
| Appointment, A's words leaked | B's 44 bits | nothing about B's | 44 | 2^-38 |
| Appointment, B's words leaked | A's 55 bits | 16 bits | 39 | 2^-33 |
| Physical token, token read by the attacker | 66 bits | nothing about the words | 66 | 2^-60 |
| Physical token, words leaked, token safe | 256-bit secret | nothing | 256 | negligible |

Only A's words reach the rendezvous id of an appointment. If its id came from all 9 words, it would
be an offline test of all of them: 2^99 hashes, but only 2^44 once A's 5 words leak, few enough to
try within the window. Mixing in the start time and the window bounds the guessing further:
outside it, no device answers, and messages bound to another start time never complete.

### 11.3. Man in the middle with the words

CPace proves that both sides hold the words, not that nobody else does. An attacker M that knows
them can run one handshake with A, posing as B, and another with B, posing as A. Both complete.
The safety words catch it: the two sessions have different transcripts, so A's and B's safety
words differ unless M makes them collide.

M cannot steer the collision within a session. In its session with B, M commits to its nonce in
msg1 before it sees B's fresh msg2, so that session's safety words are fixed before M can
influence them. In its session with A, M must send its msg2 before A reveals the nonce committed
in msg1, and the safety words depend on that nonce. One session with each side therefore matches
with probability 2^-44.

M can still open several sessions with B, since B answers every msg1 at the rendezvous up to its
cap (section 10). M finishes with A first, computes the safety words of each of its sessions with
B on its own, completes only one that matches and lets the others expire unseen. With `q` msg1
answered by B, at most B's `max_answers`, M goes unnoticed with probability at most `q * 2^-44`:
2^-38 with the recommended cap of 64. A takes a single msg2 to the end, so A's side adds no such factor. Every failed attempt
is a handshake that two people saw fail or never complete. This is the commit-then-reveal
construction of short authentication string protocols [SAS], [ZRTP], with their usual bound for
parallel sessions.

The commitment must hide the payload, which may be low-entropy or public: hence the 32-byte
random nonce in it.

### 11.4. Quantum attackers

Key secrecy rests on three shared secrets, combined in `ikm`: breaking it needs CPace's ISK,
X25519's and ML-KEM-768's. A passive attacker with a quantum computer, recording now and
decrypting later, still faces ML-KEM-768.

Authentication rests on CPace and the safety words. CPace is not post-quantum, but it is
"quantum-annoying" [CPACE] section 10.12: with a fresh `sid` and the context in `CI`, a quantum
attacker must solve one discrete logarithm per guess at the words, within `invite_ttl`, online.
A longer `invite_ttl` does not give more guesses (the answer cap bounds them), but it widens this
window, keeps pending secrets in memory longer and lets the timing of an answer reveal more about
who is online. The token's secret is symmetric and 256 bits long, so a quantum attacker without the token
gains nothing on it. The safety words do not depend on any computational assumption.

### 11.5. Forward secrecy

Every key in the handshake is ephemeral. Learning the words after the handshake does not reveal
`key`. Learning a device's state during the handshake does.

### 11.6. Confirmation and replay

Each `Seal` tag doubles as key confirmation: only someone with `ikm`, and so with the words, can
produce it. A replayed msg1 is answered (msg1 carries no time) but cannot be completed without the
words; an old msg2 or msg3 fails because every transcript includes fresh randomness from both
sides.

### 11.7. Asynchrony

Both devices must take part within `invite_ttl` of each other. This bounds the online guessing
window and keeps pending secrets short-lived. The appointment and physical-token modes keep that
bound but let the people choose when: at an agreed time, which each brings their own words for,
or at any time before the token expires. Each answer still waits for a message from the other
side, so it shows that the person who sent it was online then: in an appointment, within a window
both people already agreed on. Applications that care delay their answers by a random time
within the remaining `ttl`.

The window of an appointment and the expiry of a token are checked against the device's wall clock,
at every step, and the network can move that clock. Moving it only changes whether that device
uses the invitation: the other device checks its own clock, and the start time is part of `CI`, so
a moved clock never makes an old invitation complete with a new one. Checking at every step gives
the network no more power than checking once at construction, as earlier drafts did.

### 11.8. Metadata

Message lengths reveal payload lengths, more so as a larger `max_payload` lets them vary more, and
the encodings of `Ya`, `Xa`, `Yb`, `Xb`, `ek` and `ct`
can be recognized, so an observer can tell a Nachalo message apart from random bytes.
Applications that must hide this wrap messages in fixed-size, encrypted frames of their own.

### 11.9. Implementation

Secret values (words, scalars, private keys, `ISK`, `ikm`, nonces) should be erased after use.
Comparisons of tags and commitments must be constant time. Error results should not say which
check failed.

## 12. Test vectors

`vectors/v0.json` (live), `vectors/v0-appointment.json` and `vectors/v0-physical-token.json` each
hold a full handshake with every random value fixed: the inputs, the random values of each role in
the order of section 7, the intermediate values (rendezvous, CPace generator, transcript and ISK,
shared secrets, `ikm`, commitment, transcript hashes, seal keys and safety bytes), the three
messages and the outputs. An implementation that injects those random
values must reproduce every byte. The local parameters (section 3.1) do not affect them.

The CPace layer can be checked on its own against [CPACE] appendix B.3.

## 13. Changes from the Janus Knot handshake

Nachalo began as the invitation of Janus Knot. Compared with it, v0:

- uses CPace exactly as in [CPACE], not the earlier construction of the `pake-cpace` crate, so any
  implementation of the draft interoperates and test vectors are possible;
- carries an opaque payload each way instead of Janus' ratchet key and rotation interval, and
  commits to a random nonce, which keeps the safety words safe whatever the payload is;
- confirms keys with the `Seal` tags of the payloads;
- takes an application context instead of Janus' network id, and returns a 32-byte rendezvous id.

## 14. References

- [BIP39] M. Palatinus et al., "Mnemonic code for generating deterministic keys", BIP 39.
- [CPACE] M. Abdalla, B. Haase, J. Hesse, "CPace, a balanced composable PAKE",
  draft-irtf-cfrg-cpace-21, 2026.
- [FIPS180-4] NIST, "Secure Hash Standard", FIPS 180-4.
- [FIPS203] NIST, "Module-Lattice-Based Key-Encapsulation Mechanism Standard", FIPS 203.
- [PIGEONHOLE] Katzenpost, "Pigeonhole" specification,
  <https://katzenpost.network/docs/specs/pigeonhole/>, and arXiv:2501.02933.
- [RFC5869] H. Krawczyk, P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function".
- [RFC7748] A. Langley, M. Hamburg, S. Turner, "Elliptic Curves for Security".
- [RFC8439] Y. Nir, A. Langley, "ChaCha20 and Poly1305 for IETF Protocols".
- [WORMHOLE] B. Warner, "Magic Wormhole: Attacks and defenses",
  <https://magic-wormhole.readthedocs.io/en/latest/attacks.html>.
- [SAS] S. Vaudenay, "Secure Communications over Insecure Channels Based on Short Authenticated
  Strings", CRYPTO 2005.
- [ZRTP] P. Zimmermann, A. Johnston, J. Callas, "ZRTP: Media Path Key Agreement for Unicast Secure
  RTP", RFC 6189.
