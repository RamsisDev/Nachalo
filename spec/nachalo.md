# Nachalo v0

**Status:** draft. Not audited, not formally verified. Version `v0` may still change without
notice; the first stable version will be `v1`.

**License:** this document is licensed under [CC BY 4.0](LICENSE).

## 1. Introduction

Nachalo ("beginning") is a three-message handshake for first contact between two people who
share nothing but 6 words. One person, the initiator A, draws 6 random words and gives them to
the other, the responder B, outside the system: spoken, written down or over another app. With
those words alone, the two devices:

- agree on a shared key that a network attacker cannot learn, even with a quantum computer later
  (CPace + X25519 + ML-KEM-768);
- swap one opaque payload each way, such as the first public key of a ratchet or the read
  capability of a channel;
- catch an attacker who learned the 6 words and sits in the middle: B shows 4 safety words and A
  types them.

Nachalo is a protocol, not a library. This document is its definition; the Rust crate in the same
repository is a reference implementation, and `vectors/v0.json` lets any other implementation
check itself byte by byte.

### 1.1. Goals

- Only online guesses at the words: every guess costs the attacker one live exchange with a
  victim, and victims cap how many they take.
- Key secrecy against a passive attacker with a future quantum computer.
- Detection of an active attacker who knows the words, with probability at least 1 - 2^-38 per
  attempt (section 11.3).
- No identifiers, accounts, or clocks on the wire. Messages are byte strings that the application
  carries over any transport.

### 1.2. Non-goals

- Hiding that a handshake took place, or the payload lengths. Applications that care pad their
  payloads and wrap the messages in their own fixed-size frames.
- Long-term identity. Nachalo authenticates a session with the words and the safety words, not a
  person. Applications build identity on top, for example by sending long-term keys as payloads.
- Group or asynchronous first contact. Both devices take part within the invitation lifetime
  (`INVITE_TTL`, 10 minutes). Section 11.7 discusses this.

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
| `INVITE_TTL` | 600 seconds | Lifetime of each side's pending step |
| `MAX_ANSWERS` | 64 | Wrong msg2 an initiator accepts before it gives up |
| `MAX_PAYLOAD` | 1024 bytes | Largest payload either side may send |
| `WORD_COUNT` | 6 | Invitation words, 66 bits |
| `SAFETY_LEN` | 8 bytes | Safety words: 4 words, 44 bits |

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

## 4. Inputs

- `words`: the 6 invitation words (section 5).
- `context`: a byte string the application chooses, equal on both sides, such as the name and
  version of the application and of the network it runs on. It never travels on the wire.
  Devices with different contexts never complete a handshake.
- `payload_a`, `payload_b`: up to `MAX_PAYLOAD` bytes each, possibly empty, from A and B.
- `now`: seconds on a clock of the device itself. Only differences on one device matter. It
  should be a monotonic clock that keeps counting while the device sleeps, never the wall clock,
  which the network can move.

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

A draws `to_words(random(12))`: 6 words, 66 bits. People must never choose the words themselves,
since chosen words are far easier to guess.

### 5.4. Normalization

Before any use, words typed by a person are normalized: lowercase, split on whitespace, rejoined
with single spaces. The result must be exactly 6 words from the list; otherwise the input is
rejected. The normalized words, as bytes, are `PRS`, the CPace password.

### 5.5. Comparing safety words

Typed safety words match when, lowercased and split on whitespace, they equal the 4 words of
`to_words(safety)` in order.

## 6. Rendezvous

The two devices must find each other's messages without any identifier. A posts msg1 at a public
rendezvous id that B computes from the same words and context:

```text
tag = HKDF(salt = context, ikm = PRS, info = L_RV_TAG, 3)
rendezvous = HKDF(salt = context, ikm = tag, info = L_RV, 32)
```

The application maps the 32-byte id onto its transport: a mailbox queue, a storage address, a
topic, truncating it if needed. Since only 24 bits of the words go in, anyone watching the id
learns at most those 24 bits, and unrelated invitations sometimes share an id: B answers every
msg1 it finds there, up to a cap (section 10).

Replies (msg2, msg3) travel wherever the application decides, for example to an id derived from
the previous message. This specification leaves that to the application.

## 7. Messages

```text
msg1 A->B | sid 16 | Ya 32 | Xa 32 | commitment 32 | ek 1184 |               1296 bytes
msg2 B->A | Yb 32 | Xb 32 | ct 1088 | sealed_b (len(payload_b) + 16) |     1168 + len(payload_b)
msg3 A->B | sealed_a (32 + len(payload_a) + 16) |                          48 + len(payload_a)
```

The lengths of msg2 and msg3 reveal the payload lengths. Receivers reject any message whose
length is not one of the lengths allowed for payloads from 0 to `MAX_PAYLOAD` bytes.

Shared definitions:

```text
CI = lv_cat(PROTOCOL, context)                      CPace channel identifier
T(m1, ..., mk) = SHA256(lv_cat(PROTOCOL, m1, ..., mk))   transcript hash
ikm = ISK || ss_x || ss_kem                          128 bytes
```

### 7.1. A: msg1

1. Normalize the words into `PRS` (section 5.4). Reject payloads over `MAX_PAYLOAD`.
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
6. `msg1 = sid || Ya || Xa || commitment || ek`. Send it to the rendezvous id. Record
   `started = now` and `answers = 0`.

### 7.2. B: msg2

1. Normalize the words. Reject payloads over `MAX_PAYLOAD`. Reject msg1 unless it is exactly 1296
   bytes, and unless `ek` passes the FIPS 203 encapsulation key check.
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
   `commitment`, and record `started = now`.

Every random value is drawn fresh for each msg1 answered.

### 7.3. A: msg3

On each candidate msg2:

1. If A has already finished, `answers >= MAX_ANSWERS`, or `now > started + INVITE_TTL`, the
   invitation is dead: stop.
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

1. If `now > started + INVITE_TTL`, stop.
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
- keeps the session pending until `started + INVITE_TTL`; a typo leaves it pending, so the user
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

- A takes at most `MAX_ANSWERS` wrong msg2 per invitation.
- B answers every msg1 at the rendezvous, since unrelated invitations can share it and B cannot
  tell its peer's apart before the handshake ends. Each answer is one online guess for whoever
  sent that msg1, so B should cap how many msg1 it answers per invitation; this implementation
  recommends `MAX_ANSWERS` as well. The same cap bounds a man in the middle's chance of matching
  the safety words (section 11.3).
- Each pending step dies `INVITE_TTL` after it started, on its own device's clock. No time travels
  on the wire, so the two clocks never need to agree.

## 11. Security considerations

### 11.1. Threat model

The attacker controls the network: it reads, drops, delays, replays, and forges messages, and it
can run as many sessions as it likes. It may later have a quantum computer. It may also learn the
6 words, for example by reading the message they were sent in. It does not control the channel
where the safety words are compared: the two people recognize each other there.

### 11.2. Guessing the words

The words are a 66-bit secret. CPace [CPACE] makes every guess an online one: a transcript, passive
or from a failed active session, does not let an attacker test guesses offline. The rendezvous
reveals at most 24 bits, leaving 42. An attacker that answers A's msg1 gets one guess per msg2,
and A takes at most 64, so one invitation is broken this way with probability at most
2^6 / 2^42 = 2^-36. The same bound holds for msg1 sent to B, with B's cap.

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
answered by B, M goes unnoticed with probability at most `q * 2^-44`: 2^-38 with the recommended
cap of 64. A takes a single msg2 to the end, so A's side adds no such factor. Every failed attempt
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
attacker must solve one discrete logarithm per guess at the words, during the 10-minute window,
online. The safety words do not depend on any computational assumption.

### 11.5. Forward secrecy

Every key in the handshake is ephemeral. Learning the words after the handshake does not reveal
`key`. Learning a device's state during the handshake does.

### 11.6. Confirmation and replay

Each `Seal` tag doubles as key confirmation: only someone with `ikm`, and so with the words, can
produce it. A replayed msg1 is answered (msg1 carries no time) but cannot be completed without the
words; an old msg2 or msg3 fails because every transcript includes fresh randomness from both
sides.

### 11.7. Asynchrony

Both devices must take part within `INVITE_TTL`. This bounds the online guessing window and keeps
pending secrets short-lived. Making first contact fully asynchronous, like a voucher token left
for the other side, would extend that window and is left for a future version.

### 11.8. Metadata

Message lengths reveal payload lengths, and the encodings of `Ya`, `Xa`, `Yb`, `Xb`, `ek` and `ct`
can be recognized, so an observer can tell a Nachalo message apart from random bytes.
Applications that must hide this wrap messages in fixed-size, encrypted frames of their own.

### 11.9. Implementation

Secret values (words, scalars, private keys, `ISK`, `ikm`, nonces) should be erased after use.
Comparisons of tags and commitments must be constant time. Error results should not say which
check failed.

## 12. Test vectors

`vectors/v0.json` holds a full handshake with every random value fixed: the inputs, the random
values of each role in the order of section 7, the intermediate values (rendezvous, CPace
generator, transcript and ISK, shared secrets, `ikm`, commitment, transcript hashes, seal keys and
safety bytes), the three messages and the outputs. An implementation that injects those random
values must reproduce every byte.

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
- [SAS] S. Vaudenay, "Secure Communications over Insecure Channels Based on Short Authenticated
  Strings", CRYPTO 2005.
- [ZRTP] P. Zimmermann, A. Johnston, J. Callas, "ZRTP: Media Path Key Agreement for Unicast Secure
  RTP", RFC 6189.
