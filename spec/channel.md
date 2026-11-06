# Nachalo Channel v1

**Status:** draft v0.1, unaudited. This is **not** part of the Nachalo v0 specification
(`spec/nachalo.md`). It defines what two peers run after a Nachalo handshake completes and the
safety words match. Its reference implementation is the `nachalo-channel` crate.

The channel takes inspiration from the symmetric-key chain of Signal's Double Ratchet. It uses
only standard primitives: HKDF-SHA256 (RFC 5869), ChaCha20-Poly1305 (RFC 8439) and the
`lv_cat` encoding of the Nachalo specification (each part as its LEB128 length, then its bytes).

## 1. Inputs

An established Nachalo session gives both sides:

- `export(label)`: an independent 32-byte key per label, equal on both sides;
- `transcript`: the public 32-byte hash of the handshake;
- `role`: initiator (A) or responder (B).

The application picks a public **peer id** of 1 to 64 bytes, equal on both sides. The Hermes
plugin uses:

```text
peer_id = base32(SHA256(lv_cat("hermes-nachalo/1 peer-id", transcript)))[:16]
```

## 2. Keys

| Label | Use |
| --- | --- |
| `hermes-nachalo/1 chain i2r` | Initial chain key, A to B |
| `hermes-nachalo/1 chain r2i` | Initial chain key, B to A |
| `hermes-nachalo/1 topic i2r` | Topic seed, A to B |
| `hermes-nachalo/1 topic r2i` | Topic seed, B to A |
| `hermes-nachalo/1 root` | Root for the hybrid re-key (v1.1) |

A sends on `i2r` and receives on `r2i`; B the reverse. The raw handshake key (`key()`) is never
used.

## 3. Ratchet

For message `n` of one direction, with `HKDF(salt, ikm, info, len)`:

```text
mk_n     = HKDF("", ck_n, "hermes-nachalo/1 msg",   32)
ck_(n+1) = HKDF("", ck_n, "hermes-nachalo/1 chain", 32)
```

`ck_0` is the direction's initial chain key. A sender erases `ck_n` once it derives
`ck_(n+1)`, which gives forward secrecy: the state of today does not open frames of yesterday.

A receiver that sees counter `c` greater than its next expected counter `r`:

1. rejects the frame if `c - r > 64`;
2. derives `mk_r … mk_(c-1)` and keeps them as **skipped keys**, at most 64 per direction (the
   lowest counters are dropped first), each for 7 days;
3. opens the frame with `mk_c`; only if the tag verifies does it commit the new chain key,
   `r = c + 1` and the skipped keys.

A frame with `c < r` opens only with its skipped key, which is then deleted. Any other `c < r`
is a replay and is rejected.

## 4. Frames

Every frame is exactly **512** or **2048** bytes. A sender uses the small size whenever the body
fits.

| Field | Bytes | Value |
| --- | --- | --- |
| `version` | 1 | `0x01` |
| `kind` | 1 | `0x01` data, `0x02` ack, `0x03` re-key (v1.1), `0x04` close |
| `epoch` | 4 | `floor(unix_time / 86400)` at sealing, big-endian |
| `counter` | 8 | `n`, big-endian |
| `ciphertext` | size − 30 | the padded plaintext, encrypted |
| `tag` | 16 | Poly1305 |

- Key: `mk_n`. Nonce: four zero bytes, then `be64(n)`. Each `mk_n` seals one frame only, so the
  nonce would be unique even if it were constant; the counter is defence in depth.
- Associated data: the 14 header bytes, then the peer id.
- Plaintext: `be16(len) || body || zeros`, filling the frame. A small frame carries up to 480
  bytes of body, a large one up to 2016.
- A receiver rejects, without detail, a frame of any other size, an unknown version or kind, a
  tag that does not verify or a `len` larger than the plaintext.

The body format belongs to the application. The Hermes plugin sends UTF-8 JSON:

```json
{ "id": "01JC…", "type": "note|ask|answer|ack|close", "reply_to": "01JB…",
  "ts": 1762444800, "part": [1, 1], "text": "…" }
```

Messages longer than one large frame are split into up to 8 parts. Receivers de-duplicate by
`id` for 7 days, on top of the counter check.

## 5. Topics

A relay topic names where one direction publishes on UTC day `e`:

```text
topic(seed, e) = "nh" || base64url(HKDF("", seed, lv_cat("hermes-nachalo/1 epoch", be32(e)), 24))
```

The result is 34 characters of `[-_A-Za-z0-9]`, valid for ntfy. Receivers read `e - 1`, `e` and
`e + 1` to absorb clock skew. Topics come from a secret, so the relay can neither guess them nor
link one day's traffic of a pair to another's, except through IP addresses and timing.

## 6. Sealed state

The whole state (role, peer id, both chain keys and counters, both topic seeds, the root and the
skipped keys with their times) is serialized and sealed as:

```text
0x01 || nonce(12, random) || ChaCha20-Poly1305(store_key, nonce, state,
                                               aad = lv_cat("hermes-nachalo/1 state", peer_id))
```

Opening checks the tag, the version and that the serialized peer id equals the requested one.
Restoring an older blob rolls the receive window back, so the host must not let an attacker swap
blobs; that is part of the local-machine trust the channel assumes.

## 7. Vectors

With the stand-in `export(label) = HKDF("", label, "nachalo-channel v1 vectors", 32)`, peer id `K7QX2M9PABCDEFGH`, `unix_time = 1762444800` (`e = 20398`) and the initiator sealing the
data body `{"text":"hola"}` twice:

| Value | Result |
| --- | --- |
| topic i2r | `nhbMoZxUPGos0o71sjRXkQkuQ1LpCwOkbq` |
| topic r2i | `nhOrhcqm-AClDGAwo0cYeGlF-oFLZ4PckA` |
| frame 0 header | `010100004fae0000000000000000` |
| frame 0 tag | `24616557944957cde42509f673d17a72` |
| frame 1 header | `010100004fae0000000000000001` |
| frame 1 tag | `c51dad69eec8e99cd6858c896dda235a` |

These values were reproduced by an independent Python implementation (`cryptography`).

## 8. What this does not give

- **Post-compromise security.** Until the hybrid re-key of v1.1 (a fresh X25519 and ML-KEM-768
  exchange every 100 messages or 24 hours, mixed into the root), whoever steals the state reads
  everything after it until the pair is revoked.
- **Metadata privacy.** The relay sees topics, IP addresses, timing and the two frame sizes.
- **Availability.** A relay can drop or delay frames.
- **An audit.** Neither this channel nor the handshake has been audited.
