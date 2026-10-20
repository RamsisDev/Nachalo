# Formal model

A symbolic model of Nachalo v0 in [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/),
covering the handshake of sections 7 and 8 of the [specification](../spec/nachalo.md) in each
invitation mode. It checks what a symbolic model can check: secrecy, authentication and the
absence of offline tests of the words. The probabilities of section 11 (`max_answers / 2^r`, the
2^-38 of the safety words) are outside its reach.

## Running it

With ProVerif 2.05 on the `PATH`:

```sh
formal/check.sh                 # every model, in parallel
formal/check.sh live.pv         # one model
proverif -lib nachalo live.pv   # from formal/, to read the full output
```

`check.sh` compares the `RESULT` lines of each model with the expected results written at its
end, and fails on any difference. Set `PROVERIF` to use another binary.

The models take about 15 minutes, so CI runs them only when a release is published
([`formal.yml`](../.github/workflows/formal.yml)), or by hand from the Actions tab.

## Models

| Model | Attacker | Checks |
| --- | --- | --- |
| `nachalo.pvl` | | Primitives and the two roles, shared by every model |
| `live.pv` | Network | No offline test of the words; payloads and keys secret; each side finishes only against the other |
| `appointment.pv` | Network | The same, with both groups of words; messages for one start time never complete with an invitation for another |
| `appointment-a-leaked.pv` | Network, with A's words | No offline test of B's words |
| `appointment-b-leaked.pv` | Network, with B's words | No offline test of A's words |
| `appointment-rendezvous.pv` | Network, with B's words | Expected attack: a rendezvous id made from A's words in full would be an offline test of them |
| `physical-token.pv` | Network, with the token or with the words | No offline test of the words when the token is read; nothing at all without the token |
| `mitm.pv` | Knows the words | Matching safety words imply the same transcript on both sides and a secret key |
| `quantum.pv` | Records now, later breaks CPace and X25519 and learns the words | ML-KEM-768 keeps the keys secret |

A property could also hold because the model never runs. So `live.pv`, `appointment.pv` and
`physical-token.pv` check that an honest handshake reaches its end, and the other models expect
at least one attack, which ProVerif must find.

## Abstractions

- **Hashes, HKDF and ChaCha20-Poly1305** are ideal: random oracles and authenticated
  encryption. Truncation is not modeled, so the safety words never collide.
- **CPace** is a shared point `cpace_dh(g, ya, yb)`, symmetric in the scalars, which only a
  holder of one scalar and the other share on the same generator computes. A share on another
  generator gives an unrelated point, as `scalar_mult_vfy` does. A commuting equation on a
  variable base would be closer to the group, but ProVerif does not terminate with it.
- **X25519** is Diffie-Hellman on the fixed base point, and **ML-KEM-768** a deterministic
  encapsulation in `m`. Point validation and the all-zero check are not modeled.
- **The rendezvous id** of a live or appointment invitation carries 24 or 16 bits of the words.
  ProVerif cannot express a partial leak: a published id would be a full offline test. Those
  models leave it out, and `appointment-rendezvous.pv` shows the attack it would allow. The id
  of a physical token comes from its 256-bit secret, and is published, and so is an
  appointment's in `appointment-a-leaked.pv`, where it reveals nothing about B's words.
- **Time** is not modeled: windows, expiries and `invite_ttl` only limit when a step runs, and
  the attacker may run any number of sessions. `max_answers` is not modeled either.
- **Each side takes one msg2 or msg3 per state.** The specification lets A and B wait for
  another after a wrong one; in a symbolic model, a wrong guess is never right, so this only
  matters for the bounds of section 11.
- **The safety words** travel over a channel the attacker can read but not write, as in
  section 11.1.

## Findings

- **B's payload against a future quantum attacker** (`quantum.pv`). B seals `payload_b` in
  msg2, before it can tell who sent msg1. An attacker that sends msg1 today with its own ML-KEM
  key knows `ss_kem`, so only CPace protects that msg2. Later, with a quantum computer, it can
  recover B's CPace scalar for each guess at the words and test it against the sealed payload:
  one discrete logarithm per guess, offline and with no time limit. Section 11.4 of the
  specification now describes this case and what applications should keep out of `payload_b`.
