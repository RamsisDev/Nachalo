# Nachalo documentation

These pages explain how Nachalo works and how to use it. They are a guide, not the definition:
where they and [the specification](../spec/nachalo.md) differ, the specification wins.

- [The handshake](handshake.md): the three messages, the payloads, the safety words, and what the
  application provides. The same in every mode.
- [Live](live.md): one person gives the other 6 words, and both connect within minutes.
- [Appointment](appointment.md): each person brings words, and they connect at an agreed time.
- [Physical token](physical-token.md): one person hands the other a token in person, and they
  connect whenever they like before it expires.

## Choosing a mode

The three modes differ only in how the invitation is set up. Once both devices hold it, the
handshake and the safety words are identical.

| | [Live](live.md) | [Appointment](appointment.md) | [Physical token](physical-token.md) |
| --- | --- | --- | --- |
| What people swap | 6 words | 5 words one way, 4 the other, and a start time | A token in person, and 6 words |
| When the devices connect | Within 10 minutes, by default | In a window at the agreed time, 30 minutes by default | Any time before the token expires |
| Who starts | Who drew the words | Who drew the 5 words | Who received the token |
| One leaked message gives away | The whole invitation | Half of it | The words, useless without the token |
| Online guessing, per side, default limits | 2^-36 | 2^-77 | 2^-60 if the token is stolen |
| Needs the wall clock | No | Yes | Yes |

Pick:

- **Live** when both people are available now: on a call, or side by side.
- **Appointment** when they cannot connect right away, or want the invitation split so a single
  intercepted message is not enough.
- **Physical token** when they meet in person now but will connect later, at a moment that is not
  fixed yet.

In every mode, someone who learned the full invitation can sit in the middle and read both
payloads, and the safety words are what catches them. Compare them where the two people recognize
each other, and if they differ, discard everything and start over.

## Glossary

- **Invitation**: what the two people swap outside the protocol, and what each device builds from
  it: a CPace password, a CPace channel identifier, a rendezvous id and a time limit.
- **Context**: a byte string the application picks, such as its name and version, equal on both
  sides. It never travels on the wire, and devices with different contexts never connect.
- **Rendezvous id**: a public 32-byte id where the initiator posts msg1 and the responder looks
  for it. The application maps it onto its transport.
- **Initiator / responder**: the device that sends msg1 and msg3, and the device that answers
  with msg2.
- **Payload**: opaque bytes each side sends to the other, up to its own `max_payload` (1 KiB by
  default). Every device accepts up to 8 KiB.
- **Profile**: in the reference implementation, a named set of local limits with allowed ranges:
  `INTERACTIVE` (the default), `PQ_MESSENGER` or `NEARBY`. See
  [the handshake](handshake.md#time-and-limits).
- **Safety words**: 4 words derived from the whole handshake. The responder shows them, the
  initiator types them.
- **Online guess**: a guess at the invitation that costs the attacker a live exchange with a
  victim. Nachalo allows no other kind.
