# Changelog

## Unreleased

The wire format, `CI` and the test vectors are unchanged; `PROTOCOL` stays `"Nachalo v0"`.

- **Receivers accept payloads up to `PAYLOAD_CEILING` (8192 bytes)**, whatever they send
  themselves. An implementation that still rejects payloads over 1024 bytes fails against one
  that sends more.
- **Local, configurable limits.** `INVITE_TTL`, `MAX_ANSWERS`, `MAX_PAYLOAD` and
  `APPOINTMENT_WINDOW` are no longer constants: each device picks `invite_ttl`, `max_answers`,
  `max_payload` and `appointment_window` through a `Config`, from the profiles `INTERACTIVE` (the
  previous values, and the default), `PQ_MESSENGER` and `NEARBY`, within each profile's ranges.
- **The wall clock is checked at every step.** An appointment or physical-token invitation kept
  in memory used to complete a handshake after its window closed or its token expired. Every step
  now takes a `Clock` (`now` and `now_unix`) and returns `Expired` outside the window.
- **The responder's answer cap is enforced** by `Listener`, which replaces `Responder::respond`.
- `new_physical_token` returns a `Result` and rejects an expiry that overflows. `Error` is
  `#[non_exhaustive]` and gains `OutOfRange`.
