# Nachalo for TypeScript and JavaScript

`nachalo-wasm` compiles the Rust crate to WebAssembly with
[wasm-bindgen](https://github.com/wasm-bindgen/wasm-bindgen), with TypeScript definitions. Each
binding converts types and calls the core; the core's documentation holds for every function
here.

## Build

With the `wasm32-unknown-unknown` target and [wasm-pack](https://github.com/drager/wasm-pack)
0.15:

```bash
rustup target add wasm32-unknown-unknown
wasm-pack build bindings/wasm --target nodejs    # or --target web, or --target bundler
node --test bindings/wasm/tests/handshake.test.mts
```

The package lands in `bindings/wasm/pkg`. Randomness comes from `crypto.getRandomValues`, through
getrandom's `wasm_js` backend: browsers, web workers and Node.js 19 or later. The test runs a live
handshake, wrong words, a man in the middle, and the appointment and physical-token modes; it uses
`using`, so it needs Node.js 24.

## The API

The Rust API in camelCase. Where Rust returns a pair, these return a two-element array:
`Initiator.start` gives `[Initiator, msg1]`, `listener.respond` gives `[Responder, msg2]` and
`initiator.finish` gives `[Unconfirmed, msg3]`. Messages, payloads and keys are `Uint8Array`;
times are `bigint`, as are the durations, in seconds, of `Config.with*`. The constants are
functions: `payloadCeiling()`, `msg1Len()`, `msg2Len(payload)`, `msg3Len(payload)`,
`rendezvousLen()`, `tokenLen()`, `wordCount()`, `appointmentWordsA()`, `appointmentWordsB()`.

**Errors**: every fallible call throws an `Error` whose `name` is `"NachaloError"` and whose
`message` is a `NachaloErrorKind`: `"BadWords"`, `"Expired"`, `"PayloadTooLarge"`, `"Rejected"`,
`"OutOfRange"`, `"Rng"`, or `"Other"` for a failure these bindings do not know yet. `"Rejected"`
never says which check failed. As in Rust, a failed `finish` leaves its object usable, and
`unconfirmed.confirm` consumes the object, even when it throws.

## Secrets

Every class holding secret material (`Invitation`, `Initiator`, `Listener`, `Responder`,
`Unconfirmed`, `Established`) wipes it in Rust once freed. Free them as soon as a step is done:
call `free()`, or declare them with `using`. Without it the memory waits for the garbage
collector.

What crosses into JavaScript is a copy that Rust's zeroizing does not reach: the words, the
physical token, both payloads, `key()`, `export()`, and the strings and arrays you pass in, of
which a copy also passes through WebAssembly memory. Overwrite the arrays you own with
`fill(0)` once done (strings cannot be wiped), and keep them out of logs.

## Example

The live example of [the root README](../../README.md#reference-implementation):

```ts
import { Clock, Config, Initiator, Invitation, Listener, Profile, wordCount, words } from "nachalo-wasm";

const bytes = (text: string) => new TextEncoder().encode(text);
const context = bytes("my-app v1"); // equal on both sides, never sent
const config = new Config(Profile.Interactive); // local limits; each side may pick its own
// Each device's monotonic seconds and wall-clock Unix seconds, read before every step.
const clock = new Clock(0n, 1_900_000_000n);

// A's device draws the words, and A gives them to B; both sides build the invitation.
using invitation = Invitation.live(words(wordCount()), context, config);

// A posts msg1 at invitation.rendezvous(); B listens there and answers.
const [initiator, msg1] = Initiator.start(invitation, bytes("A's payload"), clock);
using a = initiator;
using listener = new Listener(invitation);
const [responder, msg2] = listener.respond(msg1, bytes("B's payload"), clock);
using b = responder;
const [unconfirmedA, msg3] = a.finish(msg2, clock);
using ua = unconfirmedA;
const ub = b.finish(msg3, clock);

// B reads out ub.safetyWords(), A types them, and B confirms once A says they matched.
using sessionA = ua.verify(ub.safetyWords(), clock);
using sessionB = ub.confirm(clock); // consumes ub

console.assert(sessionA.key().every((byte, i) => byte === sessionB.key()[i]));
```

The other modes only change how the invitation is built: `Invitation.appointment(wordsA, wordsB,
at, context, nowUnix, config)` and `Invitation.physicalToken(words, token, context, nowUnix,
config)`, with `newPhysicalToken(lifetime, nowUnix)` making the token.
