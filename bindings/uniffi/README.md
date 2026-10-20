# Nachalo for Kotlin and Swift

`nachalo-uniffi` exposes the Rust crate through [UniFFI](https://mozilla.github.io/uniffi-rs/)
0.31.0, pinned exactly because [the Go bindings](../go/README.md) are generated from the same
library by uniffi-bindgen-go v0.7.1+v0.31.0. Each binding converts types and calls the core; the
core's documentation holds for every function here.

## Build

```bash
cargo build -p nachalo-uniffi --lib --release   # cdylib for Kotlin (JNA), staticlib for Swift
cargo run -p nachalo-uniffi --bin uniffi-bindgen -- generate \
  --library target/release/libnachalo_uniffi.so --language kotlin --out-dir out/kotlin
cargo run -p nachalo-uniffi --bin uniffi-bindgen -- generate \
  --library target/release/libnachalo_uniffi.dylib --language swift --out-dir out/swift
```

- **Kotlin** gets `out/kotlin/uniffi/nachalo/nachalo.kt`, package `uniffi.nachalo`. It needs
  [JNA](https://github.com/java-native-access/jna) and loads `libnachalo_uniffi` from
  `jna.library.path` (on Android, put one build per ABI in `jniLibs`, for example with
  `cargo ndk`).
- **Swift** gets `nachalo.swift`, `nachaloFFI.h` and `nachaloFFI.modulemap`. Compile
  `nachalo.swift` with `-Xcc -fmodule-map-file=nachaloFFI.modulemap` and link
  `libnachalo_uniffi.a`; for iOS, build the static library for each target and wrap it in an
  XCFramework.

The tests run the same scenarios as the other bindings: a live handshake, wrong words, a man in
the middle, and the appointment and physical-token modes.

```bash
# Kotlin, with JNA's jar at jna.jar
kotlinc -classpath jna.jar out/kotlin/uniffi/nachalo/nachalo.kt -d nachalo.jar
kotlinc -classpath jna.jar:nachalo.jar -J-Djna.library.path=target/release \
  -script bindings/uniffi/tests/kotlin/handshake.kts
# Swift, on macOS
swiftc -Xcc -fmodule-map-file=out/swift/nachaloFFI.modulemap -I out/swift out/swift/nachalo.swift \
  bindings/uniffi/tests/swift/main.swift target/release/libnachalo_uniffi.a -o swift-test && ./swift-test
```

## The API

The Rust API, in each language's naming. Where Rust returns a pair, the bindings return the
object with its message: `Initiator.start` returns an `Initiator` whose `msg1()` is the first
message, `Listener.respond` an `Answer` (`responder`, `msg2`), and `Initiator.finish` a `Finished`
(`unconfirmed`, `msg3`). Times are `ULong` in Kotlin and `UInt64` in Swift; durations in
`Config.with*` are seconds. The constants are functions: `payloadCeiling()`, `msg1Len()`,
`msg2Len(payload)`, `msg3Len(payload)`, `rendezvousLen()`, `tokenLen()`, `wordCount()`,
`appointmentWordsA()`, `appointmentWordsB()`.

**Errors** are `NachaloException` in Kotlin (a sealed class: `BadWords`, `Expired`,
`PayloadTooLarge`, `Rejected`, `OutOfRange`, `Rng`, and `Other` for a failure these bindings do
not know yet) and `NachaloError` in Swift (the same cases). `Rejected` never says which check
failed. As in Rust, a failed `finish` leaves its object usable, and `Initiator.finish` returns
`Expired` once it has succeeded. `Unconfirmed.confirm` consumes the object: any later call on it,
`safetyWords` included, returns `Expired`.

## Secrets

Every object holding secret material (`Invitation`, `Initiator`, `Listener`, `Responder`,
`Unconfirmed`, `Established`, and the `Answer` and `Finished` holding them) wipes it in Rust once
released. Release them as soon as a step is done:

- **Kotlin**: every object is `AutoCloseable`; call `close()` (or `destroy()`) or use `use { }`.
  Without it the memory waits for the garbage collector.
- **Swift**: an object is released, deterministically, when its last reference goes: keep them
  in a narrow scope or set the variable to `nil`.

What crosses into Kotlin or Swift is a copy that Rust's zeroizing does not reach: the words, the
physical token, both payloads, `key()`, `export()` and the strings and byte arrays you pass in.
Overwrite them yourself where the platform allows it (`ByteArray.fill(0)`, a `Data` you own),
and keep them out of logs.

## Example

The live example of [the root README](../../README.md#reference-implementation), in Kotlin:

```kotlin
import uniffi.nachalo.*

val context = "my-app v1".toByteArray() // equal on both sides, never sent
val config = Config(Profile.INTERACTIVE) // local limits; each side may pick its own
// Each device's monotonic seconds and wall-clock Unix seconds, read before every step.
val clock = Clock(now = 0uL, nowUnix = 1_900_000_000uL)

// A's device draws the words, and A gives them to B; both sides build the invitation.
Invitation.live(words(wordCount()), context, config).use { invitation ->
    // A posts msg1 at invitation.rendezvous(); B listens there and answers.
    Initiator.start(invitation, "A's payload".toByteArray(), clock).use { a ->
        Listener(invitation).use { listener ->
            val (b, msg2) = listener.respond(a.msg1(), "B's payload".toByteArray(), clock)
            b.use {
                val (unconfirmedA, msg3) = a.finish(msg2, clock)
                val unconfirmedB = b.finish(msg3, clock)
                // B reads out the safety words, A types them, and B confirms once they matched.
                unconfirmedA.use {
                    unconfirmedB.use {
                        unconfirmedA.verify(unconfirmedB.safetyWords(), clock).use { ea ->
                            unconfirmedB.confirm(clock).use { eb ->
                                check(ea.key().contentEquals(eb.key()))
                                check(ea.peerPayload().contentEquals("B's payload".toByteArray()))
                            }
                        }
                    }
                }
            }
        }
    }
}
```

In Swift, where each object is released at the end of the `do` block:

```swift
let context = Data("my-app v1".utf8)
let config = Config(profile: .interactive)
let clock = Clock(now: 0, nowUnix: 1_900_000_000)

do {
    let invitation = try Invitation.live(words: try words(count: wordCount()), context: context, config: config)
    let a = try Initiator.start(invitation: invitation, payload: Data("A's payload".utf8), clock: clock)
    let listener = Listener(invitation: invitation)
    let answer = try listener.respond(msg1: a.msg1(), payload: Data("B's payload".utf8), clock: clock)
    let finished = try a.finish(msg2: answer.msg2, clock: clock)
    let unconfirmedB = try answer.responder.finish(msg3: finished.msg3, clock: clock)

    let sessionA = try finished.unconfirmed.verify(typed: try unconfirmedB.safetyWords(), clock: clock)
    let sessionB = try unconfirmedB.confirm(clock: clock)
    assert(sessionA.key() == sessionB.key())
    assert(sessionA.peerPayload() == Data("B's payload".utf8))
}
```

The other modes only change how the invitation is built: `Invitation.appointment(wordsA, wordsB,
at, context, nowUnix, config)` and `Invitation.physicalToken(words, token, context, nowUnix,
config)`, with `newPhysicalToken(lifetime, nowUnix)` making the token.
