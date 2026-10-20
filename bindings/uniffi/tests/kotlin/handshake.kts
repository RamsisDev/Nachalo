// Run with kotlinc -script, the generated bindings and JNA on the classpath (see ../../README.md).
import uniffi.nachalo.*

val context = "my-app v1".toByteArray()
val clock = Clock(now = 0uL, nowUnix = 1_900_000_000uL)
val config = Config(Profile.INTERACTIVE)
val WORDS = "alpha cable echo forest orbit velvet"

inline fun <reified E : NachaloException> throws(block: () -> Unit) {
    try {
        block()
    } catch (e: NachaloException) {
        check(e is E) { "expected ${E::class.simpleName}, got $e" }
        return
    }
    throw AssertionError("expected ${E::class.simpleName}")
}

/** msg1 from [invitationA], answered by [invitationB]: both sides before the safety words. */
fun handshake(invitationA: Invitation, invitationB: Invitation): Pair<Unconfirmed, Unconfirmed> =
    Initiator.start(invitationA, "A's payload".toByteArray(), clock).use { a ->
        Listener(invitationB).use { listener ->
            val (b, msg2) = listener.respond(a.msg1(), "B's payload".toByteArray(), clock)
            b.use {
                val (unconfirmedA, msg3) = a.finish(msg2, clock)
                Pair(unconfirmedA, b.finish(msg3, clock))
            }
        }
    }

// A live handshake runs end to end.
Invitation.live(words(wordCount()), context, config).use { invitation ->
    check(invitation.rendezvous().size.toUInt() == rendezvousLen())
    val (ua, ub) = handshake(invitation, invitation)
    check(ua.role() == Role.INITIATOR && ub.role() == Role.RESPONDER)
    ua.verify(ub.safetyWords(), clock).use { a ->
        ub.confirm(clock).use { b ->
            check(a.key().contentEquals(b.key()))
            check(a.transcript().contentEquals(b.transcript()))
            check(a.export("x".toByteArray()).contentEquals(b.export("x".toByteArray())))
            check(a.peerPayload().contentEquals("B's payload".toByteArray()))
            check(b.peerPayload().contentEquals("A's payload".toByteArray()))
        }
    }
    // confirm consumed ub.
    throws<NachaloException.Expired> { ub.confirm(clock) }
    throws<NachaloException.Expired> { ub.safetyWords() }
    ua.close()
    ub.close()
}

// Wrong words are rejected, and leave the initiator usable.
Invitation.live(WORDS, context, config).use { invitation ->
    Invitation.live("alpha cable echo forest orbit zoo", context, config).use { wrong ->
        Initiator.start(invitation, "A".toByteArray(), clock).use { a ->
            val guess = Listener(wrong).use { it.respond(a.msg1(), "M".toByteArray(), clock) }
            throws<NachaloException.Rejected> { a.finish(guess.msg2, clock) }
            guess.destroy()
            val answer = Listener(invitation).use { it.respond(a.msg1(), "B".toByteArray(), clock) }
            a.finish(answer.msg2, clock).destroy()
            throws<NachaloException.Expired> { a.finish(answer.msg2, clock) }
            answer.destroy()
        }
    }
}
throws<NachaloException.BadWords> { Invitation.live("alpha cable", context, config) }

// A man in the middle with the words shows different safety words.
Invitation.live(WORDS, context, config).use { invitation ->
    // M answers A as B, and invites B as A, with the same words.
    val (a, mWithA) = handshake(invitation, invitation)
    val (mWithB, b) = handshake(invitation, invitation)
    check(a.safetyWords() == mWithA.safetyWords())
    check(b.safetyWords() == mWithB.safetyWords())
    check(a.safetyWords() != b.safetyWords())
    throws<NachaloException.Rejected> { a.verify(b.safetyWords(), clock) }
    listOf(a, b, mWithA, mWithB).forEach { it.close() }
}

// Appointment and physical-token invitations complete.
val at = clock.nowUnix
val wordsA = words(appointmentWordsA())
val wordsB = words(appointmentWordsB())
val token = newPhysicalToken(3600uL, clock.nowUnix)
val drawn = words(wordCount())
for (build in listOf(
    { Invitation.appointment(wordsA, wordsB, at, context, clock.nowUnix, config) },
    { Invitation.physicalToken(drawn, token, context, clock.nowUnix, config) },
)) {
    build().use { a ->
        build().use { b ->
            check(a.rendezvous().contentEquals(b.rendezvous()))
            val (ua, ub) = handshake(a, b)
            ua.verify(ub.safetyWords(), clock).close()
            ua.close()
            ub.close()
        }
    }
}
throws<NachaloException.Rejected> {
    Invitation.physicalToken(drawn, token.copyOfRange(1, token.size), context, at, config)
}
throws<NachaloException.Expired> {
    Invitation.appointment(wordsA, wordsB, at + 7200uL, context, at, config)
}

println("kotlin: all handshake scenarios passed")
