// Compiled with the generated nachalo.swift into one executable (see ../../README.md).
import Foundation

let context = Data("my-app v1".utf8)
let clock = Clock(now: 0, nowUnix: 1_900_000_000)
let config = Config(profile: .interactive)
let fixedWords = "alpha cable echo forest orbit velvet"

func expect(_ condition: Bool, _ message: String = "check failed", line: UInt = #line) {
    if !condition { fatalError("line \(line): \(message)") }
}

func throwsError(_ expected: NachaloError, line: UInt = #line, _ run: () throws -> Any) {
    do {
        _ = try run()
        fatalError("line \(line): expected \(expected)")
    } catch let error as NachaloError {
        expect(error == expected, "expected \(expected), got \(error)", line: line)
    } catch {
        fatalError("line \(line): unexpected \(error)")
    }
}

/// msg1 from `invitationA`, answered by `invitationB`: both sides before the safety words.
/// Each object is released when its last reference goes, here at the end of this function.
func handshake(_ invitationA: Invitation, _ invitationB: Invitation) throws -> (Unconfirmed, Unconfirmed) {
    let a = try Initiator.start(invitation: invitationA, payload: Data("A's payload".utf8), clock: clock)
    let answer = try Listener(invitation: invitationB)
        .respond(msg1: a.msg1(), payload: Data("B's payload".utf8), clock: clock)
    let finished = try a.finish(msg2: answer.msg2, clock: clock)
    return (finished.unconfirmed, try answer.responder.finish(msg3: finished.msg3, clock: clock))
}

// A live handshake runs end to end.
do {
    let invitation = try Invitation.live(words: words(count: wordCount()), context: context, config: config)
    expect(UInt32(invitation.rendezvous().count) == rendezvousLen())
    let (ua, ub) = try handshake(invitation, invitation)
    expect(ua.role() == .initiator && ub.role() == .responder)
    let a = try ua.verify(typed: try ub.safetyWords(), clock: clock)
    let b = try ub.confirm(clock: clock)
    expect(a.key() == b.key())
    expect(a.transcript() == b.transcript())
    expect(a.export(label: Data("x".utf8)) == b.export(label: Data("x".utf8)))
    expect(a.peerPayload() == Data("B's payload".utf8))
    expect(b.peerPayload() == Data("A's payload".utf8))
    // confirm consumed ub.
    throwsError(.Expired) { try ub.confirm(clock: clock) }
    throwsError(.Expired) { try ub.safetyWords() }
}

// Wrong words are rejected, and leave the initiator usable.
do {
    let invitation = try Invitation.live(words: fixedWords, context: context, config: config)
    let wrong = try Invitation.live(words: "alpha cable echo forest orbit zoo", context: context, config: config)
    let a = try Initiator.start(invitation: invitation, payload: Data("A".utf8), clock: clock)
    let guess = try Listener(invitation: wrong).respond(msg1: a.msg1(), payload: Data("M".utf8), clock: clock)
    throwsError(.Rejected) { try a.finish(msg2: guess.msg2, clock: clock) }
    let answer = try Listener(invitation: invitation).respond(msg1: a.msg1(), payload: Data("B".utf8), clock: clock)
    _ = try a.finish(msg2: answer.msg2, clock: clock)
    throwsError(.Expired) { try a.finish(msg2: answer.msg2, clock: clock) }
    throwsError(.BadWords) { try Invitation.live(words: "alpha cable", context: context, config: config) }
}

// A man in the middle with the words shows different safety words.
do {
    let invitation = try Invitation.live(words: fixedWords, context: context, config: config)
    // M answers A as B, and invites B as A, with the same words.
    let (a, mWithA) = try handshake(invitation, invitation)
    let (mWithB, b) = try handshake(invitation, invitation)
    expect(try a.safetyWords() == mWithA.safetyWords())
    expect(try b.safetyWords() == mWithB.safetyWords())
    expect(try a.safetyWords() != b.safetyWords())
    throwsError(.Rejected) { try a.verify(typed: try b.safetyWords(), clock: clock) }
}

// Appointment and physical-token invitations complete.
do {
    let at = clock.nowUnix
    let wordsA = try words(count: appointmentWordsA())
    let wordsB = try words(count: appointmentWordsB())
    let token = try newPhysicalToken(lifetime: 3600, nowUnix: clock.nowUnix)
    let drawn = try words(count: wordCount())
    let builds: [() throws -> Invitation] = [
        { try Invitation.appointment(wordsA: wordsA, wordsB: wordsB, at: at, context: context, nowUnix: at, config: config) },
        { try Invitation.physicalToken(words: drawn, token: token, context: context, nowUnix: at, config: config) },
    ]
    for build in builds {
        let (a, b) = (try build(), try build())
        expect(a.rendezvous() == b.rendezvous())
        let (ua, ub) = try handshake(a, b)
        _ = try ua.verify(typed: try ub.safetyWords(), clock: clock)
    }
    throwsError(.Rejected) {
        try Invitation.physicalToken(words: drawn, token: token.dropFirst(), context: context, nowUnix: at, config: config)
    }
    throwsError(.Expired) {
        try Invitation.appointment(wordsA: wordsA, wordsB: wordsB, at: at + 7200, context: context, nowUnix: at, config: config)
    }
}

print("swift: all handshake scenarios passed")
