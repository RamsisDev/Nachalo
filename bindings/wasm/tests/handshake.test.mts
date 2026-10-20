// After `wasm-pack build --target nodejs`, from bindings/wasm: node --test tests/handshake.test.mts
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Clock,
  Config,
  Initiator,
  Invitation,
  Listener,
  Profile,
  Role,
  Unconfirmed,
  appointmentWordsA,
  appointmentWordsB,
  msg1Len,
  newPhysicalToken,
  wordCount,
  words,
  type NachaloErrorKind,
} from "../pkg/nachalo_wasm.js";

const bytes = (text: string) => new TextEncoder().encode(text);
const context = bytes("my-app v1");
const clock = new Clock(0n, 1_900_000_000n);
const config = new Config(Profile.Interactive);
const WORDS = "alpha cable echo forest orbit velvet";

function throwsKind(run: () => unknown, kind: NachaloErrorKind) {
  assert.throws(run, { name: "NachaloError", message: kind });
}

/** msg1 from `invitationA`, answered by `invitationB`: both sides before the safety words. */
function handshake(invitationA: Invitation, invitationB: Invitation): [Unconfirmed, Unconfirmed] {
  const [initiator, msg1] = Initiator.start(invitationA, bytes("A's payload"), clock);
  using a = initiator;
  using listener = new Listener(invitationB);
  const [responder, msg2] = listener.respond(msg1, bytes("B's payload"), clock);
  using b = responder;
  const [unconfirmedA, msg3] = a.finish(msg2, clock);
  return [unconfirmedA, b.finish(msg3, clock)];
}

test("a live handshake runs end to end", () => {
  const drawn = words(wordCount());
  assert.equal(drawn.split(" ").length, 6);
  using invitation = Invitation.live(drawn, context, config);
  assert.equal(invitation.rendezvous().length, 32);

  const [initiator, msg1] = Initiator.start(invitation, bytes("A's payload"), clock);
  using a = initiator;
  assert.equal(msg1.length, msg1Len());
  using listener = new Listener(invitation);
  const [responder, msg2] = listener.respond(msg1, bytes("B's payload"), clock);
  using b = responder;
  const [unconfirmedA, msg3] = a.finish(msg2, clock);
  using ua = unconfirmedA;
  throwsKind(() => a.finish(msg2, clock), "Expired");
  const ub = b.finish(msg3, clock);

  assert.deepEqual([ua.role(), ub.role()], [Role.Initiator, Role.Responder]);
  using established = ua.verify(ub.safetyWords(), clock);
  using other = ub.confirm(clock); // consumes ub
  assert.deepEqual(established.key(), other.key());
  assert.deepEqual(established.transcript(), other.transcript());
  assert.deepEqual(established.export(bytes("x")), other.export(bytes("x")));
  assert.deepEqual(established.peerPayload(), bytes("B's payload"));
  assert.deepEqual(other.peerPayload(), bytes("A's payload"));
});

test("wrong words are rejected, and leave the initiator usable", () => {
  using invitation = Invitation.live(WORDS, context, config);
  using wrong = Invitation.live("alpha cable echo forest orbit zoo", context, config);
  const [initiator, msg1] = Initiator.start(invitation, bytes("A"), clock);
  using a = initiator;
  using guess = new Listener(wrong);
  throwsKind(() => a.finish(guess.respond(msg1, bytes("M"), clock)[1], clock), "Rejected");

  using listener = new Listener(invitation);
  assert.ok(a.finish(listener.respond(msg1, bytes("B"), clock)[1], clock));
  throwsKind(() => Invitation.live("alpha cable", context, config), "BadWords");
});

test("a man in the middle with the words shows different safety words", () => {
  using invitation = Invitation.live(WORDS, context, config);
  // M answers A as B, and invites B as A, with the same words.
  const [a, mWithA] = handshake(invitation, invitation);
  const [mWithB, b] = handshake(invitation, invitation);
  assert.equal(a.safetyWords(), mWithA.safetyWords());
  assert.equal(b.safetyWords(), mWithB.safetyWords());
  assert.notEqual(a.safetyWords(), b.safetyWords());
  throwsKind(() => a.verify(b.safetyWords(), clock), "Rejected");
  for (const side of [a, b, mWithA, mWithB]) side.free();
});

test("appointment and physical-token invitations complete", () => {
  const at = clock.nowUnix;
  const wordsA = words(appointmentWordsA());
  const wordsB = words(appointmentWordsB());
  const token = newPhysicalToken(3600n, clock.nowUnix);
  const drawn = words(wordCount());
  for (const build of [
    () => Invitation.appointment(wordsA, wordsB, at, context, clock.nowUnix, config),
    () => Invitation.physicalToken(drawn, token, context, clock.nowUnix, config),
  ]) {
    using a = build();
    using b = build();
    assert.deepEqual(a.rendezvous(), b.rendezvous());
    const [ua, ub] = handshake(a, b);
    assert.ok(ua.verify(ub.safetyWords(), clock));
    ua.free();
    ub.free();
  }
  throwsKind(() => Invitation.physicalToken(drawn, token.slice(1), context, at, config), "Rejected");
  throwsKind(() => Invitation.appointment(wordsA, wordsB, at + 7200n, context, at, config), "Expired");
});
