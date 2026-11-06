import pytest

import nachalo

NOW = 1_900_000_000
WORDS = "alpha cable echo forest orbit velvet"
WRONG = "alpha cable echo forest orbit zoo"


def clock(now=0):
    return nachalo.Clock(now=now, now_unix=NOW + now)


def live(words):
    return nachalo.Invitation.live(words, b"test", nachalo.Config(nachalo.Profile.INTERACTIVE))


def handshake(words_a=WORDS, words_b=WORDS):
    a = nachalo.Initiator.start(live(words_a), b"A", clock())
    answer = nachalo.Listener(live(words_b)).respond(a.msg1(), b"B", clock())
    return a, answer


def established():
    a, answer = handshake()
    finished = a.finish(answer.msg2, clock())
    b = answer.responder.finish(finished.msg3, clock())
    return finished.unconfirmed.verify(b.safety_words(), clock()), b.confirm(clock())


def test_words_are_drawn_from_the_list():
    words = nachalo.words(6).split(" ")
    assert len(words) == nachalo.word_count() == 6
    with pytest.raises(nachalo.NachaloError.BadWords):
        nachalo.Invitation.live("one two", b"", nachalo.Config(nachalo.Profile.NEARBY))


def test_a_live_handshake_completes_and_both_sides_agree():
    a, b = established()
    assert a.key() == b.key()
    assert a.transcript() == b.transcript()
    assert a.export(b"x") == b.export(b"x") != a.export(b"y")
    assert (a.peer_payload(), b.peer_payload()) == (b"B", b"A")
    assert (a.role(), b.role()) == (nachalo.Role.INITIATOR, nachalo.Role.RESPONDER)


def test_a_wrong_msg2_leaves_the_initiator_usable():
    a, answer = handshake()
    _, guess = handshake(words_b=WRONG)
    with pytest.raises(nachalo.NachaloError.Rejected):
        a.finish(guess.msg2, clock())
    a.finish(answer.msg2, clock())
    with pytest.raises(nachalo.NachaloError.Expired):
        a.finish(answer.msg2, clock())


def test_a_typo_in_the_safety_words_leaves_the_session_pending():
    a, answer = handshake()
    finished = a.finish(answer.msg2, clock())
    b = answer.responder.finish(finished.msg3, clock())
    with pytest.raises(nachalo.NachaloError.Rejected):
        finished.unconfirmed.verify("wrong words here please", clock())
    finished.unconfirmed.verify(b.safety_words(), clock())


def test_the_deadline_expires_the_handshake():
    a, answer = handshake()
    late = clock(a.deadline() + 1)
    with pytest.raises(nachalo.NachaloError.Expired):
        a.finish(answer.msg2, late)


def test_a_man_in_the_middle_who_knows_the_words_gets_different_safety_words():
    alice = nachalo.Initiator.start(live(WORDS), b"A", clock())
    mallory_b = nachalo.Listener(live(WORDS)).respond(alice.msg1(), b"M", clock())
    mallory_a = nachalo.Initiator.start(live(WORDS), b"M", clock())
    bob = nachalo.Listener(live(WORDS)).respond(mallory_a.msg1(), b"B", clock())

    alice_side = alice.finish(mallory_b.msg2, clock())
    mallory_b.responder.finish(alice_side.msg3, clock())
    mallory_side = mallory_a.finish(bob.msg2, clock())
    bob_unconfirmed = bob.responder.finish(mallory_side.msg3, clock())

    with pytest.raises(nachalo.NachaloError.Rejected):
        alice_side.unconfirmed.verify(bob_unconfirmed.safety_words(), clock())


def test_the_channel_runs_over_the_handshake():
    a, b = established()
    ca = nachalo.Channel.from_established(a, b"PEER")
    cb = nachalo.Channel.from_established(b, b"PEER")
    epoch = nachalo.channel_epoch(NOW)
    assert ca.send_topic(epoch) == cb.recv_topic(epoch)

    frame = ca.seal(nachalo.FrameKind.DATA, b"hola", NOW)
    assert len(frame) == 512
    assert b"hola" not in frame
    opened = cb.open(frame, NOW)
    assert (opened.kind, opened.body, opened.counter) == (nachalo.FrameKind.DATA, b"hola", 0)
    with pytest.raises(nachalo.ChannelError.Replay):
        cb.open(frame, NOW)

    big = ca.seal(nachalo.FrameKind.DATA, b"x" * 1000, NOW)
    assert len(big) == 2048
    tampered = bytearray(big)
    tampered[100] ^= 1
    with pytest.raises(nachalo.ChannelError.Rejected):
        cb.open(bytes(tampered), NOW)
    assert cb.open(big, NOW).body == b"x" * 1000
    with pytest.raises(nachalo.ChannelError.TooLarge):
        ca.seal(nachalo.FrameKind.DATA, b"x" * (nachalo.channel_max_body() + 1), NOW)


def test_sealed_state_round_trips():
    a, b = established()
    cb = nachalo.Channel.from_established(b, b"PEER")
    key = bytes(range(32))
    blob = cb.seal_state(key)
    restored = nachalo.Channel.open_state(blob, key, b"PEER")
    assert restored.role() == nachalo.Role.RESPONDER
    ca = nachalo.Channel.from_established(a, b"PEER")
    assert restored.open(ca.seal(nachalo.FrameKind.DATA, b"hi", NOW), NOW).body == b"hi"
    with pytest.raises(nachalo.ChannelError.BadState):
        nachalo.Channel.open_state(blob, bytes(32), b"PEER")
    with pytest.raises(nachalo.ChannelError.BadState):
        nachalo.Channel.open_state(blob, key, b"OTHER")
