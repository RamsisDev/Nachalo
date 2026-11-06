use proptest::prelude::*;

use super::*;

const NOW: u64 = 1_762_444_800;
const PEER: &[u8] = b"K7QX2M9PABCDEFGH";

fn secrets(seed: u8) -> Secrets {
    Secrets::derive(|label| {
        let mut ikm = vec![seed];
        ikm.extend_from_slice(label);
        hkdf::<32>(&ikm, b"test export")
    })
}

fn pair() -> (Channel, Channel) {
    let s = secrets(7);
    (
        Channel::new(Role::Initiator, &s, PEER).unwrap(),
        Channel::new(Role::Responder, &s, PEER).unwrap(),
    )
}

fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[test]
fn lv_cat_matches_the_spec() {
    assert_eq!(lv_cat(&[b""]), [0]);
    assert_eq!(lv_cat(&[b"1234"]), hex::decode("0431323334").unwrap());
    let long = [0u8; 128];
    assert_eq!(&lv_cat(&[&long])[..3], hex::decode("800100").unwrap());
    assert_eq!(lv_cat(&[&long[..127]])[0], 0x7f);
    assert_eq!(
        lv_cat(&[b"1234", b"5", b"", b"678"]),
        hex::decode("043132333401350003363738").unwrap()
    );
}

#[test]
fn base64url_has_no_padding() {
    assert_eq!(base64url(b""), "");
    assert_eq!(base64url(b"f"), "Zg");
    assert_eq!(base64url(b"fo"), "Zm8");
    assert_eq!(base64url(b"foo"), "Zm9v");
    assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
}

#[test]
fn frames_round_trip_both_ways_at_fixed_sizes() {
    let (mut a, mut b) = pair();
    for (body, size) in [
        (&b""[..], FRAME_SMALL),
        (&[1u8; MAX_BODY_SMALL][..], FRAME_SMALL),
        (&[2u8; MAX_BODY_SMALL + 1][..], FRAME_LARGE),
        (&[3u8; MAX_BODY][..], FRAME_LARGE),
    ] {
        let frame = a.seal(Kind::Data, body, NOW).unwrap();
        assert_eq!(frame.len(), size);
        assert!(
            !frame
                .windows(body.len().max(1))
                .any(|w| w == body && !body.is_empty())
        );
        let opened = b.open(&frame, NOW).unwrap();
        assert_eq!((opened.kind, opened.body.as_slice()), (Kind::Data, body));

        let back = b.seal(Kind::Ack, body, NOW).unwrap();
        assert_eq!(a.open(&back, NOW).unwrap().body.as_slice(), body);
    }
    assert_eq!(
        a.seal(Kind::Data, &[0; MAX_BODY + 1], NOW).err(),
        Some(Error::TooLarge)
    );
    assert_eq!((a.sent(), b.received()), (4, 4));
}

#[test]
fn a_side_cannot_open_its_own_frames() {
    let (mut a, _) = pair();
    let frame = a.seal(Kind::Data, b"hola", NOW).unwrap();
    assert_eq!(a.open(&frame, NOW).err(), Some(Error::Rejected));
}

#[test]
fn the_header_carries_version_kind_epoch_and_counter() {
    let (mut a, mut b) = pair();
    a.seal(Kind::Data, b"0", NOW).unwrap();
    let frame = a.seal(Kind::Close, b"bye", NOW).unwrap();
    assert_eq!(frame[0], VERSION);
    assert_eq!(frame[1], 4);
    assert_eq!(&frame[2..6], &epoch_of(NOW).to_be_bytes());
    assert_eq!(&frame[6..14], &1u64.to_be_bytes());
    let opened = b.open(&frame, NOW).unwrap();
    assert_eq!(
        (opened.kind, opened.epoch, opened.counter),
        (Kind::Close, epoch_of(NOW), 1)
    );
}

#[test]
fn replays_are_rejected() {
    let (mut a, mut b) = pair();
    let first = a.seal(Kind::Data, b"one", NOW).unwrap();
    let second = a.seal(Kind::Data, b"two", NOW).unwrap();
    b.open(&first, NOW).unwrap();
    assert_eq!(b.open(&first, NOW).err(), Some(Error::Replay));
    b.open(&second, NOW).unwrap();
    assert_eq!(b.open(&second, NOW).err(), Some(Error::Replay));
}

#[test]
fn out_of_order_frames_open_once_each() {
    let (mut a, mut b) = pair();
    let frames: Vec<_> = (0..5u8)
        .map(|i| a.seal(Kind::Data, &[i], NOW).unwrap())
        .collect();
    for i in [3usize, 0, 4, 1, 2] {
        assert_eq!(b.open(&frames[i], NOW).unwrap().body.as_slice(), [i as u8]);
    }
    for frame in &frames {
        assert_eq!(b.open(frame, NOW).err(), Some(Error::Replay));
    }
    assert!(b.skipped.is_empty());
}

#[test]
fn a_counter_too_far_ahead_is_refused() {
    let (mut a, mut b) = pair();
    let frames: Vec<_> = (0..=MAX_SKIP + 1)
        .map(|_| a.seal(Kind::Data, b"x", NOW).unwrap())
        .collect();
    assert_eq!(
        b.open(&frames[MAX_SKIP as usize + 1], NOW).err(),
        Some(Error::TooFarAhead)
    );
    b.open(&frames[MAX_SKIP as usize], NOW).unwrap();
    assert_eq!(b.skipped.len(), MAX_SKIPPED);
    b.open(&frames[0], NOW).unwrap();
}

#[test]
fn skipped_keys_expire() {
    let (mut a, mut b) = pair();
    let first = a.seal(Kind::Data, b"late", NOW).unwrap();
    let second = a.seal(Kind::Data, b"early", NOW).unwrap();
    b.open(&second, NOW).unwrap();
    assert_eq!(b.open(&first, NOW + SKIPPED_TTL).err(), Some(Error::Replay));
}

#[test]
fn any_tampering_is_rejected_and_changes_nothing() {
    let (mut a, mut b) = pair();
    let frame = a.seal(Kind::Data, b"secret", NOW).unwrap();
    for at in [0, 1, 2, 6, 13, 14, 100, frame.len() - 1] {
        let mut bad = frame.clone();
        bad[at] ^= 1;
        assert!(b.open(&bad, NOW).is_err(), "flip at {at}");
        assert_eq!(b.received(), 0);
    }
    assert_eq!(
        b.open(&frame[..FRAME_SMALL - 1], NOW).err(),
        Some(Error::Rejected)
    );
    let other = Channel::new(Role::Responder, &secrets(7), b"another-peer-id").unwrap();
    let mut other = other;
    assert_eq!(other.open(&frame, NOW).err(), Some(Error::Rejected));
    assert_eq!(b.open(&frame, NOW).unwrap().body.as_slice(), b"secret");
}

#[test]
fn topics_rotate_per_day_and_direction_and_match_across_sides() {
    let (a, b) = pair();
    let e = epoch_of(NOW);
    assert_eq!(a.send_topic(e), b.recv_topic(e));
    assert_eq!(b.send_topic(e), a.recv_topic(e));
    assert_ne!(a.send_topic(e), a.recv_topic(e));
    assert_ne!(a.send_topic(e), a.send_topic(e + 1));
    let topic = a.send_topic(e);
    assert_eq!(topic.len(), TOPIC_LEN);
    assert!(topic.starts_with("nh"));
    assert!(
        topic
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    );
}

#[test]
fn state_survives_sealing_and_binds_key_and_peer() {
    let (mut a, mut b) = pair();
    let store = [9u8; 32];
    let early = a.seal(Kind::Data, b"0", NOW).unwrap();
    let late = a.seal(Kind::Data, b"1", NOW).unwrap();
    b.open(&late, NOW).unwrap();

    let blob = b.seal_state(&store).unwrap();
    assert!(!blob.windows(32).any(|w| w == b.recv_chain.as_ref()));
    assert_ne!(blob, b.seal_state(&store).unwrap());
    assert_eq!(
        Channel::open_state(&blob, &[8u8; 32], PEER).err(),
        Some(Error::BadState)
    );
    assert_eq!(
        Channel::open_state(&blob, &store, b"someone-else").err(),
        Some(Error::BadState)
    );
    let mut bad = blob.clone();
    bad[20] ^= 1;
    assert_eq!(
        Channel::open_state(&bad, &store, PEER).err(),
        Some(Error::BadState)
    );

    let mut restored = Channel::open_state(&blob, &store, PEER).unwrap();
    assert_eq!(restored.role(), Role::Responder);
    assert_eq!(restored.received(), 2);
    assert_eq!(restored.open(&early, NOW).unwrap().body.as_slice(), b"0");
    assert_eq!(restored.open(&late, NOW).err(), Some(Error::Replay));
    let reply = restored.seal(Kind::Data, b"back", NOW).unwrap();
    assert_eq!(a.open(&reply, NOW).unwrap().body.as_slice(), b"back");
}

#[test]
fn bad_peer_ids_are_refused() {
    let s = secrets(1);
    assert_eq!(
        Channel::new(Role::Initiator, &s, b"").err(),
        Some(Error::BadState)
    );
    assert_eq!(
        Channel::new(Role::Initiator, &s, &[0; MAX_PEER_ID + 1]).err(),
        Some(Error::BadState)
    );
}

/// Deterministic vectors: fixed secrets, peer id and time give fixed topics and frames.
#[test]
fn vectors() {
    let s = Secrets::derive(|label| hkdf::<32>(label, b"nachalo-channel v1 vectors"));
    let mut a = Channel::new(Role::Initiator, &s, PEER).unwrap();
    let e = epoch_of(NOW);
    assert_eq!(e, 20_398);
    assert_eq!(a.send_topic(e), "nhbMoZxUPGos0o71sjRXkQkuQ1LpCwOkbq");
    assert_eq!(a.recv_topic(e), "nhOrhcqm-AClDGAwo0cYeGlF-oFLZ4PckA");
    let frame = a.seal(Kind::Data, br#"{"text":"hola"}"#, NOW).unwrap();
    assert_eq!(hex(&frame[..HEADER_LEN]), "010100004fae0000000000000000");
    assert_eq!(
        hex(&frame[frame.len() - TAG_LEN..]),
        "24616557944957cde42509f673d17a72"
    );
    let frame = a.seal(Kind::Data, br#"{"text":"hola"}"#, NOW).unwrap();
    assert_eq!(hex(&frame[..HEADER_LEN]), "010100004fae0000000000000001");
    assert_eq!(
        hex(&frame[frame.len() - TAG_LEN..]),
        "c51dad69eec8e99cd6858c896dda235a"
    );
}

proptest! {
    #[test]
    fn any_order_within_the_window_opens_each_frame_exactly_once(
        order in Just((0..24usize).collect::<Vec<_>>()).prop_shuffle(),
        dupes in proptest::collection::vec(0..24usize, 0..10),
    ) {
        let (mut a, mut b) = pair();
        let frames: Vec<_> = (0..24u8).map(|i| a.seal(Kind::Data, &[i], NOW).unwrap()).collect();
        let mut opened = [0u32; 24];
        for i in order.iter().chain(dupes.iter()) {
            if let Ok(o) = b.open(&frames[*i], NOW) {
                opened[o.body[0] as usize] += 1;
            }
        }
        prop_assert!(opened.iter().all(|&n| n == 1));
    }

    #[test]
    fn random_bytes_never_open(bytes in proptest::collection::vec(any::<u8>(), FRAME_SMALL)) {
        let (_, mut b) = pair();
        prop_assert!(b.open(&bytes, NOW).is_err());
        prop_assert_eq!(b.received(), 0);
    }
}
