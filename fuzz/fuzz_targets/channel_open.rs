//! `Channel::open` on any frame, and `Channel::open_state` on any blob.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nachalo_channel::{Channel, Role, Secrets};
use zeroize::Zeroizing;

const NOW: u64 = 1_900_000_000;
const PEER: &[u8] = b"FUZZPEERID000000";

fn channel() -> Channel {
    let secrets = Secrets::derive(|label| {
        let mut key = Zeroizing::new([0u8; 32]);
        for (k, b) in key.iter_mut().zip(label.iter().cycle()) {
            *k = *b;
        }
        key
    });
    Channel::new(Role::Responder, &secrets, PEER).unwrap()
}

fuzz_target!(|data: &[u8]| {
    let mut channel = channel();
    let before = (channel.received(), channel.sent());
    if channel.open(data, NOW).is_err() {
        assert_eq!(before, (channel.received(), channel.sent()));
    }
    let _ = Channel::open_state(data, &[7; 32], PEER);
});
