//! `Initiator::finish` on any msg2.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use nachalo::{Clock, Config, Initiator, Invitation};

const CLOCK: Clock = Clock {
    now: 0,
    now_unix: 1_900_000_000,
};
/// A pending initiator, restored fresh for every input so `max_answers` never runs out.
static SAVED: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let words = "alpha cable echo forest orbit velvet";
    let invitation = Invitation::live(words, b"fuzz", &Config::default()).unwrap();
    Initiator::start(&invitation, b"A", CLOCK)
        .unwrap()
        .0
        .to_bytes()
        .to_vec()
});

fuzz_target!(|msg2: &[u8]| {
    let _ = Initiator::from_bytes(&SAVED).unwrap().finish(msg2, CLOCK);
});
