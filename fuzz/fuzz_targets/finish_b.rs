//! `Responder::finish` on any msg3.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use nachalo::{Clock, Config, Initiator, Invitation, Listener, Responder};

const CLOCK: Clock = Clock {
    now: 0,
    now_unix: 1_900_000_000,
};
static RESPONDER: LazyLock<Responder> = LazyLock::new(|| {
    let words = "alpha cable echo forest orbit velvet";
    let invitation = Invitation::live(words, b"fuzz", &Config::default()).unwrap();
    let (_, msg1) = Initiator::start(&invitation, b"A", CLOCK).unwrap();
    Listener::new(&invitation)
        .respond(&msg1, b"B", CLOCK)
        .unwrap()
        .0
});

fuzz_target!(|msg3: &[u8]| {
    let _ = RESPONDER.finish(msg3, CLOCK);
});
