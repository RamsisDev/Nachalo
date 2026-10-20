//! `Listener::respond` on any msg1.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use nachalo::{Clock, Config, Invitation, Listener};

const CLOCK: Clock = Clock {
    now: 0,
    now_unix: 1_900_000_000,
};
static INVITATION: LazyLock<Invitation> = LazyLock::new(|| {
    Invitation::live(
        "alpha cable echo forest orbit velvet",
        b"fuzz",
        &Config::default(),
    )
    .unwrap()
});

fuzz_target!(|msg1: &[u8]| {
    let _ = Listener::new(&INVITATION).respond(msg1, b"B", CLOCK);
});
