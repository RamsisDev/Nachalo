//! Word normalization, through the invitations that run it, on any text.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nachalo::{Config, Invitation};

fuzz_target!(|data: &[u8]| {
    let Ok(words) = std::str::from_utf8(data) else {
        return;
    };
    let config = Config::default();
    let _ = Invitation::live(words, b"fuzz", &config);
    let _ = Invitation::appointment(words, words, 0, b"fuzz", 0, &config);
});
