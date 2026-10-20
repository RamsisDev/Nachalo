//! `from_bytes` of every saved state on any bytes. Whatever restores must save back unchanged.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nachalo::{Initiator, Listener, Responder};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(state) = Initiator::from_bytes(bytes) {
        assert_eq!(state.to_bytes().as_slice(), bytes);
    }
    if let Ok(state) = Responder::from_bytes(bytes) {
        assert_eq!(state.to_bytes().as_slice(), bytes);
    }
    if let Ok(state) = Listener::from_bytes(bytes) {
        assert_eq!(state.to_bytes().as_slice(), bytes);
    }
});
