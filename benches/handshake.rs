//! What each step of a live handshake costs, with 1 KiB payloads: `cargo bench`.

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nachalo::{Clock, Config, Initiator, Invitation, Listener};

const WORDS: &str = "alpha cable echo forest orbit velvet";
const CONTEXT: &[u8] = b"nachalo bench";
const PAYLOAD: &[u8] = &[7; 1024];
const CLOCK: Clock = Clock {
    now: 0,
    now_unix: 1_900_000_000,
};

fn steps(c: &mut Criterion) {
    let config = Config::default();
    let invitation = Invitation::live(WORDS, CONTEXT, &config).unwrap();
    let (a, msg1) = Initiator::start(&invitation, PAYLOAD, CLOCK).unwrap();
    let (b, msg2) = Listener::new(&invitation)
        .respond(&msg1, PAYLOAD, CLOCK)
        .unwrap();
    let saved = a.to_bytes();
    let (_, msg3) = Initiator::from_bytes(&saved)
        .unwrap()
        .finish(&msg2, CLOCK)
        .unwrap();

    c.bench_function("invitation", |x| {
        x.iter(|| Invitation::live(WORDS, CONTEXT, &config))
    });
    c.bench_function("start", |x| {
        x.iter(|| Initiator::start(&invitation, PAYLOAD, CLOCK))
    });
    c.bench_function("respond", |x| {
        x.iter(|| Listener::new(&invitation).respond(&msg1, PAYLOAD, CLOCK))
    });
    c.bench_function("finish_a", |x| {
        x.iter_batched(
            || Initiator::from_bytes(&saved).unwrap(),
            |mut a| a.finish(&msg2, CLOCK),
            BatchSize::SmallInput,
        )
    });
    c.bench_function("finish_b", |x| x.iter(|| b.finish(&msg3, CLOCK)));
}

criterion_group!(benches, steps);
criterion_main!(benches);
