use super::*;
use parking_lot::Mutex;
use std::hint::black_box;
use std::sync::Barrier;

fn hash(index: usize) -> TokenHash {
    let mut hash = [0; 32];
    hash[..8].copy_from_slice(&(index as u64).to_le_bytes());
    hash
}

fn populated(fixture: &Fixture, entries: usize, now: Instant) -> ManagerState {
    let mut state = ManagerState::default();
    for index in 0..entries {
        insert_bootstrap(
            &mut state,
            hash(index),
            fixture.bootstrap(
                now,
                now + Duration::from_secs(60 + index as u64 % 120),
                (index % 4) as u8,
            ),
        );
    }
    for index in 0..entries * 4 {
        insert_closed_token(
            &mut state,
            hash(index),
            now + Duration::from_secs(60 + index as u64 % 120),
        );
    }
    state
}

fn report(label: &str, mut samples: Vec<u128>) {
    samples.sort_unstable();
    eprintln!(
        "{label}: n={} p50={}ns p95={}ns p99={}ns",
        samples.len(),
        samples[samples.len() / 2],
        samples[samples.len() * 95 / 100],
        samples[samples.len() * 99 / 100]
    );
}

#[test]
#[ignore = "manual optimized-profile latency comparison; no timing assertions"]
fn compare_registry_sweep_latency() {
    let fixture = Fixture::new();
    let now = Instant::now();
    for repeat in 0..3 {
        for entries in [0, 512, 8192] {
            for workers in [1, 32] {
                for hinted in [false, true] {
                    let state = Mutex::new(populated(&fixture, entries, now));
                    let barrier = Barrier::new(workers);
                    let sweep = if hinted {
                        remove_expired_locked
                    } else {
                        reference::exhaustive
                    };
                    let samples = std::thread::scope(|scope| {
                        let handles = (0..workers)
                            .map(|_| {
                                let state = &state;
                                let barrier = &barrier;
                                scope.spawn(move || {
                                    let mut samples = Vec::with_capacity(300);
                                    barrier.wait();
                                    for _ in 0..300 {
                                        let start = Instant::now();
                                        {
                                            let mut state = state.lock();
                                            black_box(sweep(black_box(&mut state), black_box(now)));
                                        }
                                        samples.push(start.elapsed().as_nanos());
                                    }
                                    samples
                                })
                            })
                            .collect::<Vec<_>>();
                        handles
                            .into_iter()
                            .flat_map(|h| h.join().unwrap())
                            .collect()
                    });
                    report(
                        &format!(
                            "registry no-expiry repeat={repeat} entries={entries} workers={workers} hinted={hinted}"
                        ),
                        samples,
                    );
                }
            }
            for hinted in [false, true] {
                let sweep = if hinted {
                    remove_expired_locked
                } else {
                    reference::exhaustive
                };
                let mut state = populated(&fixture, entries, now);
                let mut samples = Vec::with_capacity(300);
                for index in 0..300 {
                    // Force both gates due while most entries retain mixed future deadlines.
                    insert_bootstrap(
                        &mut state,
                        hash(entries + index),
                        fixture.bootstrap(
                            now - Duration::from_secs(2),
                            now - Duration::from_secs(1),
                            2,
                        ),
                    );
                    insert_closed_token(
                        &mut state,
                        hash(entries * 4 + index),
                        now - Duration::from_secs(1),
                    );
                    let start = Instant::now();
                    assert_eq!(black_box(sweep(black_box(&mut state), black_box(now))), 1);
                    samples.push(start.elapsed().as_nanos());
                }
                report(
                    &format!(
                        "registry expiry-churn repeat={repeat} entries={entries} workers=1 hinted={hinted}"
                    ),
                    samples,
                );
            }
        }
    }
}
