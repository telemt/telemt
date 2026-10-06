use super::*;
use std::hint::black_box;
use std::time::Instant;

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
fn compare_bridge_render_latency() {
    for diagnostics in [false, true] {
        let samples = (0..100)
            .map(|_| {
                let start = Instant::now();
                drop(black_box(assemble_template(diagnostics)));
                start.elapsed().as_nanos()
            })
            .collect();
        report(
            &format!("bridge template initialization diagnostics={diagnostics}"),
            samples,
        );
    }
    prepare_templates();
    for repeat in 0..3 {
        for diagnostics in [false, true] {
            for workers in [1, 32] {
                for cached in [false, true] {
                    let barrier = Barrier::new(workers);
                    let samples = std::thread::scope(|scope| {
                        let handles = (0..workers)
                            .map(|worker| {
                                let barrier = &barrier;
                                scope.spawn(move || {
                                    let rng = SecureRandom::new();
                                    let mut case = Case::new(worker);
                                    case.diagnostics = diagnostics;
                                    for _ in 0..20 {
                                        drop(case.render(&rng));
                                    }
                                    let mut samples = Vec::with_capacity(300);
                                    barrier.wait();
                                    for _ in 0..300 {
                                        let start = Instant::now();
                                        let page = if cached {
                                            case.render(&rng)
                                        } else {
                                            let mut nonce = [0; 18];
                                            rng.fill(&mut nonce);
                                            let nonce =
                                                base64::engine::general_purpose::URL_SAFE_NO_PAD
                                                    .encode(nonce);
                                            case.reference(&nonce)
                                        };
                                        drop(black_box(page));
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
                            "bridge repeat={repeat} diagnostics={diagnostics} workers={workers} cached={cached}"
                        ),
                        samples,
                    );
                }
            }
        }
    }
}
