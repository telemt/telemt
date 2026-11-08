use super::*;
use std::hint::black_box;
use std::time::Instant;

fn memory() -> (u64, u64) {
    let smaps = std::fs::read_to_string("/proc/self/smaps_rollup").unwrap();
    let value = |name: &str| {
        smaps
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    (value("Rss:"), value("Anonymous:"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual matched before/after source-snapshot measurement"]
async fn matched_host_group_probe() {
    let path = std::env::var("TELEMT_F1_PROBE_CONFIG").unwrap();
    let before = memory();
    let started = Instant::now();
    let mut config = ProxyConfig::load(std::path::Path::new(&path)).unwrap();
    let load_us = started.elapsed().as_micros();
    black_box(&config);
    let after = memory();
    let snapshot = config.web.runtime.as_ref().unwrap();
    let host_count = snapshot.vhosts.len();
    let profile_count = snapshot.profiles.len();
    let profile = &snapshot.profiles[0];
    let host = profile.host.clone();
    let cap = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(profile.capability);
    let base = snapshot.vhosts[&host].base.clone();
    config.web.limits.max_bootstraps_per_ip = 512;
    let generation = test_runtime_generation(1, config);
    generation.proxy_shared.apply_user_config(
        &generation.config().access.users,
        &std::collections::HashMap::new(),
    );
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let raw = format!("GET {base}?bridge={cap} HTTP/1.1\r\nHost: {host}\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close\r\n\r\n").into_bytes();
    let mut samples = Vec::new();
    for index in 0..110 {
        let started = Instant::now();
        let response = request(&listener, &runtime, raw.clone()).await;
        let elapsed = started.elapsed().as_micros();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        if index >= 10 {
            samples.push(elapsed);
        }
    }
    samples.sort_unstable();
    println!(
        "F1_PROBE {}",
        serde_json::json!({
            "load_us": load_us, "rss_kib": after.0, "anonymous_kib": after.1,
            "rss_delta_kib": after.0 as i64 - before.0 as i64,
            "anonymous_delta_kib": after.1 as i64 - before.1 as i64,
            "hosts": host_count, "profiles": profile_count,
            "bridge_p50_us": samples[50], "bridge_p95_us": samples[95]
        })
    );
    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
