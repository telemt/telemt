use super::*;
use std::time::Instant;

fn memory() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/self/smaps_rollup").unwrap();
    let value = |name: &str| {
        text.lines()
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
#[ignore = "manual bounded wildcard loopback and retained-memory measurement"]
async fn wildcard_loopback_probe() {
    let profiles = std::env::var("TELEMT_WILDCARD_PROFILES")
        .unwrap_or_else(|_| "128".to_string())
        .parse::<usize>()
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("index.html"), "ordinary site").unwrap();
    let users = (1..profiles)
        .map(|index| format!("u{index} = \"{index:032x}\"\n"))
        .collect::<String>();
    let policies = (1..profiles)
        .map(|index| {
            format!("[[web.vhosts.profiles]]\nuser = \"u{index}\"\nsecret_mode = \"plain\"\n")
        })
        .collect::<String>();
    let source = wildcard_source("host = \"*.example.com\"", "127.0.0.1:18081".parse().unwrap())
        .replace("[access.users]", &format!("[access.users]\n{users}"))
        .replace("mode = \"http_upstream\"\nupstream = \"http://127.0.0.1:18081\"",
            &format!("mode = \"static_directory\"\ndirectory = {:?}", directory.path()))
        .replace("[web.limits]", &format!("{policies}[web.limits]\nmax_profiles = {profiles}\nmax_bootstraps_global = 1024\nmax_bootstraps_per_ip = 1024\nnew_bootstraps_burst = 1024\nnew_bootstraps_per_minute = 60000"));
    let path = directory.path().join("probe.toml");
    std::fs::write(&path, source).unwrap();
    let before = memory();
    let started = Instant::now();
    let config = ProxyConfig::load(path).unwrap();
    let load_us = started.elapsed().as_micros();
    let loaded = memory();
    let generation = test_runtime_generation(1, config);
    generation
        .proxy_shared
        .apply_user_config(&generation.config().access.users, &HashMap::new());
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = bridge(&listener, &runtime, "warm.example.com").await;
    let session = create(&runtime, "warm.example.com", &bootstrap).unwrap();
    let mut results = serde_json::Map::new();
    let hostile = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xbbu8; 32]);
    for phase in ["warm", "cold", "carrier", "hostile"] {
        let mut samples = Vec::new();
        let cache_before = runtime.wildcard.as_ref().unwrap().test_stats();
        for index in 0..110 {
            let host = match phase {
                "cold" => format!("cold{index}.example.com"),
                "hostile" => format!("random{index}.example.com"),
                _ => "warm.example.com".to_string(),
            };
            let cap = if phase == "hostile" {
                hostile.clone()
            } else {
                capability(&generation.config(), &host)
            };
            let raw = if phase == "carrier" {
                raw_request(
                    "POST",
                    "/relay/api/v1/up",
                    &host,
                    &format!(
                        "Authorization: Bearer {session}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: {}\r\n",
                        index + 1
                    ),
                    &frame::encode(FrameType::Pong, 0, &[]),
                )
            } else {
                raw_request("GET", &format!("/relay/?bridge={cap}"), &host, "", &[])
            };
            let started = Instant::now();
            let response = request(&listener, &runtime, raw).await;
            let elapsed = started.elapsed().as_micros();
            let status = match phase {
                "carrier" => b"HTTP/1.1 204",
                "hostile" => b"HTTP/1.1 404",
                _ => b"HTTP/1.1 200",
            };
            assert!(
                response.starts_with(status),
                "{}",
                String::from_utf8_lossy(&response)
            );
            if index >= 10 {
                samples.push(elapsed);
            }
        }
        samples.sort_unstable();
        let after = runtime.wildcard.as_ref().unwrap().test_stats();
        results.insert(phase.to_string(), serde_json::json!({"p50_us": samples[50], "p95_us": samples[95],
            "hmac_evaluations": after.2 - cache_before.2, "cache_hosts": after.0, "charged_cache_bytes": after.1}));
    }
    let retained = memory();
    println!(
        "WILDCARD_PROBE {}",
        serde_json::json!({"profiles": profiles, "load_us": load_us,
        "load_anonymous_delta_kib": loaded.1 as i64 - before.1 as i64,
        "retained_anonymous_kib": retained.1, "retained_rss_kib": retained.0, "phases": results})
    );
    stop(runtime, &[generation]).await;
}
