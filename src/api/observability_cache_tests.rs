use super::*;
use crate::api::discovery::http_tests::Fixture;
use crate::maestro::generation::test_runtime_generation;
use std::time::Instant;

fn enabled_config(fixture: &Fixture) -> ProxyConfig {
    let mut cfg = (*fixture
        .shared
        .active_runtime
        .load()
        .config_rx
        .borrow()
        .clone())
    .clone();
    cfg.server.api.minimal_runtime_enabled = true;
    cfg.server.api.minimal_runtime_cache_ttl_ms = 60_000;
    cfg.server.api.runtime_edge_enabled = true;
    cfg.server.api.runtime_edge_cache_ttl_ms = 60_000;
    cfg.server.api.runtime_edge_top_n = 7;
    cfg
}

#[tokio::test]
async fn late_edge_recompute_cannot_contaminate_new_generation_reads() {
    let fixture = Fixture::new(false);
    let old_cfg = enabled_config(&fixture);
    let old_runtime = test_runtime_generation(1, old_cfg.clone());
    let old_request = fixture.shared.for_runtime(&old_runtime);
    let (release, resume) = tokio::sync::oneshot::channel();
    // A request already pinned to generation 1 finishes after generation 2's
    // handler has invalidated the shared caches.
    let pending = tokio::spawn(async move {
        resume.await.unwrap();
        build_runtime_connections_summary_data(&old_request, &old_cfg).await
    });
    let mut new_cfg = enabled_config(&fixture);
    new_cfg.server.api.runtime_edge_top_n = 1;
    fixture
        .shared
        .active_runtime
        .store(test_runtime_generation(2, new_cfg));
    assert_eq!(fixture.request("GET", "/v1/health", true).await.0, 200);
    release.send(()).unwrap();
    assert_eq!(pending.await.unwrap().data.unwrap().top.limit, 7);

    let mut reads = tokio::task::JoinSet::new();
    let fixture = Arc::new(fixture);
    for _ in 0..16 {
        let fixture = fixture.clone();
        reads.spawn(async move {
            let (status, _, body) = fixture
                .request("GET", "/v1/runtime/connections/summary", true)
                .await;
            assert_eq!(status, 200);
            assert_eq!(body["data"]["enabled"], true);
            if let Some(payload) = body["data"].get("data") {
                assert_eq!(payload["top"]["limit"], 1, "{body}");
                assert_eq!(payload["cache"]["ttl_ms"], 60_000);
            } else {
                assert_eq!(body["data"]["reason"], "source_unavailable");
            }
        });
    }
    while let Some(result) = reads.join_next().await {
        result.unwrap();
    }
}

#[tokio::test]
async fn late_minimal_cache_publication_is_not_served_by_new_generation() {
    let fixture = Fixture::new(false);
    let cfg = enabled_config(&fixture);
    let old_request = fixture
        .shared
        .for_runtime(&test_runtime_generation(1, cfg.clone()));
    let payload = build_minimal_all_data(&old_request, &cfg.server.api)
        .await
        .data
        .unwrap();
    fixture
        .shared
        .active_runtime
        .store(test_runtime_generation(2, cfg));
    assert_eq!(fixture.request("GET", "/v1/health", true).await.0, 200);
    // Model the publication of a completed old-generation pool snapshot after
    // invalidation. The new generation has no pool and must report that fact.
    *fixture.shared.minimal_cache.lock().await = Some(MinimalCacheEntry {
        generation: 1,
        expires_at: Instant::now() + Duration::from_secs(60),
        payload,
        generated_at_epoch_secs: 42,
    });
    let (status, _, body) = fixture.request("GET", "/v1/stats/minimal/all", true).await;
    assert_eq!(status, 200);
    assert_eq!(body["data"]["reason"], "source_unavailable", "{body}");
    assert_ne!(body["data"]["generated_at_epoch_secs"], 42);
}

#[tokio::test]
async fn edge_cache_respects_ttl_zero_expiry_top_n_and_recompute_contention() {
    let fixture = Fixture::new(false);
    let mut cfg = enabled_config(&fixture);
    cfg.server.api.runtime_edge_top_n = 1;
    let runtime = test_runtime_generation(1, cfg.clone());
    let request = fixture.shared.for_runtime(&runtime);
    request.stats.add_user_octets_from("alice", 20);
    request.stats.add_user_octets_from("bob", 10);
    let fresh = build_runtime_connections_summary_data(&request, &cfg)
        .await
        .data
        .unwrap();
    assert!(!fresh.cache.served_from_cache);
    assert_eq!(fresh.top.by_throughput.len(), 1);
    assert_eq!(fresh.top.by_throughput[0].username, "alice");
    request.stats.add_user_octets_from("bob", 100);
    let cached = build_runtime_connections_summary_data(&request, &cfg)
        .await
        .data
        .unwrap();
    assert!(cached.cache.served_from_cache);
    assert!(!cached.cache.stale_cache_used);
    assert_eq!(cached.top.by_throughput[0].username, "alice");
    request
        .runtime_edge_connections_cache
        .lock()
        .await
        .as_mut()
        .unwrap()
        .expires_at = Instant::now();
    let guard = request.runtime_edge_recompute_lock.lock().await;
    let stale = build_runtime_connections_summary_data(&request, &cfg)
        .await
        .data
        .unwrap();
    assert!(stale.cache.stale_cache_used);
    let new_request = fixture
        .shared
        .for_runtime(&test_runtime_generation(2, cfg.clone()));
    let unavailable = build_runtime_connections_summary_data(&new_request, &cfg).await;
    assert_eq!(unavailable.reason, Some("source_unavailable"));
    assert!(unavailable.data.is_none());
    cfg.server.api.runtime_edge_cache_ttl_ms = 0;
    let zero = build_runtime_connections_summary_data(&request, &cfg).await;
    assert_eq!(zero.reason, Some("source_unavailable"));
    assert!(zero.data.is_none());
    drop(guard);
    for _ in 0..2 {
        let uncached = build_runtime_connections_summary_data(&request, &cfg)
            .await
            .data
            .unwrap();
        assert_eq!(uncached.cache.ttl_ms, 0);
        assert!(!uncached.cache.served_from_cache);
        assert_eq!(uncached.top.by_throughput[0].username, "bob");
    }
    cfg.server.api.runtime_edge_cache_ttl_ms = 60_000;
    let refreshed = build_runtime_connections_summary_data(&request, &cfg)
        .await
        .data
        .unwrap();
    assert!(!refreshed.cache.served_from_cache);
    assert_eq!(refreshed.top.by_throughput[0].username, "bob");
}

#[tokio::test]
async fn minimal_cache_checks_generation_expiry_and_zero_ttl() {
    let fixture = Fixture::new(false);
    let mut cfg = enabled_config(&fixture);
    let request = fixture
        .shared
        .for_runtime(&test_runtime_generation(1, cfg.clone()));
    let payload = build_minimal_all_data(&request, &cfg.server.api)
        .await
        .data
        .unwrap();
    *request.minimal_cache.lock().await = Some(MinimalCacheEntry {
        generation: 1,
        expires_at: Instant::now() + Duration::from_secs(60),
        payload,
        generated_at_epoch_secs: 42,
    });
    let cached = build_minimal_all_data(&request, &cfg.server.api).await;
    assert_eq!(cached.generated_at_epoch_secs, 42);
    assert!(cached.reason.is_none());
    cfg.server.api.minimal_runtime_cache_ttl_ms = 0;
    assert_eq!(
        build_minimal_all_data(&request, &cfg.server.api)
            .await
            .reason,
        Some("source_unavailable")
    );
    cfg.server.api.minimal_runtime_cache_ttl_ms = 60_000;
    request
        .minimal_cache
        .lock()
        .await
        .as_mut()
        .unwrap()
        .expires_at = Instant::now();
    assert_eq!(
        build_minimal_all_data(&request, &cfg.server.api)
            .await
            .reason,
        Some("source_unavailable")
    );
}
