use super::*;

fn cached_with_cert_info(
    domain: &str,
    subject_cn: Option<&str>,
    san_names: Vec<&str>,
) -> CachedTlsData {
    CachedTlsData {
        server_hello_template: ParsedServerHello {
            version: [0x03, 0x03],
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suite: [0x13, 0x01],
            compression: 0,
            extensions: Vec::new(),
        },
        cert_info: Some(crate::tls_front::types::ParsedCertificateInfo {
            not_after_unix: None,
            not_before_unix: None,
            issuer_cn: None,
            subject_cn: subject_cn.map(str::to_string),
            san_names: san_names.into_iter().map(str::to_string).collect(),
        }),
        cert_payload: None,
        app_data_records_sizes: vec![1024],
        total_app_data_len: 1024,
        behavior_profile: TlsBehaviorProfile::default(),
        fetched_at: SystemTime::now(),
        domain: domain.to_string(),
    }
}

#[test]
fn cert_info_domain_match_accepts_exact_san() {
    let cached = cached_with_cert_info("b.com", Some("a.com"), vec!["b.com"]);
    assert!(cert_info_matches_domain(&cached));
}

#[test]
fn cert_info_domain_match_rejects_wrong_san() {
    let cached = cached_with_cert_info("b.com", Some("b.com"), vec!["a.com"]);
    assert!(!cert_info_matches_domain(&cached));
}

#[test]
fn cert_info_domain_match_accepts_single_label_wildcard_san() {
    let cached = cached_with_cert_info("api.b.com", None, vec!["*.b.com"]);
    assert!(cert_info_matches_domain(&cached));
}

#[test]
fn cert_info_domain_match_rejects_multi_label_wildcard_san() {
    let cached = cached_with_cert_info("deep.api.b.com", None, vec!["*.b.com"]);
    assert!(!cert_info_matches_domain(&cached));
}

#[tokio::test]
async fn default_profile_domains_reports_only_unprepared_entries() {
    let domains = vec!["ready.example".to_string(), "pending.example".to_string()];
    let cache = TlsFrontCache::new(&domains, 1024, "tlsfront-test-cache");
    cache
        .set(
            "ready.example",
            cached_with_cert_info("ready.example", None, Vec::new()),
        )
        .await;

    assert_eq!(
        cache.default_profile_domains(&domains).await,
        vec!["pending.example".to_string()]
    );
}

#[tokio::test]
async fn test_take_full_cert_budget_for_ip_uses_ttl() {
    let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
    let ip: IpAddr = "127.0.0.1".parse().expect("ip");
    let ttl = Duration::from_millis(80);

    assert!(
        cache
            .take_full_cert_budget_for_ip("example.com", ip, ttl)
            .await
    );
    assert!(
        !cache
            .take_full_cert_budget_for_ip("example.com", ip, ttl)
            .await
    );

    tokio::time::sleep(Duration::from_millis(90)).await;

    assert!(
        cache
            .take_full_cert_budget_for_ip("example.com", ip, ttl)
            .await
    );
}

#[tokio::test]
async fn test_take_full_cert_budget_for_ip_zero_ttl_always_allows_full_payload() {
    let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
    let ttl = Duration::ZERO;

    for idx in 0..100_000u32 {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            ((idx >> 16) & 0xff) as u8,
            ((idx >> 8) & 0xff) as u8,
            (idx & 0xff) as u8,
        ));
        assert!(
            cache
                .take_full_cert_budget_for_ip("example.com", ip, ttl)
                .await
        );
    }

    assert!(cache.full_cert_sent_is_empty_for_tests().await);
}

#[tokio::test]
async fn test_take_full_cert_budget_for_ip_sweeps_expired_entries_when_due() {
    let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
    let stale_ip: IpAddr = "127.0.0.1".parse().expect("ip");
    let new_ip: IpAddr = "127.0.0.2".parse().expect("ip");
    let ttl = Duration::from_secs(1);
    let stale_expires_at = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);

    cache
        .insert_full_cert_sent_for_tests("example.com", stale_ip, stale_expires_at)
        .await;
    let stale_key = FullCertBudgetKey {
        domain: cache.full_cert_domain_key("example.com"),
        client_ip: stale_ip,
    };
    cache.full_cert_budget.sweep_cursor.store(
        cache.full_cert_budget.shard_index(&stale_key),
        Ordering::Relaxed,
    );
    cache
        .full_cert_budget
        .last_sweep_epoch_secs
        .store(0, Ordering::Relaxed);

    assert!(
        cache
            .take_full_cert_budget_for_ip("example.com", new_ip, ttl)
            .await
    );

    assert!(
        !cache
            .full_cert_sent_contains_for_tests("example.com", stale_ip)
            .await
    );
    assert!(
        cache
            .full_cert_sent_contains_for_tests("example.com", new_ip)
            .await
    );
}

#[tokio::test]
async fn test_take_full_cert_budget_for_ip_does_not_sweep_every_call() {
    let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
    let stale_ip: IpAddr = "127.0.0.1".parse().expect("ip");
    let new_ip: IpAddr = "127.0.0.2".parse().expect("ip");
    let ttl = Duration::from_secs(1);
    let stale_expires_at = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let now_epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    cache
        .insert_full_cert_sent_for_tests("example.com", stale_ip, stale_expires_at)
        .await;
    cache
        .full_cert_budget
        .last_sweep_epoch_secs
        .store(now_epoch_secs, Ordering::Relaxed);

    assert!(
        cache
            .take_full_cert_budget_for_ip("example.com", new_ip, ttl)
            .await
    );

    assert!(
        cache
            .full_cert_sent_contains_for_tests("example.com", stale_ip)
            .await
    );
    assert!(
        cache
            .full_cert_sent_contains_for_tests("example.com", new_ip)
            .await
    );
}

#[tokio::test]
async fn full_cert_budget_is_shared_across_cache_generations_and_scoped_by_domain() {
    let budget = Arc::new(TlsFullCertBudget::new());
    let domains = ["one.example".to_string(), "two.example".to_string()];
    let first = TlsFrontCache::new_with_full_cert_budget(
        &domains,
        1024,
        "tlsfront-test-cache",
        budget.clone(),
    );
    let second =
        TlsFrontCache::new_with_full_cert_budget(&domains, 1024, "tlsfront-test-cache", budget);
    let ip: IpAddr = "127.0.0.1".parse().expect("ip");
    let ttl = Duration::from_secs(60);

    assert!(
        first
            .take_full_cert_budget_for_ip("one.example", ip, ttl)
            .await
    );
    assert!(
        !second
            .take_full_cert_budget_for_ip("one.example", ip, ttl)
            .await
    );
    assert!(
        second
            .take_full_cert_budget_for_ip("two.example", ip, ttl)
            .await
    );
    assert_eq!(second.full_cert_budget_entries_for_metrics(), 2);
}

#[tokio::test]
async fn existing_full_cert_entry_keeps_its_own_expiry_after_ttl_change() {
    let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, "tlsfront-test-cache");
    let ip: IpAddr = "127.0.0.1".parse().expect("ip");

    assert!(
        cache
            .take_full_cert_budget_for_ip("example.com", ip, Duration::from_millis(80))
            .await
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !cache
            .take_full_cert_budget_for_ip("example.com", ip, Duration::from_millis(1))
            .await
    );
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert!(
        cache
            .take_full_cert_budget_for_ip("example.com", ip, Duration::from_millis(1))
            .await
    );
}

#[tokio::test]
async fn disk_reader_rejects_an_entry_above_the_hard_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("oversized.json");
    tokio::fs::write(
        &path,
        vec![0u8; TLS_FRONT_DISK_ENTRY_MAX_BYTES as usize + 1],
    )
    .await
    .unwrap();

    let error = read_disk_entry_bounded(&path).await.unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

#[cfg(unix)]
#[tokio::test]
async fn disk_loader_does_not_follow_a_configured_name_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("outside.json");
    let cached = cached_with_cert_info("example.com", None, Vec::new());
    tokio::fs::write(&target, serde_json::to_vec(&cached).unwrap())
        .await
        .unwrap();
    std::os::unix::fs::symlink(&target, directory.path().join("example.com.json")).unwrap();
    let cache = TlsFrontCache::new(&["example.com".to_string()], 1024, directory.path());

    cache.load_from_disk().await;

    assert_eq!(cache.get("example.com").await.domain, "default");
}
