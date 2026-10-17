use super::*;

fn config() -> ProxyConfig {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(
        &path,
        r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"
bob = "100102030405060708090a0b0c0d0e0f"
[web]
allow_wildcard_hosts = true
[web.limits]
memory_envelope_bytes = 1610612736
[[web.vhosts]]
host = "*.example.com"
public_addr = "203.0.113.10:443"
[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"
[[web.vhosts.profiles]]
user = "alice"
secret_mode = "plain"
[[web.vhosts.profiles]]
user = "bob"
secret_mode = "dd"
"#,
    )
    .unwrap();
    ProxyConfig::load(path).unwrap()
}

#[test]
fn cold_budget_reserves_full_table_and_warm_hits_remain_available() {
    let config = config();
    let web = config.web.runtime.as_ref().unwrap();
    let vhost = &web.wildcards["example.com"];
    let cache = WildcardState::new(WebWildcardLimitsConfig {
        cold_hmac_burst: 3,
        cold_hmac_per_minute: 1,
        ..Default::default()
    });
    let table = cache.prepare(&config, vhost, "a.example.com").unwrap();
    assert_eq!(cache.test_stats(), (0, 0, 2));
    cache.publish(web.snapshot_id, vhost, "a.example.com", table, || true);
    assert!(cache.prepare(&config, vhost, "b.example.com").is_none());
    assert!(matches!(
        cache.prepare(&config, vhost, "a.example.com"),
        Some(CapabilityTable::Warm(_))
    ));
    assert_eq!(cache.test_stats().2, 2);
    let mut state = State::default();
    let now = Instant::now();
    assert!(reserve(&mut state, now, 2, &cache.limits));
    assert!(!reserve(&mut state, now, 2, &cache.limits));
    assert!(reserve(
        &mut state,
        now + std::time::Duration::from_secs(60),
        2,
        &cache.limits
    ));
}

#[test]
fn evicted_borrowers_keep_their_byte_lease_and_no_configuration_snapshot() {
    let config = config();
    let web = config.web.runtime.as_ref().unwrap();
    let vhost = &web.wildcards["example.com"];
    let weak = Arc::downgrade(vhost);
    let cost = 2 * 256 + 2048 + 2 * "a.example.com".len();
    let cache = WildcardState::new(WebWildcardLimitsConfig {
        cache_hosts: 1,
        cache_bytes: cost,
        ..Default::default()
    });
    let table = cache.prepare(&config, vhost, "a.example.com").unwrap();
    let capability = table.capabilities()[0];
    cache.publish(web.snapshot_id, vhost, "a.example.com", table, || true);
    let borrowed = cache.prepare(&config, vhost, "a.example.com").unwrap();
    assert!(cache.contains(&capability));
    let next = cache.prepare(&config, vhost, "b.example.com").unwrap();
    cache.publish(web.snapshot_id, vhost, "b.example.com", next, || true);
    assert_eq!(cache.test_stats().0, 0);
    assert_eq!(cache.test_stats().1, cost);
    assert!(!cache.contains(&capability));
    drop(config);
    assert!(weak.upgrade().is_none());
    drop(borrowed);
    assert_eq!(cache.test_stats().1, 0);
}

#[test]
fn hostile_misses_do_not_pollute_cache_and_snapshot_identity_fences_hits() {
    let config = config();
    let web = config.web.runtime.as_ref().unwrap();
    let vhost = &web.wildcards["example.com"];
    let cache = WildcardState::new(WebWildcardLimitsConfig::default());
    for index in 0..1000 {
        drop(
            cache
                .prepare(&config, vhost, &format!("h{index}.example.com"))
                .unwrap(),
        );
    }
    assert_eq!(cache.test_stats(), (0, 0, 2000));
    let table = cache.prepare(&config, vhost, "a.example.com").unwrap();
    cache.publish(web.snapshot_id, vhost, "a.example.com", table, || true);
    let next = self::config();
    let next_vhost = &next.web.runtime.as_ref().unwrap().wildcards["example.com"];
    assert!(matches!(
        cache.prepare(&next, next_vhost, "a.example.com"),
        Some(CapabilityTable::Cold(_))
    ));
    let disabled = WildcardState::new(WebWildcardLimitsConfig {
        cache_hosts: 0,
        ..Default::default()
    });
    let table = disabled.prepare(&config, vhost, "a.example.com").unwrap();
    disabled.publish(web.snapshot_id, vhost, "a.example.com", table, || true);
    assert_eq!(disabled.test_stats(), (0, 0, 2));
}

#[test]
fn concurrent_publication_and_eviction_keep_entry_and_byte_bounds() {
    let config = Arc::new(config());
    let cache = Arc::new(WildcardState::new(WebWildcardLimitsConfig {
        cache_hosts: 4,
        cache_bytes: 8192,
        ..Default::default()
    }));
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let cache = Arc::clone(&cache);
            let config = Arc::clone(&config);
            scope.spawn(move || {
                let web = config.web.runtime.as_ref().unwrap();
                let vhost = &web.wildcards["example.com"];
                for index in 0..100 {
                    let host = format!("h{worker}-{index}.example.com");
                    let table = cache.prepare(&config, vhost, &host).unwrap();
                    cache.publish(web.snapshot_id, vhost, &host, table, || true);
                    let (hosts, bytes, _) = cache.test_stats();
                    assert!(hosts <= 4 && bytes <= 8192);
                }
            });
        }
    });
}

#[test]
fn stale_publication_cannot_evict_current_warm_table() {
    let old = config();
    let current = config();
    let cache = WildcardState::new(WebWildcardLimitsConfig::default());
    let old_web = old.web.runtime.as_ref().unwrap();
    let current_web = current.web.runtime.as_ref().unwrap();
    let old_vhost = &old_web.wildcards["example.com"];
    let current_vhost = &current_web.wildcards["example.com"];
    let late = cache.prepare(&old, old_vhost, "a.example.com").unwrap();
    let latest = cache
        .prepare(&current, current_vhost, "a.example.com")
        .unwrap();
    cache.publish(
        current_web.snapshot_id,
        current_vhost,
        "a.example.com",
        latest,
        || true,
    );
    cache.publish(
        old_web.snapshot_id,
        old_vhost,
        "a.example.com",
        late,
        || false,
    );
    assert!(matches!(
        cache.prepare(&current, current_vhost, "a.example.com"),
        Some(CapabilityTable::Warm(_))
    ));
    assert_eq!(cache.test_stats().2, 4);
    // A prepared generation can activate after a later-built watcher snapshot.
    // Numeric ID ordering must not prevent that active snapshot from warming.
    let reactivated = cache.prepare(&old, old_vhost, "a.example.com").unwrap();
    cache.publish(
        old_web.snapshot_id,
        old_vhost,
        "a.example.com",
        reactivated,
        || true,
    );
    assert!(matches!(
        cache.prepare(&old, old_vhost, "a.example.com"),
        Some(CapabilityTable::Warm(_))
    ));
}
