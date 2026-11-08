use super::*;

#[tokio::test]
async fn wildcard_same_generation_reload_fences_cache_and_preserves_only_equivalent_profiles() {
    let text = wildcard_source(
        "host = \"*.example.com\"",
        "127.0.0.1:18081".parse().unwrap(),
    );
    let mut initial = generation(11, &text);
    let (config_tx, config_rx) = tokio::sync::watch::channel(initial.config());
    Arc::get_mut(&mut initial).unwrap().config_rx = config_rx;
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(initial.clone())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let old = bridge(&listener, &runtime, HOSTS[0]).await;
    let old_snapshot = initial.config().web.runtime.as_ref().unwrap().snapshot_id;
    let equivalent = generation(99, &text.replace("max_sessions = 1", "max_sessions = 2"));
    config_tx.send_replace(equivalent.config());
    assert_eq!(runtime.active_generation().id, 11);
    assert_ne!(
        initial.config().web.runtime.as_ref().unwrap().snapshot_id,
        old_snapshot
    );
    assert!(create(&runtime, HOSTS[0], &old).is_ok());
    let before = runtime.wildcard.as_ref().unwrap().test_stats().2;
    let unused = bridge(&listener, &runtime, HOSTS[0]).await;
    assert_eq!(
        runtime.wildcard.as_ref().unwrap().test_stats().2,
        before + 1
    );
    let changed = generation(
        99,
        &text.replace("base_path = \"relay\"", "base_path = \"new\""),
    );
    config_tx.send_replace(changed.config());
    assert_eq!(
        create(&runtime, HOSTS[0], &unused),
        Err(ManagerError::Authentication)
    );
    config_tx.send_replace(equivalent.config());
    let unused = bridge(&listener, &runtime, HOSTS[0]).await;
    let changed_secret = generation(
        99,
        &text.replace(
            "000102030405060708090a0b0c0d0e0f",
            "100102030405060708090a0b0c0d0e0f",
        ),
    );
    config_tx.send_replace(changed_secret.config());
    assert_eq!(
        create(&runtime, HOSTS[0], &unused),
        Err(ManagerError::Authentication)
    );
    // A new exact winner fences the wildcard even when its old template remains loaded.
    config_tx.send_replace(equivalent.config());
    let unused = bridge(&listener, &runtime, HOSTS[1]).await;
    let (prefix, group) = text.split_once("[[web.vhosts]]").unwrap();
    let (group, limits) = group.split_once("[web.limits]").unwrap();
    let exact = generation(
        99,
        &format!(
            "{prefix}[[web.vhosts]]{group}\n[[web.vhosts]]{}\n[web.limits]{limits}",
            group
                .replace("host = \"*.example.com\"", "host = \"b.example.com\"")
                .replace("base_path = \"relay\"", "base_path = \"other\"")
        ),
    );
    config_tx.send_replace(exact.config());
    assert_eq!(
        create(&runtime, HOSTS[1], &unused),
        Err(ManagerError::Authentication)
    );
    stop(
        runtime,
        &[initial, equivalent, changed, changed_secret, exact],
    )
    .await;
}

#[tokio::test]
async fn wildcard_rule_precedence_never_falls_through_after_failed_authentication() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let text = wildcard_source("host = \"*\"", origin.local_addr().unwrap());
    let (prefix, group) = text.split_once("[[web.vhosts]]").unwrap();
    let (group, limits) = group.split_once("[web.limits]").unwrap();
    let text = format!(
        "{prefix}[[web.vhosts]]{group}\n[[web.vhosts]]{}\n[[web.vhosts]]{}\n[[web.vhosts]]{}\n[web.limits]{limits}",
        group
            .replace("host = \"*\"", "host = \"*.example.com\"")
            .replace("base_path = \"relay\"", "base_path = \"suffix\""),
        group
            .replace("host = \"*\"", "host = \"*.deep.example.com\"")
            .replace("base_path = \"relay\"", "base_path = \"deep\""),
        group
            .replace("host = \"*\"", "host = \"a.deep.example.com\"")
            .replace("base_path = \"relay\"", "base_path = \"exact\"")
    );
    let generation = generation(1, &text);
    let config = generation.config();
    let web = config.web.runtime.as_ref().unwrap();
    assert_eq!(web.route("a.deep.example.com").unwrap().base, "/exact/");
    assert_eq!(web.route("b.deep.example.com").unwrap().base, "/deep/");
    assert_eq!(web.route("b.example.com").unwrap().base, "/suffix/");
    assert_eq!(web.route("example.com").unwrap().base, "/relay/");
    assert_eq!(web.route("elsewhere.org").unwrap().base, "/relay/");
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cap = capability(&config, "b.deep.example.com");
    let server = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nordinary")
            .await
            .unwrap();
        head
    });
    let response = request(
        &listener,
        &runtime,
        raw_request(
            "GET",
            &format!("/deep/?bridge={cap}"),
            "b.deep.example.com",
            "",
            &[],
        ),
    )
    .await;
    assert_eq!(split_response(&response).1, b"ordinary");
    assert!(
        String::from_utf8(server.await.unwrap())
            .unwrap()
            .contains("/deep/")
    );
    assert_eq!(runtime.wildcard.as_ref().unwrap().test_stats().0, 0);
    stop(runtime, &[generation]).await;
}

#[tokio::test]
async fn wildcard_reordered_profiles_do_not_reuse_stale_capability_indexes() {
    let text = wildcard_source(
        "host = \"*.example.com\"",
        "127.0.0.1:18081".parse().unwrap(),
    )
    .replace(
        "[access.users]",
        "[access.users]\nbob = \"100102030405060708090a0b0c0d0e0f\"",
    )
    .replace(
        "[web.limits]",
        "[[web.vhosts.profiles]]\nuser = \"bob\"\nsecret_mode = \"plain\"\n[web.limits]",
    );
    let mut initial = generation(1, &text);
    let (tx, rx) = tokio::sync::watch::channel(initial.config());
    Arc::get_mut(&mut initial).unwrap().config_rx = rx;
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(initial.clone())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused = bridge(&listener, &runtime, HOSTS[0]).await;
    let mut config = (*initial.config()).clone();
    config.web.vhosts[0].profiles.reverse();
    config.rebuild_runtime_web().unwrap();
    tx.send_replace(Arc::new(config));
    assert!(create(&runtime, HOSTS[0], &unused).is_ok());
    let fresh = bridge(&listener, &runtime, HOSTS[0]).await;
    let (_, profile, _) = runtime
        .bootstrap_trace_identity(token_hash(&fresh), HOSTS[0])
        .unwrap();
    assert_eq!(profile.shared.user, "alice");
    assert_eq!(runtime.wildcard.as_ref().unwrap().test_stats().2, 4);
    stop(runtime, &[initial]).await;
}
