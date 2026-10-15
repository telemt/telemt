use super::*;
use tokio::sync::Barrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_host_quotas_survive_concurrent_creation_and_generation_swaps() {
    let source = source(SELECTOR, "127.0.0.1:18081".parse().unwrap());
    let initial = generation(1, &source);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(initial.clone())));
    let mut generations = vec![initial];
    for id in 2..=9 {
        let selector = if id % 2 == 0 {
            "hosts = [\"b.example.com\", \"a.example.com\"]"
        } else {
            SELECTOR
        };
        generations.push(generation(id, &source.replace(SELECTOR, selector)));
    }
    let barrier = Arc::new(Barrier::new(34));
    let mut tasks = Vec::new();
    for host in HOSTS {
        for _ in 0..16 {
            let token = bootstrap(&runtime, host);
            let runtime = runtime.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                (host, create(&runtime, host, &token))
            }));
        }
    }
    let reloader = {
        let runtime = runtime.clone();
        let barrier = barrier.clone();
        let generations = generations[1..].to_vec();
        tokio::spawn(async move {
            barrier.wait().await;
            for generation in generations {
                runtime.activate_generation(generation);
                tokio::task::yield_now().await;
            }
        })
    };
    barrier.wait().await;
    let mut accepted = Vec::new();
    for task in tasks {
        let (host, result) = task.await.unwrap();
        match result {
            Ok(token) => accepted.push((host, token)),
            Err(error) => assert_eq!(error, ManagerError::Limit),
        }
    }
    reloader.await.unwrap();
    assert_eq!(accepted.len(), 2);
    for host in HOSTS {
        assert_eq!(
            accepted.iter().filter(|(owner, _)| *owner == host).count(),
            1
        );
    }
    let sessions: Vec<_> = accepted
        .iter()
        .map(|(host, token)| runtime.get_session(token_hash(token), host).unwrap())
        .collect();
    assert_ne!(sessions[0].profile_key(), sessions[1].profile_key());
    assert_eq!(
        serde_json::to_value(runtime.try_status()).unwrap()["manager"]["profiles"],
        2
    );

    let barrier = Arc::new(Barrier::new(33));
    let mut tasks = Vec::new();
    let ip = "192.0.2.10".parse().unwrap();
    let addr = "203.0.113.10:443".parse().unwrap();
    for session in &sessions {
        let key = session.profile_key();
        for _ in 0..16 {
            let runtime = runtime.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                (key, runtime.try_acquire_stream(key, 1, ip, addr))
            }));
        }
    }
    barrier.wait().await;
    let mut ports = Vec::new();
    for task in tasks {
        let (key, result) = task.await.unwrap();
        match result {
            Ok(port) => ports.push((key, port)),
            Err(error) => assert_eq!(error, ManagerError::Limit),
        }
    }
    assert_eq!(ports.len(), 2);
    assert_ne!(ports[0].0, ports[1].0);
    assert_eq!(
        serde_json::to_value(runtime.try_status()).unwrap()["streams"]["profiles"],
        2
    );
    for (key, port) in ports {
        runtime.release_stream(key, ip, addr, port);
    }
    assert_eq!(
        serde_json::to_value(runtime.try_status()).unwrap()["streams"]["profiles"],
        0
    );
    stop(runtime, &generations).await;
}

#[tokio::test]
async fn regrouping_preserves_live_quota_and_bootstrap_when_limits_change() {
    let grouped = source(SELECTOR, "127.0.0.1:18081".parse().unwrap());
    let (prefix, group) = grouped.split_once("[[web.vhosts]]").unwrap();
    let separate = format!(
        "{prefix}[[web.vhosts]]{}\n[[web.vhosts]]{}",
        group.replace(SELECTOR, "host = \"a.example.com\""),
        group.replace(SELECTOR, "host = \"b.example.com\"")
    );
    let initial = generation(1, &separate);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(initial.clone())));
    let a = create(&runtime, HOSTS[0], &bootstrap(&runtime, HOSTS[0])).unwrap();
    let key = runtime
        .get_session(token_hash(&a), HOSTS[0])
        .unwrap()
        .profile_key();
    let unused_b = bootstrap(&runtime, HOSTS[1]);
    let next = generation(
        2,
        &grouped
            .replace(SELECTOR, "hosts = [\"b.example.com\", \"a.example.com\"]")
            .replace("max_sessions = 1", "max_sessions = 2"),
    );
    runtime.activate_generation(next.clone());
    let b = create(&runtime, HOSTS[1], &unused_b).unwrap();
    assert_eq!(
        runtime
            .get_session(token_hash(&a), HOSTS[0])
            .unwrap()
            .profile_key(),
        key
    );
    let second_a = create(&runtime, HOSTS[0], &bootstrap(&runtime, HOSTS[0])).unwrap();
    assert_eq!(
        runtime
            .get_session(token_hash(&second_a), HOSTS[0])
            .unwrap()
            .profile_key(),
        key
    );
    assert_eq!(
        create(&runtime, HOSTS[0], &bootstrap(&runtime, HOSTS[0])),
        Err(ManagerError::Limit)
    );

    let stale_b = bootstrap(&runtime, HOSTS[1]);
    let removed = generation(
        3,
        &grouped
            .replace(SELECTOR, "hosts = [\"a.example.com\"]")
            .replace("max_sessions = 1", "max_sessions = 2"),
    );
    runtime.activate_generation(removed.clone());
    assert_eq!(
        create(&runtime, HOSTS[1], &stale_b),
        Err(ManagerError::Authentication)
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let response = request(
        &listener,
        &runtime,
        raw_request("GET", "/relay/", HOSTS[1], "", &[]),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 404"));
    assert!(runtime.get_session(token_hash(&a), HOSTS[0]).is_ok());
    assert!(runtime.get_session(token_hash(&b), HOSTS[1]).is_ok());
    assert_eq!(
        create(&runtime, HOSTS[0], &bootstrap(&runtime, HOSTS[0])),
        Err(ManagerError::Limit)
    );
    stop(runtime, &[initial, next, removed]).await;
}

#[tokio::test]
async fn grouped_profiles_keep_process_and_ip_session_limits() {
    for global in [1, 2] {
        let text = format!(
            "{}\n[web.limits]\nmax_sessions_global = {global}\nmax_sessions_per_ip = 1\n",
            source(SELECTOR, "127.0.0.1:18081".parse().unwrap())
        );
        let generation = generation(1, &text);
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
        create(&runtime, HOSTS[0], &bootstrap(&runtime, HOSTS[0])).unwrap();
        let b = bootstrap(&runtime, HOSTS[1]);
        assert_eq!(create(&runtime, HOSTS[1], &b), Err(ManagerError::Limit));
        let result = runtime.create_session(
            token_hash(&b),
            HOSTS[1],
            "192.0.2.11".parse().unwrap(),
            &frame::encode(FrameType::Hello, 0, &[1]),
            CarrierRequest::legacy([0; 32]),
            false,
        );
        if global == 1 {
            assert!(matches!(result, Err(ManagerError::Limit)));
        } else {
            assert!(result.is_ok());
        }
        stop(runtime, &[generation]).await;
    }
}
