use super::*;
use crate::config::ProxyConfig;
use crate::maestro::generation::test_runtime_generation;
use crate::web::frame::{self, FrameType};
use crate::web::manager::{CarrierRequest, ManagerError, WebProcessRuntime};
use arc_swap::ArcSwap;

fn generation(id: u64, lifetime: u64) -> Arc<RuntimeGeneration> {
    let fixture = Fixture::new();
    let mut config = ProxyConfig::default();
    config.web.enabled = true;
    config.web.timeouts.bootstrap_lifetime_secs = lifetime;
    config.web.timeouts.shutdown_secs = 1;
    config.web.limits.max_bootstraps_global = 1024;
    config.web.limits.max_bootstraps_per_ip = 512;
    config.web.limits.max_sessions_global = 1024;
    config.web.limits.max_sessions_per_ip = 512;
    config.web.limits.new_bootstraps_burst = 4096;
    config.web.limits.new_sessions_burst = 4096;
    config.web.runtime = Some(Arc::new(WebRuntimeConfig {
        vhosts: BTreeMap::new(),
        profiles: vec![Arc::clone(&fixture.profile)],
        capabilities: vec![fixture.profile.capability].into_boxed_slice(),
    }));
    let generation = test_runtime_generation(id, config);
    generation.proxy_shared.apply_user_config(
        &HashMap::from([(
            "alice".to_string(),
            "0123456789abcdef0123456789abcdef".to_string(),
        )]),
        &HashMap::new(),
    );
    generation
}

fn token_hash(token: &str) -> TokenHash {
    Sha256::digest(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .unwrap(),
    )
    .into()
}

fn assert_live_invariants(runtime: &WebProcessRuntime) {
    let state = runtime.state.lock();
    let mut per_ip = HashMap::new();
    for bootstrap in state.bootstraps.values() {
        assert!(state.bootstrap_expiry.unwrap() <= bootstrap.expires_at);
        if !bootstrap.used {
            *per_ip.entry(bootstrap.issuance_ip).or_insert(0) += 1;
        }
    }
    assert_eq!(state.bootstraps_per_ip, per_ip);
    for closed in state.closed_tokens.values() {
        assert!(state.closed_token_expiry.unwrap() <= closed.expires_at);
    }
}

#[tokio::test]
async fn real_issuance_reload_renewal_and_shutdown_preserve_expiry_hints() {
    let initial = generation(1, 120);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&initial))));
    let profile = initial.config().web.runtime.as_ref().unwrap().profiles[0].clone();
    let ip = "192.0.2.10".parse().unwrap();
    let issued = runtime.issue_bootstrap(Arc::clone(&profile), ip).unwrap();
    let hash = token_hash(&issued.token);
    let first_expiry = runtime.state.lock().bootstraps[&hash].expires_at;
    assert_eq!(runtime.state.lock().bootstrap_expiry, Some(first_expiry));

    let replacement = generation(2, 60);
    runtime.activate_generation(Arc::clone(&replacement));
    let newer = runtime.issue_bootstrap(Arc::clone(&profile), ip).unwrap();
    let newer_hash = token_hash(&newer.token);
    let shorter_expiry = runtime.state.lock().bootstraps[&newer_hash].expires_at;
    assert!(shorter_expiry < first_expiry);
    assert_eq!(runtime.state.lock().bootstrap_expiry, Some(shorter_expiry));

    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let create = runtime
        .create_session(
            hash,
            &profile.host,
            ip,
            &hello,
            CarrierRequest::legacy([0; 32]),
            false,
        )
        .unwrap();
    let replay = runtime
        .create_session(
            hash,
            &profile.host,
            ip,
            &hello,
            CarrierRequest::legacy([0; 32]),
            false,
        )
        .unwrap();
    assert_eq!(create.token, replay.token);
    {
        let state = runtime.state.lock();
        assert!(state.bootstraps[&hash].expires_at >= first_expiry);
        assert_eq!(
            state.bootstraps[&hash].timeouts.bootstrap_lifetime_secs,
            120
        );
        assert_eq!(state.bootstrap_expiry, Some(shorter_expiry));
    }
    assert_live_invariants(&runtime);
    runtime.shutdown().await;
    assert_eq!(runtime.state.lock().bootstrap_expiry, None);
    assert!(matches!(
        runtime.issue_bootstrap(profile, ip),
        Err(ManagerError::AdmissionPaused)
    ));
    for generation in [initial, replacement] {
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_issuance_creation_close_and_reload_preserve_quota_and_hint_invariants() {
    let initial = generation(1, 120);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&initial))));
    let barrier = Arc::new(tokio::sync::Barrier::new(33));
    let mut workers = Vec::new();
    for worker in 0..32 {
        let runtime = Arc::clone(&runtime);
        let barrier = Arc::clone(&barrier);
        workers.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..8 {
                let active = runtime.active_generation();
                let profile = active.config().web.runtime.as_ref().unwrap().profiles[0].clone();
                let ip = IpAddr::from([192, 0, 2, worker + 1]);
                let issued = runtime.issue_bootstrap(profile.clone(), ip).unwrap();
                let hello = frame::encode(FrameType::Hello, 0, &[1]);
                let created = runtime
                    .create_session(
                        token_hash(&issued.token),
                        &profile.host,
                        ip,
                        &hello,
                        CarrierRequest::legacy([0; 32]),
                        false,
                    )
                    .unwrap();
                let hash = token_hash(&created.token);
                let session = runtime.get_session(hash, &profile.host).unwrap();
                runtime.close_token(hash, &profile.host, None).unwrap();
                session.wait().await;
                runtime.close_token(hash, &profile.host, None).unwrap();
                runtime.cleanup();
                assert_live_invariants(&runtime);
            }
        }));
    }
    barrier.wait().await;
    let mut generations = vec![initial];
    for id in 2..=8 {
        let next = generation(id, if id % 2 == 0 { 60 } else { 120 });
        runtime.activate_generation(Arc::clone(&next));
        generations.push(next);
        tokio::task::yield_now().await;
    }
    for worker in workers {
        worker.await.unwrap();
    }
    assert_live_invariants(&runtime);
    {
        let state = runtime.state.lock();
        assert!(state.sessions.is_empty());
        assert!(state.sessions_per_ip.is_empty());
        assert!(state.sessions_per_profile.is_empty());
        assert!(state.bootstraps_per_ip.is_empty());
    }
    runtime.shutdown().await;
    for generation in generations {
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}
