use super::*;
use http_body_util::BodyExt;

#[tokio::test]
async fn busy_state_preserves_runtime_identity_and_does_not_queue_more_work() {
    let (fixture, _sender) = fixture("", true).await;
    let permits = fixture
        .shared
        .config_state_slots
        .clone()
        .acquire_many_owned(2)
        .await
        .unwrap();
    let data = inspect(&fixture, None).await;
    assert_eq!(data["desired_status"], "busy");
    assert_eq!(data["desired_error"]["code"], "config_state_busy");
    assert_eq!(data["runtime"]["active_generation"], 1);
    assert!(data["effective"].is_null());
    assert_eq!(data["comparison"]["status"], "unknown");
    drop(permits);
    assert_eq!(inspect(&fixture, None).await["desired_status"], "valid");
}

#[tokio::test]
async fn large_deployment_bounds_fields_paths_bytes_and_dynamic_identities() {
    let (fixture, _sender) = fixture("", true).await;
    let mut text =
        String::from("[access.users]\nprivate_identity='000102030405060708090a0b0c0d0e0f'\n");
    for _ in 0..1200 {
        text.push_str("[[upstreams]]\ntype='socks5'\naddress='127.0.0.1:1080'\nusername='private_socks_user'\npassword='private_socks_password'\n");
    }
    source(&fixture, &text, true);
    let response = response(&fixture.shared, None).await.unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert!(bytes.len() <= MAX_RESPONSE_BYTES);
    let data: Json = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(data["data"]["desired_status"], "valid");
    assert_eq!(data["data"]["desired"]["truncated"], true);
    assert!(data["data"]["desired"]["fields"].as_array().unwrap().len() <= 1024);
    assert_eq!(data["data"]["comparison"]["truncated"], true);
    assert!(
        data["data"]["comparison"]["pending_paths"]
            .as_array()
            .unwrap()
            .len()
            <= MAX_STATE_PATHS
    );
    let encoded = String::from_utf8(bytes.to_vec()).unwrap();
    for private in [
        "private_identity",
        "private_socks_user",
        "private_socks_password",
        "000102030405060708090a0b0c0d0e0f",
        "Bearer discovery-test",
    ] {
        assert!(!encoded.contains(private));
    }
}

fn abandoned_state_retains_budget(timeout: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (fixture, _sender) = fixture("", true).await;
        let original = std::fs::read(&fixture.shared.config_path).unwrap();
        let active = fixture.shared.active_runtime.load_full();
        let (release, wait) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
        });
        ready.await.unwrap();
        tokio::time::pause();
        let shared = fixture.shared.clone();
        let task = tokio::spawn(async move { state(&shared, None).await });
        while fixture.shared.config_state_slots.available_permits() == 2 {
            tokio::task::yield_now().await;
        }
        if timeout {
            fixture
                .shared
                .active_runtime
                .store(test_runtime_generation(2, active.config().as_ref().clone()));
            tokio::time::advance(Duration::from_secs(6)).await;
            let data = serde_json::to_value(task.await.unwrap().unwrap()).unwrap();
            assert_eq!(data["runtime"]["active_generation"], 1);
            assert_eq!(data["runtime_sample_current"], false);
            assert_eq!(data["desired_status"], "unavailable");
            assert_eq!(
                data["projection_error"]["code"],
                "effective_projection_unavailable"
            );
        } else {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        assert_eq!(fixture.shared.config_state_slots.available_permits(), 1);
        tokio::time::resume();
        release.send(()).unwrap();
        blocker.await.unwrap();
        let _permits = tokio::time::timeout(
            Duration::from_secs(5),
            fixture
                .shared
                .config_state_slots
                .clone()
                .acquire_many_owned(2),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            std::fs::read(&fixture.shared.config_path).unwrap(),
            original
        );
        assert!(fixture.shared.reload_control.status(1).await.is_none());
    });
}

#[test]
fn cancellation_retains_read_slot_until_detached_worker_finishes() {
    abandoned_state_retains_budget(false);
}

#[test]
fn timeout_retains_read_slot_and_reports_a_stale_runtime_sample() {
    abandoned_state_retains_budget(true);
}

#[test]
fn desired_worker_timeout_preserves_effective_and_retains_its_read_slot() {
    use std::future::Future;
    use std::task::Poll;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (fixture, _sender) = fixture("", true).await;
        let (release_initial, wait_initial) = std::sync::mpsc::channel();
        let (initial_started, initial_ready) = tokio::sync::oneshot::channel();
        let initial_blocker = tokio::task::spawn_blocking(move || {
            initial_started.send(()).unwrap();
            wait_initial.recv().unwrap();
        });
        initial_ready.await.unwrap();
        let mut read = Box::pin(state(&fixture.shared, None));
        // Queue effective projection, then occupy the only blocking thread once
        // it completes. The desired-source worker will have to wait behind it.
        std::future::poll_fn(|context| {
            assert!(read.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        let (release, wait) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            wait.recv().unwrap();
        });
        release_initial.send(()).unwrap();
        initial_blocker.await.unwrap();
        ready.await.unwrap();
        tokio::time::pause();
        std::future::poll_fn(|context| {
            assert!(read.as_mut().poll(context).is_pending());
            Poll::Ready(())
        })
        .await;
        tokio::time::advance(Duration::from_secs(6)).await;
        let data = serde_json::to_value(read.await.unwrap()).unwrap();
        assert_eq!(data["desired_status"], "timeout");
        assert_eq!(data["desired_error"]["code"], "desired_read_timeout");
        assert!(!data["effective"].is_null());
        assert_eq!(data["comparison"]["status"], "unknown");
        assert_eq!(fixture.shared.config_state_slots.available_permits(), 1);
        tokio::time::resume();
        release.send(()).unwrap();
        blocker.await.unwrap();
        let _permits = tokio::time::timeout(
            Duration::from_secs(5),
            fixture
                .shared
                .config_state_slots
                .clone()
                .acquire_many_owned(2),
        )
        .await
        .unwrap()
        .unwrap();
    });
}
