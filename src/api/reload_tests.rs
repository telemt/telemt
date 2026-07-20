use super::*;
use crate::config::ProxyConfig;

async fn config_file() -> (tempfile::TempDir, PathBuf, String) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let mut config = ProxyConfig::default();
    config.server.max_connections = 4_242;
    let body = toml::to_string_pretty(&config).unwrap();
    tokio::fs::write(&path, &body).await.unwrap();
    let revision = config_store::compute_revision(&body);
    (directory, path, revision)
}

#[tokio::test]
async fn reload_submission_uses_matching_disk_revision_and_snapshot() {
    let (_directory, path, revision) = config_file().await;
    let mutation_lock = Mutex::new(());
    let (control, mut commands) = ReloadControl::channel(1);
    let request = ReloadRequest::default();

    let (accepted, response_revision) = submit_reload_from_disk(
        &path,
        &mutation_lock,
        &control,
        Some(&revision),
        request.clone(),
    )
    .await
    .unwrap();
    let command = commands.recv().await.unwrap();

    assert_eq!(response_revision, revision);
    assert_eq!(accepted.config_revision, revision);
    assert_eq!(command.config_revision, revision);
    assert_eq!(command.request, request);
    assert_eq!(command.config.server.max_connections, 4_242);
}

#[tokio::test]
async fn revision_conflict_rejects_without_enqueuing_reload() {
    let (_directory, path, _revision) = config_file().await;
    let mutation_lock = Mutex::new(());
    let (control, _commands) = ReloadControl::channel(1);

    let error = submit_reload_from_disk(
        &path,
        &mutation_lock,
        &control,
        Some("stale-revision"),
        ReloadRequest::default(),
    )
    .await
    .unwrap_err();

    assert_eq!(error.status, StatusCode::CONFLICT);
    assert_eq!(error.code, "revision_conflict");
    assert_eq!(control.in_progress().await, None);
}

#[tokio::test]
async fn reload_conflict_and_closed_coordinator_map_to_http_contract() {
    let (_directory, path, _revision) = config_file().await;
    let mutation_lock = Mutex::new(());
    let (control, mut commands) = ReloadControl::channel(1);
    let _accepted = submit_reload_from_disk(
        &path,
        &mutation_lock,
        &control,
        None,
        ReloadRequest::default(),
    )
    .await
    .unwrap();
    let _command = commands.recv().await.unwrap();

    let conflict = submit_reload_from_disk(
        &path,
        &mutation_lock,
        &control,
        None,
        ReloadRequest::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    assert_eq!(conflict.code, "reload_in_progress");

    control.fail(1, "test cleanup").await;
    drop(commands);
    let unavailable = submit_reload_from_disk(
        &path,
        &mutation_lock,
        &control,
        None,
        ReloadRequest::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(unavailable.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unavailable.code, "maestro_unavailable");
}

#[test]
fn reload_routes_expose_only_documented_methods_and_ids() {
    assert_eq!(
        allowed_methods_for_path("/v1/system/reload"),
        Some(ALLOW_POST)
    );
    assert_eq!(
        allowed_methods_for_path("/v1/system/reload/42"),
        Some(ALLOW_GET)
    );
    assert_eq!(reload_status_route_id("/v1/system/reload/42"), Some(42));
    assert_eq!(
        reload_status_route_id("/v1/system/reload/not-a-number"),
        None
    );
}
