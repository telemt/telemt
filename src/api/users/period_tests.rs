use super::*;
use crate::api::{ApiRuntimeState, events::ApiEventStore};
use crate::config::UserQuotaPeriod;
use crate::maestro::{
    control_plane::ProcessControlPlane, generation::test_runtime_generation, reload::ReloadControl,
};
use crate::proxy::{shared_state::ProxySharedState, user_admission::UserAdmissionAuthority};
use crate::quota_state::QuotaStateOwner;
use crate::stats::QuotaStore;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use tokio::sync::{Mutex, watch};

struct Fixture {
    _dir: tempfile::TempDir,
    shared: ApiShared,
    store: Arc<QuotaStore>,
    config_tx: watch::Sender<Arc<ProxyConfig>>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "# preserve this operator comment\n[access.users]\nadmin = '00000000000000000000000000000000'\n").unwrap();
        let cfg = ProxyConfig::load(&config_path).unwrap();
        let store = Arc::new(QuotaStore::default());
        let stats = Arc::new(Stats::with_quota_store(store.clone()));
        let mut runtime = test_runtime_generation(1, cfg.clone());
        let authority = UserAdmissionAuthority::new_with_quota_store(store.clone());
        let proxy_shared = ProxySharedState::new_with_direct_buffer_budget_and_user_admission(
            runtime.proxy_shared.direct_buffer_budget.clone(),
            authority,
        );
        proxy_shared.activate_user_config_source(
            1,
            None,
            &cfg.access.users,
            &cfg.access.user_enabled,
        );
        let (config_tx, config_rx) = watch::channel(Arc::new(cfg.clone()));
        let mutable = Arc::get_mut(&mut runtime).unwrap();
        mutable.stats = stats.clone();
        mutable.proxy_shared = proxy_shared.clone();
        mutable.config_rx = config_rx;
        let shared = ApiShared {
            stats,
            ip_tracker: runtime.ip_tracker.clone(),
            me_pool: runtime.me_pool_runtime.clone(),
            upstream_manager: runtime.upstream_manager.clone(),
            config_path,
            quota_state: QuotaStateOwner::new(dir.path().join("quota.json"), store.clone()),
            detected_ips_rx: watch::channel((None, None)).1,
            mutation_lock: Arc::new(Mutex::new(())),
            minimal_cache: Arc::new(Mutex::new(None)),
            runtime_edge_connections_cache: Arc::new(Mutex::new(None)),
            runtime_edge_recompute_lock: Arc::new(Mutex::new(())),
            cache_generation: Arc::new(AtomicU64::new(1)),
            runtime_events: Arc::new(ApiEventStore::new(64)),
            request_id: Arc::new(AtomicU64::new(1)),
            runtime_state: Arc::new(ApiRuntimeState {
                process_started_at_epoch_secs: 0,
                config_reload_count: AtomicU64::new(0),
                last_config_reload_epoch_secs: AtomicU64::new(0),
                admission_open: AtomicBool::new(true),
            }),
            startup_tracker: Arc::new(crate::startup::StartupTracker::new(0)),
            route_runtime: runtime.route_runtime.clone(),
            proxy_shared,
            reload_control: ReloadControl::channel(1).0,
            active_runtime: Arc::new(arc_swap::ArcSwap::from(runtime)),
            web_trace: crate::web::trace::WebTraceStore::new(
                cfg.web.debug.clone(),
                &cfg.web.limits,
            ),
            web_runtime_rx: crate::web::control::WebRuntimeControl::new().subscribe(),
            control_plane: ProcessControlPlane::new(),
        };
        Self {
            _dir: dir,
            shared,
            store,
            config_tx,
        }
    }

    async fn publish(&self) {
        let cfg = Arc::new(ProxyConfig::load(&self.shared.config_path).unwrap());
        let guard = self.shared.quota_state.lock().await;
        self.config_tx.send_replace(cfg.clone());
        assert!(
            self.shared
                .proxy_shared
                .apply_user_config_from_source(1, &cfg.access.users, &cfg.access.user_enabled)
                .is_some()
        );
        self.shared.proxy_shared.publish_quota_config(1, &cfg, true);
        drop(guard);
        self.shared
            .quota_state
            .process_schedules(crate::quota_state::now_epoch_secs(), false)
            .await
            .unwrap();
    }

    async fn finish(&self) {
        assert!(
            self.shared
                .control_plane
                .shutdown(std::time::Duration::from_secs(1))
                .await
        );
    }
}

fn patch(value: serde_json::Value) -> PatchUserRequest {
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn quota_period_api_updates_included_owner_and_preserves_root_bytes() {
    let fixture = Fixture::new();
    let root = "# root remains unchanged\ninclude = \"users.toml\"\n";
    let included = fixture.shared.config_path.with_file_name("users.toml");
    std::fs::write(&included, "[access.users]\nadmin = '00000000000000000000000000000000'\n[access.user_data_quota]\nadmin = 1024\n[access.user_quota_periods]\nadmin = 'daily'\n").unwrap();
    std::fs::write(&fixture.shared.config_path, root).unwrap();
    patch_user(
        "admin",
        patch(serde_json::json!({"quota_period":"monthly"})),
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(&fixture.shared.config_path).unwrap(),
        root
    );
    let cfg = ProxyConfig::load(&fixture.shared.config_path).unwrap();
    assert_eq!(
        cfg.access.user_quota_periods["admin"],
        UserQuotaPeriod::Monthly
    );
    assert!(
        std::fs::read_to_string(included)
            .unwrap()
            .contains("monthly")
    );
    fixture.finish().await;
}

#[tokio::test]
async fn quota_period_prepared_before_recreation_cannot_attach_retired_schedule() {
    let fixture = Fixture::new();
    let create = |period| {
        serde_json::from_value(serde_json::json!({
            "username":"alice", "secret":"0123456789abcdef0123456789abcdef",
            "data_quota_bytes":1024, "quota_period":period
        }))
        .unwrap()
    };
    create_user(create("daily"), None, &fixture.shared)
        .await
        .unwrap();
    fixture.publish().await;
    // Capture a real source before recreation; its asynchronous preparation finishes later.
    let mut stale = ProxyConfig::parse_source(&fixture.shared.config_path).unwrap();
    stale.config.general.ad_tag = Some("11111111111111111111111111111111".into());
    delete_user("alice", None, &fixture.shared).await.unwrap();
    create_user(create("monthly"), None, &fixture.shared)
        .await
        .unwrap();
    let stale = Arc::new(stale.prepare().await.unwrap().config);
    let guard = fixture.shared.quota_state.lock().await;
    fixture.config_tx.send_replace(stale.clone());
    fixture.shared.proxy_shared.apply_user_config_from_source(
        1,
        &stale.access.users,
        &stale.access.user_enabled,
    );
    fixture
        .shared
        .proxy_shared
        .publish_quota_config(1, &stale, true);
    drop(guard);
    fixture
        .shared
        .quota_state
        .process_schedules(crate::quota_state::now_epoch_secs(), false)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .store
            .current_handle("alice")
            .unwrap()
            .schedule_checkpoint()
            .quota_period,
        None
    );
    assert_eq!(
        fixture
            .shared
            .quota_state
            .schedule_status("alice", Some(UserQuotaPeriod::Monthly))
            .quota_schedule_state,
        "pending"
    );
    fixture.publish().await;
    assert_eq!(
        fixture
            .store
            .current_handle("alice")
            .unwrap()
            .schedule_checkpoint()
            .quota_period,
        Some(UserQuotaPeriod::Monthly)
    );
    fixture.finish().await;
}

#[tokio::test]
async fn quota_period_fresh_patch_and_rotation_accept_matching_stale_epoch_candidate() {
    let fixture = Fixture::new();
    create_user(
        serde_json::from_value(serde_json::json!({
            "username":"alice", "data_quota_bytes":1024, "quota_period":"daily"
        }))
        .unwrap(),
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    patch_user(
        "alice",
        patch(serde_json::json!({"quota_period":"monthly"})),
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    rotate_secret(
        "alice",
        RotateSecretRequest {
            secret: Some("11111111111111111111111111111111".into()),
        },
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    let cfg = Arc::new(ProxyConfig::load(&fixture.shared.config_path).unwrap());
    let guard = fixture.shared.quota_state.lock().await;
    fixture
        .shared
        .proxy_shared
        .publish_quota_config(1, &cfg, false);
    drop(guard);
    fixture
        .shared
        .quota_state
        .process_schedules(crate::quota_state::now_epoch_secs(), false)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .store
            .current_handle("alice")
            .unwrap()
            .schedule_checkpoint()
            .quota_period,
        Some(UserQuotaPeriod::Monthly)
    );
    fixture.finish().await;
}

#[tokio::test]
async fn quota_period_api_create_patch_remove_delete_and_effective_status() {
    let fixture = Fixture::new();
    let created = create_user(serde_json::from_value(serde_json::json!({
        "username": "alice", "secret": "0123456789abcdef0123456789abcdef", "data_quota_bytes": 1024, "quota_period": "daily"
    })).unwrap(), None, &fixture.shared).await.unwrap().0;
    assert_eq!(created.user.quota_period, Some(UserQuotaPeriod::Daily));
    assert_eq!(
        fixture
            .shared
            .quota_state
            .schedule_status("alice", Some(UserQuotaPeriod::Daily))
            .quota_schedule_state,
        "pending"
    );
    fixture.store.current_handle("alice").unwrap().charge(300);
    fixture.publish().await;
    assert_eq!(fixture.store.used("alice"), 300);
    let before = fixture
        .store
        .current_handle("alice")
        .unwrap()
        .schedule_checkpoint();
    patch_user(
        "alice",
        patch(serde_json::json!({"quota_period":"monthly"})),
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    let status = fixture
        .shared
        .quota_state
        .schedule_status("alice", Some(UserQuotaPeriod::Monthly));
    assert_eq!(status.active_quota_period, Some(UserQuotaPeriod::Daily));
    assert_eq!(status.quota_schedule_state, "pending");
    fixture.publish().await;
    assert_eq!(fixture.store.used("alice"), 300);
    assert!(
        fixture
            .store
            .current_handle("alice")
            .unwrap()
            .schedule_checkpoint()
            .period_cursor_epoch_secs
            >= before.period_cursor_epoch_secs
    );
    let bytes = std::fs::read(&fixture.shared.config_path).unwrap();
    assert!(
        patch_user(
            "alice",
            patch(serde_json::json!({"data_quota_bytes":null})),
            None,
            &fixture.shared
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), bytes);
    patch_user(
        "alice",
        patch(serde_json::json!({"data_quota_bytes":null,"quota_period":null})),
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    fixture.publish().await;
    assert_eq!(fixture.store.used("alice"), 300);
    assert_eq!(
        fixture
            .shared
            .quota_state
            .schedule_status("alice", None)
            .quota_schedule_state,
        "disabled"
    );
    patch_user(
        "alice",
        patch(serde_json::json!({"data_quota_bytes":1024,"quota_period":"weekly"})),
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    fixture.publish().await;
    delete_user("alice", None, &fixture.shared).await.unwrap();
    let cfg = ProxyConfig::load(&fixture.shared.config_path).unwrap();
    assert!(!cfg.access.users.contains_key("alice"));
    assert!(!cfg.access.user_quota_periods.contains_key("alice"));
    assert!(fixture.store.current_handle("alice").is_none());
    assert!(
        std::fs::read_to_string(&fixture.shared.config_path)
            .unwrap()
            .contains("# preserve this operator comment")
    );
    fixture.finish().await;
}

#[tokio::test]
async fn quota_period_api_early_rotation_and_revision_conflicts_are_safe() {
    let fixture = Fixture::new();
    let (_, old_revision) = create_user(
        serde_json::from_value(serde_json::json!({
            "username":"alice", "data_quota_bytes":1024, "quota_period":"monthly"
        }))
        .unwrap(),
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    fixture.store.current_handle("alice").unwrap().charge(200);
    rotate_secret(
        "alice",
        RotateSecretRequest {
            secret: Some("11111111111111111111111111111111".into()),
        },
        None,
        &fixture.shared,
    )
    .await
    .unwrap();
    fixture.publish().await;
    assert_eq!(fixture.store.used("alice"), 200);
    assert_eq!(
        fixture
            .shared
            .quota_state
            .schedule_status("alice", Some(UserQuotaPeriod::Monthly))
            .quota_schedule_state,
        "active"
    );
    let bytes = std::fs::read(&fixture.shared.config_path).unwrap();
    let error = patch_user(
        "alice",
        patch(serde_json::json!({"quota_period":"daily"})),
        Some(old_revision),
        &fixture.shared,
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.code, "revision_conflict");
    assert_eq!(std::fs::read(&fixture.shared.config_path).unwrap(), bytes);
    fixture.finish().await;
}

#[test]
fn quota_period_patch_preserves_omitted_null_and_set_semantics() {
    assert!(matches!(
        patch(serde_json::json!({})).quota_period,
        Patch::Unchanged
    ));
    assert!(matches!(
        patch(serde_json::json!({"quota_period":null})).quota_period,
        Patch::Remove
    ));
    assert!(matches!(
        patch(serde_json::json!({"quota_period":"weekly"})).quota_period,
        Patch::Set(UserQuotaPeriod::Weekly)
    ));
    assert!(
        serde_json::from_value::<PatchUserRequest>(serde_json::json!({"quota_period":"Weekly"}))
            .is_err()
    );
}
