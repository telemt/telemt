use super::*;
use crate::config::UserQuotaPeriod;
use crate::proxy::shared_state::ProxySharedState;
use crate::proxy::user_admission::{
    UserAdmissionAuthority, UserSessionRegistration, credential_id_from_hex,
};
use crate::quota_state::QuotaStateOwner;
use crate::stats::Stats;

// Quota policy freshness is independent of admission epoch changes.
#[path = "reload_supervisor_quota_freshness_tests.rs"]
mod freshness;

const OLD_SECRET: &str = "00112233445566778899aabbccddeeff";
const NEW_SECRET: &str = "ffeeddccbbaa99887766554433221100";

fn user_config() -> ProxyConfig {
    let mut config = ProxyConfig::default();
    config.access.users.clear();
    config
        .access
        .users
        .insert("alice".into(), OLD_SECRET.into());
    config.access.user_data_quota.insert("alice".into(), 1024);
    config
}

fn shared_generation(
    id: u64,
    config: ProxyConfig,
    store: &Arc<QuotaStore>,
    authority: &Arc<UserAdmissionAuthority>,
) -> Arc<RuntimeGeneration> {
    let mut generation = test_runtime_generation(id, config);
    let state = Arc::get_mut(&mut generation).unwrap();
    state.stats = Arc::new(Stats::with_quota_store(store.clone()));
    state.proxy_shared = ProxySharedState::new_with_direct_buffer_budget_and_user_admission(
        state.proxy_shared.direct_buffer_budget.clone(),
        authority.clone(),
    );
    generation
}

async fn shared_fixture(
    initial: ProxyConfig,
    candidate: ProxyConfig,
    mode: ReloadMode,
) -> (ReloadFixture, Arc<UserAdmissionAuthority>, Arc<QuotaStore>) {
    let store = Arc::new(QuotaStore::default());
    let authority = UserAdmissionAuthority::new_with_quota_store(store.clone());
    authority
        .activate_config_source(1, None, &initial.access.users, &initial.access.user_enabled)
        .unwrap();
    let old_runtime = shared_generation(1, initial, &store, &authority);
    let new_runtime = shared_generation(2, candidate, &store, &authority);
    let active_runtime = Arc::new(ArcSwap::from(old_runtime.clone()));
    let (control, commands) = ReloadControl::channel(1);
    let request = ReloadRequest {
        mode,
        timeout_secs: (mode == ReloadMode::Drain).then_some(1),
        ..ReloadRequest::default()
    };
    assert_eq!(request.failure_policy, ReloadFailurePolicy::KeepNew);
    let accepted = control
        .submit(
            new_runtime.config(),
            "before-mutation".into(),
            request.clone(),
        )
        .await
        .unwrap();
    let (detected_ips_tx, _) = watch::channel((None, None));
    let (runtime_watch_tx, runtime_watch_rx) = watch::channel(Some(old_runtime.watch_state()));
    let supervisor = Arc::new(ReloadSupervisor {
        active_runtime: active_runtime.clone(),
        control: control.clone(),
        commands,
        config_path: PathBuf::new(),
        quota_store: store.clone(),
        tls_full_cert_budget: Arc::new(crate::tls_front::cache::TlsFullCertBudget::new()),
        detected_ips_tx,
        runtime_log_filter: runtime_log_filter(),
        runtime_watch_tx,
        listener_manager: Arc::new(Mutex::new(ListenerManager::empty(active_runtime))),
        web_trace: crate::web::trace::WebTraceStore::new(
            old_runtime.config().web.debug.clone(),
            &old_runtime.config().web.limits,
        ),
        conntrack_firewall: None,
    });
    let command = ReloadCommand {
        reload_id: accepted.reload_id,
        target_generation: accepted.target_generation,
        config: new_runtime.config(),
        config_revision: accepted.config_revision,
        request,
    };
    (
        ReloadFixture {
            supervisor,
            control,
            command,
            old_runtime,
            new_runtime,
            runtime_watch_rx,
        },
        authority,
        store,
    )
}

fn register_owner(
    authority: &Arc<UserAdmissionAuthority>,
    secret: &str,
) -> UserSessionRegistration {
    let mut publication = authority
        .claim_authenticated("alice", credential_id_from_hex(secret).unwrap())
        .unwrap();
    let owner = publication.take_registration().unwrap();
    publication.commit();
    owner
}

#[derive(Clone, Copy, Debug)]
enum Mutation {
    Disable,
    Rotate,
    Delete,
}

async fn check_stale_activation(mutation: Mutation) {
    for acknowledged in [false, true] {
        for mode in [ReloadMode::Instant, ReloadMode::Drain] {
            let initial = user_config();
            assert!(initial.access.user_quota_periods.is_empty());
            let (fixture, authority, store) =
                shared_fixture(initial.clone(), initial.clone(), mode).await;
            let prepared = prepared_runtime(fixture.new_runtime.clone());
            let old_owner = register_owner(&authority, OLD_SECRET);
            store.current_handle("alice").unwrap().charge(700);
            let mut current = initial.clone();
            let gate = authority.quota_mutation_gate().lock_owned().await;
            match mutation {
                Mutation::Disable => {
                    current.access.user_enabled.insert("alice".into(), false);
                    fixture
                        .old_runtime
                        .proxy_shared
                        .stage_user("alice", OLD_SECRET, false)
                        .unwrap();
                }
                Mutation::Rotate => {
                    current
                        .access
                        .users
                        .insert("alice".into(), NEW_SECRET.into());
                    fixture
                        .old_runtime
                        .proxy_shared
                        .stage_user("alice", NEW_SECRET, true)
                        .unwrap();
                }
                Mutation::Delete => {
                    current.access.users.remove("alice");
                    current.access.user_data_quota.remove("alice");
                    fixture.old_runtime.proxy_shared.delete_user("alice");
                }
            }
            assert!(old_owner.is_cancelled());
            if acknowledged {
                // The matching old-generation watcher consumes the API override.
                authority
                    .apply_config_from_source(
                        1,
                        &current.access.users,
                        &current.access.user_enabled,
                    )
                    .unwrap();
            }
            let incarnation = store
                .current_handle("alice")
                .map(|handle| handle.incarnation());
            let current_owner = matches!(mutation, Mutation::Rotate)
                .then(|| register_owner(&authority, NEW_SECRET));
            let mutation_epoch = authority.epoch();
            assert_ne!(mutation_epoch, prepared.user_admission_epoch);
            drop(gate);

            fixture
                .supervisor
                .activate_prepared(
                    fixture.command,
                    fixture.old_runtime.clone(),
                    prepared,
                    RevisionGateAction::Warn("config revision changed during preparation".into()),
                )
                .await;

            assert_eq!(fixture.supervisor.active_runtime.load().id, 2);
            assert_eq!(
                fixture.control.status(1).await.unwrap().state,
                ReloadPhase::Succeeded
            );
            assert!(
                authority
                    .authenticated_incarnation("alice", credential_id_from_hex(OLD_SECRET).unwrap())
                    .is_none(),
                "{mutation:?}, acknowledged={acknowledged}, mode={mode:?}: stale activation restored revoked access"
            );
            assert_eq!(authority.epoch(), mutation_epoch);
            assert_eq!(
                store
                    .current_handle("alice")
                    .map(|handle| handle.incarnation()),
                incarnation
            );
            if let Some(owner) = &current_owner {
                assert!(!owner.is_cancelled());
                assert_eq!(
                    authority.authenticated_incarnation(
                        "alice",
                        credential_id_from_hex(NEW_SECRET).unwrap()
                    ),
                    incarnation
                );
            } else {
                assert!(!authority.is_user_enabled("alice"));
            }
            if matches!(mutation, Mutation::Delete) {
                assert!(store.current_handle("alice").is_none());
            } else {
                assert_eq!(store.used("alice"), 700);
            }

            let gate = authority.quota_mutation_gate().lock_owned().await;
            assert!(
                authority
                    .apply_config_from_source(
                        1,
                        &initial.access.users,
                        &initial.access.user_enabled
                    )
                    .is_none()
            );
            assert!(
                authority
                    .apply_config_from_source(
                        2,
                        &current.access.users,
                        &current.access.user_enabled
                    )
                    .is_some()
            );
            assert!(
                authority
                    .authenticated_incarnation("alice", credential_id_from_hex(OLD_SECRET).unwrap())
                    .is_none()
            );
            // A fresh owner publication can intentionally enable or recreate the account.
            current
                .access
                .users
                .insert("alice".into(), NEW_SECRET.into());
            current.access.user_enabled.remove("alice");
            authority
                .apply_config_from_source(2, &current.access.users, &current.access.user_enabled)
                .unwrap();
            assert!(
                authority
                    .authenticated_incarnation("alice", credential_id_from_hex(NEW_SECRET).unwrap())
                    .is_some()
            );
            drop(gate);
            fixture.new_runtime.stop_sessions().await;
            fixture.new_runtime.stop_background_tasks().await;
        }
    }
}

#[tokio::test]
async fn stale_reload_preserves_disabled_user() {
    check_stale_activation(Mutation::Disable).await;
}

#[tokio::test]
async fn stale_reload_preserves_rotated_secret() {
    check_stale_activation(Mutation::Rotate).await;
}

#[tokio::test]
async fn stale_reload_preserves_deleted_user() {
    check_stale_activation(Mutation::Delete).await;
}

#[tokio::test]
async fn current_reload_applies_admission_and_quota_policy_once() {
    let mut initial = user_config();
    initial
        .access
        .user_quota_periods
        .insert("alice".into(), UserQuotaPeriod::Daily);
    let mut candidate = initial.clone();
    candidate
        .access
        .users
        .insert("alice".into(), NEW_SECRET.into());
    candidate
        .access
        .user_quota_periods
        .insert("alice".into(), UserQuotaPeriod::Monthly);
    let (fixture, authority, store) = shared_fixture(initial, candidate, ReloadMode::Instant).await;
    let dir = tempfile::tempdir().unwrap();
    let quota = QuotaStateOwner::new(dir.path().join("quota.json"), store.clone());
    let gate = quota.lock().await;
    authority.publish_quota_config(1, &fixture.old_runtime.config(), true);
    drop(gate);
    quota
        .process_schedules(crate::quota_state::now_epoch_secs(), false)
        .await
        .unwrap();
    store.current_handle("alice").unwrap().charge(700);
    let old_owner = register_owner(&authority, OLD_SECRET);
    let prepared = prepared_runtime(fixture.new_runtime.clone());
    let epoch = prepared.user_admission_epoch;
    fixture
        .supervisor
        .activate_prepared(
            fixture.command,
            fixture.old_runtime.clone(),
            prepared,
            RevisionGateAction::Proceed,
        )
        .await;
    assert_eq!(authority.epoch(), epoch + 1);
    assert!(old_owner.is_cancelled());
    assert!(
        authority
            .authenticated_incarnation("alice", credential_id_from_hex(OLD_SECRET).unwrap())
            .is_none()
    );
    assert!(
        authority
            .authenticated_incarnation("alice", credential_id_from_hex(NEW_SECRET).unwrap())
            .is_some()
    );
    quota
        .process_schedules(crate::quota_state::now_epoch_secs(), false)
        .await
        .unwrap();
    assert_eq!(store.used("alice"), 700);
    assert_eq!(
        quota
            .schedule_status("alice", Some(UserQuotaPeriod::Monthly))
            .active_quota_period,
        Some(UserQuotaPeriod::Monthly)
    );
    assert_eq!(
        fixture.control.status(1).await.unwrap().state,
        ReloadPhase::Succeeded
    );
    fixture.new_runtime.stop_sessions().await;
    fixture.new_runtime.stop_background_tasks().await;
}
