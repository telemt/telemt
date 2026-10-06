use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{RwLock, Semaphore, watch};

use crate::config::{
    ProxyConfig, ServerConfig, WEB_CARRIER_LEARNING_MIN_ENTRIES, web_debug_fits_limits,
};
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
use crate::network::probe::{decide_network_capabilities, run_probe};
use crate::proxy::direct_buffer_budget::{DirectBufferBudget, run_direct_buffer_budget_controller};
use crate::proxy::pending_handshake::PendingHandshakeLimiter;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::shared_state::ProxySharedState;
use crate::proxy::traffic_limiter::TrafficLimiter;
use crate::proxy::user_admission::UserAdmissionAuthority;
use crate::proxy::user_connection_authority::UserConnectionAuthority;
use crate::startup::StartupTracker;
use crate::stats::beobachten::BeobachtenStore;
use crate::stats::telemetry::TelemetryPolicy;
use crate::stats::{QuotaStore, ReplayChecker, Stats};
use crate::stream::BufferPool;
use crate::tls_front::cache::TlsFullCertBudget;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;

use super::admission;
use super::generation::{RuntimeGeneration, RuntimeTaskScope, RuntimeTaskScopePreparationGuard};
use super::listeners::listener_rebind_supported;
use super::runtime_tasks::RuntimeLogFilter;
use super::{me_startup, runtime_tasks, tls_bootstrap};

/// Fully prepared candidate runtime and its activation-gated config watcher.
pub(crate) struct PreparedRuntime {
    /// Candidate generation ready for publication.
    pub(crate) generation: Arc<RuntimeGeneration>,
    /// Detected public addresses associated with the candidate.
    pub(crate) detected_ips: (Option<IpAddr>, Option<IpAddr>),
    /// Gate opened only after the candidate becomes the active generation.
    pub(crate) config_watcher_activation: watch::Sender<bool>,
    /// User-authority epoch captured before candidate construction.
    pub(crate) user_admission_epoch: u64,
}

pub(crate) async fn prepare_runtime(
    generation_id: u64,
    config: ProxyConfig,
    config_path: &Path,
    quota_store: Arc<QuotaStore>,
    connection_authority: Arc<UserConnectionAuthority>,
    runtime_log_filter: RuntimeLogFilter,
    tls_full_cert_budget: Arc<TlsFullCertBudget>,
    user_admission: Arc<UserAdmissionAuthority>,
    ip_tracker: Arc<UserIpTracker>,
    traffic_limiter: Arc<TrafficLimiter>,
    direct_buffer_budget: Arc<DirectBufferBudget>,
    max_connections: Arc<Semaphore>,
    pending_handshakes: Arc<PendingHandshakeLimiter>,
) -> Result<PreparedRuntime, String> {
    let user_admission_epoch = user_admission.epoch();
    config
        .validate_web_decoy_listener_separation()
        .map_err(|error| error.to_string())?;
    let started_at_epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let startup_tracker = Arc::new(StartupTracker::new(started_at_epoch_secs));
    let task_scope = RuntimeTaskScope::new();
    let task_scope_guard = RuntimeTaskScopePreparationGuard::new(task_scope.clone());
    let stats = Arc::new(Stats::with_process_authorities(
        quota_store,
        connection_authority,
    ));
    stats.apply_telemetry_policy(TelemetryPolicy::from_config(&config.general.telemetry));

    let upstream_manager = Arc::new(
        UpstreamManager::new(
            config.upstreams.clone(),
            config.general.upstream_connect_retry_attempts,
            config.general.upstream_connect_retry_backoff_ms,
            config.general.upstream_connect_budget_ms,
            config.general.tg_connect,
            config.general.upstream_unhealthy_fail_threshold,
            config.general.upstream_connect_failfast_hard_errors,
            stats.clone(),
        )
        .with_dns_overrides(&config.network.dns_overrides)
        .map_err(|error| format!("DNS override preparation failed: {}", error))?,
    );
    let proxy_shared = ProxySharedState::new_with_process_authorities(
        direct_buffer_budget.clone(),
        traffic_limiter,
        user_admission,
        pending_handshakes,
    );

    let probe = run_probe(
        &config.network,
        &config.upstreams,
        config.general.middle_proxy_nat_probe,
        config.general.stun_nat_probe_concurrency,
    )
    .await
    .map_err(|error| format!("network probe failed: {}", error))?;
    let decision =
        decide_network_capabilities(&config.network, &probe, config.general.middle_proxy_nat_ip);
    let prefer_ipv6 = decision.prefer_ipv6();

    let mut tls_domains = Vec::with_capacity(1 + config.censorship.tls_domains.len());
    tls_domains.push(config.censorship.tls_domain.clone());
    for domain in &config.censorship.tls_domains {
        if !tls_domains.contains(domain) {
            tls_domains.push(domain.clone());
        }
    }
    let tls_cache = tls_bootstrap::bootstrap_tls_front(
        &config,
        &tls_domains,
        upstream_manager.clone(),
        &startup_tracker,
        task_scope.clone(),
        tls_full_cert_budget,
        tls_bootstrap::TlsBootstrapPolicy::RequireReady,
    )
    .await
    .map_err(|error| error.to_string())?;

    let beobachten = Arc::new(BeobachtenStore::new());
    let rng = Arc::new(SecureRandom::new());
    let route_mode = if !config.general.use_middle_proxy || config.general.me2dc_fallback {
        RelayRouteMode::Direct
    } else {
        RelayRouteMode::Middle
    };
    let route_runtime = Arc::new(RouteRuntimeController::new(route_mode));
    let me_pool_runtime = Arc::new(RwLock::new(None::<Arc<MePool>>));
    let (me_ready_tx, me_ready_rx) = watch::channel(0_u64);
    let direct_first_startup = config.general.use_middle_proxy && config.general.me2dc_fallback;
    let me_pool = if direct_first_startup {
        None
    } else {
        me_startup::initialize_me_pool(
            config.general.use_middle_proxy,
            &config,
            &decision,
            &probe,
            &startup_tracker,
            upstream_manager.clone(),
            rng.clone(),
            stats.clone(),
            me_pool_runtime.clone(),
            me_ready_tx.clone(),
            task_scope.clone(),
        )
        .await
    };
    if strict_middle_proxy_unavailable(
        config.general.use_middle_proxy,
        direct_first_startup,
        me_pool.is_some(),
    ) {
        task_scope.stop().await;
        return Err(
            "Middle-End pool is required but did not become ready during reload preparation"
                .to_string(),
        );
    }

    let config = Arc::new(config);
    let replay_checker = Arc::new(ReplayChecker::new(
        config.access.replay_check_len,
        Duration::from_secs(config.access.replay_window_secs),
    ));
    let buffer_pool = Arc::new(BufferPool::with_config(64 * 1024, 4096));
    let (config_watcher_activation, config_watcher_activation_rx) = watch::channel(false);
    let watches = runtime_tasks::spawn_runtime_tasks(
        generation_id,
        &config,
        config_path,
        &probe,
        prefer_ipv6,
        decision.ipv4_dc,
        decision.ipv6_dc,
        &startup_tracker,
        stats.clone(),
        upstream_manager.clone(),
        replay_checker.clone(),
        me_pool.clone(),
        rng.clone(),
        ip_tracker.clone(),
        beobachten.clone(),
        me_pool.clone(),
        proxy_shared.clone(),
        me_ready_tx.clone(),
        task_scope.clone(),
        Some(config_watcher_activation_rx),
    )
    .await;
    let config_rx = watches.config_rx;
    runtime_log_filter.spawn_watcher(watches.log_level_rx, task_scope.clone());
    let initial_admission_open = !config.general.use_middle_proxy || me_pool.is_some();
    let (admission_tx, admission_rx) = watch::channel(initial_admission_open);
    admission::configure_admission_gate(
        &config,
        me_pool.clone(),
        me_pool_runtime.clone(),
        route_runtime.clone(),
        &admission_tx,
        config_rx.clone(),
        me_ready_rx,
        task_scope.clone(),
    )
    .await;

    if direct_first_startup {
        let config_bg = config.clone();
        let decision_bg = decision.clone();
        let probe_bg = probe.clone();
        let startup_tracker_bg = startup_tracker.clone();
        let upstream_manager_bg = upstream_manager.clone();
        let rng_bg = rng.clone();
        let stats_bg = stats.clone();
        let me_pool_runtime_bg = me_pool_runtime.clone();
        let me_ready_tx_bg = me_ready_tx.clone();
        let config_rx_bg = config_rx.clone();
        let task_scope_bg = task_scope.clone();
        let retry_limit = config.general.me_init_retry_attempts;
        task_scope.spawn(async move {
            let mut attempt = 0_u32;
            loop {
                attempt = attempt.saturating_add(1);
                let pool = me_startup::initialize_me_pool(
                    true,
                    config_bg.as_ref(),
                    &decision_bg,
                    &probe_bg,
                    &startup_tracker_bg,
                    upstream_manager_bg.clone(),
                    rng_bg.clone(),
                    stats_bg.clone(),
                    me_pool_runtime_bg.clone(),
                    me_ready_tx_bg.clone(),
                    task_scope_bg.clone(),
                )
                .await;
                if let Some(pool) = pool {
                    runtime_tasks::spawn_middle_proxy_runtime_tasks(
                        config_bg.as_ref(),
                        config_rx_bg,
                        pool,
                        rng_bg,
                        me_ready_tx_bg,
                        task_scope_bg,
                    );
                    break;
                }
                if retry_limit > 0 && attempt >= retry_limit {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }

    let conntrack_scope = task_scope.clone();
    task_scope.spawn(crate::conntrack_control::run_conntrack_controller(
        config_rx.clone(),
        stats.clone(),
        proxy_shared.clone(),
        conntrack_scope.cancellation_token(),
    ));
    task_scope.spawn(run_direct_buffer_budget_controller(
        generation_id,
        direct_buffer_budget,
        buffer_pool.clone(),
        stats.clone(),
        proxy_shared.clone(),
        max_connections.clone(),
        config.server.max_connections,
    ));
    let generation = RuntimeGeneration::new(
        generation_id,
        config_rx,
        admission_rx,
        stats,
        upstream_manager,
        replay_checker,
        buffer_pool,
        rng,
        me_pool,
        me_pool_runtime,
        route_runtime,
        tls_cache,
        ip_tracker,
        beobachten,
        proxy_shared,
        max_connections,
        task_scope,
    );
    task_scope_guard.disarm();
    drop(admission_tx);

    Ok(PreparedRuntime {
        generation,
        config_watcher_activation,
        user_admission_epoch,
        detected_ips: (
            probe.detected_ipv4.map(IpAddr::V4),
            probe.detected_ipv6.map(IpAddr::V6),
        ),
    })
}

fn strict_middle_proxy_unavailable(
    use_middle_proxy: bool,
    direct_first_startup: bool,
    pool_available: bool,
) -> bool {
    use_middle_proxy && !direct_first_startup && !pool_available
}

pub(crate) struct ResolvedReloadConfig {
    /// Runtime-safe candidate with process-owned values retained from active state.
    pub(crate) effective: ProxyConfig,
    /// Stable public labels for desired fields deferred until process restart.
    pub(crate) deferred_process_fields: Vec<String>,
    /// Whether activating the effective candidate changes runtime-owned state.
    pub(crate) runtime_changed: bool,
}

/// Resolves desired configuration into effective runtime and deferred process state.
pub(crate) fn resolve_reload_config(
    old: &ProxyConfig,
    desired: &ProxyConfig,
) -> Result<ResolvedReloadConfig, String> {
    let mut effective = desired.clone();
    let mut fields = Vec::new();
    let listener_identity_matches = listeners_have_same_bind_identity(&old.server, &desired.server);
    let global_listener_policy_changed = old.server.port != desired.server.port
        || old.server.listen_addr_ipv4 != desired.server.listen_addr_ipv4
        || old.server.listen_addr_ipv6 != desired.server.listen_addr_ipv6
        || old.server.listen_tcp != desired.server.listen_tcp
        || old.server.client_mss != desired.server.client_mss
        || old.server.client_mss_bulk != desired.server.client_mss_bulk
        || old.server.proxy_protocol != desired.server.proxy_protocol
        || old.server.listen_backlog != desired.server.listen_backlog;
    let listener_policy_changed =
        listener_identity_matches && !listener_process_fields_equal(&old.server, &desired.server);
    let unsupported_identity_change =
        !listener_identity_matches && !listener_rebind_supported(old, desired);
    if global_listener_policy_changed || listener_policy_changed || unsupported_identity_change {
        fields.push("server.listeners".to_string());
        effective.server.port = old.server.port;
        effective.server.listen_addr_ipv4 = old.server.listen_addr_ipv4.clone();
        effective.server.listen_addr_ipv6 = old.server.listen_addr_ipv6.clone();
        effective.server.listen_tcp = old.server.listen_tcp;
        effective.server.client_mss = old.server.client_mss.clone();
        effective.server.client_mss_bulk = old.server.client_mss_bulk.clone();
        effective.server.proxy_protocol = old.server.proxy_protocol;
        effective.server.listen_backlog = old.server.listen_backlog;
        effective.server.listeners = old.server.listeners.clone();
        if listener_identity_matches {
            for (effective_listener, desired_listener) in effective
                .server
                .listeners
                .iter_mut()
                .zip(&desired.server.listeners)
            {
                effective_listener.announce = desired_listener.announce.clone();
                effective_listener.announce_ip = desired_listener.announce_ip;
            }
        }
    }
    if old.server.listen_unix_sock != desired.server.listen_unix_sock
        || old.server.listen_unix_sock_perm != desired.server.listen_unix_sock_perm
    {
        fields.push("server.listen_unix_sock".to_string());
        effective.server.listen_unix_sock = old.server.listen_unix_sock.clone();
        effective.server.listen_unix_sock_perm = old.server.listen_unix_sock_perm.clone();
    }
    if old.server.api.listen != desired.server.api.listen
        || old.server.api.enabled != desired.server.api.enabled
    {
        fields.push("server.api.listen".to_string());
        effective.server.api.listen = old.server.api.listen.clone();
        effective.server.api.enabled = old.server.api.enabled;
    }
    if old.server.api.runtime_edge_events_capacity
        != desired.server.api.runtime_edge_events_capacity
    {
        fields.push("server.api.runtime_edge_events_capacity".to_string());
        effective.server.api.runtime_edge_events_capacity =
            old.server.api.runtime_edge_events_capacity;
    }
    if old.server.metrics_listen != desired.server.metrics_listen
        || old.server.metrics_port != desired.server.metrics_port
    {
        fields.push("server.metrics_listen".to_string());
        effective.server.metrics_listen = old.server.metrics_listen.clone();
        effective.server.metrics_port = old.server.metrics_port;
    }
    if old.server.max_connections != desired.server.max_connections {
        fields.push("server.max_connections".to_string());
        effective.server.max_connections = old.server.max_connections;
    }
    if serde_json::to_value(&old.server.conntrack_control).ok()
        != serde_json::to_value(&desired.server.conntrack_control).ok()
    {
        fields.push("server.conntrack_control".to_string());
        effective.server.conntrack_control = old.server.conntrack_control.clone();
    }
    if old.general.direct_relay_buffer_budget_max_bytes
        != desired.general.direct_relay_buffer_budget_max_bytes
    {
        fields.push("general.direct_relay_buffer_budget_max_bytes".to_string());
        effective.general.direct_relay_buffer_budget_max_bytes =
            old.general.direct_relay_buffer_budget_max_bytes;
    }
    if old.general.quota_state_path != desired.general.quota_state_path {
        fields.push("general.quota_state_path".to_string());
        effective.general.quota_state_path = old.general.quota_state_path.clone();
    }
    if old.general.disable_colors != desired.general.disable_colors {
        fields.push("general.disable_colors".to_string());
        effective.general.disable_colors = old.general.disable_colors;
    }
    if old.general.data_path != desired.general.data_path {
        fields.push("general.data_path".to_string());
        effective.general.data_path = old.general.data_path.clone();
    }
    if serde_json::to_value(&old.logging).ok() != serde_json::to_value(&desired.logging).ok() {
        fields.push("logging".to_string());
        effective.logging = old.logging.clone();
    }
    if serde_json::to_value(&old.web.limits).ok() != serde_json::to_value(&desired.web.limits).ok()
    {
        fields.push("web.limits".to_string());
        effective.web.limits = old.web.limits.clone();
    }
    if old.web.decoy_fasttrack_mode != desired.web.decoy_fasttrack_mode {
        fields.push("web.decoy_fasttrack_mode".to_string());
        effective.web.decoy_fasttrack_mode = old.web.decoy_fasttrack_mode;
    }
    if effective.web.carrier_negotiation_enabled()
        && effective.web.carrier_learning
        && effective.web.limits.max_carrier_learning_entries < WEB_CARRIER_LEARNING_MIN_ENTRIES
    {
        if old.web.carrier_learning != desired.web.carrier_learning {
            fields.push("web.carrier_learning".to_string());
            effective.web.carrier_learning = old.web.carrier_learning;
        } else {
            fields.push("web.carriers".to_string());
            effective.web.carriers = old.web.carriers.clone();
        }
    }
    if !web_debug_fits_limits(&effective.web.debug, &effective.web.limits) {
        fields.push("web.debug".to_string());
        effective.web.debug = old.web.debug.clone();
    }
    effective
        .validate_effective_web()
        .map_err(|error| format!("effective WEB configuration is invalid: {error}"))?;
    effective
        .rebuild_runtime_user_auth()
        .map_err(|error| format!("effective user runtime preparation failed: {error}"))?;
    effective
        .rebuild_runtime_web()
        .map_err(|error| format!("effective WEB runtime preparation failed: {error}"))?;
    let runtime_changed = !configs_equal(old, &effective);
    Ok(ResolvedReloadConfig {
        effective,
        deferred_process_fields: fields,
        runtime_changed,
    })
}

fn listeners_have_same_bind_identity(old: &ServerConfig, desired: &ServerConfig) -> bool {
    old.listeners.len() == desired.listeners.len()
        && old
            .listeners
            .iter()
            .zip(&desired.listeners)
            .all(|(old_listener, desired_listener)| {
                old_listener.ip == desired_listener.ip
                    && old_listener.port.unwrap_or(old.port)
                        == desired_listener.port.unwrap_or(desired.port)
            })
}

fn listener_process_fields_equal(old: &ServerConfig, desired: &ServerConfig) -> bool {
    let mut old_listeners = old.listeners.clone();
    let mut desired_listeners = desired.listeners.clone();
    for listener in &mut old_listeners {
        listener.announce = None;
        listener.announce_ip = None;
    }
    for listener in &mut desired_listeners {
        listener.announce = None;
        listener.announce_ip = None;
    }
    serde_json::to_value(old_listeners).ok() == serde_json::to_value(desired_listeners).ok()
}

/// Returns process-owned fields that cannot change in the current generation.
pub(crate) fn deferred_process_fields(
    old: &ProxyConfig,
    new: &ProxyConfig,
) -> Result<Vec<String>, String> {
    resolve_reload_config(old, new).map(|resolved| resolved.deferred_process_fields)
}

fn configs_equal(old: &ProxyConfig, new: &ProxyConfig) -> bool {
    serde_json::to_value(old).ok() == serde_json::to_value(new).ok()
        && old.web_decoy_endpoints_equal(new)
}

#[cfg(test)]
#[path = "runtime_build_tests.rs"]
mod tests;
