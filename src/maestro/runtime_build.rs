use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{RwLock, Semaphore, watch};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
use crate::network::probe::{decide_network_capabilities, run_probe};
use crate::proxy::direct_buffer_budget::{
    DirectBufferBudget, resolve_direct_buffer_hard_limit, run_direct_buffer_budget_controller,
};
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::shared_state::ProxySharedState;
use crate::startup::StartupTracker;
use crate::stats::beobachten::BeobachtenStore;
use crate::stats::telemetry::TelemetryPolicy;
use crate::stats::{QuotaStore, ReplayChecker, Stats};
use crate::stream::BufferPool;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;

use super::admission;
use super::generation::{RuntimeGeneration, RuntimeTaskScope};
use super::runtime_tasks::RuntimeLogFilter;
use super::{me_startup, runtime_tasks, tls_bootstrap};

pub(crate) struct PreparedRuntime {
    pub(crate) generation: Arc<RuntimeGeneration>,
    pub(crate) detected_ips: (Option<IpAddr>, Option<IpAddr>),
}

pub(crate) async fn prepare_runtime(
    generation_id: u64,
    mut config: ProxyConfig,
    config_path: &Path,
    quota_store: Arc<QuotaStore>,
    runtime_log_filter: RuntimeLogFilter,
) -> Result<PreparedRuntime, String> {
    let started_at_epoch_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let startup_tracker = Arc::new(StartupTracker::new(started_at_epoch_secs));
    let task_scope = RuntimeTaskScope::new();
    let stats = Arc::new(Stats::with_quota_store(quota_store));
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
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker
        .load_limits(
            config.access.user_max_unique_ips_global_each,
            &config.access.user_max_unique_ips,
        )
        .await;
    ip_tracker
        .set_limit_policy(
            config.access.user_max_unique_ips_mode,
            config.access.user_max_unique_ips_window_secs,
        )
        .await;

    let hard_limit =
        resolve_direct_buffer_hard_limit(config.general.direct_relay_buffer_budget_max_bytes).await;
    let direct_buffer_budget = DirectBufferBudget::new(hard_limit);
    let proxy_shared =
        ProxySharedState::new_with_direct_buffer_budget(direct_buffer_budget.clone());
    proxy_shared.apply_user_enabled_config(&config.access.user_enabled);
    proxy_shared.traffic_limiter.apply_policy(
        config.access.user_rate_limits.clone(),
        config.access.cidr_rate_limits.clone(),
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
    )
    .await;

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
        )
        .await
    };
    if config.general.use_middle_proxy && me_pool.is_none() && !direct_first_startup {
        config.general.use_middle_proxy = false;
    }

    let config = Arc::new(config);
    let replay_checker = Arc::new(ReplayChecker::new(
        config.access.replay_check_len,
        Duration::from_secs(config.access.replay_window_secs),
    ));
    let buffer_pool = Arc::new(BufferPool::with_config(64 * 1024, 4096));
    let max_connections_limit = if config.server.max_connections == 0 {
        Semaphore::MAX_PERMITS
    } else {
        config.server.max_connections as usize
    };
    let max_connections = Arc::new(Semaphore::new(max_connections_limit));
    let (api_config_tx, _) = watch::channel(config.clone());
    let watches = runtime_tasks::spawn_runtime_tasks(
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
        api_config_tx,
        me_pool.clone(),
        proxy_shared.clone(),
        me_ready_tx.clone(),
        task_scope.clone(),
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
        direct_buffer_budget,
        buffer_pool.clone(),
        stats.clone(),
        proxy_shared.clone(),
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
    drop(admission_tx);

    Ok(PreparedRuntime {
        generation,
        detected_ips: (
            probe.detected_ipv4.map(IpAddr::V4),
            probe.detected_ipv6.map(IpAddr::V6),
        ),
    })
}

pub(crate) fn deferred_process_fields(old: &ProxyConfig, new: &ProxyConfig) -> Vec<String> {
    let mut fields = Vec::new();
    if old.server.port != new.server.port
        || old.server.proxy_protocol != new.server.proxy_protocol
        || old.server.listen_backlog != new.server.listen_backlog
        || serde_json::to_value(&old.server.listeners).ok()
            != serde_json::to_value(&new.server.listeners).ok()
    {
        fields.push("server.listeners".to_string());
    }
    if old.server.listen_unix_sock != new.server.listen_unix_sock
        || old.server.listen_unix_sock_perm != new.server.listen_unix_sock_perm
    {
        fields.push("server.listen_unix_sock".to_string());
    }
    if old.server.api.listen != new.server.api.listen
        || old.server.api.enabled != new.server.api.enabled
    {
        fields.push("server.api.listen".to_string());
    }
    if old.server.metrics_listen != new.server.metrics_listen
        || old.server.metrics_port != new.server.metrics_port
    {
        fields.push("server.metrics_listen".to_string());
    }
    if old.general.quota_state_path != new.general.quota_state_path {
        fields.push("general.quota_state_path".to_string());
    }
    if old.general.disable_colors != new.general.disable_colors {
        fields.push("general.disable_colors".to_string());
    }
    if old.general.data_path != new.general.data_path {
        fields.push("general.data_path".to_string());
    }
    if serde_json::to_value(&old.logging).ok() != serde_json::to_value(&new.logging).ok() {
        fields.push("logging".to_string());
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_socket_and_logging_changes_are_deferred() {
        let old = ProxyConfig::default();
        let mut new = old.clone();
        new.server.listen_backlog = new.server.listen_backlog.saturating_add(1);
        new.general.disable_colors = !new.general.disable_colors;

        let fields = deferred_process_fields(&old, &new);
        assert!(fields.contains(&"server.listeners".to_string()));
        assert!(fields.contains(&"general.disable_colors".to_string()));
    }

    #[test]
    fn runtime_only_change_does_not_require_process_rebind() {
        let old = ProxyConfig::default();
        let mut new = old.clone();
        new.censorship.tls_domain = "reload.example".to_string();
        assert!(deferred_process_fields(&old, &new).is_empty());
    }
}
