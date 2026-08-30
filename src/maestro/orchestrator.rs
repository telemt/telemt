use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::{RwLock, watch};
use tracing::{error, info};

use crate::api;
use crate::ip_tracker::UserIpTracker;
use crate::network::probe::{decide_network_capabilities, log_probe_result, run_probe};
use crate::proxy::direct_buffer_budget::{DirectBufferBudget, resolve_direct_buffer_hard_limit};
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::shared_state::ProxySharedState;
use crate::startup::{COMPONENT_API_BOOTSTRAP, COMPONENT_NETWORK_PROBE};
use crate::stats::telemetry::TelemetryPolicy;
use crate::stats::{QuotaStore, Stats};
use crate::synlimit_control;
use crate::tls_front::cache::TlsFullCertBudget;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;
use crate::web::control::WebRuntimeControl;
use crate::web::trace::WebTraceStore;

use super::{
    bootstrap, control_plane, generation, listeners, reload, reload_supervisor, runtime_startup,
    runtime_tasks, shutdown, tls_bootstrap,
};

// Shared maestro startup and main loop. `drop_after_bind` runs on Unix after listeners are bound
// and privileged firewall setup completes; it is a no-op on other platforms.
pub(super) async fn run_telemt_core(
    privilege_drop_requested: bool,
    drop_after_bind: impl FnOnce(),
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let bootstrap::BootstrapState {
        process_started_at,
        process_started_at_epoch_secs,
        startup_tracker,
        config,
        config_path,
        has_rust_log,
        effective_log_level,
        runtime_log_filter,
        logging_guard: _logging_guard,
    } = bootstrap::bootstrap(privilege_drop_requested).await?;

    let quota_store = Arc::new(QuotaStore::default());
    let stats = Arc::new(Stats::with_quota_store(quota_store.clone()));
    let tls_full_cert_budget = Arc::new(TlsFullCertBudget::new());
    let process_control_plane = control_plane::ProcessControlPlane::new();
    let runtime_task_scope = generation::RuntimeTaskScope::new();
    stats.apply_telemetry_policy(TelemetryPolicy::from_config(&config.general.telemetry));
    let quota_state_path = config.general.quota_state_path.clone();
    let quota_state =
        crate::quota_state::QuotaStateOwner::new(quota_state_path, quota_store.clone());
    let configured_quota_users = config.access.users.keys().cloned().collect::<BTreeSet<_>>();
    quota_state.load(&configured_quota_users).await;

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
        .with_dns_overrides(&config.network.dns_overrides)?,
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
    if config.access.user_max_unique_ips_global_each > 0
        || !config.access.user_max_unique_ips.is_empty()
    {
        info!(
            global_each_limit = config.access.user_max_unique_ips_global_each,
            explicit_user_limits = config.access.user_max_unique_ips.len(),
            "User unique IP limits configured"
        );
    }
    if !config.network.dns_overrides.is_empty() {
        info!(
            "Runtime DNS overrides configured: {} entries",
            config.network.dns_overrides.len()
        );
    }
    let direct_buffer_hard_limit =
        resolve_direct_buffer_hard_limit(config.general.direct_relay_buffer_budget_max_bytes).await;
    let direct_buffer_budget = DirectBufferBudget::new(direct_buffer_hard_limit);
    info!(
        hard_limit_bytes = direct_buffer_hard_limit,
        configured_override_bytes = config.general.direct_relay_buffer_budget_max_bytes,
        "Direct relay buffer budget initialized"
    );
    let shared_state =
        ProxySharedState::new_with_direct_buffer_budget(direct_buffer_budget.clone());
    shared_state.apply_user_enabled_config(&config.access.user_enabled);
    shared_state.traffic_limiter.apply_policy(
        config.access.user_rate_limits.clone(),
        config.access.cidr_rate_limits.clone(),
    );
    let web_trace = WebTraceStore::new(config.web.debug.clone(), &config.web.limits);
    let web_runtime_control = WebRuntimeControl::new();

    let (detected_ips_tx, detected_ips_rx) = watch::channel((None::<IpAddr>, None::<IpAddr>));
    let initial_direct_first = config.general.use_middle_proxy && config.general.me2dc_fallback;
    let initial_admission_open = !config.general.use_middle_proxy || initial_direct_first;
    let (admission_tx, admission_rx) = watch::channel(initial_admission_open);
    let (reload_control, reload_commands) = reload::ReloadControl::channel(1);
    let (active_runtime_tx, active_runtime_rx) =
        watch::channel(None::<Arc<ArcSwap<generation::RuntimeGeneration>>>);
    let (runtime_watch_tx, runtime_watch_rx) =
        watch::channel(None::<generation::RuntimeWatchState>);
    let initial_route_mode = if !config.general.use_middle_proxy || initial_direct_first {
        RelayRouteMode::Direct
    } else {
        RelayRouteMode::Middle
    };
    let route_runtime = Arc::new(RouteRuntimeController::new(initial_route_mode));
    let api_me_pool = Arc::new(RwLock::new(None::<Arc<MePool>>));
    startup_tracker
        .start_component(
            COMPONENT_API_BOOTSTRAP,
            Some("spawn API listener task".to_string()),
        )
        .await;

    if config.server.api.enabled {
        let listen = match config.server.api.listen.parse::<SocketAddr>() {
            Ok(listen) => listen,
            Err(error) => {
                let message = format!(
                    "invalid server.api.listen \"{}\": {}",
                    config.server.api.listen, error
                );
                startup_tracker
                    .fail_component(COMPONENT_API_BOOTSTRAP, Some(message.clone()))
                    .await;
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, message).into());
            }
        };
        if listen.port() != 0 {
            let api_listener = match tokio::net::TcpListener::bind(listen).await {
                Ok(listener) => listener,
                Err(error) => {
                    startup_tracker
                        .fail_component(
                            COMPONENT_API_BOOTSTRAP,
                            Some(format!("API listener bind failed on {listen}: {error}")),
                        )
                        .await;
                    return Err(error.into());
                }
            };
            let stats_api = stats.clone();
            let ip_tracker_api = ip_tracker.clone();
            let me_pool_api = api_me_pool.clone();
            let upstream_manager_api = upstream_manager.clone();
            let route_runtime_api = route_runtime.clone();
            let proxy_shared_api = shared_state.clone();
            let config_path_api = config_path.clone();
            let quota_state_api = quota_state.clone();
            let startup_tracker_api = startup_tracker.clone();
            let detected_ips_rx_api = detected_ips_rx.clone();
            let reload_control_api = reload_control.clone();
            let active_runtime_rx_api = active_runtime_rx.clone();
            let runtime_watch_rx_api = runtime_watch_rx.clone();
            let web_trace_api = web_trace.clone();
            let web_runtime_rx_api = web_runtime_control.subscribe();
            let api_control_plane = process_control_plane.clone();
            let api_task_control_plane = process_control_plane.clone();
            let api_task = async move {
                api::serve(
                    api_listener,
                    stats_api,
                    ip_tracker_api,
                    me_pool_api,
                    route_runtime_api,
                    proxy_shared_api,
                    upstream_manager_api,
                    config_path_api,
                    quota_state_api,
                    detected_ips_rx_api,
                    process_started_at_epoch_secs,
                    startup_tracker_api,
                    reload_control_api,
                    active_runtime_rx_api,
                    runtime_watch_rx_api,
                    web_trace_api,
                    web_runtime_rx_api,
                    api_task_control_plane,
                )
                .await;
            };
            if api_control_plane.spawn(api_task).is_err() {
                let message = "process control-plane task admission closed during API startup";
                startup_tracker
                    .fail_component(COMPONENT_API_BOOTSTRAP, Some(message.to_string()))
                    .await;
                return Err(std::io::Error::other(message).into());
            }
            startup_tracker
                .complete_component(
                    COMPONENT_API_BOOTSTRAP,
                    Some(format!("API listener bound and supervised on {}", listen)),
                )
                .await;
        } else {
            startup_tracker
                .skip_component(
                    COMPONENT_API_BOOTSTRAP,
                    Some("server.api.listen has zero port".to_string()),
                )
                .await;
        }
    } else {
        startup_tracker
            .skip_component(
                COMPONENT_API_BOOTSTRAP,
                Some("server.api.enabled is false".to_string()),
            )
            .await;
    }

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
        runtime_task_scope.clone(),
        tls_full_cert_budget.clone(),
        tls_bootstrap::TlsBootstrapPolicy::BestEffort,
    )
    .await?;

    startup_tracker
        .start_component(
            COMPONENT_NETWORK_PROBE,
            Some("probe network capabilities".to_string()),
        )
        .await;
    let probe = run_probe(
        &config.network,
        &config.upstreams,
        config.general.middle_proxy_nat_probe,
        config.general.stun_nat_probe_concurrency,
    )
    .await?;
    detected_ips_tx.send_replace((
        probe.detected_ipv4.map(IpAddr::V4),
        probe.detected_ipv6.map(IpAddr::V6),
    ));
    let decision =
        decide_network_capabilities(&config.network, &probe, config.general.middle_proxy_nat_ip);
    log_probe_result(&probe, &decision);
    startup_tracker
        .complete_component(
            COMPONENT_NETWORK_PROBE,
            Some("network capabilities determined".to_string()),
        )
        .await;

    let runtime = runtime_startup::prepare_runtime(
        config,
        &config_path,
        &probe,
        &decision,
        process_started_at,
        &startup_tracker,
        stats.clone(),
        upstream_manager.clone(),
        ip_tracker.clone(),
        shared_state.clone(),
        direct_buffer_budget,
        route_runtime.clone(),
        api_me_pool.clone(),
        runtime_task_scope.clone(),
        admission_tx,
        &runtime_log_filter,
        has_rust_log,
        &effective_log_level,
    )
    .await;
    let _admission_tx_hold = runtime.admission_tx;

    let runtime_generation = generation::RuntimeGeneration::new(
        1,
        runtime.config_rx.clone(),
        admission_rx,
        stats.clone(),
        upstream_manager.clone(),
        runtime.replay_checker,
        runtime.buffer_pool,
        runtime.rng,
        runtime.me_pool,
        api_me_pool,
        route_runtime,
        tls_cache,
        ip_tracker,
        runtime.beobachten,
        shared_state,
        runtime.max_connections,
        runtime_task_scope,
    );
    let active_runtime = Arc::new(ArcSwap::from(runtime_generation));
    let bound = listeners::bind_listeners(
        &runtime.config,
        runtime.detected_ip_v4,
        runtime.detected_ip_v6,
        &startup_tracker,
    )
    .await?;
    if bound.is_empty() {
        error!("No listeners. Exiting.");
        std::process::exit(1);
    }

    synlimit_control::reconcile_synlimit_rules(&runtime.config)
        .await
        .map_err(std::io::Error::other)?;

    drop_after_bind();

    runtime_tasks::spawn_metrics_if_configured(
        &runtime.config,
        &startup_tracker,
        active_runtime.clone(),
        web_runtime_control.subscribe(),
        tls_full_cert_budget.clone(),
        process_control_plane.clone(),
    )
    .await?;

    runtime_watch_tx.send_replace(Some(active_runtime.load_full().watch_state()));
    active_runtime_tx.send_replace(Some(active_runtime.clone()));
    runtime_tasks::mark_runtime_ready(&startup_tracker).await;

    let listener_manager = listeners::ListenerManager::start(
        bound,
        active_runtime.clone(),
        web_trace.clone(),
        web_runtime_control,
    );
    let reload_supervisor = reload_supervisor::ReloadSupervisor::spawn(
        active_runtime.clone(),
        reload_control,
        reload_commands,
        config_path,
        quota_store,
        tls_full_cert_budget,
        detected_ips_tx,
        runtime_log_filter,
        runtime_watch_tx,
        listener_manager,
        web_trace,
    );

    shutdown::spawn_signal_handlers(
        active_runtime.clone(),
        process_started_at,
        process_control_plane.clone(),
    );
    shutdown::wait_for_shutdown(
        process_started_at,
        active_runtime,
        quota_state,
        reload_supervisor,
        process_control_plane,
    )
    .await;

    Ok(())
}
