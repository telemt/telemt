use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{RwLock, Semaphore, watch};
use tracing::{info, warn};

use crate::config::{LogLevel, ProxyConfig};
use crate::conntrack_control;
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
use crate::network::probe::{NetworkDecision, NetworkProbe};
use crate::proxy::direct_buffer_budget::{DirectBufferBudget, run_direct_buffer_budget_controller};
use crate::proxy::route_mode::RouteRuntimeController;
use crate::proxy::shared_state::ProxySharedState;
use crate::startup::{
    COMPONENT_DC_CONNECTIVITY_PING, COMPONENT_ME_CONNECTIVITY_PING, COMPONENT_ME_POOL_CONSTRUCT,
    COMPONENT_ME_POOL_INIT_STAGE1, COMPONENT_ME_PROXY_CONFIG_V4, COMPONENT_ME_PROXY_CONFIG_V6,
    COMPONENT_ME_SECRET_FETCH, StartupMeStatus, StartupTracker,
};
use crate::stats::beobachten::BeobachtenStore;
use crate::stats::{ReplayChecker, Stats};
use crate::stream::BufferPool;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;

use super::admission;
use super::generation::RuntimeTaskScope;
use super::{connectivity, me_startup, runtime_tasks};

pub(super) struct RuntimeStartupState {
    pub(super) config: Arc<ProxyConfig>,
    pub(super) beobachten: Arc<BeobachtenStore>,
    pub(super) rng: Arc<SecureRandom>,
    pub(super) max_connections: Arc<Semaphore>,
    pub(super) me_pool: Option<Arc<MePool>>,
    pub(super) replay_checker: Arc<ReplayChecker>,
    pub(super) buffer_pool: Arc<BufferPool>,
    pub(super) config_rx: watch::Receiver<Arc<ProxyConfig>>,
    pub(super) detected_ip_v4: Option<IpAddr>,
    pub(super) detected_ip_v6: Option<IpAddr>,
    pub(super) admission_tx: watch::Sender<bool>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn prepare_runtime(
    mut config: ProxyConfig,
    config_path: &Path,
    probe: &NetworkProbe,
    decision: &NetworkDecision,
    process_started_at: Instant,
    startup_tracker: &Arc<StartupTracker>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    ip_tracker: Arc<UserIpTracker>,
    shared_state: Arc<ProxySharedState>,
    direct_buffer_budget: Arc<DirectBufferBudget>,
    max_connections: Arc<Semaphore>,
    route_runtime: Arc<RouteRuntimeController>,
    api_me_pool: Arc<RwLock<Option<Arc<MePool>>>>,
    runtime_task_scope: RuntimeTaskScope,
    admission_tx: watch::Sender<bool>,
    runtime_log_filter: &runtime_tasks::RuntimeLogFilter,
    has_rust_log: bool,
    effective_log_level: &LogLevel,
) -> RuntimeStartupState {
    let prefer_ipv6 = decision.prefer_ipv6();
    let mut use_middle_proxy = config.general.use_middle_proxy;
    let beobachten = Arc::new(BeobachtenStore::new());
    let rng = Arc::new(SecureRandom::new());

    let me2dc_fallback = config.general.me2dc_fallback;
    let me_init_retry_attempts = config.general.me_init_retry_attempts;
    if use_middle_proxy && !decision.ipv4_me && !decision.ipv6_me {
        if me2dc_fallback {
            warn!(
                "No usable IP family for Middle Proxy detected; Direct-DC startup fallback is active while ME init retries continue"
            );
        } else {
            warn!(
                "No usable IP family for Middle Proxy detected; me2dc_fallback=false, ME init retries stay active"
            );
        }
    }

    if use_middle_proxy {
        startup_tracker
            .set_me_status(StartupMeStatus::Initializing, COMPONENT_ME_SECRET_FETCH)
            .await;
        startup_tracker
            .start_component(
                COMPONENT_ME_SECRET_FETCH,
                Some("fetch proxy-secret from source/cache".to_string()),
            )
            .await;
        startup_tracker
            .set_me_retry_limit(if !me2dc_fallback || me_init_retry_attempts == 0 {
                "unlimited".to_string()
            } else {
                me_init_retry_attempts.to_string()
            })
            .await;
    } else {
        startup_tracker
            .set_me_status(StartupMeStatus::Skipped, "skipped")
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_ME_SECRET_FETCH,
                Some("middle proxy mode disabled".to_string()),
            )
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_ME_PROXY_CONFIG_V4,
                Some("middle proxy mode disabled".to_string()),
            )
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_ME_PROXY_CONFIG_V6,
                Some("middle proxy mode disabled".to_string()),
            )
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_ME_POOL_CONSTRUCT,
                Some("middle proxy mode disabled".to_string()),
            )
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_ME_POOL_INIT_STAGE1,
                Some("middle proxy mode disabled".to_string()),
            )
            .await;
    }

    let (me_ready_tx, me_ready_rx) = watch::channel(0_u64);
    let direct_first_startup = use_middle_proxy && me2dc_fallback;

    let me_pool: Option<Arc<MePool>> = if direct_first_startup {
        None
    } else {
        me_startup::initialize_me_pool(
            use_middle_proxy,
            &config,
            decision,
            probe,
            startup_tracker,
            upstream_manager.clone(),
            rng.clone(),
            stats.clone(),
            api_me_pool.clone(),
            me_ready_tx.clone(),
            runtime_task_scope.clone(),
        )
        .await
    };

    if direct_first_startup {
        startup_tracker.set_transport_mode("direct").await;
        startup_tracker.set_degraded(true).await;
        info!(
            "Transport: Direct DC startup fallback active; Middle-End bootstrap continues in background"
        );
    } else if me_pool.is_some() {
        startup_tracker.set_transport_mode("middle_proxy").await;
        startup_tracker.set_degraded(false).await;
        info!("Transport: Middle-End Proxy - all DC-over-RPC");
    } else {
        let _ = use_middle_proxy;
        use_middle_proxy = false;
        if config.general.use_middle_proxy {
            config.provenance = crate::config::observation::ConfigProvenance::Mixed;
        }
        config.general.use_middle_proxy = false;
        startup_tracker.set_transport_mode("direct").await;
        startup_tracker.set_degraded(true).await;
        if me2dc_fallback {
            startup_tracker
                .set_me_status(StartupMeStatus::Failed, "fallback_to_direct")
                .await;
        } else {
            startup_tracker
                .set_me_status(StartupMeStatus::Skipped, "skipped")
                .await;
        }
        info!("Transport: Direct DC - TCP - standard DC-over-TCP");
    }

    let config = Arc::new(config);
    let replay_checker = Arc::new(ReplayChecker::new(
        config.access.replay_check_len,
        Duration::from_secs(config.access.replay_window_secs),
    ));
    let buffer_pool = Arc::new(BufferPool::with_config(64 * 1024, 4096));

    if direct_first_startup {
        startup_tracker
            .skip_component(
                COMPONENT_ME_CONNECTIVITY_PING,
                Some("deferred by direct-first startup".to_string()),
            )
            .await;
        startup_tracker
            .skip_component(
                COMPONENT_DC_CONNECTIVITY_PING,
                Some("background health checks active".to_string()),
            )
            .await;
    } else {
        connectivity::run_startup_connectivity(
            &config,
            &me_pool,
            rng.clone(),
            startup_tracker,
            upstream_manager.clone(),
            prefer_ipv6,
            decision,
            process_started_at,
            api_me_pool.clone(),
        )
        .await;
    }

    let runtime_watches = runtime_tasks::spawn_runtime_tasks(
        1,
        &config,
        config_path,
        probe,
        prefer_ipv6,
        decision.ipv4_dc,
        decision.ipv6_dc,
        startup_tracker,
        stats.clone(),
        upstream_manager.clone(),
        replay_checker.clone(),
        me_pool.clone(),
        rng.clone(),
        ip_tracker.clone(),
        beobachten.clone(),
        me_pool.clone(),
        shared_state.clone(),
        me_ready_tx.clone(),
        runtime_task_scope.clone(),
        None,
    )
    .await;
    let config_rx = runtime_watches.config_rx;
    let log_level_rx = runtime_watches.log_level_rx;
    let detected_ip_v4 = runtime_watches.detected_ip_v4;
    let detected_ip_v6 = runtime_watches.detected_ip_v6;
    runtime_log_filter.start(
        has_rust_log,
        effective_log_level,
        log_level_rx,
        runtime_task_scope.clone(),
    );

    if direct_first_startup {
        let config_bg = config.clone();
        let decision_bg = decision.clone();
        let probe_bg = probe.clone();
        let startup_tracker_bg = startup_tracker.clone();
        let upstream_manager_bg = upstream_manager.clone();
        let rng_bg = rng.clone();
        let stats_bg = stats.clone();
        let api_me_pool_bg = api_me_pool.clone();
        let me_ready_tx_bg = me_ready_tx.clone();
        let config_rx_bg = config_rx.clone();
        let task_scope_bg = runtime_task_scope.clone();
        runtime_task_scope.spawn(async move {
            let mut bootstrap_attempt: u32 = 0;
            loop {
                bootstrap_attempt = bootstrap_attempt.saturating_add(1);
                let pool = me_startup::initialize_me_pool(
                    true,
                    config_bg.as_ref(),
                    &decision_bg,
                    &probe_bg,
                    &startup_tracker_bg,
                    upstream_manager_bg.clone(),
                    rng_bg.clone(),
                    stats_bg.clone(),
                    api_me_pool_bg.clone(),
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
                if me_init_retry_attempts > 0 && bootstrap_attempt >= me_init_retry_attempts {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        let startup_tracker_ready = startup_tracker.clone();
        let api_me_pool_ready = api_me_pool.clone();
        let mut me_ready_rx_transport = me_ready_tx.subscribe();
        runtime_task_scope.spawn(async move {
            if me_ready_rx_transport.changed().await.is_ok() {
                if let Some(pool) = api_me_pool_ready.read().await.as_ref() {
                    pool.set_runtime_ready(true);
                }
                startup_tracker_ready
                    .set_transport_mode("middle_proxy")
                    .await;
                startup_tracker_ready.set_degraded(false).await;
                info!("Transport: Middle-End Proxy restored for new sessions");
            }
        });
    }

    admission::configure_admission_gate(
        &config,
        me_pool.clone(),
        api_me_pool,
        route_runtime,
        &admission_tx,
        config_rx.clone(),
        me_ready_rx,
        runtime_task_scope.clone(),
    )
    .await;
    let conntrack_scope = runtime_task_scope.clone();
    runtime_task_scope.spawn(conntrack_control::run_conntrack_controller(
        config_rx.clone(),
        stats.clone(),
        shared_state.clone(),
        conntrack_scope.cancellation_token(),
    ));
    runtime_task_scope.spawn(run_direct_buffer_budget_controller(
        1,
        direct_buffer_budget,
        buffer_pool.clone(),
        stats,
        shared_state,
        max_connections.clone(),
        config.server.max_connections,
    ));

    RuntimeStartupState {
        config,
        beobachten,
        rng,
        max_connections,
        me_pool,
        replay_checker,
        buffer_pool,
        config_rx,
        detected_ip_v4,
        detected_ip_v6,
        admission_tx,
    }
}
