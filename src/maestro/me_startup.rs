#![allow(clippy::too_many_arguments)]

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::network::probe::{NetworkDecision, NetworkProbe};
use crate::startup::{
    COMPONENT_ME_POOL_CONSTRUCT, COMPONENT_ME_POOL_INIT_STAGE1, COMPONENT_ME_PROXY_CONFIG_V4,
    COMPONENT_ME_PROXY_CONFIG_V6, COMPONENT_ME_SECRET_FETCH, StartupMeStatus, StartupTracker,
};
use crate::stats::Stats;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;

use super::helpers::load_startup_proxy_config_snapshot;

pub(crate) async fn initialize_me_pool(
    use_middle_proxy: bool,
    config: &ProxyConfig,
    decision: &NetworkDecision,
    probe: &NetworkProbe,
    startup_tracker: &Arc<StartupTracker>,
    upstream_manager: Arc<UpstreamManager>,
    rng: Arc<SecureRandom>,
    stats: Arc<Stats>,
    api_me_pool: Arc<RwLock<Option<Arc<MePool>>>>,
) -> Option<Arc<MePool>> {
    if !use_middle_proxy {
        return None;
    }

    info!("=== Middle Proxy Mode ===");
    let me_nat_probe = config.general.middle_proxy_nat_probe && config.network.stun_use;
    if config.general.middle_proxy_nat_probe && !config.network.stun_use {
        info!("Middle-proxy STUN probing disabled by network.stun_use=false");
    }

    let me2dc_fallback = config.general.me2dc_fallback;
    let me_init_retry_attempts = config.general.me_init_retry_attempts;
    let me_init_warn_after_attempts: u32 = 3;

    // Global ad_tag (pool default). Used when user has no per-user tag in access.user_ad_tags.
    let proxy_tag = config
        .general
        .ad_tag
        .as_ref()
        .map(|tag| hex::decode(tag).expect("general.ad_tag must be validated before startup"));

    // =============================================================
    // CRITICAL: Download Telegram proxy-secret (NOT user secret!)
    //
    // C MTProxy uses TWO separate secrets:
    //   -S flag    = 16-byte user secret for client obfuscation
    //   --aes-pwd  = 32-512 byte binary file for ME RPC auth
    //
    // proxy-secret is from: https://core.telegram.org/getProxySecret
    // =============================================================
    let proxy_secret_path = config.general.proxy_secret_path.as_deref();
    let pool_size = config.general.middle_proxy_pool_size.max(1);
    let proxy_secret = loop {
        match crate::transport::middle_proxy::fetch_proxy_secret(
            proxy_secret_path,
            config.general.proxy_secret_len_max,
        )
        .await
        {
            Ok(proxy_secret) => break Some(proxy_secret),
            Err(e) => {
                startup_tracker.set_me_last_error(Some(e.to_string())).await;
                if me2dc_fallback {
                    error!(
                        error = %e,
                        "ME startup failed: proxy-secret is unavailable and no saved secret found; falling back to direct mode"
                    );
                    break None;
                }

                warn!(
                    error = %e,
                    retry_in_secs = 2,
                    "ME startup failed: proxy-secret is unavailable and no saved secret found; retrying because me2dc_fallback=false"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    match proxy_secret {
        Some(proxy_secret) => {
            startup_tracker
                .complete_component(
                    COMPONENT_ME_SECRET_FETCH,
                    Some("proxy-secret loaded".to_string()),
                )
                .await;
            info!(
                secret_len = proxy_secret.len(),
                key_sig = format_args!(
                    "0x{:08x}",
                    if proxy_secret.len() >= 4 {
                        u32::from_le_bytes([
                            proxy_secret[0],
                            proxy_secret[1],
                            proxy_secret[2],
                            proxy_secret[3],
                        ])
                    } else {
                        0
                    }
                ),
                "Proxy-secret loaded"
            );

            startup_tracker
                .start_component(
                    COMPONENT_ME_PROXY_CONFIG_V4,
                    Some("load startup proxy-config v4".to_string()),
                )
                .await;
            startup_tracker
                .set_me_status(StartupMeStatus::Initializing, COMPONENT_ME_PROXY_CONFIG_V4)
                .await;
            let cfg_v4 = load_startup_proxy_config_snapshot(
                "https://core.telegram.org/getProxyConfig",
                config.general.proxy_config_v4_cache_path.as_deref(),
                me2dc_fallback,
                "getProxyConfig",
            )
            .await;
            if cfg_v4.is_some() {
                startup_tracker
                    .complete_component(
                        COMPONENT_ME_PROXY_CONFIG_V4,
                        Some("proxy-config v4 loaded".to_string()),
                    )
                    .await;
            } else {
                startup_tracker
                    .fail_component(
                        COMPONENT_ME_PROXY_CONFIG_V4,
                        Some("proxy-config v4 unavailable".to_string()),
                    )
                    .await;
            }
            startup_tracker
                .start_component(
                    COMPONENT_ME_PROXY_CONFIG_V6,
                    Some("load startup proxy-config v6".to_string()),
                )
                .await;
            startup_tracker
                .set_me_status(StartupMeStatus::Initializing, COMPONENT_ME_PROXY_CONFIG_V6)
                .await;
            let cfg_v6 = load_startup_proxy_config_snapshot(
                "https://core.telegram.org/getProxyConfigV6",
                config.general.proxy_config_v6_cache_path.as_deref(),
                me2dc_fallback,
                "getProxyConfigV6",
            )
            .await;
            if cfg_v6.is_some() {
                startup_tracker
                    .complete_component(
                        COMPONENT_ME_PROXY_CONFIG_V6,
                        Some("proxy-config v6 loaded".to_string()),
                    )
                    .await;
            } else {
                startup_tracker
                    .fail_component(
                        COMPONENT_ME_PROXY_CONFIG_V6,
                        Some("proxy-config v6 unavailable".to_string()),
                    )
                    .await;
            }

            if let (Some(cfg_v4), Some(cfg_v6)) = (cfg_v4, cfg_v6) {
                startup_tracker
                    .start_component(
                        COMPONENT_ME_POOL_CONSTRUCT,
                        Some("construct ME pool".to_string()),
                    )
                    .await;
                startup_tracker
                    .set_me_status(StartupMeStatus::Initializing, COMPONENT_ME_POOL_CONSTRUCT)
                    .await;
                let pool = MePool::new(
                    proxy_tag.clone(),
                    proxy_secret,
                    config.general.middle_proxy_nat_ip,
                    me_nat_probe,
                    None,
                    config.network.stun_servers.clone(),
                    config.general.stun_nat_probe_concurrency,
                    probe.detected_ipv6,
                    config.timeouts.me_one_retry,
                    config.timeouts.me_one_timeout_ms,
                    cfg_v4.map.clone(),
                    cfg_v6.map.clone(),
                    cfg_v4.default_dc.or(cfg_v6.default_dc),
                    decision.clone(),
                    Some(upstream_manager.clone()),
                    rng.clone(),
                    stats.clone(),
                    config.general.me_keepalive_enabled,
                    config.general.me_keepalive_interval_secs,
                    config.general.me_keepalive_jitter_secs,
                    config.general.me_keepalive_payload_random,
                    config.general.rpc_proxy_req_every,
                    config.general.me_warmup_stagger_enabled,
                    config.general.me_warmup_step_delay_ms,
                    config.general.me_warmup_step_jitter_ms,
                    config.general.me_reconnect_max_concurrent_per_dc,
                    config.general.me_reconnect_backoff_base_ms,
                    config.general.me_reconnect_backoff_cap_ms,
                    config.general.me_reconnect_fast_retry_count,
                    config.general.me_single_endpoint_shadow_writers,
                    config.general.me_single_endpoint_outage_mode_enabled,
                    config.general.me_single_endpoint_outage_disable_quarantine,
                    config.general.me_single_endpoint_outage_backoff_min_ms,
                    config.general.me_single_endpoint_outage_backoff_max_ms,
                    config.general.me_single_endpoint_shadow_rotate_every_secs,
                    config.general.me_floor_mode,
                    config.general.me_adaptive_floor_idle_secs,
                    config.general.me_adaptive_floor_min_writers_single_endpoint,
                    config.general.me_adaptive_floor_min_writers_multi_endpoint,
                    config.general.me_adaptive_floor_recover_grace_secs,
                    config.general.me_adaptive_floor_writers_per_core_total,
                    config.general.me_adaptive_floor_cpu_cores_override,
                    config
                        .general
                        .me_adaptive_floor_max_extra_writers_single_per_core,
                    config
                        .general
                        .me_adaptive_floor_max_extra_writers_multi_per_core,
                    config.general.me_adaptive_floor_max_active_writers_per_core,
                    config.general.me_adaptive_floor_max_warm_writers_per_core,
                    config.general.me_adaptive_floor_max_active_writers_global,
                    config.general.me_adaptive_floor_max_warm_writers_global,
                    config.general.hardswap,
                    config.general.me_pool_drain_ttl_secs,
                    config.general.me_instadrain,
                    config.general.me_pool_drain_threshold,
                    config.general.me_pool_drain_soft_evict_enabled,
                    config.general.me_pool_drain_soft_evict_grace_secs,
                    config.general.me_pool_drain_soft_evict_per_writer,
                    config.general.me_pool_drain_soft_evict_budget_per_core,
                    config.general.me_pool_drain_soft_evict_cooldown_ms,
                    config.general.effective_me_pool_force_close_secs(),
                    config.general.me_pool_min_fresh_ratio,
                    config.general.me_hardswap_warmup_delay_min_ms,
                    config.general.me_hardswap_warmup_delay_max_ms,
                    config.general.me_hardswap_warmup_extra_passes,
                    config.general.me_hardswap_warmup_pass_backoff_base_ms,
                    config.general.me_bind_stale_mode,
                    config.general.me_bind_stale_ttl_secs,
                    config.general.me_secret_atomic_snapshot,
                    config.general.me_deterministic_writer_sort,
                    config.general.me_writer_pick_mode,
                    config.general.me_writer_pick_sample_size,
                    config.general.me_socks_kdf_policy,
                    config.general.me_writer_cmd_channel_capacity,
                    config.general.me_route_channel_capacity,
                    config.general.me_route_backpressure_base_timeout_ms,
                    config.general.me_route_backpressure_high_timeout_ms,
                    config.general.me_route_backpressure_high_watermark_pct,
                    config.general.me_reader_route_data_wait_ms,
                    config.general.me_health_interval_ms_unhealthy,
                    config.general.me_health_interval_ms_healthy,
                    config.general.me_warn_rate_limit_ms,
                    config.general.me_route_no_writer_mode,
                    config.general.me_route_no_writer_wait_ms,
                    config.general.me_route_inline_recovery_attempts,
                    config.general.me_route_inline_recovery_wait_ms,
                );
                startup_tracker
                    .complete_component(
                        COMPONENT_ME_POOL_CONSTRUCT,
                        Some("ME pool object created".to_string()),
                    )
                    .await;
                *api_me_pool.write().await = Some(pool.clone());
                startup_tracker
                    .start_component(
                        COMPONENT_ME_POOL_INIT_STAGE1,
                        Some("initialize ME pool writers".to_string()),
                    )
                    .await;
                startup_tracker
                    .set_me_status(StartupMeStatus::Initializing, COMPONENT_ME_POOL_INIT_STAGE1)
                    .await;

                if me2dc_fallback {
                    let pool_bg = pool.clone();
                    let rng_bg = rng.clone();
                    let startup_tracker_bg = startup_tracker.clone();
                    let retry_limit = if me_init_retry_attempts == 0 {
                        String::from("unlimited")
                    } else {
                        me_init_retry_attempts.to_string()
                    };
                    std::thread::spawn(move || {
                        let runtime = match tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        {
                            Ok(runtime) => runtime,
                            Err(error) => {
                                error!(error = %error, "Failed to build background runtime for ME initialization");
                                return;
                            }
                        };
                        runtime.block_on(async move {
                            let mut init_attempt: u32 = 0;
                            loop {
                                init_attempt = init_attempt.saturating_add(1);
                                startup_tracker_bg.set_me_init_attempt(init_attempt).await;
                                match pool_bg.init(pool_size, &rng_bg).await {
                                    Ok(()) => {
                                        startup_tracker_bg.set_me_last_error(None).await;
                                        startup_tracker_bg
                                            .complete_component(
                                                COMPONENT_ME_POOL_INIT_STAGE1,
                                                Some("ME pool initialized".to_string()),
                                            )
                                            .await;
                                        startup_tracker_bg
                                            .set_me_status(StartupMeStatus::Ready, "ready")
                                            .await;
                                        info!(
                                            attempt = init_attempt,
                                            "Middle-End pool initialized successfully"
                                        );

                                            // ── Supervised background tasks ──────────────────
                                            // Each task runs inside a nested tokio::spawn so
                                            // that a panic is caught via JoinHandle and the
                                            // outer loop restarts the task automatically.
                                            let pool_health = pool_bg.clone();
                                            let rng_health = rng_bg.clone();
                                            let min_conns = pool_size;
                                            tokio::spawn(async move {
                                                loop {
                                                    let p = pool_health.clone();
                                                    let r = rng_health.clone();
                                                    let res = tokio::spawn(async move {
                                                        crate::transport::middle_proxy::me_health_monitor(
                                                            p, r, min_conns,
                                                        )
                                                        .await;
                                                    })
                                                    .await;
                                                    match res {
                                                        Ok(()) => warn!("me_health_monitor exited unexpectedly, restarting"),
                                                        Err(e) => {
                                                            error!(error = %e, "me_health_monitor panicked, restarting in 1s");
                                                            tokio::time::sleep(Duration::from_secs(1)).await;
                                                        }
                                                    }
                                                }
                                            });
                                            let pool_drain_enforcer = pool_bg.clone();
                                            tokio::spawn(async move {
                                                loop {
                                                    let p = pool_drain_enforcer.clone();
                                                    let res = tokio::spawn(async move {
                                                        crate::transport::middle_proxy::me_drain_timeout_enforcer(p).await;
                                                    })
                                                    .await;
                                                    match res {
                                                        Ok(()) => warn!("me_drain_timeout_enforcer exited unexpectedly, restarting"),
                                                        Err(e) => {
                                                            error!(error = %e, "me_drain_timeout_enforcer panicked, restarting in 1s");
                                                            tokio::time::sleep(Duration::from_secs(1)).await;
                                                        }
                                                    }
                                                }
                                            });
                                            let pool_watchdog = pool_bg.clone();
                                            tokio::spawn(async move {
                                                loop {
                                                    let p = pool_watchdog.clone();
                                                    let res = tokio::spawn(async move {
                                                        crate::transport::middle_proxy::me_zombie_writer_watchdog(p).await;
                                                    })
                                                    .await;
                                                    match res {
                                                        Ok(()) => warn!("me_zombie_writer_watchdog exited unexpectedly, restarting"),
                                                        Err(e) => {
                                                            error!(error = %e, "me_zombie_writer_watchdog panicked, restarting in 1s");
                                                            tokio::time::sleep(Duration::from_secs(1)).await;
                                                        }
                                                    }
                                                }
                                            });
                                            // CRITICAL: keep the current-thread runtime
                                            // alive. Without this, block_on() returns,
                                            // the Runtime is dropped, and ALL spawned
                                            // background tasks (health monitor, drain
                                            // enforcer, zombie watchdog) are silently
                                            // cancelled — causing the draining-writer
                                            // leak that brought us here.
                                            std::future::pending::<()>().await;
                                            unreachable!();
                                    }
                                    Err(e) => {
                                        startup_tracker_bg.set_me_last_error(Some(e.to_string())).await;
                                        if init_attempt >= me_init_warn_after_attempts {
                                            warn!(
                                                error = %e,
                                                attempt = init_attempt,
                                                retry_limit = %retry_limit,
                                                retry_in_secs = 2,
                                                "ME pool is not ready yet; retrying background initialization"
                                            );
                                        } else {
                                            info!(
                                                error = %e,
                                                attempt = init_attempt,
                                                retry_limit = %retry_limit,
                                                retry_in_secs = 2,
                                                "ME pool startup warmup: retrying background initialization"
                                            );
                                        }
                                        pool_bg.reset_stun_state();
                                        tokio::time::sleep(Duration::from_secs(2)).await;
                                    }
                                }
                            }
                        });
                    });
                    startup_tracker
                        .set_me_status(StartupMeStatus::Initializing, "background_init")
                        .await;
                    info!(
                        startup_grace_secs = 80,
                        "ME pool initialization continues in background; startup continues with conditional Direct fallback"
                    );
                    Some(pool)
                } else {
                    let mut init_attempt: u32 = 0;
                    loop {
                        init_attempt = init_attempt.saturating_add(1);
                        startup_tracker.set_me_init_attempt(init_attempt).await;
                        match pool.init(pool_size, &rng).await {
                            Ok(()) => {
                                startup_tracker.set_me_last_error(None).await;
                                startup_tracker
                                    .complete_component(
                                        COMPONENT_ME_POOL_INIT_STAGE1,
                                        Some("ME pool initialized".to_string()),
                                    )
                                    .await;
                                startup_tracker
                                    .set_me_status(StartupMeStatus::Ready, "ready")
                                    .await;
                                info!(
                                    attempt = init_attempt,
                                    "Middle-End pool initialized successfully"
                                );

                                // ── Supervised background tasks ──────────────────
                                let pool_clone = pool.clone();
                                let rng_clone = rng.clone();
                                let min_conns = pool_size;
                                tokio::spawn(async move {
                                    loop {
                                        let p = pool_clone.clone();
                                        let r = rng_clone.clone();
                                        let res = tokio::spawn(async move {
                                            crate::transport::middle_proxy::me_health_monitor(
                                                p, r, min_conns,
                                            )
                                            .await;
                                        })
                                        .await;
                                        match res {
                                            Ok(()) => warn!(
                                                "me_health_monitor exited unexpectedly, restarting"
                                            ),
                                            Err(e) => {
                                                error!(error = %e, "me_health_monitor panicked, restarting in 1s");
                                                tokio::time::sleep(Duration::from_secs(1)).await;
                                            }
                                        }
                                    }
                                });
                                let pool_drain_enforcer = pool.clone();
                                tokio::spawn(async move {
                                    loop {
                                        let p = pool_drain_enforcer.clone();
                                        let res = tokio::spawn(async move {
                                                crate::transport::middle_proxy::me_drain_timeout_enforcer(p).await;
                                            })
                                            .await;
                                        match res {
                                            Ok(()) => warn!(
                                                "me_drain_timeout_enforcer exited unexpectedly, restarting"
                                            ),
                                            Err(e) => {
                                                error!(error = %e, "me_drain_timeout_enforcer panicked, restarting in 1s");
                                                tokio::time::sleep(Duration::from_secs(1)).await;
                                            }
                                        }
                                    }
                                });
                                let pool_watchdog = pool.clone();
                                tokio::spawn(async move {
                                    loop {
                                        let p = pool_watchdog.clone();
                                        let res = tokio::spawn(async move {
                                                crate::transport::middle_proxy::me_zombie_writer_watchdog(p).await;
                                            })
                                            .await;
                                        match res {
                                            Ok(()) => warn!(
                                                "me_zombie_writer_watchdog exited unexpectedly, restarting"
                                            ),
                                            Err(e) => {
                                                error!(error = %e, "me_zombie_writer_watchdog panicked, restarting in 1s");
                                                tokio::time::sleep(Duration::from_secs(1)).await;
                                            }
                                        }
                                    }
                                });

                                break Some(pool);
                            }
                            Err(e) => {
                                startup_tracker.set_me_last_error(Some(e.to_string())).await;
                                let retries_limited = me_init_retry_attempts > 0;
                                if retries_limited && init_attempt >= me_init_retry_attempts {
                                    startup_tracker
                                        .fail_component(
                                            COMPONENT_ME_POOL_INIT_STAGE1,
                                            Some("ME init retry budget exhausted".to_string()),
                                        )
                                        .await;
                                    startup_tracker
                                        .set_me_status(StartupMeStatus::Failed, "failed")
                                        .await;
                                    error!(
                                        error = %e,
                                        attempt = init_attempt,
                                        retry_limit = me_init_retry_attempts,
                                        "ME pool init retries exhausted; startup cannot continue in middle-proxy mode"
                                    );
                                    break None;
                                }

                                let retry_limit = if me_init_retry_attempts == 0 {
                                    String::from("unlimited")
                                } else {
                                    me_init_retry_attempts.to_string()
                                };
                                if init_attempt >= me_init_warn_after_attempts {
                                    warn!(
                                        error = %e,
                                        attempt = init_attempt,
                                        retry_limit = retry_limit,
                                        me2dc_fallback = me2dc_fallback,
                                        retry_in_secs = 2,
                                        "ME pool is not ready yet; retrying startup initialization"
                                    );
                                } else {
                                    info!(
                                        error = %e,
                                        attempt = init_attempt,
                                        retry_limit = retry_limit,
                                        me2dc_fallback = me2dc_fallback,
                                        retry_in_secs = 2,
                                        "ME pool startup warmup: retrying initialization"
                                    );
                                }
                                pool.reset_stun_state();
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                        }
                    }
                }
            } else {
                startup_tracker
                    .skip_component(
                        COMPONENT_ME_POOL_CONSTRUCT,
                        Some("ME configs are incomplete".to_string()),
                    )
                    .await;
                startup_tracker
                    .fail_component(
                        COMPONENT_ME_POOL_INIT_STAGE1,
                        Some("ME configs are incomplete".to_string()),
                    )
                    .await;
                startup_tracker
                    .set_me_status(StartupMeStatus::Failed, "failed")
                    .await;
                None
            }
        }
        None => {
            startup_tracker
                .fail_component(
                    COMPONENT_ME_SECRET_FETCH,
                    Some("proxy-secret unavailable".to_string()),
                )
                .await;
            startup_tracker
                .skip_component(
                    COMPONENT_ME_PROXY_CONFIG_V4,
                    Some("proxy-secret unavailable".to_string()),
                )
                .await;
            startup_tracker
                .skip_component(
                    COMPONENT_ME_PROXY_CONFIG_V6,
                    Some("proxy-secret unavailable".to_string()),
                )
                .await;
            startup_tracker
                .skip_component(
                    COMPONENT_ME_POOL_CONSTRUCT,
                    Some("proxy-secret unavailable".to_string()),
                )
                .await;
            startup_tracker
                .fail_component(
                    COMPONENT_ME_POOL_INIT_STAGE1,
                    Some("proxy-secret unavailable".to_string()),
                )
                .await;
            startup_tracker
                .set_me_status(StartupMeStatus::Failed, "failed")
                .await;
            None
        }
    }
}
