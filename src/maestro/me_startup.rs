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
use crate::transport::middle_proxy::MePool;
use crate::transport::UpstreamManager;

use super::helpers::{load_startup_proxy_config_snapshot, retry_backoff_ms};

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
    let backoff_base_ms = config.general.me_init_retry_backoff_base_ms;
    let backoff_cap_ms = config.general.me_init_retry_backoff_cap_ms;

    // Global ad_tag (pool default). Used when user has no per-user tag in access.user_ad_tags.
    let proxy_tag = match parse_global_proxy_tag(config) {
        Ok(proxy_tag) => proxy_tag,
        Err(err) => {
            let detail = format!("general.ad_tag is invalid: {err}");
            startup_tracker.set_me_last_error(Some(detail.clone())).await;
            error!(error = %err, "{detail}; refusing ME startup");
            return None;
        }
    };

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
    let mut secret_fetch_attempt: u32 = 0;
    let proxy_secret = loop {
        secret_fetch_attempt = secret_fetch_attempt.saturating_add(1);
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

                let delay_ms = retry_backoff_ms(secret_fetch_attempt, backoff_base_ms, backoff_cap_ms);
                warn!(
                    error = %e,
                    attempt = secret_fetch_attempt,
                    retry_in_ms = delay_ms,
                    "ME startup failed: proxy-secret is unavailable and no saved secret found; retrying because me2dc_fallback=false"
                );
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
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
                backoff_base_ms,
                backoff_cap_ms,
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
                backoff_base_ms,
                backoff_cap_ms,
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
                    config.general.me_adaptive_floor_max_extra_writers_single_per_core,
                    config.general.me_adaptive_floor_max_extra_writers_multi_per_core,
                    config.general.me_adaptive_floor_max_active_writers_per_core,
                    config.general.me_adaptive_floor_max_warm_writers_per_core,
                    config.general.me_adaptive_floor_max_active_writers_global,
                    config.general.me_adaptive_floor_max_warm_writers_global,
                    config.general.hardswap,
                    config.general.me_pool_drain_ttl_secs,
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
                    let backoff_base_ms_bg = backoff_base_ms;
                    let backoff_cap_ms_bg = backoff_cap_ms;
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

                                        let pool_health = pool_bg.clone();
                                        let rng_health = rng_bg.clone();
                                        let min_conns = pool_size;
                                        tokio::spawn(async move {
                                            crate::transport::middle_proxy::me_health_monitor(
                                                pool_health,
                                                rng_health,
                                                min_conns,
                                            )
                                            .await;
                                        });
                                        break;
                                    }
                                    Err(e) => {
                                        startup_tracker_bg.set_me_last_error(Some(e.to_string())).await;
                                        let delay_ms = retry_backoff_ms(init_attempt, backoff_base_ms_bg, backoff_cap_ms_bg);
                                        if init_attempt >= me_init_warn_after_attempts {
                                            warn!(
                                                error = %e,
                                                attempt = init_attempt,
                                                retry_limit = %retry_limit,
                                                retry_in_ms = delay_ms,
                                                "ME pool is not ready yet; retrying background initialization"
                                            );
                                        } else {
                                            info!(
                                                error = %e,
                                                attempt = init_attempt,
                                                retry_limit = %retry_limit,
                                                retry_in_ms = delay_ms,
                                                "ME pool startup warmup: retrying background initialization"
                                            );
                                        }
                                        pool_bg.reset_stun_state();
                                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
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

                                let pool_clone = pool.clone();
                                let rng_clone = rng.clone();
                                let min_conns = pool_size;
                                tokio::spawn(async move {
                                    crate::transport::middle_proxy::me_health_monitor(
                                        pool_clone, rng_clone, min_conns,
                                    )
                                    .await;
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
                                let delay_ms = retry_backoff_ms(init_attempt, backoff_base_ms, backoff_cap_ms);
                                if init_attempt >= me_init_warn_after_attempts {
                                    warn!(
                                        error = %e,
                                        attempt = init_attempt,
                                        retry_limit = retry_limit,
                                        me2dc_fallback = me2dc_fallback,
                                        retry_in_ms = delay_ms,
                                        "ME pool is not ready yet; retrying startup initialization"
                                    );
                                } else {
                                    info!(
                                        error = %e,
                                        attempt = init_attempt,
                                        retry_limit = retry_limit,
                                        me2dc_fallback = me2dc_fallback,
                                        retry_in_ms = delay_ms,
                                        "ME pool startup warmup: retrying initialization"
                                    );
                                }
                                pool.reset_stun_state();
                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
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

fn parse_global_proxy_tag(config: &ProxyConfig) -> std::result::Result<Option<Vec<u8>>, hex::FromHexError> {
    config
        .general
        .ad_tag
        .as_deref()
        .map(hex::decode)
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::parse_global_proxy_tag;
    use crate::config::ProxyConfig;

    #[test]
    fn parse_global_proxy_tag_absent_returns_none() {
        let cfg = ProxyConfig::default();
        let parsed = parse_global_proxy_tag(&cfg);
        assert!(parsed.is_ok());
        assert!(parsed.ok().flatten().is_none());
    }

    #[test]
    fn parse_global_proxy_tag_valid_hex_returns_bytes() {
        let mut cfg = ProxyConfig::default();
        cfg.general.ad_tag = Some("00112233445566778899aabbccddeeff".to_string());

        let parsed = parse_global_proxy_tag(&cfg);
        assert!(parsed.is_ok());
        let bytes = parsed.ok().flatten();
        assert!(bytes.is_some());
        assert_eq!(bytes.unwrap_or_default().len(), 16);
    }

    #[test]
    fn parse_global_proxy_tag_invalid_hex_returns_error() {
        let mut cfg = ProxyConfig::default();
        cfg.general.ad_tag = Some("zz".to_string());

        let parsed = parse_global_proxy_tag(&cfg);
        assert!(parsed.is_err());
    }
}
