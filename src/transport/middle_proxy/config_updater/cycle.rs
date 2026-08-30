use super::*;

pub(super) fn snapshot_passes_guards(
    cfg: &ProxyConfig,
    snapshot: &ProxyConfigData,
    snapshot_name: &'static str,
) -> bool {
    if cfg.general.me_snapshot_require_http_2xx && !(200..=299).contains(&snapshot.http_status) {
        warn!(
            snapshot = snapshot_name,
            http_status = snapshot.http_status,
            "ME snapshot rejected by non-2xx HTTP status"
        );
        return false;
    }

    let min_proxy_for = cfg.general.me_snapshot_min_proxy_for_lines;
    if snapshot.proxy_for_lines < min_proxy_for {
        warn!(
            snapshot = snapshot_name,
            parsed_proxy_for_lines = snapshot.proxy_for_lines,
            min_proxy_for_lines = min_proxy_for,
            "ME snapshot rejected by proxy_for line floor"
        );
        return false;
    }

    true
}

pub(super) async fn run_update_cycle(
    pool: &Arc<MePool>,
    cfg: &ProxyConfig,
    state: &mut UpdaterState,
    reinit_tx: &mpsc::Sender<MeReinitTrigger>,
) {
    let upstream = pool.upstream.clone();

    let required_cfg_snapshots = cfg.general.me_config_stable_snapshots.max(1);
    let required_secret_snapshots = cfg.general.proxy_secret_stable_snapshots.max(1);
    let apply_cooldown = Duration::from_secs(cfg.general.me_config_apply_cooldown_secs);
    let mut maps_changed = false;

    let mut ready_v4: Option<(ProxyConfigData, u64)> = None;
    let cfg_v4 = retry_fetch(
        cfg.general
            .proxy_config_v4_url
            .as_deref()
            .unwrap_or("https://core.telegram.org/getProxyConfig"),
        upstream.clone(),
    )
    .await;
    if let Some(cfg_v4) = cfg_v4
        && snapshot_passes_guards(cfg, &cfg_v4, "getProxyConfig")
    {
        let cfg_v4_hash = hash_proxy_config(&cfg_v4);
        let stable_hits = state.config_v4.observe(cfg_v4_hash);
        if stable_hits < required_cfg_snapshots {
            debug!(
                stable_hits,
                required_cfg_snapshots,
                snapshot = format_args!("0x{cfg_v4_hash:016x}"),
                "ME config v4 candidate observed"
            );
        } else if state.config_v4.is_applied(cfg_v4_hash) {
            debug!(
                snapshot = format_args!("0x{cfg_v4_hash:016x}"),
                "ME config v4 stable snapshot already applied"
            );
        } else {
            ready_v4 = Some((cfg_v4, cfg_v4_hash));
        }
    }

    let mut ready_v6: Option<(ProxyConfigData, u64)> = None;
    let cfg_v6 = retry_fetch(
        cfg.general
            .proxy_config_v6_url
            .as_deref()
            .unwrap_or("https://core.telegram.org/getProxyConfigV6"),
        upstream.clone(),
    )
    .await;
    if let Some(cfg_v6) = cfg_v6
        && snapshot_passes_guards(cfg, &cfg_v6, "getProxyConfigV6")
    {
        let cfg_v6_hash = hash_proxy_config(&cfg_v6);
        let stable_hits = state.config_v6.observe(cfg_v6_hash);
        if stable_hits < required_cfg_snapshots {
            debug!(
                stable_hits,
                required_cfg_snapshots,
                snapshot = format_args!("0x{cfg_v6_hash:016x}"),
                "ME config v6 candidate observed"
            );
        } else if state.config_v6.is_applied(cfg_v6_hash) {
            debug!(
                snapshot = format_args!("0x{cfg_v6_hash:016x}"),
                "ME config v6 stable snapshot already applied"
            );
        } else {
            ready_v6 = Some((cfg_v6, cfg_v6_hash));
        }
    }

    if ready_v4.is_some() || ready_v6.is_some() {
        if map_apply_cooldown_ready(state.last_map_apply_at, apply_cooldown) {
            let update_v4 = ready_v4
                .as_ref()
                .map(|(snapshot, _)| snapshot.map.clone())
                .unwrap_or_default();
            let update_v6 = ready_v6.as_ref().map(|(snapshot, _)| snapshot.map.clone());
            let update_is_empty =
                update_v4.is_empty() && update_v6.as_ref().is_none_or(|v| v.is_empty());
            let apply_outcome = if update_is_empty && !cfg.general.me_snapshot_reject_empty_map {
                crate::transport::middle_proxy::pool_config::SnapshotApplyOutcome::AppliedNoDelta
            } else {
                pool.update_proxy_maps(update_v4, update_v6).await
            };

            if matches!(
                apply_outcome,
                crate::transport::middle_proxy::pool_config::SnapshotApplyOutcome::RejectedEmpty
            ) {
                warn!("ME config stable snapshot rejected (empty endpoint map)");
            } else {
                if let Some((snapshot, hash)) = ready_v4 {
                    if let Some(dc) = snapshot.default_dc {
                        pool.default_dc
                            .store(dc, std::sync::atomic::Ordering::Relaxed);
                    }
                    state.config_v4.mark_applied(hash);
                }

                if let Some((_snapshot, hash)) = ready_v6 {
                    state.config_v6.mark_applied(hash);
                }

                state.last_map_apply_at = Some(tokio::time::Instant::now());

                if apply_outcome.changed() {
                    maps_changed = true;
                    info!("ME config update applied after stable-gate");
                } else {
                    debug!("ME config stable-gate applied with no map delta");
                }
            }
        } else if let Some(last) = state.last_map_apply_at {
            let wait_secs = map_apply_cooldown_remaining_secs(last, apply_cooldown);
            debug!(wait_secs, "ME config stable snapshot deferred by cooldown");
        }
    }

    if maps_changed {
        enqueue_reinit_trigger(reinit_tx, MeReinitTrigger::MapChanged);
    }

    pool.reset_stun_state();

    if cfg.general.proxy_secret_rotate_runtime {
        match download_proxy_secret_with_max_len_via_upstream(
            cfg.general.proxy_secret_len_max,
            upstream,
            cfg.general.proxy_secret_url.as_deref(),
        )
        .await
        {
            Ok(secret) => {
                let secret_hash = hash_secret(&secret);
                let stable_hits = state.secret.observe(secret_hash);
                if stable_hits < required_secret_snapshots {
                    debug!(
                        stable_hits,
                        required_secret_snapshots,
                        snapshot = format_args!("0x{secret_hash:016x}"),
                        "proxy-secret candidate observed"
                    );
                } else if state.secret.is_applied(secret_hash) {
                    debug!(
                        snapshot = format_args!("0x{secret_hash:016x}"),
                        "proxy-secret stable snapshot already applied"
                    );
                } else {
                    let rotated = pool.update_secret(secret).await;
                    state.secret.mark_applied(secret_hash);
                    if rotated {
                        info!("proxy-secret rotated after stable-gate");
                    } else {
                        debug!("proxy-secret stable snapshot confirmed as unchanged");
                    }
                }
            }
            Err(e) => warn!(error = %e, "proxy-secret update failed"),
        }
    } else {
        debug!("proxy-secret runtime rotation disabled by config");
    }
}
