use super::*;

pub(super) async fn handle(
    method: &Method,
    normalized_path: &str,
    query: Option<&str>,
    shared: &ApiShared,
    cfg: &ProxyConfig,
    config_rx: &watch::Receiver<Arc<ProxyConfig>>,
) -> Result<Option<Response<Full<Bytes>>>, ApiFailure> {
    let api_cfg = &cfg.server.api;
    match (method.as_str(), normalized_path) {
        ("GET", "/web-status") => Ok(web_status::render(query, &shared.web_trace).await),
        ("GET", "/v1/health") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = HealthData {
                status: "ok",
                read_only: api_cfg.read_only,
            };
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/health/ready") => {
            let revision = current_revision(&shared.config_path).await?;
            let admission_open = shared.runtime_state.admission_open.load(Ordering::Relaxed);
            let upstream_health = shared.upstream_manager.api_health_summary().await;
            let ready = admission_open && upstream_health.healthy_total > 0;
            let reason = if ready {
                None
            } else if !admission_open {
                Some("admission_closed")
            } else {
                Some("no_healthy_upstreams")
            };
            let data = HealthReadyData {
                ready,
                status: if ready { "ready" } else { "not_ready" },
                reason,
                admission_open,
                healthy_upstreams: upstream_health.healthy_total,
                total_upstreams: upstream_health.configured_total,
            };
            let status_code = if ready {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            Ok(success_response(status_code, data, revision))
        }
        ("GET", "/v1/system/info") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_system_info_data(shared, cfg, &revision);
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/runtime/gates") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_runtime_gates_data(shared, cfg).await;
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/runtime/initialization") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_runtime_initialization_data(shared).await;
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/limits/effective") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_limits_effective_data(cfg);
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/security/posture") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_security_posture_data(cfg);
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/security/whitelist") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_security_whitelist_data(cfg);
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/stats/summary") => {
            let revision = current_revision(&shared.config_path).await?;
            let connections_bad_by_class = shared
                .stats
                .get_connects_bad_class_counts()
                .into_iter()
                .map(|(class, total)| ClassCount { class, total })
                .collect();
            let handshake_failures_by_class = shared
                .stats
                .get_handshake_failure_class_counts()
                .into_iter()
                .map(|(class, total)| ClassCount { class, total })
                .collect();
            let data = SummaryData {
                uptime_seconds: shared.stats.uptime_secs(),
                connections_total: shared.stats.get_connects_all(),
                connections_bad_total: shared.stats.get_connects_bad(),
                connections_bad_by_class,
                handshake_failures_by_class,
                handshake_timeouts_total: shared.stats.get_handshake_timeouts(),
                configured_users: cfg.access.users.len(),
            };
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/stats/zero/all") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_zero_all_data(&shared.stats, cfg.access.users.len());
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/stats/upstreams") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_upstreams_data(shared, api_cfg);
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/stats/minimal/all") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_minimal_all_data(shared, api_cfg).await;
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/stats/me-writers") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_me_writers_data(shared, api_cfg).await;
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/stats/dcs") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_dcs_data(shared, api_cfg).await;
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/runtime/me-pool-state") | ("GET", "/v1/runtime/me_pool_state") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_runtime_me_pool_state_data(shared).await;
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/runtime/me-quality") | ("GET", "/v1/runtime/me_quality") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_runtime_me_quality_data(shared).await;
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/runtime/upstream-quality") | ("GET", "/v1/runtime/upstream_quality") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_runtime_upstream_quality_data(shared).await;
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/runtime/nat-stun") | ("GET", "/v1/runtime/nat_stun") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_runtime_nat_stun_data(shared).await;
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/runtime/me-selftest") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_runtime_me_selftest_data(shared, cfg).await;
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/runtime/connections/summary") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_runtime_connections_summary_data(shared, cfg).await;
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/runtime/events/recent") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_runtime_events_recent_data(shared, cfg, query);
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/runtime/tls-fingerprints") => {
            let revision = current_revision(&shared.config_path).await?;
            let data = build_runtime_tls_fingerprints_data(shared, cfg, query);
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/stats/users/active-ips") => {
            let revision = current_revision(&shared.config_path).await?;
            let usernames: Vec<_> = cfg.access.users.keys().cloned().collect();
            let active_ips_map = shared.ip_tracker.get_active_ips_for_users(&usernames).await;
            let mut data: Vec<UserActiveIps> = active_ips_map
                .into_iter()
                .filter(|(_, ips)| !ips.is_empty())
                .map(|(username, active_ips)| UserActiveIps {
                    username,
                    active_ips,
                })
                .collect();
            data.sort_by(|a, b| a.username.cmp(&b.username));
            Ok(success_response(StatusCode::OK, data, revision))
        }
        ("GET", "/v1/stats/users") | ("GET", "/v1/users") => {
            let revision = current_revision(&shared.config_path).await?;
            let disk_cfg = load_config_from_disk(&shared.config_path).await?;
            let runtime_cfg = config_rx.borrow().clone();
            let (detected_ip_v4, detected_ip_v6) = shared.detected_link_ips();
            let users = users_from_config(
                &disk_cfg,
                &shared.stats,
                &shared.ip_tracker,
                detected_ip_v4,
                detected_ip_v6,
                Some(runtime_cfg.as_ref()),
            )
            .await;
            Ok(success_response(StatusCode::OK, users, revision))
        }
        ("GET", "/v1/stats/users/quota") => {
            let revision = current_revision(&shared.config_path).await?;
            let disk_cfg = load_config_from_disk(&shared.config_path).await?;
            let data = build_user_quota_list(&disk_cfg, shared.stats.as_ref());
            Ok(success_response(StatusCode::OK, data, revision))
        }

        _ => return Ok(None),
    }
    .map(Some)
}
