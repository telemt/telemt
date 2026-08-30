use super::*;

impl UpstreamManager {
    /// Background health check based on reachable DC groups through each upstream.
    /// Upstream stays healthy while at least `MIN_HEALTHY_DC_GROUPS` groups are reachable.
    pub async fn run_health_checks(
        &self,
        prefer_ipv6: bool,
        ipv4_enabled: bool,
        ipv6_enabled: bool,
        dc_overrides: HashMap<String, Vec<String>>,
    ) {
        let (health_ipv4_enabled, health_ipv6_enabled) = {
            let guard = self.upstreams.read().await;
            (
                ipv4_enabled
                    || guard
                        .iter()
                        .any(|upstream| upstream.config.ipv4 == Some(true)),
                ipv6_enabled
                    || guard
                        .iter()
                        .any(|upstream| upstream.config.ipv6 == Some(true)),
            )
        };
        let groups = Self::build_health_check_groups(
            health_ipv4_enabled,
            health_ipv6_enabled,
            &dc_overrides,
        );
        let required_healthy_groups = Self::required_healthy_group_count(groups.len());
        let mut endpoint_rotation: HashMap<(usize, i16, bool), usize> = HashMap::new();

        if groups.is_empty() {
            warn!("No DC groups available for upstream health-checks");
        }

        loop {
            tokio::time::sleep(Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS)).await;

            if groups.is_empty() || required_healthy_groups == 0 {
                continue;
            }

            let target_upstreams: Vec<usize> = {
                let guard = self.upstreams.read().await;
                let has_unscoped = guard
                    .iter()
                    .any(|upstream| Self::is_unscoped_upstream(&upstream.config));
                guard
                    .iter()
                    .enumerate()
                    .filter(|(_, upstream)| {
                        Self::should_check_in_default_dc_connectivity(
                            has_unscoped,
                            &upstream.config,
                        )
                    })
                    .map(|(idx, _)| idx)
                    .collect()
            };

            for i in target_upstreams {
                let (config, bind_rr) = {
                    let guard = self.upstreams.read().await;
                    let u = &guard[i];
                    (u.config.clone(), u.bind_rr.clone())
                };
                let (upstream_ipv4_enabled, upstream_ipv6_enabled) =
                    Self::resolve_probe_dc_families(&config, ipv4_enabled, ipv6_enabled);
                let upstream_prefer_ipv6 = config.prefer_ipv6(prefer_ipv6);

                let mut healthy_groups = 0usize;
                let mut latency_updates: Vec<(usize, f64)> = Vec::new();

                for group in &groups {
                    let mut group_ok = false;
                    let mut group_rtt_ms = None;

                    for (is_primary, endpoints) in
                        Self::health_check_endpoint_order(group, upstream_prefer_ipv6)
                    {
                        if endpoints.is_empty() {
                            continue;
                        }

                        let filtered_endpoints: Vec<SocketAddr> = endpoints
                            .iter()
                            .copied()
                            .filter(|endpoint| {
                                if endpoint.is_ipv4() {
                                    upstream_ipv4_enabled
                                } else {
                                    upstream_ipv6_enabled
                                }
                            })
                            .collect();

                        if filtered_endpoints.is_empty() {
                            continue;
                        }

                        let rotation_key = (i, group.dc_idx, is_primary);
                        let start_idx = *endpoint_rotation.entry(rotation_key).or_insert(0)
                            % filtered_endpoints.len();
                        let mut next_idx = (start_idx + 1) % filtered_endpoints.len();

                        for step in 0..filtered_endpoints.len() {
                            let endpoint_idx = (start_idx + step) % filtered_endpoints.len();
                            let endpoint = filtered_endpoints[endpoint_idx];

                            let start = Instant::now();
                            let result = tokio::time::timeout(
                                Duration::from_secs(HEALTH_CHECK_CONNECT_TIMEOUT_SECS),
                                self.connect_via_upstream(
                                    i,
                                    &config,
                                    endpoint,
                                    Some(bind_rr.clone()),
                                    Duration::from_secs(HEALTH_CHECK_CONNECT_TIMEOUT_SECS),
                                ),
                            )
                            .await;

                            match result {
                                Ok(Ok(_stream)) => {
                                    group_ok = true;
                                    group_rtt_ms = Some(start.elapsed().as_secs_f64() * 1000.0);
                                    next_idx = (endpoint_idx + 1) % filtered_endpoints.len();
                                    break;
                                }
                                Ok(Err(e)) => {
                                    debug!(
                                        upstream = i,
                                        dc = group.dc_idx,
                                        endpoint = %endpoint,
                                        primary = is_primary,
                                        error = %e,
                                        "Health-check endpoint failed"
                                    );
                                }
                                Err(_) => {
                                    debug!(
                                        upstream = i,
                                        dc = group.dc_idx,
                                        endpoint = %endpoint,
                                        primary = is_primary,
                                        "Health-check endpoint timed out"
                                    );
                                }
                            }
                        }

                        endpoint_rotation.insert(rotation_key, next_idx);

                        if group_ok {
                            break;
                        }
                    }

                    if group_ok {
                        healthy_groups += 1;
                        if let (Some(dc_array_idx), Some(rtt_ms)) =
                            (UpstreamState::dc_array_idx(group.dc_idx), group_rtt_ms)
                        {
                            latency_updates.push((dc_array_idx, rtt_ms));
                        }
                    }
                }

                let mut guard = self.upstreams.write().await;
                let u = &mut guard[i];

                for (dc_array_idx, rtt_ms) in latency_updates {
                    u.dc_latency[dc_array_idx].update(rtt_ms);
                }

                if healthy_groups >= required_healthy_groups {
                    if !u.healthy {
                        info!(
                            upstream = i,
                            healthy_groups,
                            total_groups = groups.len(),
                            required_groups = required_healthy_groups,
                            "Upstream recovered by DC-group health threshold"
                        );
                    }
                    u.healthy = true;
                    u.fails = 0;
                } else {
                    u.fails += 1;
                    debug!(
                        upstream = i,
                        healthy_groups,
                        total_groups = groups.len(),
                        required_groups = required_healthy_groups,
                        fails = u.fails,
                        "Upstream health-check below DC-group threshold"
                    );
                    if u.fails >= self.unhealthy_fail_threshold {
                        u.healthy = false;
                        warn!(
                            upstream = i,
                            healthy_groups,
                            total_groups = groups.len(),
                            required_groups = required_healthy_groups,
                            fails = u.fails,
                            threshold = self.unhealthy_fail_threshold,
                            "Upstream unhealthy (insufficient reachable DC groups)"
                        );
                    }
                }

                u.last_check = std::time::Instant::now();
            }
        }
    }

    /// Get the preferred IP for a DC (for use by other components)
    #[allow(dead_code)]
    pub async fn get_dc_ip_preference(&self, dc_idx: i16) -> Option<IpPreference> {
        let guard = self.upstreams.read().await;
        if guard.is_empty() {
            return None;
        }

        UpstreamState::dc_array_idx(dc_idx).map(|idx| guard[0].dc_ip_pref[idx])
    }

    /// Get preferred DC address based on config preference
    #[allow(dead_code)]
    pub async fn get_dc_addr(&self, dc_idx: i16, prefer_ipv6: bool) -> Option<SocketAddr> {
        let arr_idx = UpstreamState::dc_array_idx(dc_idx)?;

        let ip = if prefer_ipv6 {
            TG_DATACENTERS_V6[arr_idx]
        } else {
            TG_DATACENTERS_V4[arr_idx]
        };

        Some(SocketAddr::new(ip, TG_DATACENTER_PORT))
    }
}
