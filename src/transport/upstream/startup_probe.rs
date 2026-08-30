use super::*;

impl UpstreamManager {
    /// Ping all Telegram DCs through all upstreams.
    /// Tests BOTH IPv6 and IPv4, returns separate results for each.
    pub async fn ping_all_dcs(
        &self,
        prefer_ipv6: bool,
        dc_overrides: &HashMap<String, Vec<String>>,
        ipv4_enabled: bool,
        ipv6_enabled: bool,
    ) -> Vec<StartupPingResult> {
        let upstreams: Vec<(usize, UpstreamConfig, Arc<AtomicUsize>)> = {
            let guard = self.upstreams.read().await;
            guard
                .iter()
                .enumerate()
                .map(|(i, u)| (i, u.config.clone(), u.bind_rr.clone()))
                .collect()
        };
        let has_unscoped = upstreams
            .iter()
            .any(|(_, cfg, _)| Self::is_unscoped_upstream(cfg));

        let mut all_results = Vec::new();

        for (upstream_idx, upstream_config, bind_rr) in &upstreams {
            // DC connectivity checks should follow the default routing path.
            // Scoped upstreams are included only when no unscoped upstream exists.
            if !Self::should_check_in_default_dc_connectivity(has_unscoped, upstream_config) {
                continue;
            }

            let (upstream_ipv4_enabled, upstream_ipv6_enabled) =
                Self::resolve_probe_dc_families(upstream_config, ipv4_enabled, ipv6_enabled);
            let upstream_prefer_ipv6 = upstream_config.prefer_ipv6(prefer_ipv6);
            let upstream_name = match &upstream_config.upstream_type {
                UpstreamType::Direct {
                    interface,
                    bind_addresses,
                    bindtodevice,
                } => {
                    let mut direct_parts = Vec::new();
                    if let Some(dev) = interface.as_deref().filter(|v| !v.is_empty()) {
                        direct_parts.push(format!("dev={dev}"));
                    }
                    if let Some(src) = bind_addresses.as_ref().filter(|v| !v.is_empty()) {
                        direct_parts.push(format!("src={}", src.join(",")));
                    }
                    if let Some(device) = bindtodevice.as_deref().filter(|v| !v.is_empty()) {
                        direct_parts.push(format!("bindtodevice={device}"));
                    }
                    if direct_parts.is_empty() {
                        "direct".to_string()
                    } else {
                        format!("direct {}", direct_parts.join(" "))
                    }
                }
                UpstreamType::Socks4 { address, .. } => format!("socks4://{}", address),
                UpstreamType::Socks5 { address, .. } => format!("socks5://{}", address),
                UpstreamType::Shadowsocks { url, .. } => {
                    let address =
                        sanitize_shadowsocks_url(url).unwrap_or_else(|_| "invalid".to_string());
                    format!("shadowsocks://{address}")
                }
            };

            let mut v6_results = Vec::with_capacity(NUM_DCS);
            if upstream_ipv6_enabled {
                for dc_zero_idx in 0..NUM_DCS {
                    let dc_v6 = TG_DATACENTERS_V6[dc_zero_idx];
                    let addr_v6 = SocketAddr::new(dc_v6, TG_DATACENTER_PORT);

                    let result = tokio::time::timeout(
                        Duration::from_secs(DC_PING_TIMEOUT_SECS),
                        self.ping_single_dc(
                            *upstream_idx,
                            upstream_config,
                            Some(bind_rr.clone()),
                            addr_v6,
                        ),
                    )
                    .await;

                    let ping_result = match result {
                        Ok(Ok(rtt_ms)) => {
                            let mut guard = self.upstreams.write().await;
                            if let Some(u) = guard.get_mut(*upstream_idx) {
                                u.dc_latency[dc_zero_idx].update(rtt_ms);
                            }
                            DcPingResult {
                                dc_idx: dc_zero_idx + 1,
                                dc_addr: addr_v6,
                                rtt_ms: Some(rtt_ms),
                                error: None,
                            }
                        }
                        Ok(Err(e)) => DcPingResult {
                            dc_idx: dc_zero_idx + 1,
                            dc_addr: addr_v6,
                            rtt_ms: None,
                            error: Some(e.to_string()),
                        },
                        Err(_) => DcPingResult {
                            dc_idx: dc_zero_idx + 1,
                            dc_addr: addr_v6,
                            rtt_ms: None,
                            error: Some("timeout".to_string()),
                        },
                    };
                    v6_results.push(ping_result);
                }
            } else {
                for dc_zero_idx in 0..NUM_DCS {
                    let dc_v6 = TG_DATACENTERS_V6[dc_zero_idx];
                    v6_results.push(DcPingResult {
                        dc_idx: dc_zero_idx + 1,
                        dc_addr: SocketAddr::new(dc_v6, TG_DATACENTER_PORT),
                        rtt_ms: None,
                        error: Some(if ipv6_enabled {
                            "ipv6 disabled by upstream policy".to_string()
                        } else {
                            "ipv6 disabled".to_string()
                        }),
                    });
                }
            }

            let mut v4_results = Vec::with_capacity(NUM_DCS);
            if upstream_ipv4_enabled {
                for dc_zero_idx in 0..NUM_DCS {
                    let dc_v4 = TG_DATACENTERS_V4[dc_zero_idx];
                    let addr_v4 = SocketAddr::new(dc_v4, TG_DATACENTER_PORT);

                    let result = tokio::time::timeout(
                        Duration::from_secs(DC_PING_TIMEOUT_SECS),
                        self.ping_single_dc(
                            *upstream_idx,
                            upstream_config,
                            Some(bind_rr.clone()),
                            addr_v4,
                        ),
                    )
                    .await;

                    let ping_result = match result {
                        Ok(Ok(rtt_ms)) => {
                            let mut guard = self.upstreams.write().await;
                            if let Some(u) = guard.get_mut(*upstream_idx) {
                                u.dc_latency[dc_zero_idx].update(rtt_ms);
                            }
                            DcPingResult {
                                dc_idx: dc_zero_idx + 1,
                                dc_addr: addr_v4,
                                rtt_ms: Some(rtt_ms),
                                error: None,
                            }
                        }
                        Ok(Err(e)) => DcPingResult {
                            dc_idx: dc_zero_idx + 1,
                            dc_addr: addr_v4,
                            rtt_ms: None,
                            error: Some(e.to_string()),
                        },
                        Err(_) => DcPingResult {
                            dc_idx: dc_zero_idx + 1,
                            dc_addr: addr_v4,
                            rtt_ms: None,
                            error: Some("timeout".to_string()),
                        },
                    };
                    v4_results.push(ping_result);
                }
            } else {
                for dc_zero_idx in 0..NUM_DCS {
                    let dc_v4 = TG_DATACENTERS_V4[dc_zero_idx];
                    v4_results.push(DcPingResult {
                        dc_idx: dc_zero_idx + 1,
                        dc_addr: SocketAddr::new(dc_v4, TG_DATACENTER_PORT),
                        rtt_ms: None,
                        error: Some(if ipv4_enabled {
                            "ipv4 disabled by upstream policy".to_string()
                        } else {
                            "ipv4 disabled".to_string()
                        }),
                    });
                }
            }

            // === Ping DC overrides (v4/v6) ===
            for (dc_key, addrs) in dc_overrides {
                let dc_num: i16 = match dc_key.parse::<i16>() {
                    Ok(v) if v > 0 => v,
                    Err(_) => {
                        warn!(dc = %dc_key, "Invalid dc_overrides key, skipping");
                        continue;
                    }
                    _ => continue,
                };
                let dc_idx = dc_num as usize;
                for addr_str in addrs {
                    match addr_str.parse::<SocketAddr>() {
                        Ok(addr) => {
                            let is_v6 = addr.is_ipv6();
                            if (is_v6 && !upstream_ipv6_enabled)
                                || (!is_v6 && !upstream_ipv4_enabled)
                            {
                                continue;
                            }
                            let result = tokio::time::timeout(
                                Duration::from_secs(DC_PING_TIMEOUT_SECS),
                                self.ping_single_dc(
                                    *upstream_idx,
                                    upstream_config,
                                    Some(bind_rr.clone()),
                                    addr,
                                ),
                            )
                            .await;

                            let ping_result = match result {
                                Ok(Ok(rtt_ms)) => DcPingResult {
                                    dc_idx,
                                    dc_addr: addr,
                                    rtt_ms: Some(rtt_ms),
                                    error: None,
                                },
                                Ok(Err(e)) => DcPingResult {
                                    dc_idx,
                                    dc_addr: addr,
                                    rtt_ms: None,
                                    error: Some(e.to_string()),
                                },
                                Err(_) => DcPingResult {
                                    dc_idx,
                                    dc_addr: addr,
                                    rtt_ms: None,
                                    error: Some("timeout".to_string()),
                                },
                            };

                            if is_v6 {
                                v6_results.push(ping_result);
                            } else {
                                v4_results.push(ping_result);
                            }
                        }
                        Err(_) => {
                            warn!(dc = %dc_idx, addr = %addr_str, "Invalid dc_overrides address, skipping")
                        }
                    }
                }
            }

            // Check if both IP versions have at least one working DC
            let v6_has_working = v6_results.iter().any(|r| r.rtt_ms.is_some());
            let v4_has_working = v4_results.iter().any(|r| r.rtt_ms.is_some());
            let both_available = v6_has_working && v4_has_working;

            // Update IP preference for each DC
            {
                let mut guard = self.upstreams.write().await;
                if let Some(u) = guard.get_mut(*upstream_idx) {
                    for dc_zero_idx in 0..NUM_DCS {
                        let v6_ok = v6_results[dc_zero_idx].rtt_ms.is_some();
                        let v4_ok = v4_results[dc_zero_idx].rtt_ms.is_some();

                        u.dc_ip_pref[dc_zero_idx] = match (v6_ok, v4_ok) {
                            (true, true) => IpPreference::BothWork,
                            (true, false) => IpPreference::PreferV6,
                            (false, true) => IpPreference::PreferV4,
                            (false, false) => IpPreference::Unavailable,
                        };
                    }
                }
            }

            all_results.push(StartupPingResult {
                v6_results,
                v4_results,
                upstream_name,
                prefer_ipv6: upstream_prefer_ipv6,
                both_available,
            });
        }

        all_results
    }

    pub(super) async fn ping_single_dc(
        &self,
        upstream_id: usize,
        config: &UpstreamConfig,
        bind_rr: Option<Arc<AtomicUsize>>,
        target: SocketAddr,
    ) -> Result<f64> {
        let start = Instant::now();
        let _ = self
            .connect_via_upstream(
                upstream_id,
                config,
                target,
                bind_rr,
                Duration::from_secs(DC_PING_TIMEOUT_SECS),
            )
            .await?;
        Ok(start.elapsed().as_secs_f64() * 1000.0)
    }

    pub(super) fn required_healthy_group_count(total_groups: usize) -> usize {
        if total_groups == 0 {
            0
        } else {
            total_groups.min(MIN_HEALTHY_DC_GROUPS)
        }
    }

    pub(super) fn build_health_check_groups(
        ipv4_enabled: bool,
        ipv6_enabled: bool,
        dc_overrides: &HashMap<String, Vec<String>>,
    ) -> Vec<HealthCheckGroup> {
        let mut v4_by_dc: HashMap<i16, Vec<SocketAddr>> = HashMap::new();
        let mut v6_by_dc: HashMap<i16, Vec<SocketAddr>> = HashMap::new();

        if ipv4_enabled {
            for (idx, dc_ip) in TG_DATACENTERS_V4.iter().enumerate() {
                let dc_idx = (idx + 1) as i16;
                v4_by_dc
                    .entry(dc_idx)
                    .or_default()
                    .push(SocketAddr::new(*dc_ip, TG_DATACENTER_PORT));
            }
        }

        if ipv6_enabled {
            for (idx, dc_ip) in TG_DATACENTERS_V6.iter().enumerate() {
                let dc_idx = (idx + 1) as i16;
                v6_by_dc
                    .entry(dc_idx)
                    .or_default()
                    .push(SocketAddr::new(*dc_ip, TG_DATACENTER_PORT));
            }
        }

        for (dc_key, addrs) in dc_overrides {
            let dc_idx = match dc_key.parse::<i16>() {
                Ok(v) if v > 0 => v,
                _ => {
                    warn!(dc = %dc_key, "Invalid dc_overrides key for health-check, skipping");
                    continue;
                }
            };

            for addr_str in addrs {
                match addr_str.parse::<SocketAddr>() {
                    Ok(addr) if addr.is_ipv6() => {
                        if ipv6_enabled {
                            v6_by_dc.entry(dc_idx).or_default().push(addr);
                        }
                    }
                    Ok(addr) => {
                        if ipv4_enabled {
                            v4_by_dc.entry(dc_idx).or_default().push(addr);
                        }
                    }
                    Err(_) => {
                        warn!(
                            dc = %dc_idx,
                            addr = %addr_str,
                            "Invalid dc_overrides address for health-check, skipping"
                        );
                    }
                }
            }
        }

        for addrs in v4_by_dc.values_mut() {
            addrs.sort_unstable();
            addrs.dedup();
        }
        for addrs in v6_by_dc.values_mut() {
            addrs.sort_unstable();
            addrs.dedup();
        }

        let mut all_dcs = BTreeSet::new();
        all_dcs.extend(v4_by_dc.keys().copied());
        all_dcs.extend(v6_by_dc.keys().copied());

        let mut groups = Vec::with_capacity(all_dcs.len());
        for dc_idx in all_dcs {
            let v4_endpoints = v4_by_dc.remove(&dc_idx).unwrap_or_default();
            let v6_endpoints = v6_by_dc.remove(&dc_idx).unwrap_or_default();

            if v4_endpoints.is_empty() && v6_endpoints.is_empty() {
                continue;
            }

            groups.push(HealthCheckGroup {
                dc_idx,
                v4_endpoints,
                v6_endpoints,
            });
        }

        groups
    }

    pub(super) fn health_check_endpoint_order(
        group: &HealthCheckGroup,
        prefer_ipv6: bool,
    ) -> [(bool, &[SocketAddr]); 2] {
        if prefer_ipv6 {
            [(true, &group.v6_endpoints), (false, &group.v4_endpoints)]
        } else {
            [(true, &group.v4_endpoints), (false, &group.v6_endpoints)]
        }
    }
}
