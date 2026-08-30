use super::*;

impl UpstreamManager {
    pub(super) fn is_unscoped_upstream(upstream: &UpstreamConfig) -> bool {
        upstream.scopes.is_empty()
    }

    pub(super) fn should_check_in_default_dc_connectivity(
        has_unscoped: bool,
        upstream: &UpstreamConfig,
    ) -> bool {
        !has_unscoped || Self::is_unscoped_upstream(upstream)
    }

    pub fn new(
        configs: Vec<UpstreamConfig>,
        connect_retry_attempts: u32,
        connect_retry_backoff_ms: u64,
        connect_budget_ms: u64,
        tg_connect_timeout_secs: u64,
        unhealthy_fail_threshold: u32,
        connect_failfast_hard_errors: bool,
        stats: Arc<Stats>,
    ) -> Self {
        let states = configs
            .into_iter()
            .filter(|c| c.enabled)
            .map(UpstreamState::new)
            .collect();

        Self {
            upstreams: Arc::new(RwLock::new(states)),
            connect_retry_attempts: connect_retry_attempts.max(1),
            connect_retry_backoff: Duration::from_millis(connect_retry_backoff_ms),
            connect_budget: Duration::from_millis(connect_budget_ms.max(1)),
            tg_connect_timeout_secs: tg_connect_timeout_secs.max(1),
            unhealthy_fail_threshold: unhealthy_fail_threshold.max(1),
            connect_failfast_hard_errors,
            no_upstreams_warn_epoch_ms: Arc::new(AtomicU64::new(0)),
            no_healthy_warn_epoch_ms: Arc::new(AtomicU64::new(0)),
            stats,
            dns_resolver: Arc::new(GenerationDnsResolver::default()),
        }
    }

    pub(crate) fn with_dns_overrides(self, entries: &[String]) -> Result<Self> {
        self.dns_resolver.apply_entries(entries)?;
        Ok(self)
    }

    pub(crate) fn update_dns_overrides(&self, entries: &[String]) -> Result<()> {
        self.dns_resolver.apply_entries(entries)
    }

    pub(crate) fn dns_resolver(&self) -> Arc<GenerationDnsResolver> {
        Arc::clone(&self.dns_resolver)
    }

    pub(crate) async fn resolve_all(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if let Some(addr) = self.dns_resolver.resolve_socket_addr(host, port) {
            return Ok(vec![addr]);
        }
        let addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(ProxyError::Io)?
            .take(DNS_RESULT_MAX_ADDRESSES)
            .collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err(ProxyError::Proxy(format!(
                "DNS returned no addresses for {host}:{port}"
            )));
        }
        Ok(addrs)
    }

    pub(crate) async fn resolve_hostname(&self, host: &str, port: u16) -> Result<SocketAddr> {
        let addrs = self.resolve_all(host, port).await?;
        if let Some(addr) = addrs.iter().copied().find(SocketAddr::is_ipv4) {
            return Ok(addr);
        }
        addrs.first().copied().ok_or_else(|| {
            ProxyError::Proxy(format!("DNS returned no addresses for {host}:{port}"))
        })
    }

    pub(super) fn now_epoch_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    pub(super) fn should_emit_warn(last_epoch_ms: &AtomicU64, cooldown_ms: u64) -> bool {
        let now_epoch_ms = Self::now_epoch_ms();
        let previous_epoch_ms = last_epoch_ms.load(Ordering::Relaxed);
        if now_epoch_ms.saturating_sub(previous_epoch_ms) < cooldown_ms {
            return false;
        }
        last_epoch_ms
            .compare_exchange(
                previous_epoch_ms,
                now_epoch_ms,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    pub fn try_api_snapshot(&self) -> Option<UpstreamApiSnapshot> {
        let guard = self.upstreams.try_read().ok()?;
        let now = std::time::Instant::now();

        let mut summary = UpstreamApiSummarySnapshot {
            configured_total: guard.len(),
            ..UpstreamApiSummarySnapshot::default()
        };
        let mut upstreams = Vec::with_capacity(guard.len());

        for (idx, upstream) in guard.iter().enumerate() {
            if upstream.healthy {
                summary.healthy_total += 1;
            } else {
                summary.unhealthy_total += 1;
            }

            let (route_kind, address) = Self::describe_upstream(&upstream.config.upstream_type);
            match route_kind {
                UpstreamRouteKind::Direct => summary.direct_total += 1,
                UpstreamRouteKind::Socks4 => summary.socks4_total += 1,
                UpstreamRouteKind::Socks5 => summary.socks5_total += 1,
                UpstreamRouteKind::Shadowsocks => summary.shadowsocks_total += 1,
            }

            let mut dc = Vec::with_capacity(NUM_DCS);
            for dc_idx in 0..NUM_DCS {
                dc.push(UpstreamApiDcSnapshot {
                    dc: (dc_idx + 1) as i16,
                    latency_ema_ms: upstream.dc_latency[dc_idx].get(),
                    ip_preference: upstream.dc_ip_pref[dc_idx],
                });
            }

            upstreams.push(UpstreamApiItemSnapshot {
                upstream_id: idx,
                route_kind,
                address,
                weight: upstream.config.weight,
                scopes: upstream.config.scopes.clone(),
                healthy: upstream.healthy,
                fails: upstream.fails,
                last_check_age_secs: now.saturating_duration_since(upstream.last_check).as_secs(),
                effective_latency_ms: upstream.effective_latency(None),
                dc,
            });
        }

        Some(UpstreamApiSnapshot { summary, upstreams })
    }

    pub async fn api_health_summary(&self) -> UpstreamApiHealthSummary {
        let guard = self.upstreams.read().await;
        let mut summary = UpstreamApiHealthSummary {
            configured_total: guard.len(),
            healthy_total: 0,
        };
        for upstream in guard.iter() {
            if upstream.healthy {
                summary.healthy_total += 1;
            }
        }
        summary
    }

    pub(super) fn describe_upstream(upstream_type: &UpstreamType) -> (UpstreamRouteKind, String) {
        match upstream_type {
            UpstreamType::Direct { .. } => (UpstreamRouteKind::Direct, "direct".to_string()),
            UpstreamType::Socks4 { address, .. } => (UpstreamRouteKind::Socks4, address.clone()),
            UpstreamType::Socks5 { address, .. } => (UpstreamRouteKind::Socks5, address.clone()),
            UpstreamType::Shadowsocks { url, .. } => (
                UpstreamRouteKind::Shadowsocks,
                sanitize_shadowsocks_url(url).unwrap_or_else(|_| "invalid".to_string()),
            ),
        }
    }

    pub fn api_policy_snapshot(&self) -> UpstreamApiPolicySnapshot {
        UpstreamApiPolicySnapshot {
            connect_retry_attempts: self.connect_retry_attempts,
            connect_retry_backoff_ms: self.connect_retry_backoff.as_millis() as u64,
            connect_budget_ms: self.connect_budget.as_millis() as u64,
            unhealthy_fail_threshold: self.unhealthy_fail_threshold,
            connect_failfast_hard_errors: self.connect_failfast_hard_errors,
        }
    }

    pub(super) fn resolve_probe_dc_families(
        upstream: &UpstreamConfig,
        ipv4_available: bool,
        ipv6_available: bool,
    ) -> (bool, bool) {
        (
            upstream.ipv4.unwrap_or(ipv4_available),
            upstream.ipv6.unwrap_or(ipv6_available),
        )
    }

    pub(super) fn resolve_runtime_dc_families(
        upstream: &UpstreamConfig,
        dc_preference: IpPreference,
    ) -> (bool, bool) {
        let (auto_ipv4, auto_ipv6) = match dc_preference {
            IpPreference::PreferV4 => (true, false),
            IpPreference::PreferV6 => (false, true),
            IpPreference::BothWork | IpPreference::Unknown | IpPreference::Unavailable => {
                (true, true)
            }
        };

        (
            upstream.ipv4.unwrap_or(auto_ipv4),
            upstream.ipv6.unwrap_or(auto_ipv6),
        )
    }

    pub(super) fn dc_table_addr(dc_idx: i16, ipv6: bool, port: u16) -> Option<SocketAddr> {
        let arr_idx = UpstreamState::dc_array_idx(dc_idx)?;
        let ip = if ipv6 {
            TG_DATACENTERS_V6[arr_idx]
        } else {
            TG_DATACENTERS_V4[arr_idx]
        };
        Some(SocketAddr::new(ip, port))
    }

    pub(super) fn resolve_runtime_dc_target(
        target: SocketAddr,
        dc_idx: Option<i16>,
        upstream: &UpstreamConfig,
        dc_preference: IpPreference,
    ) -> Result<SocketAddr> {
        let (allow_ipv4, allow_ipv6) = Self::resolve_runtime_dc_families(upstream, dc_preference);
        let preferred_ipv6 = match dc_preference {
            IpPreference::PreferV6 => Some(true),
            IpPreference::PreferV4 => Some(false),
            IpPreference::BothWork | IpPreference::Unknown | IpPreference::Unavailable => {
                upstream.prefer.map(|prefer| prefer == 6)
            }
        };
        if let Some(preferred_ipv6) = preferred_ipv6
            && target.is_ipv6() != preferred_ipv6
        {
            let preferred_allowed = if preferred_ipv6 {
                allow_ipv6
            } else {
                allow_ipv4
            };
            if preferred_allowed {
                if let Some(dc_idx) = dc_idx
                    && let Some(remapped) =
                        Self::dc_table_addr(dc_idx, preferred_ipv6, target.port())
                {
                    return Ok(remapped);
                }
            }
        }

        if (target.is_ipv4() && allow_ipv4) || (target.is_ipv6() && allow_ipv6) {
            return Ok(target);
        }

        if !allow_ipv4 && !allow_ipv6 {
            return Err(ProxyError::Config(format!(
                "Upstream DC family policy blocks all families for target {target}"
            )));
        }

        let Some(dc_idx) = dc_idx else {
            return Err(ProxyError::Config(format!(
                "Upstream DC family policy cannot remap target {target} without dc_idx"
            )));
        };

        let remapped = if target.is_ipv4() {
            if allow_ipv6 {
                Self::dc_table_addr(dc_idx, true, target.port())
            } else {
                None
            }
        } else if allow_ipv4 {
            Self::dc_table_addr(dc_idx, false, target.port())
        } else {
            None
        };

        remapped.ok_or_else(|| {
            ProxyError::Config(format!(
                "Upstream DC family policy rejected target {target} (dc_idx={dc_idx})"
            ))
        })
    }

    #[cfg(unix)]
    pub(super) fn resolve_interface_addrs(name: &str, want_ipv6: bool) -> Vec<IpAddr> {
        use nix::ifaddrs::getifaddrs;

        let mut out = Vec::new();
        if let Ok(addrs) = getifaddrs() {
            for iface in addrs {
                if iface.interface_name != name {
                    continue;
                }
                if let Some(address) = iface.address {
                    if let Some(v4) = address.as_sockaddr_in() {
                        if !want_ipv6 {
                            out.push(IpAddr::V4(v4.ip()));
                        }
                    } else if let Some(v6) = address.as_sockaddr_in6()
                        && want_ipv6
                    {
                        out.push(IpAddr::V6(v6.ip()));
                    }
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    pub(crate) fn resolve_bind_address(
        interface: &Option<String>,
        bind_addresses: &Option<Vec<String>>,
        target: SocketAddr,
        rr: Option<&AtomicUsize>,
        validate_ip_on_interface: bool,
    ) -> Option<IpAddr> {
        let want_ipv6 = target.is_ipv6();

        if let Some(addrs) = bind_addresses.as_ref().filter(|v| !v.is_empty()) {
            let mut candidates: Vec<IpAddr> = addrs
                .iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .filter(|ip| ip.is_ipv6() == want_ipv6)
                .collect();

            // Explicit bind IP has strict priority over interface auto-selection.
            if validate_ip_on_interface
                && let Some(iface) = interface
                && iface.parse::<IpAddr>().is_err()
            {
                #[cfg(unix)]
                {
                    let iface_addrs = Self::resolve_interface_addrs(iface, want_ipv6);
                    if !iface_addrs.is_empty() {
                        candidates.retain(|ip| {
                            let ok = iface_addrs.contains(ip);
                            if !ok {
                                warn!(
                                    interface = %iface,
                                    bind_ip = %ip,
                                    target = %target,
                                    "Configured bind address is not assigned to interface"
                                );
                            }
                            ok
                        });
                    } else if !candidates.is_empty() {
                        warn!(
                            interface = %iface,
                            target = %target,
                            "Configured interface has no addresses for target family"
                        );
                        candidates.clear();
                    }
                }
            }

            if !candidates.is_empty() {
                if let Some(counter) = rr {
                    let idx = counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                    return Some(candidates[idx]);
                }
                return candidates.first().copied();
            }

            if validate_ip_on_interface
                && interface
                    .as_ref()
                    .is_some_and(|iface| iface.parse::<IpAddr>().is_err())
            {
                warn!(
                    interface = interface.as_deref().unwrap_or(""),
                    target = %target,
                    "No valid bind_addresses left for interface"
                );
            }

            return None;
        }

        if let Some(iface) = interface {
            if let Ok(ip) = iface.parse::<IpAddr>() {
                if ip.is_ipv6() == want_ipv6 {
                    return Some(ip);
                }
            } else {
                #[cfg(unix)]
                if let Some(ip) = resolve_interface_ip(iface, want_ipv6) {
                    return Some(ip);
                }
            }
        }

        None
    }

    pub(super) async fn connect_hostname_with_dns_override(
        &self,
        address: &str,
        connect_timeout: Duration,
    ) -> Result<TcpStream> {
        if let Some((host, port)) = split_host_port(address)
            && let Some(addr) = self.dns_resolver.resolve_socket_addr(&host, port)
        {
            return match tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(e)) => Err(ProxyError::Io(e)),
                Err(_) => Err(ProxyError::ConnectionTimeout {
                    addr: addr.to_string(),
                }),
            };
        }

        match tokio::time::timeout(connect_timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(ProxyError::Io(e)),
            Err(_) => Err(ProxyError::ConnectionTimeout {
                addr: address.to_string(),
            }),
        }
    }

    pub(super) fn retry_backoff_with_jitter(&self) -> Duration {
        if self.connect_retry_backoff.is_zero() {
            return Duration::ZERO;
        }
        let base_ms = self.connect_retry_backoff.as_millis() as u64;
        if base_ms == 0 {
            return self.connect_retry_backoff;
        }
        let jitter_cap_ms = (base_ms / 2).max(1);
        let jitter_ms = rand::rng().random_range(0..=jitter_cap_ms);
        Duration::from_millis(base_ms.saturating_add(jitter_ms))
    }

    pub(super) fn is_hard_connect_error(error: &ProxyError) -> bool {
        match error {
            ProxyError::Config(_) | ProxyError::ConnectionRefused { .. } => true,
            ProxyError::Io(ioe) => matches!(
                ioe.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::AddrInUse
                    | std::io::ErrorKind::AddrNotAvailable
                    | std::io::ErrorKind::InvalidInput
                    | std::io::ErrorKind::Unsupported
            ),
            _ => false,
        }
    }
}
