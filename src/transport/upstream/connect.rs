use super::*;

impl UpstreamManager {
    pub(super) async fn connect_selected_upstream(
        &self,
        idx: usize,
        upstream: UpstreamConfig,
        target: SocketAddr,
        dc_idx: Option<i16>,
        bind_rr: Option<Arc<AtomicUsize>>,
    ) -> Result<(UpstreamStream, UpstreamEgressInfo)> {
        let connect_started_at = Instant::now();
        let mut last_error: Option<ProxyError> = None;
        let mut attempts_used = 0u32;
        for attempt in 1..=self.connect_retry_attempts {
            let elapsed = connect_started_at.elapsed();
            if elapsed >= self.connect_budget {
                last_error = Some(ProxyError::ConnectionTimeout {
                    addr: target.to_string(),
                });
                break;
            }
            let remaining_budget = self.connect_budget.saturating_sub(elapsed);
            let attempt_timeout =
                Duration::from_secs(self.tg_connect_timeout_secs).min(remaining_budget);
            if attempt_timeout.is_zero() {
                last_error = Some(ProxyError::ConnectionTimeout {
                    addr: target.to_string(),
                });
                break;
            }
            attempts_used = attempt;
            self.stats.increment_upstream_connect_attempt_total();
            let start = Instant::now();
            match self
                .connect_via_upstream(idx, &upstream, target, bind_rr.clone(), attempt_timeout)
                .await
            {
                Ok((stream, egress)) => {
                    let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
                    self.stats.increment_upstream_connect_success_total();
                    self.stats
                        .observe_upstream_connect_attempts_per_request(attempts_used);
                    self.stats.observe_upstream_connect_duration_ms(
                        connect_started_at.elapsed().as_millis() as u64,
                        true,
                    );
                    let mut guard = self.upstreams.write().await;
                    if let Some(u) = guard.get_mut(idx) {
                        if !u.healthy {
                            debug!(rtt_ms = format!("{:.1}", rtt_ms), "Upstream recovered");
                        }
                        if attempt > 1 {
                            debug!(
                                attempt,
                                attempts = self.connect_retry_attempts,
                                rtt_ms = format!("{:.1}", rtt_ms),
                                "Upstream connect recovered after retry"
                            );
                        }
                        u.healthy = true;
                        u.fails = 0;

                        if let Some(di) = dc_idx.and_then(UpstreamState::dc_array_idx) {
                            u.dc_latency[di].update(rtt_ms);
                        }
                    }
                    return Ok((stream, egress));
                }
                Err(e) => {
                    let hard_error =
                        self.connect_failfast_hard_errors && Self::is_hard_connect_error(&e);
                    if hard_error {
                        self.stats
                            .increment_upstream_connect_failfast_hard_error_total();
                    }
                    if attempt < self.connect_retry_attempts && !hard_error {
                        debug!(
                            attempt,
                            attempts = self.connect_retry_attempts,
                            target = %target,
                            error = %e,
                            "Upstream connect attempt failed, retrying"
                        );
                        let backoff = self.retry_backoff_with_jitter();
                        if !backoff.is_zero() {
                            tokio::time::sleep(backoff).await;
                        }
                    } else if hard_error {
                        debug!(
                            attempt,
                            attempts = self.connect_retry_attempts,
                            target = %target,
                            error = %e,
                            "Upstream connect failed with hard error, failfast is active"
                        );
                    }
                    last_error = Some(e);
                    if hard_error {
                        break;
                    }
                }
            }
        }

        self.stats.increment_upstream_connect_fail_total();
        self.stats
            .observe_upstream_connect_attempts_per_request(attempts_used);
        self.stats.observe_upstream_connect_duration_ms(
            connect_started_at.elapsed().as_millis() as u64,
            false,
        );

        let error = last_error.unwrap_or_else(|| {
            ProxyError::Config("Upstream connect attempts exhausted".to_string())
        });

        let mut guard = self.upstreams.write().await;
        if let Some(u) = guard.get_mut(idx) {
            // Intermediate attempts are intentionally ignored here.
            // Health state is degraded only when the entire connect cycle fails.
            u.fails += 1;
            warn!(
                fails = u.fails,
                attempts = self.connect_retry_attempts,
                "Upstream failed after retries: {}",
                error
            );
            if u.fails >= self.unhealthy_fail_threshold {
                u.healthy = false;
                warn!(
                    fails = u.fails,
                    threshold = self.unhealthy_fail_threshold,
                    "Upstream marked unhealthy"
                );
            }
        }
        Err(error)
    }

    pub(super) async fn connect_via_upstream(
        &self,
        upstream_id: usize,
        config: &UpstreamConfig,
        target: SocketAddr,
        bind_rr: Option<Arc<AtomicUsize>>,
        connect_timeout: Duration,
    ) -> Result<(UpstreamStream, UpstreamEgressInfo)> {
        match &config.upstream_type {
            UpstreamType::Direct {
                interface,
                bind_addresses,
                bindtodevice,
            } => {
                let bind_ip = Self::resolve_bind_address(
                    interface,
                    bind_addresses,
                    target,
                    bind_rr.as_deref(),
                    true,
                );
                if bind_ip.is_none() && bind_addresses.as_ref().is_some_and(|v| !v.is_empty()) {
                    return Err(ProxyError::Config(format!(
                        "No valid bind_addresses for target family {target}"
                    )));
                }

                let socket = create_outgoing_socket_bound(target, bind_ip)?;
                if let Some(device) = bindtodevice.as_deref().filter(|value| !value.is_empty()) {
                    bind_outgoing_socket_to_device(&socket, device).map_err(ProxyError::Io)?;
                    debug!(bindtodevice = %device, target = %target, "Pinned socket to interface");
                }
                if let Some(ip) = bind_ip {
                    debug!(bind = %ip, target = %target, "Bound outgoing socket");
                } else if interface.is_some() || bind_addresses.is_some() {
                    debug!(target = %target, "No matching bind address for target family");
                }

                socket.set_nonblocking(true)?;
                match socket.connect(&target.into()) {
                    Ok(()) => {}
                    Err(err)
                        if err.raw_os_error() == Some(libc::EINPROGRESS)
                            || err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) => return Err(ProxyError::Io(err)),
                }

                let std_stream: std::net::TcpStream = socket.into();
                let stream = TcpStream::from_std(std_stream)?;

                match tokio::time::timeout(connect_timeout, stream.writable()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => return Err(ProxyError::Io(e)),
                    Err(_) => {
                        return Err(ProxyError::ConnectionTimeout {
                            addr: target.to_string(),
                        });
                    }
                }
                if let Some(e) = stream.take_error()? {
                    return Err(ProxyError::Io(e));
                }

                let local_addr = stream.local_addr().ok();
                Ok((
                    UpstreamStream::Tcp(stream),
                    UpstreamEgressInfo {
                        upstream_id,
                        route_kind: UpstreamRouteKind::Direct,
                        local_addr,
                        direct_bind_ip: bind_ip,
                        socks_bound_addr: None,
                        socks_proxy_addr: None,
                    },
                ))
            }
            UpstreamType::Socks4 {
                address,
                interface,
                user_id,
            } => {
                // Try to parse as SocketAddr first (IP:port), otherwise treat as hostname:port
                let mut stream = if let Ok(proxy_addr) = address.parse::<SocketAddr>() {
                    // IP:port format - use socket with optional interface binding
                    let bind_ip = Self::resolve_bind_address(
                        interface,
                        &None,
                        proxy_addr,
                        bind_rr.as_deref(),
                        false,
                    );

                    let socket = create_outgoing_socket_bound(proxy_addr, bind_ip)?;

                    socket.set_nonblocking(true)?;
                    match socket.connect(&proxy_addr.into()) {
                        Ok(()) => {}
                        Err(err)
                            if err.raw_os_error() == Some(libc::EINPROGRESS)
                                || err.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(err) => return Err(ProxyError::Io(err)),
                    }

                    let std_stream: std::net::TcpStream = socket.into();
                    let stream = TcpStream::from_std(std_stream)?;

                    match tokio::time::timeout(connect_timeout, stream.writable()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => return Err(ProxyError::Io(e)),
                        Err(_) => {
                            return Err(ProxyError::ConnectionTimeout {
                                addr: proxy_addr.to_string(),
                            });
                        }
                    }
                    if let Some(e) = stream.take_error()? {
                        return Err(ProxyError::Io(e));
                    }
                    stream
                } else {
                    // Hostname:port format - use tokio DNS resolution
                    // Note: interface binding is not supported for hostnames
                    if interface.is_some() {
                        warn!(
                            "SOCKS4 interface binding is not supported for hostname addresses, ignoring"
                        );
                    }
                    self.connect_hostname_with_dns_override(address, connect_timeout)
                        .await?
                };

                // replace socks user_id with config.selected_scope, if set
                let scope: Option<&str> =
                    Some(config.selected_scope.as_str()).filter(|s| !s.is_empty());
                let _user_id: Option<&str> = scope.or(user_id.as_deref());

                let bound = match tokio::time::timeout(
                    connect_timeout,
                    connect_socks4(&mut stream, target, _user_id),
                )
                .await
                {
                    Ok(Ok(bound)) => bound,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(ProxyError::ConnectionTimeout {
                            addr: target.to_string(),
                        });
                    }
                };
                let local_addr = stream.local_addr().ok();
                let socks_proxy_addr = stream.peer_addr().ok();
                Ok((
                    UpstreamStream::Tcp(stream),
                    UpstreamEgressInfo {
                        upstream_id,
                        route_kind: UpstreamRouteKind::Socks4,
                        local_addr,
                        direct_bind_ip: None,
                        socks_bound_addr: Some(bound.addr),
                        socks_proxy_addr,
                    },
                ))
            }
            UpstreamType::Socks5 {
                address,
                interface,
                username,
                password,
            } => {
                // Try to parse as SocketAddr first (IP:port), otherwise treat as hostname:port
                let mut stream = if let Ok(proxy_addr) = address.parse::<SocketAddr>() {
                    // IP:port format - use socket with optional interface binding
                    let bind_ip = Self::resolve_bind_address(
                        interface,
                        &None,
                        proxy_addr,
                        bind_rr.as_deref(),
                        false,
                    );

                    let socket = create_outgoing_socket_bound(proxy_addr, bind_ip)?;

                    socket.set_nonblocking(true)?;
                    match socket.connect(&proxy_addr.into()) {
                        Ok(()) => {}
                        Err(err)
                            if err.raw_os_error() == Some(libc::EINPROGRESS)
                                || err.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(err) => return Err(ProxyError::Io(err)),
                    }

                    let std_stream: std::net::TcpStream = socket.into();
                    let stream = TcpStream::from_std(std_stream)?;

                    match tokio::time::timeout(connect_timeout, stream.writable()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => return Err(ProxyError::Io(e)),
                        Err(_) => {
                            return Err(ProxyError::ConnectionTimeout {
                                addr: proxy_addr.to_string(),
                            });
                        }
                    }
                    if let Some(e) = stream.take_error()? {
                        return Err(ProxyError::Io(e));
                    }
                    stream
                } else {
                    // Hostname:port format - use tokio DNS resolution
                    // Note: interface binding is not supported for hostnames
                    if interface.is_some() {
                        warn!(
                            "SOCKS5 interface binding is not supported for hostname addresses, ignoring"
                        );
                    }
                    self.connect_hostname_with_dns_override(address, connect_timeout)
                        .await?
                };

                debug!(config = ?config, "Socks5 connection");
                // replace socks user:pass with config.selected_scope, if set
                let scope: Option<&str> =
                    Some(config.selected_scope.as_str()).filter(|s| !s.is_empty());
                let _username: Option<&str> = scope.or(username.as_deref());
                let _password: Option<&str> = scope.or(password.as_deref());

                let bound = match tokio::time::timeout(
                    connect_timeout,
                    connect_socks5(&mut stream, target, _username, _password),
                )
                .await
                {
                    Ok(Ok(bound)) => bound,
                    Ok(Err(e)) => return Err(e),
                    Err(_) => {
                        return Err(ProxyError::ConnectionTimeout {
                            addr: target.to_string(),
                        });
                    }
                };
                let local_addr = stream.local_addr().ok();
                let socks_proxy_addr = stream.peer_addr().ok();
                Ok((
                    UpstreamStream::Tcp(stream),
                    UpstreamEgressInfo {
                        upstream_id,
                        route_kind: UpstreamRouteKind::Socks5,
                        local_addr,
                        direct_bind_ip: None,
                        socks_bound_addr: Some(bound.addr),
                        socks_proxy_addr,
                    },
                ))
            }
            UpstreamType::Shadowsocks { url, interface } => {
                let stream = connect_shadowsocks(url, interface, target, connect_timeout).await?;
                let local_addr = stream.get_ref().local_addr().ok();
                Ok((
                    UpstreamStream::Shadowsocks(Box::new(stream)),
                    UpstreamEgressInfo {
                        upstream_id,
                        route_kind: UpstreamRouteKind::Shadowsocks,
                        local_addr,
                        direct_bind_ip: None,
                        socks_bound_addr: None,
                        socks_proxy_addr: None,
                    },
                ))
            }
        }
    }
}
