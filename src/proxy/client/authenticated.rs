use super::*;

impl RunningClientHandler {
    /// Main dispatch after successful handshake.
    /// Two modes:
    ///   - Direct: TCP relay to TG DC (existing behavior)
    ///   - Middle Proxy: RPC multiplex through ME pool (supports CDN DCs)
    #[cfg(test)]
    pub(super) async fn handle_authenticated_static<R, W>(
        client_reader: CryptoReader<R>,
        client_writer: CryptoWriter<W>,
        success: HandshakeSuccess,
        upstream_manager: Arc<UpstreamManager>,
        stats: Arc<Stats>,
        config: Arc<ProxyConfig>,
        buffer_pool: Arc<BufferPool>,
        rng: Arc<SecureRandom>,
        me_pool: Option<Arc<MePool>>,
        route_runtime: Arc<RouteRuntimeController>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        ip_tracker: Arc<UserIpTracker>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        Self::handle_authenticated_static_with_shared(
            client_reader,
            client_writer,
            success,
            upstream_manager,
            stats,
            config,
            buffer_pool,
            rng,
            me_pool,
            None,
            route_runtime,
            local_addr,
            peer_addr,
            ip_tracker,
            ProxySharedState::new(),
        )
        .await
    }

    pub(super) async fn handle_authenticated_static_with_shared<R, W>(
        client_reader: CryptoReader<R>,
        client_writer: CryptoWriter<W>,
        success: HandshakeSuccess,
        upstream_manager: Arc<UpstreamManager>,
        stats: Arc<Stats>,
        config: Arc<ProxyConfig>,
        buffer_pool: Arc<BufferPool>,
        rng: Arc<SecureRandom>,
        me_pool: Option<Arc<MePool>>,
        me_pool_runtime: Option<Arc<RwLock<Option<Arc<MePool>>>>>,
        route_runtime: Arc<RouteRuntimeController>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        ip_tracker: Arc<UserIpTracker>,
        shared: Arc<ProxySharedState>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        run_authenticated(
            client_reader,
            client_writer,
            success,
            ClientRuntimeDeps {
                config,
                stats,
                upstream_manager,
                buffer_pool,
                rng,
                me_pool,
                me_pool_runtime,
                route_runtime,
                ip_tracker,
                shared,
            },
            local_addr,
            peer_addr,
            ConntrackClosePolicy::Publish,
        )
        .await
    }

    #[cfg(test)]
    pub(super) async fn acquire_user_connection_reservation_static(
        user: &str,
        config: &ProxyConfig,
        stats: Arc<Stats>,
        peer_addr: SocketAddr,
        ip_tracker: Arc<UserIpTracker>,
    ) -> Result<UserConnectionReservation> {
        acquire_user_connection_reservation(user, config, stats, peer_addr, ip_tracker).await
    }

    #[cfg(test)]
    pub(super) async fn check_user_limits_static(
        user: &str,
        config: &ProxyConfig,
        stats: &Stats,
        peer_addr: SocketAddr,
        ip_tracker: &UserIpTracker,
    ) -> Result<()> {
        if let Some(expiration) = config.access.user_expirations.get(user)
            && chrono::Utc::now() > *expiration
        {
            return Err(ProxyError::UserExpired {
                user: user.to_string(),
            });
        }

        if let Some(quota) = config.access.user_data_quota.get(user)
            && stats.get_user_quota_used(user) >= *quota
        {
            return Err(ProxyError::DataQuotaExceeded {
                user: user.to_string(),
            });
        }

        let limit = config
            .access
            .user_max_tcp_conns
            .get(user)
            .copied()
            .filter(|limit| *limit > 0)
            .or((config.access.user_max_tcp_conns_global_each > 0)
                .then_some(config.access.user_max_tcp_conns_global_each))
            .map(|v| v as u64);
        if !stats.try_acquire_user_curr_connects(user, limit) {
            return Err(ProxyError::ConnectionLimitExceeded {
                user: user.to_string(),
            });
        }

        match ip_tracker.check_and_add(user, peer_addr.ip()).await {
            Ok(()) => {
                ip_tracker.remove_ip(user, peer_addr.ip()).await;
            }
            Err(reason) => {
                stats.decrement_user_curr_connects(user);
                warn!(
                    user = %user,
                    ip = %peer_addr.ip(),
                    reason = %reason,
                    "IP limit exceeded"
                );
                return Err(ProxyError::ConnectionLimitExceeded {
                    user: user.to_string(),
                });
            }
        }

        stats.decrement_user_curr_connects(user);
        Ok(())
    }
}
