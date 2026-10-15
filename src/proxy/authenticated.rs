use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tracing::warn;

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;
use crate::error::{ProxyError, Result};
use crate::ip_tracker::UserIpTracker;
use crate::proxy::direct_relay::handle_via_direct_with_shared_and_conntrack;
use crate::proxy::handshake::HandshakeSuccess;
use crate::proxy::middle_relay::{handle_via_middle_proxy, handle_via_middle_proxy_with_conntrack};
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::shared_state::{ConntrackClosePolicy, ProxySharedState};
use crate::proxy::user_admission::UserIncarnation;
use crate::proxy::user_connection_authority::UserConnectionPermit;
use crate::stats::{Stats, UserConnectionObservation, UserQuotaHandle};
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::MePool;

#[cfg(test)]
#[path = "authenticated/strict_me_tests.rs"]
mod strict_me_tests;

/// Immutable dependency snapshot pinned by one authenticated client stream.
#[derive(Clone)]
pub(crate) struct ClientRuntimeDeps {
    /// Immutable effective configuration pinned for this stream.
    pub(crate) config: Arc<ProxyConfig>,
    /// Process statistics registry.
    pub(crate) stats: Arc<Stats>,
    /// Direct Telegram upstream connector.
    pub(crate) upstream_manager: Arc<UpstreamManager>,
    /// Shared relay buffer pool.
    pub(crate) buffer_pool: Arc<BufferPool>,
    /// Process cryptographic random source.
    pub(crate) rng: Arc<SecureRandom>,
    /// Startup Middle-End pool, when immediately available.
    pub(crate) me_pool: Option<Arc<MePool>>,
    /// Hot-swappable Middle-End pool holder.
    pub(crate) me_pool_runtime: Option<Arc<RwLock<Option<Arc<MePool>>>>>,
    /// Route-mode controller shared by active generations.
    pub(crate) route_runtime: Arc<RouteRuntimeController>,
    /// Per-user source-IP admission tracker.
    pub(crate) ip_tracker: Arc<UserIpTracker>,
    /// Process-shared admission and relay coordination state.
    pub(crate) shared: Arc<ProxySharedState>,
}

/// Runs admission and relay after a successful MTProxy handshake.
pub(crate) async fn run_authenticated<R, W>(
    client_reader: CryptoReader<R>,
    client_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    deps: ClientRuntimeDeps,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    conntrack_close_policy: ConntrackClosePolicy,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let user = success.user.clone();
    let Some(credential_id) = deps.config.runtime_user_credential_id(&user) else {
        warn!(user = %user, "Authenticated user is absent from the runtime credential snapshot");
        return Err(ProxyError::UserDisabled { user });
    };
    let Some(user_incarnation) = deps
        .shared
        .authenticated_user_incarnation(&user, credential_id)
    else {
        warn!(user = %user, "Disabled user rejected");
        return Err(ProxyError::UserDisabled { user });
    };

    let user_reservation = acquire_user_connection_reservation_for_incarnation(
        &user,
        user_incarnation,
        &deps.config,
        Arc::clone(&deps.stats),
        peer_addr,
        Arc::clone(&deps.ip_tracker),
    )
    .await
    .map_err(|error| {
        warn!(user = %user, error = %error, "User admission check failed");
        error
    })?;
    let quota_handle = user_reservation.quota_handle();

    let route_snapshot = deps.route_runtime.snapshot();
    let session_id = deps.rng.u64();
    let Some(user_session) = deps
        .shared
        .register_authenticated_user_session(&user, credential_id)
    else {
        user_reservation.release_deferred();
        warn!(user = %user, "Disabled user rejected during final admission");
        return Err(ProxyError::UserDisabled { user });
    };
    if user_session.incarnation() != user_incarnation {
        drop(user_session);
        user_reservation.release_deferred();
        warn!(user = %user, "User incarnation changed during admission");
        return Err(ProxyError::UserDisabled { user });
    }
    let session_cancel = user_session.token();
    let selected_me_pool = if deps.config.general.use_middle_proxy
        && matches!(route_snapshot.mode, RelayRouteMode::Middle)
    {
        if let Some(pool) = &deps.me_pool {
            Some(Arc::clone(pool))
        } else if let Some(pool_runtime) = &deps.me_pool_runtime {
            pool_runtime.read().await.clone()
        } else {
            None
        }
    } else {
        None
    };

    if deps.config.general.use_middle_proxy
        && !deps.config.general.me2dc_fallback
        && selected_me_pool.is_none()
    {
        return Err(ProxyError::Proxy(
            "Required Middle-End route is unavailable".into(),
        ));
    }

    let relay_result = if deps.config.general.use_middle_proxy
        && matches!(route_snapshot.mode, RelayRouteMode::Middle)
    {
        if let Some(pool) = selected_me_pool {
            if conntrack_close_policy == ConntrackClosePolicy::Publish {
                handle_via_middle_proxy(
                    client_reader,
                    client_writer,
                    success,
                    pool,
                    Arc::clone(&deps.stats),
                    Arc::clone(&deps.config),
                    Arc::clone(&deps.buffer_pool),
                    local_addr,
                    Arc::clone(&deps.rng),
                    deps.route_runtime.subscribe(),
                    route_snapshot,
                    session_id,
                    session_cancel.clone(),
                    Arc::clone(&deps.shared),
                    quota_handle.clone(),
                )
                .await
            } else {
                handle_via_middle_proxy_with_conntrack(
                    client_reader,
                    client_writer,
                    success,
                    pool,
                    Arc::clone(&deps.stats),
                    Arc::clone(&deps.config),
                    Arc::clone(&deps.buffer_pool),
                    local_addr,
                    Arc::clone(&deps.rng),
                    deps.route_runtime.subscribe(),
                    route_snapshot,
                    session_id,
                    session_cancel.clone(),
                    Arc::clone(&deps.shared),
                    ConntrackClosePolicy::Suppress,
                    quota_handle.clone(),
                )
                .await
            }
        } else {
            warn!("use_middle_proxy=true but MePool not initialized, falling back to direct");
            run_direct(
                client_reader,
                client_writer,
                success,
                &deps,
                route_snapshot,
                session_id,
                local_addr,
                session_cancel.clone(),
                conntrack_close_policy,
                quota_handle.clone(),
            )
            .await
        }
    } else {
        run_direct(
            client_reader,
            client_writer,
            success,
            &deps,
            route_snapshot,
            session_id,
            local_addr,
            session_cancel,
            conntrack_close_policy,
            quota_handle,
        )
        .await
    };
    user_reservation.release().await;
    relay_result
}

async fn run_direct<R, W>(
    client_reader: CryptoReader<R>,
    client_writer: CryptoWriter<W>,
    success: HandshakeSuccess,
    deps: &ClientRuntimeDeps,
    route_snapshot: crate::proxy::route_mode::RouteCutoverState,
    session_id: u64,
    local_addr: SocketAddr,
    session_cancel: tokio_util::sync::CancellationToken,
    conntrack_close_policy: ConntrackClosePolicy,
    quota_handle: UserQuotaHandle,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    handle_via_direct_with_shared_and_conntrack(
        client_reader,
        client_writer,
        success,
        Arc::clone(&deps.upstream_manager),
        Arc::clone(&deps.stats),
        Arc::clone(&deps.config),
        Arc::clone(&deps.buffer_pool),
        Arc::clone(&deps.rng),
        deps.route_runtime.subscribe(),
        route_snapshot,
        session_id,
        local_addr,
        session_cancel,
        Arc::clone(&deps.shared),
        conntrack_close_policy,
        quota_handle,
    )
    .await
}

#[must_use = "the reservation owns user and IP admission until release or drop"]
/// Owns one authenticated user's connection and source-IP admission slots.
pub(crate) struct UserConnectionReservation {
    stats: Arc<Stats>,
    quota_handle: UserQuotaHandle,
    _connection_permit: UserConnectionPermit,
    _stats_observation: Option<UserConnectionObservation>,
    ip_permit: Option<UserIpPermit>,
    released: bool,
}

struct UserIpPermit {
    tracker: Arc<UserIpTracker>,
    owner: Option<UserIpOwner>,
}

struct UserIpOwner {
    user: String,
    incarnation: UserIncarnation,
    ip: IpAddr,
}

impl UserIpPermit {
    fn new(
        tracker: Arc<UserIpTracker>,
        user: String,
        incarnation: UserIncarnation,
        ip: IpAddr,
    ) -> Self {
        Self {
            tracker,
            owner: Some(UserIpOwner {
                user,
                incarnation,
                ip,
            }),
        }
    }

    async fn release(mut self) {
        let Some(owner) = self.owner.as_ref() else {
            return;
        };
        self.tracker
            .remove_ip_for_incarnation(&owner.user, owner.incarnation, owner.ip)
            .await;
        self.owner = None;
    }
}

impl Drop for UserIpPermit {
    fn drop(&mut self) {
        let Some(owner) = self.owner.take() else {
            return;
        };
        self.tracker
            .enqueue_cleanup_for_incarnation(owner.user, owner.incarnation, owner.ip);
    }
}

impl UserConnectionReservation {
    /// Creates an active reservation after both admission counters were acquired.
    pub(crate) fn new(
        stats: Arc<Stats>,
        ip_tracker: Arc<UserIpTracker>,
        user: String,
        ip: IpAddr,
        tracks_ip: bool,
    ) -> Self {
        let quota_handle = stats.current_user_quota_handle(&user);
        let connection_permit = stats
            .connection_authority()
            .try_acquire(&user, None)
            .expect("unlimited test connection permit must be available");
        let stats_observation = stats.observe_user_current_connection(&user);
        Self::new_for_incarnation(
            stats,
            ip_tracker,
            user,
            ip,
            0,
            quota_handle,
            connection_permit,
            stats_observation,
            tracks_ip,
        )
    }

    /// Creates a reservation fenced to one authenticated user incarnation.
    pub(crate) fn new_for_incarnation(
        stats: Arc<Stats>,
        ip_tracker: Arc<UserIpTracker>,
        user: String,
        ip: IpAddr,
        incarnation: UserIncarnation,
        quota_handle: UserQuotaHandle,
        connection_permit: UserConnectionPermit,
        stats_observation: Option<UserConnectionObservation>,
        tracks_ip: bool,
    ) -> Self {
        let ip_permit = tracks_ip.then(|| UserIpPermit::new(ip_tracker, user, incarnation, ip));
        Self {
            stats,
            quota_handle,
            _connection_permit: connection_permit,
            _stats_observation: stats_observation,
            ip_permit,
            released: false,
        }
    }

    /// Returns quota ownership pinned to the authenticated user incarnation.
    pub(crate) fn quota_handle(&self) -> UserQuotaHandle {
        self.quota_handle.clone()
    }

    /// Releases both admission counters through the asynchronous cleanup path.
    pub(crate) async fn release(mut self) {
        if let Some(ip_permit) = self.ip_permit.take() {
            ip_permit.release().await;
        }
        self.released = true;
    }

    /// Defers IP cleanup when admission fails after the asynchronous reservation step.
    pub(crate) fn release_deferred(mut self) {
        self.released = true;
    }
}

impl Drop for UserConnectionReservation {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.stats.increment_session_drop_fallback_total();
    }
}

/// Applies user quota, connection, and source-IP admission atomically.
pub(crate) async fn acquire_user_connection_reservation(
    user: &str,
    config: &ProxyConfig,
    stats: Arc<Stats>,
    peer_addr: SocketAddr,
    ip_tracker: Arc<UserIpTracker>,
) -> Result<UserConnectionReservation> {
    acquire_user_connection_reservation_for_incarnation(
        user, 0, config, stats, peer_addr, ip_tracker,
    )
    .await
}

async fn acquire_user_connection_reservation_for_incarnation(
    user: &str,
    incarnation: UserIncarnation,
    config: &ProxyConfig,
    stats: Arc<Stats>,
    peer_addr: SocketAddr,
    ip_tracker: Arc<UserIpTracker>,
) -> Result<UserConnectionReservation> {
    if let Some(expiration) = config.access.user_expirations.get(user)
        && chrono::Utc::now() > *expiration
    {
        return Err(ProxyError::UserExpired {
            user: user.to_string(),
        });
    }
    let Some(quota_handle) = stats.quota_handle_for_incarnation(user, incarnation) else {
        return Err(ProxyError::UserDisabled {
            user: user.to_string(),
        });
    };
    if let Some(quota) = config.access.user_data_quota.get(user)
        && quota_handle.used() >= *quota
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
        .map(|value| value as u64);
    let Some(connection_permit) = stats.connection_authority().try_acquire(user, limit) else {
        return Err(ProxyError::ConnectionLimitExceeded {
            user: user.to_string(),
        });
    };
    let stats_observation = stats.observe_user_current_connection(user);

    if let Err(reason) = ip_tracker
        .check_and_add_for_incarnation(user, incarnation, peer_addr.ip())
        .await
    {
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

    Ok(UserConnectionReservation::new_for_incarnation(
        stats,
        ip_tracker,
        user.to_string(),
        peer_addr.ip(),
        incarnation,
        quota_handle,
        connection_permit,
        stats_observation,
        true,
    ))
}
