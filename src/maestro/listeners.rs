use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{Semaphore, watch};
use tracing::{debug, error, info, warn};

use crate::config::{ProxyConfig, RstOnCloseMode};
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
use crate::proxy::ClientHandler;
use crate::proxy::route_mode::{ROUTE_SWITCH_ERROR_MSG, RouteRuntimeController};
use crate::proxy::shared_state::ProxySharedState;
use crate::startup::{COMPONENT_LISTENERS_BIND, StartupTracker};
use crate::stats::beobachten::BeobachtenStore;
use crate::stats::{ReplayChecker, Stats};
use crate::stream::BufferPool;
use crate::tls_front::TlsFrontCache;
use crate::transport::middle_proxy::MePool;
use crate::transport::socket::set_linger_zero;
use crate::transport::{ListenOptions, UpstreamManager, create_listener, find_listener_processes};

use super::helpers::{is_expected_handshake_eof, print_proxy_links};

pub(crate) struct BoundListeners {
    pub(crate) listeners: Vec<(TcpListener, bool)>,
    pub(crate) has_unix_listener: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn bind_listeners(
    config: &Arc<ProxyConfig>,
    decision_ipv4_dc: bool,
    decision_ipv6_dc: bool,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
    startup_tracker: &Arc<StartupTracker>,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
    admission_rx: watch::Receiver<bool>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    me_pool: Option<Arc<MePool>>,
    route_runtime: Arc<RouteRuntimeController>,
    tls_cache: Option<Arc<TlsFrontCache>>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
    shared: Arc<ProxySharedState>,
    max_connections: Arc<Semaphore>,
) -> Result<BoundListeners, Box<dyn Error>> {
    startup_tracker
        .start_component(
            COMPONENT_LISTENERS_BIND,
            Some("bind TCP/Unix listeners".to_string()),
        )
        .await;
    let mut listeners = Vec::new();

    for listener_conf in &config.server.listeners {
        let addr = SocketAddr::new(listener_conf.ip, config.server.port);
        if addr.is_ipv4() && !decision_ipv4_dc {
            warn!(%addr, "Skipping IPv4 listener: IPv4 disabled by [network]");
            continue;
        }
        if addr.is_ipv6() && !decision_ipv6_dc {
            warn!(%addr, "Skipping IPv6 listener: IPv6 disabled by [network]");
            continue;
        }
        let options = ListenOptions {
            reuse_port: listener_conf.reuse_allow,
            ipv6_only: listener_conf.ip.is_ipv6(),
            backlog: config.server.listen_backlog,
            ..Default::default()
        };

        match create_listener(addr, &options) {
            Ok(socket) => {
                let listener = TcpListener::from_std(socket.into())?;
                info!("Listening on {}", addr);
                let listener_proxy_protocol = listener_conf
                    .proxy_protocol
                    .unwrap_or(config.server.proxy_protocol);

                let public_host = if let Some(ref announce) = listener_conf.announce {
                    announce.clone()
                } else if listener_conf.ip.is_unspecified() {
                    if listener_conf.ip.is_ipv4() {
                        detected_ip_v4
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| listener_conf.ip.to_string())
                    } else {
                        detected_ip_v6
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| listener_conf.ip.to_string())
                    }
                } else {
                    listener_conf.ip.to_string()
                };

                if config.general.links.public_host.is_none()
                    && !config.general.links.show.is_empty()
                {
                    let link_port = config
                        .general
                        .links
                        .public_port
                        .unwrap_or(config.server.port);
                    print_proxy_links(&public_host, link_port, config);
                }

                listeners.push((listener, listener_proxy_protocol));
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::AddrInUse {
                    let owners = find_listener_processes(addr);
                    if owners.is_empty() {
                        error!(
                            %addr,
                            "Failed to bind: address already in use (owner process unresolved)"
                        );
                    } else {
                        for owner in owners {
                            error!(
                                %addr,
                                pid = owner.pid,
                                process = %owner.process,
                                "Failed to bind: address already in use"
                            );
                        }
                    }

                    if !listener_conf.reuse_allow {
                        error!(
                            %addr,
                            "reuse_allow=false; set [[server.listeners]].reuse_allow=true to allow multi-instance listening"
                        );
                    }
                } else {
                    error!("Failed to bind to {}: {}", addr, e);
                }
            }
        }
    }

    if !config.general.links.show.is_empty()
        && (config.general.links.public_host.is_some() || listeners.is_empty())
    {
        let (host, port) = if let Some(ref h) = config.general.links.public_host {
            (
                h.clone(),
                config
                    .general
                    .links
                    .public_port
                    .unwrap_or(config.server.port),
            )
        } else {
            let ip = detected_ip_v4.or(detected_ip_v6).map(|ip| ip.to_string());
            if ip.is_none() {
                warn!(
                    "show_link is configured but public IP could not be detected. Set public_host in config."
                );
            }
            (
                ip.unwrap_or_else(|| "UNKNOWN".to_string()),
                config
                    .general
                    .links
                    .public_port
                    .unwrap_or(config.server.port),
            )
        };

        print_proxy_links(&host, port, config);
    }

    let mut has_unix_listener = false;
    #[cfg(unix)]
    if let Some(ref unix_path) = config.server.listen_unix_sock {
        let _ = tokio::fs::remove_file(unix_path).await;

        let unix_listener = UnixListener::bind(unix_path)?;

        if let Some(ref perm_str) = config.server.listen_unix_sock_perm {
            match u32::from_str_radix(perm_str.trim_start_matches('0'), 8) {
                Ok(mode) => {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(mode);
                    if let Err(e) = std::fs::set_permissions(unix_path, perms) {
                        error!(
                            "Failed to set unix socket permissions to {}: {}",
                            perm_str, e
                        );
                    } else {
                        info!("Listening on unix:{} (mode {})", unix_path, perm_str);
                    }
                }
                Err(e) => {
                    warn!(
                        "Invalid listen_unix_sock_perm '{}': {}. Ignoring.",
                        perm_str, e
                    );
                    info!("Listening on unix:{}", unix_path);
                }
            }
        } else {
            info!("Listening on unix:{}", unix_path);
        }

        has_unix_listener = true;

        let mut config_rx_unix: watch::Receiver<Arc<ProxyConfig>> = config_rx.clone();
        let admission_rx_unix = admission_rx.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let me_pool = me_pool.clone();
        let route_runtime = route_runtime.clone();
        let tls_cache = tls_cache.clone();
        let ip_tracker = ip_tracker.clone();
        let beobachten = beobachten.clone();
        let shared = shared.clone();
        let max_connections_unix = max_connections.clone();

        tokio::spawn(async move {
            let unix_conn_counter = Arc::new(std::sync::atomic::AtomicU64::new(1));

            loop {
                match unix_listener.accept().await {
                    Ok((stream, _)) => {
                        if !*admission_rx_unix.borrow() {
                            drop(stream);
                            continue;
                        }
                        let accept_permit_timeout_ms =
                            config_rx_unix.borrow().server.accept_permit_timeout_ms;
                        let permit = if accept_permit_timeout_ms == 0 {
                            match max_connections_unix.clone().acquire_owned().await {
                                Ok(permit) => permit,
                                Err(_) => {
                                    error!("Connection limiter is closed");
                                    break;
                                }
                            }
                        } else {
                            match tokio::time::timeout(
                                Duration::from_millis(accept_permit_timeout_ms),
                                max_connections_unix.clone().acquire_owned(),
                            )
                            .await
                            {
                                Ok(Ok(permit)) => permit,
                                Ok(Err(_)) => {
                                    error!("Connection limiter is closed");
                                    break;
                                }
                                Err(_) => {
                                    stats.increment_accept_permit_timeout_total();
                                    debug!(
                                        timeout_ms = accept_permit_timeout_ms,
                                        "Dropping accepted unix connection: permit wait timeout"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            }
                        };
                        let conn_id =
                            unix_conn_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let fake_peer =
                            SocketAddr::from(([127, 0, 0, 1], (conn_id % 65535) as u16));

                        let config = config_rx_unix.borrow_and_update().clone();
                        let stats = stats.clone();
                        let upstream_manager = upstream_manager.clone();
                        let replay_checker = replay_checker.clone();
                        let buffer_pool = buffer_pool.clone();
                        let rng = rng.clone();
                        let me_pool = me_pool.clone();
                        let route_runtime = route_runtime.clone();
                        let tls_cache = tls_cache.clone();
                        let ip_tracker = ip_tracker.clone();
                        let beobachten = beobachten.clone();
                        let shared = shared.clone();
                        let proxy_protocol_enabled = config.server.proxy_protocol;

                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = crate::proxy::client::handle_client_stream_with_shared(
                                stream,
                                fake_peer,
                                config,
                                stats,
                                upstream_manager,
                                replay_checker,
                                buffer_pool,
                                rng,
                                me_pool,
                                route_runtime,
                                tls_cache,
                                ip_tracker,
                                beobachten,
                                shared,
                                proxy_protocol_enabled,
                            )
                            .await
                            {
                                debug!(error = %e, "Unix socket connection error");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Unix socket accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }

    startup_tracker
        .complete_component(
            COMPONENT_LISTENERS_BIND,
            Some(format!(
                "listeners configured tcp={} unix={}",
                listeners.len(),
                has_unix_listener
            )),
        )
        .await;

    Ok(BoundListeners {
        listeners,
        has_unix_listener,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_tcp_accept_loops(
    listeners: Vec<(TcpListener, bool)>,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
    admission_rx: watch::Receiver<bool>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    me_pool: Option<Arc<MePool>>,
    route_runtime: Arc<RouteRuntimeController>,
    tls_cache: Option<Arc<TlsFrontCache>>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
    shared: Arc<ProxySharedState>,
    max_connections: Arc<Semaphore>,
) {
    for (listener, listener_proxy_protocol) in listeners {
        let mut config_rx: watch::Receiver<Arc<ProxyConfig>> = config_rx.clone();
        let admission_rx_tcp = admission_rx.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let me_pool = me_pool.clone();
        let route_runtime = route_runtime.clone();
        let tls_cache = tls_cache.clone();
        let ip_tracker = ip_tracker.clone();
        let beobachten = beobachten.clone();
        let shared = shared.clone();
        let max_connections_tcp = max_connections.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let rst_mode = config_rx.borrow().general.rst_on_close;
                        #[cfg(unix)]
                        let raw_fd = {
                            use std::os::unix::io::AsRawFd;
                            stream.as_raw_fd()
                        };
                        if matches!(rst_mode, RstOnCloseMode::Errors | RstOnCloseMode::Always) {
                            let _ = set_linger_zero(&stream);
                        }
                        if !*admission_rx_tcp.borrow() {
                            debug!(peer = %peer_addr, "Admission gate closed, dropping connection");
                            drop(stream);
                            continue;
                        }
                        let accept_permit_timeout_ms =
                            config_rx.borrow().server.accept_permit_timeout_ms;
                        let permit = if accept_permit_timeout_ms == 0 {
                            match max_connections_tcp.clone().acquire_owned().await {
                                Ok(permit) => permit,
                                Err(_) => {
                                    error!("Connection limiter is closed");
                                    break;
                                }
                            }
                        } else {
                            match tokio::time::timeout(
                                Duration::from_millis(accept_permit_timeout_ms),
                                max_connections_tcp.clone().acquire_owned(),
                            )
                            .await
                            {
                                Ok(Ok(permit)) => permit,
                                Ok(Err(_)) => {
                                    error!("Connection limiter is closed");
                                    break;
                                }
                                Err(_) => {
                                    stats.increment_accept_permit_timeout_total();
                                    debug!(
                                        peer = %peer_addr,
                                        timeout_ms = accept_permit_timeout_ms,
                                        "Dropping accepted connection: permit wait timeout"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            }
                        };
                        let config = config_rx.borrow_and_update().clone();
                        let stats = stats.clone();
                        let upstream_manager = upstream_manager.clone();
                        let replay_checker = replay_checker.clone();
                        let buffer_pool = buffer_pool.clone();
                        let rng = rng.clone();
                        let me_pool = me_pool.clone();
                        let route_runtime = route_runtime.clone();
                        let tls_cache = tls_cache.clone();
                        let ip_tracker = ip_tracker.clone();
                        let beobachten = beobachten.clone();
                        let shared = shared.clone();
                        let proxy_protocol_enabled = listener_proxy_protocol;
                        let real_peer_report = Arc::new(std::sync::Mutex::new(None));
                        let real_peer_report_for_handler = real_peer_report.clone();

                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = ClientHandler::new_with_shared(
                                stream,
                                peer_addr,
                                config,
                                stats,
                                upstream_manager,
                                replay_checker,
                                buffer_pool,
                                rng,
                                me_pool,
                                route_runtime,
                                tls_cache,
                                ip_tracker,
                                beobachten,
                                shared,
                                proxy_protocol_enabled,
                                real_peer_report_for_handler,
                                #[cfg(unix)]
                                raw_fd,
                                rst_mode,
                            )
                            .run()
                            .await
                            {
                                let real_peer = match real_peer_report.lock() {
                                    Ok(guard) => *guard,
                                    Err(_) => None,
                                };
                                let peer_closed = matches!(
                                    &e,
                                    crate::error::ProxyError::Io(ioe)
                                        if matches!(
                                            ioe.kind(),
                                            std::io::ErrorKind::ConnectionReset
                                                | std::io::ErrorKind::ConnectionAborted
                                                | std::io::ErrorKind::BrokenPipe
                                                | std::io::ErrorKind::NotConnected
                                        )
                                ) || matches!(
                                    &e,
                                    crate::error::ProxyError::Stream(
                                        crate::error::StreamError::Io(ioe)
                                    )
                                        if matches!(
                                            ioe.kind(),
                                            std::io::ErrorKind::ConnectionReset
                                                | std::io::ErrorKind::ConnectionAborted
                                                | std::io::ErrorKind::BrokenPipe
                                                | std::io::ErrorKind::NotConnected
                                        )
                                );

                                let me_closed = matches!(
                                    &e,
                                    crate::error::ProxyError::Proxy(msg) if msg == "ME connection lost"
                                );
                                let route_switched = matches!(
                                    &e,
                                    crate::error::ProxyError::Proxy(msg) if msg == ROUTE_SWITCH_ERROR_MSG
                                );

                                match (peer_closed, me_closed) {
                                    (true, _) => {
                                        if let Some(real_peer) = real_peer {
                                            debug!(peer = %peer_addr, real_peer = %real_peer, error = %e, "Connection closed by client");
                                        } else {
                                            debug!(peer = %peer_addr, error = %e, "Connection closed by client");
                                        }
                                    }
                                    (_, true) => {
                                        if let Some(real_peer) = real_peer {
                                            warn!(peer = %peer_addr, real_peer = %real_peer, error = %e, "Connection closed: Middle-End dropped session");
                                        } else {
                                            warn!(peer = %peer_addr, error = %e, "Connection closed: Middle-End dropped session");
                                        }
                                    }
                                    _ if route_switched => {
                                        if let Some(real_peer) = real_peer {
                                            info!(peer = %peer_addr, real_peer = %real_peer, error = %e, "Connection closed by controlled route cutover");
                                        } else {
                                            info!(peer = %peer_addr, error = %e, "Connection closed by controlled route cutover");
                                        }
                                    }
                                    _ if is_expected_handshake_eof(&e) => {
                                        if let Some(real_peer) = real_peer {
                                            info!(peer = %peer_addr, real_peer = %real_peer, error = %e, "Connection closed during initial handshake");
                                        } else {
                                            info!(peer = %peer_addr, error = %e, "Connection closed during initial handshake");
                                        }
                                    }
                                    _ => {
                                        if let Some(real_peer) = real_peer {
                                            warn!(peer = %peer_addr, real_peer = %real_peer, error = %e, "Connection closed with error");
                                        } else {
                                            warn!(peer = %peer_addr, error = %e, "Connection closed with error");
                                        }
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
    }
}
