use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tracing::{debug, error, info, warn};

use crate::config::{ProxyConfig, RstOnCloseMode};
use crate::proxy::ClientHandler;
use crate::startup::{COMPONENT_LISTENERS_BIND, StartupTracker};
use crate::transport::socket::set_linger_zero;
use crate::transport::{ListenOptions, create_listener, find_listener_processes};

use super::generation::RuntimeGeneration;
use super::helpers::{
    expected_handshake_close_description, is_expected_handshake_eof, peer_close_description,
    print_proxy_links,
};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::spawn_unix_accept_loop;

pub(crate) struct BoundListeners {
    pub(crate) listeners: Vec<(TcpListener, bool)>,
    #[cfg(unix)]
    pub(crate) unix_listener: Option<UnixListener>,
}

fn listener_port_or_legacy(listener: &crate::config::ListenerConfig, config: &ProxyConfig) -> u16 {
    listener.port.unwrap_or(config.server.port)
}

fn default_link_port(config: &ProxyConfig) -> u16 {
    config
        .server
        .listeners
        .first()
        .and_then(|listener| listener.port)
        .unwrap_or(config.server.port)
}

fn mss_segment_multiplier(client_mss: u16) -> u16 {
    1460u16.div_ceil(client_mss)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn bind_listeners(
    config: &Arc<ProxyConfig>,
    decision_ipv4_dc: bool,
    decision_ipv6_dc: bool,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
    startup_tracker: &Arc<StartupTracker>,
) -> Result<BoundListeners, Box<dyn Error>> {
    startup_tracker
        .start_component(
            COMPONENT_LISTENERS_BIND,
            Some("bind TCP/Unix listeners".to_string()),
        )
        .await;
    let mut listeners = Vec::new();

    for listener_conf in &config.server.listeners {
        let listener_port = listener_port_or_legacy(listener_conf, config);
        let addr = SocketAddr::new(listener_conf.ip, listener_port);
        if addr.is_ipv4() && !decision_ipv4_dc {
            warn!(%addr, "Skipping IPv4 listener: IPv4 disabled by [network]");
            continue;
        }
        if addr.is_ipv6() && !decision_ipv6_dc {
            warn!(%addr, "Skipping IPv6 listener: IPv6 disabled by [network]");
            continue;
        }
        let client_mss = match listener_conf.effective_client_mss(&config.server) {
            Ok(value) => value,
            Err(error) => {
                warn!(
                    %addr,
                    error = %error,
                    "Invalid listener client MSS after config validation; using kernel default"
                );
                None
            }
        };
        let options = ListenOptions {
            reuse_port: listener_conf.reuse_allow,
            ipv6_only: listener_conf.ip.is_ipv6(),
            backlog: config.server.listen_backlog,
            client_mss,
            ..Default::default()
        };

        match create_listener(addr, &options) {
            Ok(socket) => {
                let listener = TcpListener::from_std(socket.into())?;
                info!("Listening on {}", addr);
                if let Some(client_mss) = client_mss {
                    info!(
                        %addr,
                        client_mss,
                        segment_multiplier = mss_segment_multiplier(client_mss),
                        "Client-facing TCP MSS configured"
                    );
                }
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
                    let link_port = config.general.links.public_port.unwrap_or(listener_port);
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
                    .unwrap_or(default_link_port(config)),
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
                    .unwrap_or(default_link_port(config)),
            )
        };

        print_proxy_links(&host, port, config);
    }

    #[cfg(unix)]
    let mut unix_listener_out = None;
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

        unix_listener_out = Some(unix_listener);
    }

    #[cfg(unix)]
    let has_unix_listener = unix_listener_out.is_some();
    #[cfg(not(unix))]
    let has_unix_listener = false;

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
        #[cfg(unix)]
        unix_listener: unix_listener_out,
    })
}

pub(crate) fn spawn_tcp_accept_loops(
    listeners: Vec<(TcpListener, bool)>,
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
) {
    for (listener, listener_proxy_protocol) in listeners {
        let active_runtime = active_runtime.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let runtime = active_runtime.load_full();
                        let config = runtime.config();
                        let rst_mode = config.general.rst_on_close;
                        #[cfg(unix)]
                        let raw_fd = {
                            use std::os::unix::io::AsRawFd;
                            stream.as_raw_fd()
                        };
                        if matches!(rst_mode, RstOnCloseMode::Errors | RstOnCloseMode::Always) {
                            let _ = set_linger_zero(&stream);
                        }
                        if !*runtime.admission_rx.borrow() {
                            debug!(peer = %peer_addr, "Admission gate closed, dropping connection");
                            drop(stream);
                            continue;
                        }
                        let accept_permit_timeout_ms = config.server.accept_permit_timeout_ms;
                        let permit = if accept_permit_timeout_ms == 0 {
                            match runtime.max_connections.clone().acquire_owned().await {
                                Ok(permit) => permit,
                                Err(_) => {
                                    error!("Connection limiter is closed");
                                    break;
                                }
                            }
                        } else {
                            match tokio::time::timeout(
                                Duration::from_millis(accept_permit_timeout_ms),
                                runtime.max_connections.clone().acquire_owned(),
                            )
                            .await
                            {
                                Ok(Ok(permit)) => permit,
                                Ok(Err(_)) => {
                                    error!("Connection limiter is closed");
                                    break;
                                }
                                Err(_) => {
                                    runtime.stats.increment_accept_permit_timeout_total();
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
                        let stats = runtime.stats.clone();
                        let upstream_manager = runtime.upstream_manager.clone();
                        let replay_checker = runtime.replay_checker.clone();
                        let buffer_pool = runtime.buffer_pool.clone();
                        let rng = runtime.rng.clone();
                        let me_pool = runtime.me_pool.clone();
                        let me_pool_runtime = runtime.me_pool_runtime.clone();
                        let route_runtime = runtime.route_runtime.clone();
                        let tls_cache = runtime.tls_cache.clone();
                        let ip_tracker = runtime.ip_tracker.clone();
                        let beobachten = runtime.beobachten.clone();
                        let shared = runtime.proxy_shared.clone();
                        let proxy_protocol_enabled = listener_proxy_protocol;
                        let real_peer_report = Arc::new(std::sync::Mutex::new(None));
                        let real_peer_report_for_handler = real_peer_report.clone();

                        let _ = runtime.spawn_session(async move {
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
                                Some(me_pool_runtime),
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
                                let peer_close_reason = peer_close_description(&e);
                                let handshake_close_reason =
                                    expected_handshake_close_description(&e);

                                let me_closed =
                                    matches!(&e, crate::error::ProxyError::MiddleConnectionLost);
                                let route_switched =
                                    matches!(&e, crate::error::ProxyError::RouteSwitched);

                                match (peer_close_reason, me_closed) {
                                    (Some(reason), _) => {
                                        if let Some(real_peer) = real_peer {
                                            debug!(
                                                peer = %peer_addr,
                                                real_peer = %real_peer,
                                                error = %e,
                                                close_reason = reason,
                                                "Connection closed by peer"
                                            );
                                        } else {
                                            debug!(
                                                peer = %peer_addr,
                                                error = %e,
                                                close_reason = reason,
                                                "Connection closed by peer"
                                            );
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
                                        let reason = handshake_close_reason
                                            .unwrap_or("Peer closed during initial handshake");
                                        if let Some(real_peer) = real_peer {
                                            info!(
                                                peer = %peer_addr,
                                                real_peer = %real_peer,
                                                error = %e,
                                                close_reason = reason,
                                                "Connection closed during initial handshake"
                                            );
                                        } else {
                                            info!(
                                                peer = %peer_addr,
                                                error = %e,
                                                close_reason = reason,
                                                "Connection closed during initial handshake"
                                            );
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
