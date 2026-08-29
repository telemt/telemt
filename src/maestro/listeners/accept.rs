use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

use crate::config::{ListenerTransport, RstOnCloseMode};
use crate::proxy::ClientHandler;
use crate::transport::socket::set_linger_zero;
use crate::web::manager::WebProcessRuntime;
use crate::web::telemetry::{WebAcceptorGuard, WebHttpConnectionOverloadOutcome};

use super::bind::BoundTcpListener;
use super::plan::ListenerBindSpec;
use super::web_overload;
use crate::maestro::generation::RuntimeGeneration;
use crate::maestro::helpers::{
    expected_handshake_close_description, is_expected_handshake_eof, peer_close_description,
};

/// One bound listener and all connection tasks accepted through its lifecycle.
pub(super) struct ListenerSlot {
    pub(super) spec: ListenerBindSpec,
    listener: Arc<TcpListener>,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
    connections: TaskTracker,
    web_runtime: Option<Arc<WebProcessRuntime>>,
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
}

enum PermitWait {
    Acquired(OwnedSemaphorePermit),
    TimedOut,
    Closed,
    Cancelled,
}

async fn wait_for_permit(
    runtime: &Arc<RuntimeGeneration>,
    cancellation: &CancellationToken,
) -> PermitWait {
    let timeout_ms = runtime.config().server.accept_permit_timeout_ms;
    let acquire = runtime.max_connections.clone().acquire_owned();
    if timeout_ms == 0 {
        return tokio::select! {
            biased;
            _ = cancellation.cancelled() => PermitWait::Cancelled,
            permit = acquire => match permit {
                Ok(permit) => PermitWait::Acquired(permit),
                Err(_) => PermitWait::Closed,
            },
        };
    }
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => PermitWait::Cancelled,
        result = tokio::time::timeout(Duration::from_millis(timeout_ms), acquire) => {
            match result {
                Ok(Ok(permit)) => PermitWait::Acquired(permit),
                Ok(Err(_)) => PermitWait::Closed,
                Err(_) => PermitWait::TimedOut,
            }
        }
    }
}

fn spawn_client_session(
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    runtime: Arc<RuntimeGeneration>,
    permit: OwnedSemaphorePermit,
    spec: &ListenerBindSpec,
) {
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
    let proxy_protocol_enabled = spec.proxy_protocol;
    let tls_response_fragment_size = spec.tls_response_fragment_size;
    let real_peer_report = Arc::new(std::sync::Mutex::new(None));
    let real_peer_report_for_handler = real_peer_report.clone();

    let _ = runtime.spawn_session(async move {
        let _permit = permit;
        if let Err(error_value) = ClientHandler::new_with_shared(
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
            tls_response_fragment_size,
        )
        .run()
        .await
        {
            let real_peer = real_peer_report.lock().ok().and_then(|guard| *guard);
            let peer_close_reason = peer_close_description(&error_value);
            let handshake_close_reason = expected_handshake_close_description(&error_value);
            let me_closed = matches!(
                &error_value,
                crate::error::ProxyError::MiddleConnectionLost
            );
            let route_switched =
                matches!(&error_value, crate::error::ProxyError::RouteSwitched);

            match (peer_close_reason, me_closed) {
                (Some(reason), _) => {
                    if let Some(real_peer) = real_peer {
                        debug!(peer = %peer_addr, real_peer = %real_peer, error = %error_value, close_reason = reason, "Connection closed by peer");
                    } else {
                        debug!(peer = %peer_addr, error = %error_value, close_reason = reason, "Connection closed by peer");
                    }
                }
                (_, true) => {
                    if let Some(real_peer) = real_peer {
                        warn!(peer = %peer_addr, real_peer = %real_peer, error = %error_value, "Connection closed: Middle-End dropped session");
                    } else {
                        warn!(peer = %peer_addr, error = %error_value, "Connection closed: Middle-End dropped session");
                    }
                }
                _ if route_switched => {
                    if let Some(real_peer) = real_peer {
                        info!(peer = %peer_addr, real_peer = %real_peer, error = %error_value, "Connection closed by controlled route cutover");
                    } else {
                        info!(peer = %peer_addr, error = %error_value, "Connection closed by controlled route cutover");
                    }
                }
                _ if is_expected_handshake_eof(&error_value) => {
                    let reason = handshake_close_reason
                        .unwrap_or("Peer closed during initial handshake");
                    if let Some(real_peer) = real_peer {
                        info!(peer = %peer_addr, real_peer = %real_peer, error = %error_value, close_reason = reason, "Connection closed during initial handshake");
                    } else {
                        info!(peer = %peer_addr, error = %error_value, close_reason = reason, "Connection closed during initial handshake");
                    }
                }
                _ => {
                    if let Some(real_peer) = real_peer {
                        warn!(peer = %peer_addr, real_peer = %real_peer, error = %error_value, "Connection closed with error");
                    } else {
                        warn!(peer = %peer_addr, error = %error_value, "Connection closed with error");
                    }
                }
            }
        }
    });
}

async fn run_accept_loop(
    listener: Arc<TcpListener>,
    spec: ListenerBindSpec,
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
    web_runtime: Option<Arc<WebProcessRuntime>>,
    connections: TaskTracker,
    cancellation: CancellationToken,
    _web_acceptor_guard: Option<WebAcceptorGuard>,
) {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, peer_addr)) => {
                if spec.transport == ListenerTransport::Web {
                    let Some(web_runtime) = web_runtime.as_ref() else {
                        error!(addr = %spec.addr, "WEB listener has no process runtime");
                        return;
                    };
                    web_runtime.telemetry().record_accept();
                    let Some(connection_permit) = web_runtime.try_http_connection() else {
                        let config = web_runtime.active_generation().config();
                        let action = config.web.http_connection_capacity_action;
                        let phase_timeout =
                            Duration::from_millis(config.web.timeouts.http_overload_timeout_ms);
                        drop(config);
                        if action == crate::config::WebHttpConnectionCapacityAction::Drop {
                            web_runtime.telemetry().record_rejection(
                                crate::web::telemetry::WebRejectionReason::HttpConnectionCapacity,
                            );
                            web_runtime
                                .telemetry()
                                .record_overload(WebHttpConnectionOverloadOutcome::Dropped);
                            drop(stream);
                            continue;
                        }
                        let Some(overload_permit) = web_runtime.try_http_overload_connection()
                        else {
                            web_runtime.telemetry().record_rejection(
                                crate::web::telemetry::WebRejectionReason::HttpConnectionCapacity,
                            );
                            web_runtime.telemetry().record_overload(
                                WebHttpConnectionOverloadOutcome::OverflowCapacityDrop,
                            );
                            drop(stream);
                            continue;
                        };
                        connections.spawn(web_overload::serve(
                            stream,
                            peer_addr,
                            spec.web_client_ip_source,
                            Arc::clone(&spec.web_trusted_proxy_cidrs),
                            Arc::clone(web_runtime),
                            cancellation.clone(),
                            overload_permit,
                            action,
                            phase_timeout,
                        ));
                        continue;
                    };
                    connections.spawn(crate::web::http::serve_connection(
                        stream,
                        peer_addr,
                        spec.web_client_ip_source,
                        Arc::clone(&spec.web_trusted_proxy_cidrs),
                        Arc::clone(web_runtime),
                        cancellation.clone(),
                        connection_permit,
                    ));
                    continue;
                }
                let runtime = active_runtime.load_full();
                if !*runtime.admission_rx.borrow() {
                    debug!(peer = %peer_addr, "Admission gate closed, dropping connection");
                    drop(stream);
                    continue;
                }
                match wait_for_permit(&runtime, &cancellation).await {
                    PermitWait::Acquired(permit) => {
                        spawn_client_session(stream, peer_addr, runtime, permit, &spec);
                    }
                    PermitWait::TimedOut => {
                        runtime.stats.increment_accept_permit_timeout_total();
                        debug!(
                            peer = %peer_addr,
                            timeout_ms = runtime.config().server.accept_permit_timeout_ms,
                            "Dropping accepted connection: permit wait timeout"
                        );
                    }
                    PermitWait::Closed => {
                        error!(addr = %spec.addr, "Connection limiter is closed");
                        return;
                    }
                    PermitWait::Cancelled => return,
                }
            }
            Err(error_value) => {
                if let Some(web_runtime) = &web_runtime {
                    web_runtime.telemetry().record_accept_error();
                }
                error!(addr = %spec.addr, error = %error_value, "TCP accept error");
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                }
            }
        }
    }
}

impl ListenerSlot {
    pub(super) fn start(
        bound: BoundTcpListener,
        active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
        web_runtime: Option<Arc<WebProcessRuntime>>,
    ) -> Self {
        let web_runtime = if bound.spec.transport == ListenerTransport::Web {
            web_runtime
        } else {
            None
        };
        let cancellation = CancellationToken::new();
        let connections = TaskTracker::new();
        let web_acceptor_guard = web_runtime
            .as_ref()
            .map(|runtime| runtime.telemetry().acceptor_guard());
        let task = tokio::spawn(run_accept_loop(
            bound.listener.clone(),
            bound.spec.clone(),
            active_runtime.clone(),
            web_runtime.clone(),
            connections.clone(),
            cancellation.clone(),
            web_acceptor_guard,
        ));
        Self {
            spec: bound.spec,
            listener: bound.listener,
            cancellation,
            task: Some(task),
            connections,
            web_runtime,
            active_runtime,
        }
    }

    pub(super) async fn stop(&mut self) -> Result<(), String> {
        self.request_stop();
        if let Some(task) = self.task.take() {
            task.await.map_err(|error_value| {
                format!("listener {} task failed: {error_value}", self.spec.addr)
            })?;
        }
        self.connections.close();
        let connection_stop_timeout = Duration::from_secs(
            self.active_runtime
                .load()
                .config()
                .web
                .timeouts
                .shutdown_secs,
        );
        tokio::time::timeout(connection_stop_timeout, self.connections.wait())
            .await
            .map_err(|_| format!("listener {} connection shutdown timed out", self.spec.addr))?;
        Ok(())
    }

    /// Cancels admission synchronously before the shared shutdown deadline starts draining.
    pub(super) fn request_stop(&self) {
        self.cancellation.cancel();
    }

    /// Joins this acceptor and its WEB connections by one process shutdown deadline.
    pub(super) async fn stop_until(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<(), String> {
        self.request_stop();
        let mut errors = Vec::new();
        if let Some(mut task) = self.task.take() {
            let joined = if task.is_finished() {
                Some(task.await)
            } else {
                match tokio::time::timeout_at(deadline, &mut task).await {
                    Ok(result) => Some(result),
                    Err(_) => {
                        task.abort();
                        let _ = task.await;
                        None
                    }
                }
            };
            match joined {
                Some(Ok(())) => {}
                Some(Err(error_value)) => errors.push(format!(
                    "listener {} task failed: {error_value}",
                    self.spec.addr
                )),
                None => errors.push(format!(
                    "listener {} accept shutdown timed out",
                    self.spec.addr
                )),
            }
        }
        self.connections.close();
        if !self.connections.is_empty()
            && tokio::time::timeout_at(deadline, self.connections.wait())
                .await
                .is_err()
        {
            errors.push(format!(
                "listener {} connection shutdown timed out",
                self.spec.addr
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    pub(super) fn restart(&mut self, active_runtime: Arc<ArcSwap<RuntimeGeneration>>) {
        self.active_runtime = active_runtime.clone();
        self.cancellation = CancellationToken::new();
        self.connections = TaskTracker::new();
        let web_acceptor_guard = self
            .web_runtime
            .as_ref()
            .map(|runtime| runtime.telemetry().acceptor_guard());
        self.task = Some(tokio::spawn(run_accept_loop(
            self.listener.clone(),
            self.spec.clone(),
            active_runtime,
            self.web_runtime.clone(),
            self.connections.clone(),
            self.cancellation.clone(),
            web_acceptor_guard,
        )));
    }
}
