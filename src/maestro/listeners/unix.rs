use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::UnixListener;
use tracing::{debug, error};

use super::RuntimeGeneration;

pub(crate) fn spawn_unix_accept_loop(
    listener: Option<UnixListener>,
    active_runtime: Arc<ArcSwap<RuntimeGeneration>>,
) {
    let Some(listener) = listener else {
        return;
    };

    tokio::spawn(async move {
        let connection_counter = AtomicU64::new(1);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let runtime = active_runtime.load_full();
                    if !*runtime.admission_rx.borrow() {
                        drop(stream);
                        continue;
                    }

                    let config = runtime.config();
                    let timeout_ms = config.server.accept_permit_timeout_ms;
                    let permit = if timeout_ms == 0 {
                        match runtime.max_connections.clone().acquire_owned().await {
                            Ok(permit) => permit,
                            Err(_) => {
                                error!("Connection limiter is closed");
                                break;
                            }
                        }
                    } else {
                        match tokio::time::timeout(
                            Duration::from_millis(timeout_ms),
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
                                    timeout_ms,
                                    "Dropping accepted unix connection: permit wait timeout"
                                );
                                drop(stream);
                                continue;
                            }
                        }
                    };

                    let connection_id = connection_counter.fetch_add(1, Ordering::Relaxed);
                    let fake_peer =
                        SocketAddr::from(([127, 0, 0, 1], (connection_id % 65535) as u16));
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
                    let proxy_protocol_enabled = config.server.proxy_protocol;

                    let _ = runtime.spawn_session(async move {
                        let _permit = permit;
                        if let Err(error) =
                            crate::proxy::client::handle_client_stream_with_shared_and_pool_runtime(
                                stream,
                                fake_peer,
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
                            )
                            .await
                        {
                            debug!(error = %error, "Unix socket connection error");
                        }
                    });
                }
                Err(error) => {
                    error!(error = %error, "Unix socket accept error");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
}
