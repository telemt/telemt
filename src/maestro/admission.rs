use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::ProxyConfig;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::transport::middle_proxy::MePool;

const STARTUP_FALLBACK_AFTER: Duration = Duration::from_secs(80);
const RUNTIME_FALLBACK_AFTER: Duration = Duration::from_secs(6);

pub(crate) async fn configure_admission_gate(
    config: &Arc<ProxyConfig>,
    me_pool: Option<Arc<MePool>>,
    route_runtime: Arc<RouteRuntimeController>,
    admission_tx: &watch::Sender<bool>,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
) {
    if config.general.use_middle_proxy {
        if let Some(pool) = me_pool.as_ref() {
            let initial_ready = pool.admission_ready_conditional_cast().await;
            let mut fallback_enabled = config.general.me2dc_fallback;
            let mut fast_fallback_enabled = fallback_enabled && config.general.me2dc_fast;
            let (initial_gate_open, initial_route_mode, initial_fallback_reason) = if initial_ready
            {
                (true, RelayRouteMode::Middle, None)
            } else if fast_fallback_enabled {
                (
                    true,
                    RelayRouteMode::Direct,
                    Some("fast_not_ready_fallback"),
                )
            } else {
                (false, RelayRouteMode::Middle, None)
            };
            admission_tx.send_replace(initial_gate_open);
            let _ = route_runtime.set_mode(initial_route_mode);
            if initial_ready {
                info!("Conditional-admission gate: open / ME pool READY");
            } else if let Some(reason) = initial_fallback_reason {
                warn!(
                    fallback_reason = reason,
                    "Conditional-admission gate opened in ME fast fallback mode"
                );
            } else {
                warn!("Conditional-admission gate: closed / ME pool is NOT ready)");
            }

            let pool_for_gate = pool.clone();
            let admission_tx_gate = admission_tx.clone();
            let route_runtime_gate = route_runtime.clone();
            let mut config_rx_gate = config_rx.clone();
            let mut admission_poll_ms = config.general.me_admission_poll_ms.max(1);
            tokio::spawn(async move {
                let mut gate_open = initial_gate_open;
                let mut route_mode = initial_route_mode;
                let mut ready_observed = initial_ready;
                let mut not_ready_since = if initial_ready {
                    None
                } else {
                    Some(Instant::now())
                };
                loop {
                    tokio::select! {
                        changed = config_rx_gate.changed() => {
                            if changed.is_err() {
                                break;
                            }
                            let cfg = config_rx_gate.borrow_and_update().clone();
                            admission_poll_ms = cfg.general.me_admission_poll_ms.max(1);
                            fallback_enabled = cfg.general.me2dc_fallback;
                            fast_fallback_enabled = cfg.general.me2dc_fallback && cfg.general.me2dc_fast;
                            continue;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(admission_poll_ms)) => {}
                    }
                    let ready = pool_for_gate.admission_ready_conditional_cast().await;
                    let now = Instant::now();
                    let (next_gate_open, next_route_mode, next_fallback_reason) = if ready {
                        ready_observed = true;
                        not_ready_since = None;
                        (true, RelayRouteMode::Middle, None)
                    } else if fast_fallback_enabled {
                        (
                            true,
                            RelayRouteMode::Direct,
                            Some("fast_not_ready_fallback"),
                        )
                    } else {
                        let not_ready_started_at = *not_ready_since.get_or_insert(now);
                        let not_ready_for = now.saturating_duration_since(not_ready_started_at);
                        let fallback_after = if ready_observed {
                            RUNTIME_FALLBACK_AFTER
                        } else {
                            STARTUP_FALLBACK_AFTER
                        };
                        if fallback_enabled && not_ready_for > fallback_after {
                            (true, RelayRouteMode::Direct, Some("strict_grace_fallback"))
                        } else {
                            (false, RelayRouteMode::Middle, None)
                        }
                    };
                    let next_fallback_active = next_fallback_reason.is_some();

                    if next_route_mode != route_mode {
                        route_mode = next_route_mode;
                        if let Some(snapshot) = route_runtime_gate.set_mode(route_mode) {
                            if matches!(route_mode, RelayRouteMode::Middle) {
                                info!(
                                    target_mode = route_mode.as_str(),
                                    cutover_generation = snapshot.generation,
                                    "Middle-End routing restored for new sessions"
                                );
                            } else {
                                let fallback_reason = next_fallback_reason.unwrap_or("unknown");
                                if fallback_reason == "strict_grace_fallback" {
                                    let fallback_after = if ready_observed {
                                        RUNTIME_FALLBACK_AFTER
                                    } else {
                                        STARTUP_FALLBACK_AFTER
                                    };
                                    warn!(
                                        target_mode = route_mode.as_str(),
                                        cutover_generation = snapshot.generation,
                                        grace_secs = fallback_after.as_secs(),
                                        fallback_reason,
                                        "ME pool stayed not-ready beyond grace; routing new sessions via Direct-DC"
                                    );
                                } else {
                                    warn!(
                                        target_mode = route_mode.as_str(),
                                        cutover_generation = snapshot.generation,
                                        fallback_reason,
                                        "ME pool not-ready; routing new sessions via Direct-DC (fast mode)"
                                    );
                                }
                            }
                        }
                    }

                    if next_gate_open != gate_open {
                        gate_open = next_gate_open;
                        admission_tx_gate.send_replace(gate_open);
                        if gate_open {
                            if next_fallback_active {
                                warn!(
                                    fallback_reason = next_fallback_reason.unwrap_or("unknown"),
                                    "Conditional-admission gate opened in ME fallback mode"
                                );
                            } else {
                                info!("Conditional-admission gate opened / ME pool READY");
                            }
                        } else {
                            warn!("Conditional-admission gate closed / ME pool is NOT ready");
                        }
                    }
                }
            });
        } else {
            admission_tx.send_replace(false);
            let _ = route_runtime.set_mode(RelayRouteMode::Direct);
            warn!("Conditional-admission gate: closed / ME pool is UNAVAILABLE");
        }
    } else {
        admission_tx.send_replace(true);
        let _ = route_runtime.set_mode(RelayRouteMode::Direct);
    }
}
