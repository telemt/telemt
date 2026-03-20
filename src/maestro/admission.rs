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
            admission_tx.send_replace(initial_ready);
            let _ = route_runtime.set_mode(RelayRouteMode::Middle);
            if initial_ready {
                info!("Conditional-admission gate: open / ME pool READY");
            } else {
                warn!("Conditional-admission gate: closed / ME pool is NOT ready)");
            }

            let pool_for_gate = pool.clone();
            let admission_tx_gate = admission_tx.clone();
            let route_runtime_gate = route_runtime.clone();
            let mut config_rx_gate = config_rx.clone();
            let mut admission_poll_ms = config.general.me_admission_poll_ms.max(1);
            let mut fallback_enabled = config.general.me2dc_fallback;
            tokio::spawn(async move {
                let mut gate_open = initial_ready;
                let mut route_mode = RelayRouteMode::Middle;
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
                            continue;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(admission_poll_ms)) => {}
                    }
                    let ready = pool_for_gate.admission_ready_conditional_cast().await;
                    let now = Instant::now();
                    let (next_gate_open, next_route_mode, next_fallback_active) = if ready {
                        ready_observed = true;
                        not_ready_since = None;
                        (true, RelayRouteMode::Middle, false)
                    } else {
                        let not_ready_started_at = *not_ready_since.get_or_insert(now);
                        let not_ready_for = now.saturating_duration_since(not_ready_started_at);
                        let fallback_after = if ready_observed {
                            RUNTIME_FALLBACK_AFTER
                        } else {
                            STARTUP_FALLBACK_AFTER
                        };
                        if fallback_enabled && not_ready_for > fallback_after {
                            (true, RelayRouteMode::Direct, true)
                        } else {
                            (false, RelayRouteMode::Middle, false)
                        }
                    };

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
                                let fallback_after = if ready_observed {
                                    RUNTIME_FALLBACK_AFTER
                                } else {
                                    STARTUP_FALLBACK_AFTER
                                };
                                warn!(
                                    target_mode = route_mode.as_str(),
                                    cutover_generation = snapshot.generation,
                                    grace_secs = fallback_after.as_secs(),
                                    "ME pool stayed not-ready beyond grace; routing new sessions via Direct-DC"
                                );
                            }
                        }
                    }

                    if next_gate_open != gate_open {
                        gate_open = next_gate_open;
                        admission_tx_gate.send_replace(gate_open);
                        if gate_open {
                            if next_fallback_active {
                                warn!("Conditional-admission gate opened in ME fallback mode");
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
