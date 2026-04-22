use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::ProxyConfig;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::startup::StartupTracker;
use crate::stats::Stats;
use crate::transport::middle_proxy::MePool;

const STARTUP_FALLBACK_AFTER: Duration = Duration::from_secs(80);
const RUNTIME_FALLBACK_AFTER: Duration = Duration::from_secs(6);
const COVERAGE_TRANSITION_LOG_RATE_LIMIT: Duration = Duration::from_secs(30);

fn log_admission_coverage_transition(
    previous_configured_dcs: &BTreeSet<i16>,
    previous_ready_dcs: &BTreeSet<i16>,
    configured_dcs: &BTreeSet<i16>,
    ready_dcs: &BTreeSet<i16>,
    now: Instant,
    last_per_dc_log_at: &mut Option<Instant>,
) {
    let should_log_per_dc = last_per_dc_log_at.is_none_or(|last| {
        now.saturating_duration_since(last) >= COVERAGE_TRANSITION_LOG_RATE_LIMIT
    });
    if should_log_per_dc {
        for dc in configured_dcs
            .intersection(previous_ready_dcs)
            .copied()
            .filter(|dc| !ready_dcs.contains(dc))
        {
            warn!(dc, "ME target DC became unavailable for session routing");
        }

        for dc in ready_dcs
            .difference(previous_ready_dcs)
            .copied()
            .filter(|dc| configured_dcs.contains(dc))
        {
            info!(dc, "ME target DC recovered for session routing");
        }

        *last_per_dc_log_at = Some(now);
    }

    let was_partial = !previous_configured_dcs.is_empty()
        && !previous_ready_dcs.is_empty()
        && previous_ready_dcs.len() < previous_configured_dcs.len();
    let is_partial =
        !configured_dcs.is_empty() && !ready_dcs.is_empty() && ready_dcs.len() < configured_dcs.len();

    if !was_partial && is_partial {
        warn!(
            covered_dcs = configured_dcs.len(),
            ready_dcs = ready_dcs.len(),
            "ME partial degradation activated"
        );
    } else if was_partial
        && !is_partial
        && !configured_dcs.is_empty()
        && ready_dcs == configured_dcs
    {
        info!(
            covered_dcs = configured_dcs.len(),
            ready_dcs = ready_dcs.len(),
            "ME partial degradation cleared"
        );
    }
}

fn update_admission_metrics(
    stats: &Stats,
    configured_dcs: &BTreeSet<i16>,
    ready_dcs: &BTreeSet<i16>,
) {
    stats.set_me_admission_configured_dcs_gauge(configured_dcs.len() as u64);
    stats.set_me_admission_ready_dcs_gauge(ready_dcs.len() as u64);
    stats.set_me_partial_degradation_active_gauge(
        !configured_dcs.is_empty() && !ready_dcs.is_empty() && ready_dcs.len() < configured_dcs.len(),
    );
}

pub(crate) async fn configure_admission_gate(
    config: &Arc<ProxyConfig>,
    me_pool: Option<Arc<MePool>>,
    stats: Arc<Stats>,
    route_runtime: Arc<RouteRuntimeController>,
    admission_tx: &watch::Sender<bool>,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
    startup_tracker: Arc<StartupTracker>,
) {
    if config.general.use_middle_proxy {
        if let Some(pool) = me_pool.as_ref() {
            let initial_coverage = pool.admission_coverage_snapshot().await;
            update_admission_metrics(
                stats.as_ref(),
                &initial_coverage.configured_dcs,
                &initial_coverage.ready_dcs,
            );
            let initial_ready = !initial_coverage.configured_dcs.is_empty()
                && initial_coverage.ready_dcs == initial_coverage.configured_dcs;
            let initial_partial_ready = !initial_coverage.configured_dcs.is_empty()
                && !initial_coverage.ready_dcs.is_empty()
                && initial_coverage.ready_dcs.len() < initial_coverage.configured_dcs.len();
            let mut fallback_enabled = config.general.me2dc_fallback;
            let mut fast_fallback_enabled = fallback_enabled && config.general.me2dc_fast;
            let (initial_gate_open, initial_route_mode, initial_fallback_reason) = if initial_ready
            {
                (true, RelayRouteMode::Middle, None)
            } else if initial_partial_ready {
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
            startup_tracker.set_degraded(!initial_ready).await;
            if initial_ready {
                info!("Conditional-admission gate: open / ME pool READY");
            } else if initial_partial_ready {
                warn!(
                    "Conditional-admission gate: open / ME pool PARTIALLY ready, per-DC Direct fallback active"
                );
            } else if let Some(reason) = initial_fallback_reason {
                warn!(
                    fallback_reason = reason,
                    "Conditional-admission gate opened in ME fast fallback mode"
                );
            } else {
                warn!("Conditional-admission gate: closed / ME pool is NOT ready)");
            }

            let pool_for_gate = pool.clone();
            let stats_for_gate = stats.clone();
            let admission_tx_gate = admission_tx.clone();
            let route_runtime_gate = route_runtime.clone();
            let startup_tracker_gate = startup_tracker.clone();
            let mut config_rx_gate = config_rx.clone();
            let mut admission_poll_ms = config.general.me_admission_poll_ms.max(1);
            tokio::spawn(async move {
                let mut gate_open = initial_gate_open;
                let mut route_mode = initial_route_mode;
                let mut ready_observed = initial_ready;
                let mut not_ready_since = if initial_ready || initial_partial_ready {
                    None
                } else {
                    Some(Instant::now())
                };
                let mut previous_configured_dcs = initial_coverage.configured_dcs;
                let mut previous_ready_dcs = initial_coverage.ready_dcs;
                let mut degraded = !initial_ready;
                let mut last_per_dc_log_at = None;
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
                    let coverage = pool_for_gate.admission_coverage_snapshot().await;
                    let configured_dcs = coverage.configured_dcs;
                    let ready_dcs = coverage.ready_dcs;
                    update_admission_metrics(stats_for_gate.as_ref(), &configured_dcs, &ready_dcs);
                    let now = Instant::now();
                    let ready =
                        !configured_dcs.is_empty() && ready_dcs.len() == configured_dcs.len();
                    let partial_ready =
                        !configured_dcs.is_empty() && !ready_dcs.is_empty() && !ready;
                    if configured_dcs != previous_configured_dcs || ready_dcs != previous_ready_dcs
                    {
                        log_admission_coverage_transition(
                            &previous_configured_dcs,
                            &previous_ready_dcs,
                            &configured_dcs,
                            &ready_dcs,
                            now,
                            &mut last_per_dc_log_at,
                        );
                        previous_configured_dcs = configured_dcs.clone();
                        previous_ready_dcs = ready_dcs.clone();
                    }
                    let (next_gate_open, next_route_mode, next_fallback_reason) = if ready {
                        ready_observed = true;
                        not_ready_since = None;
                        (true, RelayRouteMode::Middle, None)
                    } else if partial_ready {
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
                    let next_degraded = !ready;

                    if next_degraded != degraded {
                        degraded = next_degraded;
                        startup_tracker_gate.set_degraded(degraded).await;
                    }

                    if next_route_mode != route_mode {
                        route_mode = next_route_mode;
                        if let Some(snapshot) = route_runtime_gate.set_mode(route_mode) {
                            if matches!(route_mode, RelayRouteMode::Middle) {
                                if ready {
                                    info!(
                                        target_mode = route_mode.as_str(),
                                        cutover_generation = snapshot.generation,
                                        "Middle-End routing restored for new sessions"
                                    );
                                } else {
                                    warn!(
                                        target_mode = route_mode.as_str(),
                                        cutover_generation = snapshot.generation,
                                        "ME pool partially recovered; routing new sessions via Middle-End with per-DC Direct fallback"
                                    );
                                }
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
                            } else if ready {
                                info!("Conditional-admission gate opened / ME pool READY");
                            } else {
                                warn!(
                                    "Conditional-admission gate opened / ME pool PARTIALLY ready, per-DC Direct fallback active"
                                );
                            }
                        } else {
                            warn!("Conditional-admission gate closed / ME pool is NOT ready");
                        }
                    }
                }
            });
        } else {
            update_admission_metrics(stats.as_ref(), &BTreeSet::new(), &BTreeSet::new());
            admission_tx.send_replace(false);
            let _ = route_runtime.set_mode(RelayRouteMode::Direct);
            startup_tracker.set_degraded(true).await;
            warn!("Conditional-admission gate: closed / ME pool is UNAVAILABLE");
        }
    } else {
        update_admission_metrics(stats.as_ref(), &BTreeSet::new(), &BTreeSet::new());
        admission_tx.send_replace(true);
        let _ = route_runtime.set_mode(RelayRouteMode::Direct);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_metrics_follow_coverage_snapshot() {
        let stats = Stats::new();
        let configured_dcs = BTreeSet::from([1, 2, 3]);
        let partial_ready_dcs = BTreeSet::from([1, 2]);

        update_admission_metrics(&stats, &configured_dcs, &partial_ready_dcs);
        assert_eq!(stats.get_me_admission_configured_dcs_gauge(), 3);
        assert_eq!(stats.get_me_admission_ready_dcs_gauge(), 2);
        assert_eq!(stats.get_me_partial_degradation_active_gauge(), 1);

        update_admission_metrics(&stats, &configured_dcs, &configured_dcs);
        assert_eq!(stats.get_me_admission_configured_dcs_gauge(), 3);
        assert_eq!(stats.get_me_admission_ready_dcs_gauge(), 3);
        assert_eq!(stats.get_me_partial_degradation_active_gauge(), 0);

        update_admission_metrics(&stats, &BTreeSet::new(), &BTreeSet::new());
        assert_eq!(stats.get_me_admission_configured_dcs_gauge(), 0);
        assert_eq!(stats.get_me_admission_ready_dcs_gauge(), 0);
        assert_eq!(stats.get_me_partial_degradation_active_gauge(), 0);
    }
}
