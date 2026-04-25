#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::crypto::AesCbc;
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;
use crate::stats::Stats;

use super::codec::{RpcChecksumMode, WriterCommand, rpc_crc};
use super::fairness::{
    AdmissionDecision, DispatchAction, DispatchFeedback, PressureState, SchedulerDecision,
    WorkerFairnessConfig, WorkerFairnessSnapshot, WorkerFairnessState,
};
use super::registry::RouteResult;
use super::{ConnRegistry, MeResponse};
const DATA_ROUTE_MAX_ATTEMPTS: usize = 3;
const DATA_ROUTE_QUEUE_FULL_STARVATION_THRESHOLD: u8 = 3;
const FAIRNESS_DRAIN_BUDGET_PER_LOOP: usize = 128;

fn should_close_on_route_result_for_data(result: RouteResult) -> bool {
    matches!(result, RouteResult::NoConn | RouteResult::ChannelClosed)
}

fn should_close_on_route_result_for_ack(result: RouteResult) -> bool {
    matches!(result, RouteResult::NoConn | RouteResult::ChannelClosed)
}

fn is_data_route_queue_full(result: RouteResult) -> bool {
    matches!(
        result,
        RouteResult::QueueFullBase | RouteResult::QueueFullHigh
    )
}

fn should_close_on_queue_full_streak_with_policy(
    streak: u8,
    pressure_state: PressureState,
    backpressure_enabled: bool,
) -> bool {
    if !backpressure_enabled {
        return false;
    }

    if pressure_state < PressureState::Shedding {
        return false;
    }

    streak >= DATA_ROUTE_QUEUE_FULL_STARVATION_THRESHOLD
}

fn should_schedule_fairness_retry(snapshot: &WorkerFairnessSnapshot) -> bool {
    snapshot.total_queued_bytes > 0
}

fn fairness_retry_delay(route_wait_ms: u64) -> Duration {
    Duration::from_millis(route_wait_ms.max(1))
}

async fn route_data_with_retry(
    reg: &ConnRegistry,
    conn_id: u64,
    flags: u32,
    data: Bytes,
    timeout_ms: u64,
) -> RouteResult {
    let mut attempt = 0usize;
    loop {
        let routed = reg
            .route_with_timeout(
                conn_id,
                MeResponse::Data {
                    flags,
                    data: data.clone(),
                    route_permit: None,
                },
                timeout_ms,
            )
            .await;
        match routed {
            RouteResult::QueueFullBase | RouteResult::QueueFullHigh => {
                attempt = attempt.saturating_add(1);
                if attempt >= DATA_ROUTE_MAX_ATTEMPTS {
                    return routed;
                }
                tokio::task::yield_now().await;
            }
            _ => return routed,
        }
    }
}

#[inline]
fn route_feedback(result: RouteResult) -> DispatchFeedback {
    match result {
        RouteResult::Routed => DispatchFeedback::Routed,
        RouteResult::NoConn => DispatchFeedback::NoConn,
        RouteResult::ChannelClosed => DispatchFeedback::ChannelClosed,
        RouteResult::QueueFullBase | RouteResult::QueueFullHigh => DispatchFeedback::QueueFull,
    }
}

fn report_route_drop(result: RouteResult, stats: &Stats) {
    match result {
        RouteResult::NoConn => stats.increment_me_route_drop_no_conn(),
        RouteResult::ChannelClosed => stats.increment_me_route_drop_channel_closed(),
        RouteResult::QueueFullBase => {
            stats.increment_me_route_drop_queue_full();
            stats.increment_me_route_drop_queue_full_base();
        }
        RouteResult::QueueFullHigh => {
            stats.increment_me_route_drop_queue_full();
            stats.increment_me_route_drop_queue_full_high();
        }
        RouteResult::Routed => {}
    }
}

fn apply_fairness_metrics_delta(
    stats: &Stats,
    prev: &mut WorkerFairnessSnapshot,
    current: WorkerFairnessSnapshot,
) {
    stats.set_me_fair_active_flows_gauge(current.active_flows as u64);
    stats.set_me_fair_queued_bytes_gauge(current.total_queued_bytes);
    stats.set_me_fair_standing_flows_gauge(current.standing_flows as u64);
    stats.set_me_fair_backpressured_flows_gauge(current.backpressured_flows as u64);
    stats.set_me_fair_pressure_state_gauge(current.pressure_state.as_u8() as u64);
    stats.add_me_fair_scheduler_rounds_total(
        current
            .scheduler_rounds
            .saturating_sub(prev.scheduler_rounds),
    );
    stats.add_me_fair_deficit_grants_total(
        current.deficit_grants.saturating_sub(prev.deficit_grants),
    );
    stats.add_me_fair_deficit_skips_total(current.deficit_skips.saturating_sub(prev.deficit_skips));
    stats.add_me_fair_enqueue_rejects_total(
        current.enqueue_rejects.saturating_sub(prev.enqueue_rejects),
    );
    stats.add_me_fair_shed_drops_total(current.shed_drops.saturating_sub(prev.shed_drops));
    stats.add_me_fair_penalties_total(
        current
            .fairness_penalties
            .saturating_sub(prev.fairness_penalties),
    );
    stats.add_me_fair_downstream_stalls_total(
        current
            .downstream_stalls
            .saturating_sub(prev.downstream_stalls),
    );
    *prev = current;
}

async fn drain_fairness_scheduler(
    fairness: &mut WorkerFairnessState,
    reg: &ConnRegistry,
    tx: &mpsc::Sender<WriterCommand>,
    data_route_queue_full_streak: &mut HashMap<u64, u8>,
    backpressure_enabled: bool,
    route_wait_ms: u64,
    stats: &Stats,
) {
    for _ in 0..FAIRNESS_DRAIN_BUDGET_PER_LOOP {
        let now = Instant::now();
        let SchedulerDecision::Dispatch(candidate) = fairness.next_decision(now) else {
            break;
        };
        let cid = candidate.frame.conn_id;
        let pressure_state = candidate.pressure_state;
        let _flow_class = candidate.flow_class;
        let routed = route_data_with_retry(
            reg,
            cid,
            candidate.frame.flags,
            candidate.frame.data.clone(),
            route_wait_ms,
        )
        .await;
        if matches!(routed, RouteResult::Routed) {
            data_route_queue_full_streak.remove(&cid);
        } else {
            report_route_drop(routed, stats);
        }
        let action = fairness.apply_dispatch_feedback(cid, candidate, route_feedback(routed), now);
        if is_data_route_queue_full(routed) {
            let streak = data_route_queue_full_streak.entry(cid).or_insert(0);
            *streak = streak.saturating_add(1);
            if should_close_on_queue_full_streak_with_policy(
                *streak,
                pressure_state,
                backpressure_enabled,
            ) {
                fairness.remove_flow(cid);
                data_route_queue_full_streak.remove(&cid);
                reg.unregister(cid).await;
                send_close_conn(tx, cid).await;
                continue;
            }
        }
        if action == DispatchAction::CloseFlow || should_close_on_route_result_for_data(routed) {
            fairness.remove_flow(cid);
            data_route_queue_full_streak.remove(&cid);
            reg.unregister(cid).await;
            send_close_conn(tx, cid).await;
        }
    }
}

pub(crate) async fn reader_loop(
    mut rd: tokio::io::ReadHalf<TcpStream>,
    dk: [u8; 32],
    mut div: [u8; 16],
    crc_mode: RpcChecksumMode,
    reg: Arc<ConnRegistry>,
    enc_leftover: BytesMut,
    mut dec: BytesMut,
    tx: mpsc::Sender<WriterCommand>,
    ping_tracker: Arc<Mutex<HashMap<i64, Instant>>>,
    rtt_stats: Arc<Mutex<HashMap<u64, (f64, f64)>>>,
    stats: Arc<Stats>,
    writer_id: u64,
    degraded: Arc<AtomicBool>,
    writer_rtt_ema_ms_x10: Arc<AtomicU32>,
    route_backpressure_enabled: Arc<AtomicBool>,
    route_fairshare_enabled: Arc<AtomicBool>,
    reader_route_data_wait_ms: Arc<AtomicU64>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut raw = enc_leftover;
    let mut expected_seq: i32 = 0;
    let mut data_route_queue_full_streak = HashMap::<u64, u8>::new();
    let mut fairness = WorkerFairnessState::new(
        WorkerFairnessConfig {
            worker_id: (writer_id as u16).saturating_add(1),
            max_active_flows: reg.route_channel_capacity().saturating_mul(4).max(256),
            max_total_queued_bytes: (reg.route_channel_capacity() as u64)
                .saturating_mul(16 * 1024)
                .max(4 * 1024 * 1024),
            max_flow_queued_bytes: (reg.route_channel_capacity() as u64)
                .saturating_mul(2 * 1024)
                .clamp(64 * 1024, 2 * 1024 * 1024),
            backpressure_enabled: route_backpressure_enabled.load(Ordering::Relaxed),
            ..WorkerFairnessConfig::default()
        },
        Instant::now(),
    );
    let mut fairness_snapshot = fairness.snapshot();
    loop {
        let backpressure_enabled = route_backpressure_enabled.load(Ordering::Relaxed);
        let fairshare_enabled = route_fairshare_enabled.load(Ordering::Relaxed);
        fairness.set_backpressure_enabled(backpressure_enabled);
        let fairness_has_backlog = should_schedule_fairness_retry(&fairness_snapshot);
        let mut tmp = [0u8; 65_536];
        let backlog_retry_enabled = fairness_has_backlog;
        let backlog_retry_delay =
            fairness_retry_delay(reader_route_data_wait_ms.load(Ordering::Relaxed));
        let mut retry_only = false;
        let n = tokio::select! {
            res = rd.read(&mut tmp) => res.map_err(ProxyError::Io)?,
            _ = tokio::time::sleep(backlog_retry_delay), if backlog_retry_enabled => {
                retry_only = true;
                0usize
            },
            _ = cancel.cancelled() => return Ok(()),
        };
        if retry_only {
            let route_wait_ms = reader_route_data_wait_ms.load(Ordering::Relaxed);
            drain_fairness_scheduler(
                &mut fairness,
                reg.as_ref(),
                &tx,
                &mut data_route_queue_full_streak,
                backpressure_enabled,
                route_wait_ms,
                stats.as_ref(),
            )
            .await;
            let current_snapshot = fairness.snapshot();
            apply_fairness_metrics_delta(stats.as_ref(), &mut fairness_snapshot, current_snapshot);
            continue;
        }
        if n == 0 {
            stats.increment_me_reader_eof_total();
            return Err(ProxyError::Io(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "ME socket closed by peer",
            )));
        }
        raw.extend_from_slice(&tmp[..n]);

        let blocks = raw.len() / 16 * 16;
        if blocks > 0 {
            let mut chunk = raw.split_to(blocks);
            let mut new_iv = [0u8; 16];
            new_iv.copy_from_slice(&chunk[blocks - 16..blocks]);
            AesCbc::new(dk, div)
                .decrypt_in_place(&mut chunk[..])
                .map_err(|e| ProxyError::Crypto(format!("{e}")))?;
            div = new_iv;
            dec.extend_from_slice(&chunk);
        }

        while dec.len() >= 12 {
            let fl = u32::from_le_bytes(dec[0..4].try_into().unwrap()) as usize;
            if fl == 4 {
                let _ = dec.split_to(4);
                continue;
            }
            if !(12..=(1 << 24)).contains(&fl) {
                warn!(frame_len = fl, "Invalid RPC frame len");
                dec.clear();
                break;
            }
            if dec.len() < fl {
                break;
            }

            let frame = dec.split_to(fl).freeze();
            let pe = fl - 4;
            let ec = u32::from_le_bytes(frame[pe..pe + 4].try_into().unwrap());
            let actual_crc = rpc_crc(crc_mode, &frame[..pe]);
            if actual_crc != ec {
                stats.increment_me_crc_mismatch();
                warn!(
                    frame_len = fl,
                    expected_crc = format_args!("0x{ec:08x}"),
                    actual_crc = format_args!("0x{actual_crc:08x}"),
                    "CRC mismatch — CBC crypto desync, aborting ME connection"
                );
                return Err(ProxyError::Proxy("CRC mismatch (crypto desync)".into()));
            }

            let seq_no = i32::from_le_bytes(frame[4..8].try_into().unwrap());
            if seq_no != expected_seq {
                stats.increment_me_seq_mismatch();
                warn!(seq_no, expected = expected_seq, "ME RPC seq mismatch");
                return Err(ProxyError::SeqNoMismatch {
                    expected: expected_seq,
                    got: seq_no,
                });
            }
            expected_seq = expected_seq.wrapping_add(1);

            let payload = frame.slice(8..pe);
            if payload.len() < 4 {
                continue;
            }

            let pt = u32::from_le_bytes(payload[0..4].try_into().unwrap());
            let body = payload.slice(4..);

            if pt == RPC_PROXY_ANS_U32 && body.len() >= 12 {
                let flags = u32::from_le_bytes(body[0..4].try_into().unwrap());
                let cid = u64::from_le_bytes(body[4..12].try_into().unwrap());
                let data = body.slice(12..);
                trace!(cid, flags, len = data.len(), "RPC_PROXY_ANS");

                if fairshare_enabled {
                    let admission = fairness.enqueue_data(cid, flags, data, Instant::now());
                    if !matches!(admission, AdmissionDecision::Admit) {
                        stats.increment_me_route_drop_queue_full();
                        stats.increment_me_route_drop_queue_full_high();
                        let streak = data_route_queue_full_streak.entry(cid).or_insert(0);
                        *streak = streak.saturating_add(1);
                        let pressure_state = fairness.pressure_state();
                        if should_close_on_queue_full_streak_with_policy(
                            *streak,
                            pressure_state,
                            backpressure_enabled,
                        ) || (backpressure_enabled
                            && matches!(admission, AdmissionDecision::RejectSaturated))
                        {
                            fairness.remove_flow(cid);
                            data_route_queue_full_streak.remove(&cid);
                            reg.unregister(cid).await;
                            send_close_conn(&tx, cid).await;
                        }
                    }
                } else {
                    let route_wait_ms = reader_route_data_wait_ms.load(Ordering::Relaxed);
                    let routed =
                        route_data_with_retry(reg.as_ref(), cid, flags, data, route_wait_ms).await;
                    if matches!(routed, RouteResult::Routed) {
                        data_route_queue_full_streak.remove(&cid);
                        continue;
                    }
                    report_route_drop(routed, stats.as_ref());
                    if should_close_on_route_result_for_data(routed) {
                        fairness.remove_flow(cid);
                        data_route_queue_full_streak.remove(&cid);
                        reg.unregister(cid).await;
                        send_close_conn(&tx, cid).await;
                        continue;
                    }
                    if is_data_route_queue_full(routed) {
                        let streak = data_route_queue_full_streak.entry(cid).or_insert(0);
                        *streak = streak.saturating_add(1);
                        if should_close_on_queue_full_streak_with_policy(
                            *streak,
                            PressureState::Shedding,
                            backpressure_enabled,
                        ) {
                            fairness.remove_flow(cid);
                            data_route_queue_full_streak.remove(&cid);
                            reg.unregister(cid).await;
                            send_close_conn(&tx, cid).await;
                        }
                    }
                }
            } else if pt == RPC_SIMPLE_ACK_U32 && body.len() >= 12 {
                let cid = u64::from_le_bytes(body[0..8].try_into().unwrap());
                let cfm = u32::from_le_bytes(body[8..12].try_into().unwrap());
                trace!(cid, cfm, "RPC_SIMPLE_ACK");

                let routed = reg.route_nowait(cid, MeResponse::Ack(cfm)).await;
                if !matches!(routed, RouteResult::Routed) {
                    match routed {
                        RouteResult::NoConn => stats.increment_me_route_drop_no_conn(),
                        RouteResult::ChannelClosed => {
                            stats.increment_me_route_drop_channel_closed()
                        }
                        RouteResult::QueueFullBase => {
                            stats.increment_me_route_drop_queue_full();
                            stats.increment_me_route_drop_queue_full_base();
                        }
                        RouteResult::QueueFullHigh => {
                            stats.increment_me_route_drop_queue_full();
                            stats.increment_me_route_drop_queue_full_high();
                        }
                        RouteResult::Routed => {}
                    }
                    if should_close_on_route_result_for_ack(routed) {
                        reg.unregister(cid).await;
                        send_close_conn(&tx, cid).await;
                    }
                }
            } else if pt == RPC_CLOSE_EXT_U32 && body.len() >= 8 {
                let cid = u64::from_le_bytes(body[0..8].try_into().unwrap());
                debug!(cid, "RPC_CLOSE_EXT from ME");
                let _ = reg.route_nowait(cid, MeResponse::Close).await;
                reg.unregister(cid).await;
                data_route_queue_full_streak.remove(&cid);
                fairness.remove_flow(cid);
            } else if pt == RPC_CLOSE_CONN_U32 && body.len() >= 8 {
                let cid = u64::from_le_bytes(body[0..8].try_into().unwrap());
                debug!(cid, "RPC_CLOSE_CONN from ME");
                let _ = reg.route_nowait(cid, MeResponse::Close).await;
                reg.unregister(cid).await;
                data_route_queue_full_streak.remove(&cid);
                fairness.remove_flow(cid);
            } else if pt == RPC_PING_U32 && body.len() >= 8 {
                let ping_id = i64::from_le_bytes(body[0..8].try_into().unwrap());
                trace!(ping_id, "RPC_PING -> RPC_PONG");
                let mut pong = Vec::with_capacity(12);
                pong.extend_from_slice(&RPC_PONG_U32.to_le_bytes());
                pong.extend_from_slice(&ping_id.to_le_bytes());
                match tx.try_send(WriterCommand::DataAndFlush(Bytes::from(pong))) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        debug!(ping_id, "PONG dropped: writer command channel is full");
                    }
                    Err(TrySendError::Closed(_)) => {
                        warn!("PONG send failed: writer channel closed");
                        break;
                    }
                }
            } else if pt == RPC_PONG_U32 && body.len() >= 8 {
                let ping_id = i64::from_le_bytes(body[0..8].try_into().unwrap());
                stats.increment_me_keepalive_pong();
                if let Some(sent) = {
                    let mut guard = ping_tracker.lock().await;
                    guard.remove(&ping_id)
                } {
                    let rtt = sent.elapsed().as_secs_f64() * 1000.0;
                    let mut stats = rtt_stats.lock().await;
                    let entry = stats.entry(writer_id).or_insert((rtt, rtt));
                    entry.1 = entry.1 * 0.8 + rtt * 0.2;
                    if rtt < entry.0 {
                        entry.0 = rtt;
                    } else {
                        // allow slow baseline drift upward to avoid stale minimum
                        entry.0 = entry.0 * 0.99 + rtt * 0.01;
                    }
                    let degraded_now = entry.1 > entry.0 * 2.0;
                    degraded.store(degraded_now, Ordering::Relaxed);
                    writer_rtt_ema_ms_x10.store(
                        (entry.1 * 10.0).clamp(0.0, u32::MAX as f64) as u32,
                        Ordering::Relaxed,
                    );
                    trace!(
                        writer_id,
                        rtt_ms = rtt,
                        ema_ms = entry.1,
                        base_ms = entry.0,
                        degraded = degraded_now,
                        "ME RTT sample"
                    );
                }
            } else {
                debug!(
                    rpc_type = format_args!("0x{pt:08x}"),
                    len = body.len(),
                    "Unknown RPC"
                );
            }

            let route_wait_ms = reader_route_data_wait_ms.load(Ordering::Relaxed);
            drain_fairness_scheduler(
                &mut fairness,
                reg.as_ref(),
                &tx,
                &mut data_route_queue_full_streak,
                backpressure_enabled,
                route_wait_ms,
                stats.as_ref(),
            )
            .await;
            let current_snapshot = fairness.snapshot();
            apply_fairness_metrics_delta(stats.as_ref(), &mut fairness_snapshot, current_snapshot);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::PressureState;
    use crate::transport::middle_proxy::ConnRegistry;

    use super::{
        MeResponse, RouteResult, WorkerFairnessSnapshot, fairness_retry_delay,
        is_data_route_queue_full, route_data_with_retry,
        should_close_on_queue_full_streak_with_policy, should_close_on_route_result_for_ack,
        should_close_on_route_result_for_data, should_schedule_fairness_retry,
    };

    #[test]
    fn data_route_only_fatal_results_close_immediately() {
        assert!(!should_close_on_route_result_for_data(RouteResult::Routed));
        assert!(!should_close_on_route_result_for_data(
            RouteResult::QueueFullBase
        ));
        assert!(!should_close_on_route_result_for_data(
            RouteResult::QueueFullHigh
        ));
        assert!(should_close_on_route_result_for_data(RouteResult::NoConn));
        assert!(should_close_on_route_result_for_data(
            RouteResult::ChannelClosed
        ));
    }

    #[test]
    fn data_route_queue_full_uses_starvation_threshold() {
        assert!(is_data_route_queue_full(RouteResult::QueueFullBase));
        assert!(is_data_route_queue_full(RouteResult::QueueFullHigh));
        assert!(!is_data_route_queue_full(RouteResult::NoConn));
        assert!(!should_close_on_queue_full_streak_with_policy(
            1,
            PressureState::Normal,
            true
        ));
        assert!(!should_close_on_queue_full_streak_with_policy(
            2,
            PressureState::Pressured,
            true
        ));
        assert!(!should_close_on_queue_full_streak_with_policy(
            3,
            PressureState::Pressured,
            true
        ));
        assert!(should_close_on_queue_full_streak_with_policy(
            3,
            PressureState::Shedding,
            true
        ));
        assert!(should_close_on_queue_full_streak_with_policy(
            u8::MAX,
            PressureState::Saturated,
            true
        ));
        assert!(!should_close_on_queue_full_streak_with_policy(
            u8::MAX,
            PressureState::Saturated,
            false
        ));
    }

    #[test]
    fn fairness_retry_is_scheduled_only_when_queue_has_pending_bytes() {
        let mut snapshot = WorkerFairnessSnapshot::default();
        assert!(!should_schedule_fairness_retry(&snapshot));

        snapshot.total_queued_bytes = 1;
        assert!(should_schedule_fairness_retry(&snapshot));
    }

    #[test]
    fn fairness_retry_delay_never_drops_below_one_millisecond() {
        assert_eq!(fairness_retry_delay(0), Duration::from_millis(1));
        assert_eq!(fairness_retry_delay(2), Duration::from_millis(2));
    }

    #[test]
    fn ack_queue_full_is_soft_dropped_without_forced_close() {
        assert!(!should_close_on_route_result_for_ack(RouteResult::Routed));
        assert!(!should_close_on_route_result_for_ack(
            RouteResult::QueueFullBase
        ));
        assert!(!should_close_on_route_result_for_ack(
            RouteResult::QueueFullHigh
        ));
        assert!(should_close_on_route_result_for_ack(RouteResult::NoConn));
        assert!(should_close_on_route_result_for_ack(
            RouteResult::ChannelClosed
        ));
    }

    #[tokio::test]
    async fn route_data_with_retry_returns_routed_when_channel_has_capacity() {
        let reg = ConnRegistry::with_route_channel_capacity(1);
        let (conn_id, mut rx) = reg.register().await;

        let routed = route_data_with_retry(&reg, conn_id, 0, Bytes::from_static(b"a"), 20).await;
        assert!(matches!(routed, RouteResult::Routed));
        match rx.recv().await {
            Some(MeResponse::Data { flags, data, .. }) => {
                assert_eq!(flags, 0);
                assert_eq!(data, Bytes::from_static(b"a"));
            }
            other => panic!("expected routed data response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn route_data_with_retry_stops_after_bounded_attempts() {
        let reg = ConnRegistry::with_route_channel_capacity(1);
        let (conn_id, _rx) = reg.register().await;

        assert!(matches!(
            reg.route_nowait(conn_id, MeResponse::Ack(1)).await,
            RouteResult::Routed
        ));

        let routed = route_data_with_retry(&reg, conn_id, 0, Bytes::from_static(b"a"), 0).await;
        assert!(matches!(
            routed,
            RouteResult::QueueFullBase | RouteResult::QueueFullHigh
        ));
    }
}

async fn send_close_conn(tx: &mpsc::Sender<WriterCommand>, conn_id: u64) {
    let mut p = Vec::with_capacity(12);
    p.extend_from_slice(&RPC_CLOSE_CONN_U32.to_le_bytes());
    p.extend_from_slice(&conn_id.to_le_bytes());
    match tx.try_send(WriterCommand::DataAndFlush(Bytes::from(p))) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            debug!(
                conn_id,
                "ME close_conn signal skipped: writer command channel is full"
            );
        }
        Err(TrySendError::Closed(_)) => {
            debug!(
                conn_id,
                "ME close_conn signal skipped: writer command channel is closed"
            );
        }
    }
}
