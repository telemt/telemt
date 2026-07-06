#![allow(clippy::too_many_arguments)]

use std::cmp::Reverse;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, warn};

use super::MePool;
use super::codec::{ProxyReqCommand, WriterCommand};
use super::registry::ConnMeta;
use super::wire::build_proxy_req_payload;
use crate::config::{MeRouteNoWriterMode, MeWriterPickMode};
use crate::error::{ProxyError, Result};
use crate::stream::PooledBuffer;
use rand::seq::SliceRandom;

const IDLE_WRITER_PENALTY_MID_SECS: u64 = 45;
const IDLE_WRITER_PENALTY_HIGH_SECS: u64 = 55;
const HYBRID_GLOBAL_BURST_PERIOD_ROUNDS: u32 = 4;
const HYBRID_RECENT_SUCCESS_WINDOW_MS: u64 = 120_000;
const HYBRID_TIMEOUT_WARN_RATE_LIMIT_MS: u64 = 5_000;
const HYBRID_RECOVERY_TRIGGER_MIN_INTERVAL_MS: u64 = 5_000;
const PICK_PENALTY_WARM: u64 = 200;
const PICK_PENALTY_DRAINING: u64 = 600;
const PICK_PENALTY_STALE: u64 = 300;
const PICK_PENALTY_DEGRADED: u64 = 250;

mod close;
mod recovery;
mod selection;

enum WriterCommandReserveError {
    Closed,
    TimedOut,
}

fn proxy_tag_array(tag: Option<&[u8]>) -> Option<[u8; 16]> {
    tag.and_then(|tag| <[u8; 16]>::try_from(tag).ok())
}

fn proxy_req_payload_from_command(cmd: WriterCommand) -> Option<PooledBuffer> {
    match cmd {
        WriterCommand::ProxyReq(command) => Some(command.payload),
        _ => None,
    }
}

async fn reserve_writer_command_slot(
    tx: &mpsc::Sender<WriterCommand>,
    wait: Option<Duration>,
) -> std::result::Result<mpsc::OwnedPermit<WriterCommand>, WriterCommandReserveError> {
    let reserve = tx.clone().reserve_owned();
    match wait {
        Some(wait) => match tokio::time::timeout(wait, reserve).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(WriterCommandReserveError::Closed),
            Err(_) => Err(WriterCommandReserveError::TimedOut),
        },
        None => reserve.await.map_err(|_| WriterCommandReserveError::Closed),
    }
}

impl MePool {
    /// Send RPC_PROXY_REQ. `tag_override`: per-user ad_tag (from access.user_ad_tags); if None, uses pool default.
    pub async fn send_proxy_req(
        self: &Arc<Self>,
        conn_id: u64,
        target_dc: i16,
        client_addr: SocketAddr,
        our_addr: SocketAddr,
        data: &[u8],
        proto_flags: u32,
        tag_override: Option<&[u8]>,
    ) -> Result<()> {
        let tag = tag_override.or(self.proxy_tag.as_deref());
        let build_routed_payload = |effective_our_addr: SocketAddr| {
            (
                build_proxy_req_payload(
                    conn_id,
                    client_addr,
                    effective_our_addr,
                    data,
                    tag,
                    proto_flags,
                ),
                ConnMeta {
                    target_dc,
                    client_addr,
                    our_addr: effective_our_addr,
                    proto_flags,
                },
            )
        };
        let no_writer_mode = MeRouteNoWriterMode::from_u8(
            self.route_runtime
                .me_route_no_writer_mode
                .load(Ordering::Relaxed),
        );
        let (routed_dc, unknown_target_dc) =
            self.resolve_target_dc_for_routing(target_dc as i32).await;
        let mut no_writer_deadline: Option<Instant> = None;
        let mut emergency_attempts = 0u32;
        let mut async_recovery_triggered = false;
        let mut hybrid_recovery_round = 0u32;
        let mut hybrid_last_recovery_at: Option<Instant> = None;
        let mut hybrid_total_deadline: Option<Instant> = None;
        let hybrid_wait_step = self
            .route_runtime
            .me_route_no_writer_wait
            .max(Duration::from_millis(50));
        let mut hybrid_wait_current = hybrid_wait_step;

        loop {
            if let Some((current, current_meta)) = self.registry.get_writer_with_meta(conn_id).await
            {
                let (current_payload, _) = build_routed_payload(current_meta.our_addr);
                match current.tx.try_send(WriterCommand::Data(current_payload)) {
                    Ok(()) => {
                        self.note_hybrid_route_success();
                        return Ok(());
                    }
                    Err(TrySendError::Full(cmd)) => {
                        match reserve_writer_command_slot(
                            &current.tx,
                            self.route_runtime.me_route_blocking_send_timeout,
                        )
                        .await
                        {
                            Ok(permit) => {
                                permit.send(cmd);
                                self.note_hybrid_route_success();
                                return Ok(());
                            }
                            Err(WriterCommandReserveError::TimedOut) => {
                                self.stats
                                    .increment_me_writer_pick_full_total(self.writer_pick_mode());
                                return Err(ProxyError::Proxy(
                                    "ME writer channel full within blocking send timeout".into(),
                                ));
                            }
                            Err(WriterCommandReserveError::Closed) => {}
                        }
                        warn!(writer_id = current.writer_id, "ME writer channel closed");
                        self.remove_writer_and_close_clients(current.writer_id)
                            .await;
                        continue;
                    }
                    Err(TrySendError::Closed(_)) => {
                        warn!(writer_id = current.writer_id, "ME writer channel closed");
                        self.remove_writer_and_close_clients(current.writer_id)
                            .await;
                        continue;
                    }
                }
            }

            let mut writers_snapshot = {
                let ws = self.writers.snapshot();
                if ws.is_empty() {
                    match no_writer_mode {
                        MeRouteNoWriterMode::AsyncRecoveryFailfast => {
                            let deadline = *no_writer_deadline.get_or_insert_with(|| {
                                Instant::now() + self.route_runtime.me_route_no_writer_wait
                            });
                            if !async_recovery_triggered && !unknown_target_dc {
                                let triggered =
                                    self.trigger_async_recovery_for_target_dc(routed_dc).await;
                                if !triggered {
                                    self.trigger_async_recovery_global().await;
                                }
                                async_recovery_triggered = true;
                            }
                            if self.wait_for_writer_until(deadline).await {
                                continue;
                            }
                            self.stats.increment_me_no_writer_failfast_total();
                            return Err(ProxyError::Proxy(
                                "No ME writer available in failfast window".into(),
                            ));
                        }
                        MeRouteNoWriterMode::InlineRecoveryLegacy => {
                            self.stats.increment_me_inline_recovery_total();
                            if !unknown_target_dc {
                                for _ in
                                    0..self.route_runtime.me_route_inline_recovery_attempts.max(1)
                                {
                                    let preferred = self.preferred_endpoints_by_dc.load_full();
                                    for (dc, addrs) in preferred.iter() {
                                        for addr in addrs {
                                            let _ = self
                                                .connect_one_for_dc(*addr, *dc, self.rng.as_ref())
                                                .await;
                                        }
                                    }
                                    if !self.writers.snapshot().is_empty() {
                                        break;
                                    }
                                }
                            }

                            if !self.writers.snapshot().is_empty() {
                                continue;
                            }
                            let deadline = *no_writer_deadline.get_or_insert_with(|| {
                                Instant::now() + self.route_runtime.me_route_inline_recovery_wait
                            });
                            if !self.wait_for_writer_until(deadline).await {
                                if !self.writers.snapshot().is_empty() {
                                    continue;
                                }
                                self.stats.increment_me_no_writer_failfast_total();
                                return Err(ProxyError::Proxy(
                                    "All ME connections dead (legacy wait timeout)".into(),
                                ));
                            }
                            continue;
                        }
                        MeRouteNoWriterMode::HybridAsyncPersistent => {
                            let total_deadline = *hybrid_total_deadline.get_or_insert_with(|| {
                                Instant::now() + self.hybrid_total_wait_budget()
                            });
                            if Instant::now() >= total_deadline {
                                self.on_hybrid_timeout(total_deadline, routed_dc);
                                return Err(ProxyError::Proxy(
                                    "ME writer not available within hybrid timeout".into(),
                                ));
                            }
                            if !unknown_target_dc {
                                self.maybe_trigger_hybrid_recovery(
                                    routed_dc,
                                    &mut hybrid_recovery_round,
                                    &mut hybrid_last_recovery_at,
                                    hybrid_wait_current,
                                )
                                .await;
                            }
                            let deadline = Instant::now() + hybrid_wait_current;
                            let _ = self.wait_for_writer_until(deadline).await;
                            hybrid_wait_current = (hybrid_wait_current.saturating_mul(2))
                                .min(Duration::from_millis(400));
                            continue;
                        }
                    }
                }
                ws
            };

            let mut candidate_indices = self
                .candidate_indices_for_dc(&writers_snapshot, routed_dc, false)
                .await;
            if candidate_indices.is_empty() {
                candidate_indices = self
                    .candidate_indices_for_dc(&writers_snapshot, routed_dc, true)
                    .await;
            }
            if candidate_indices.is_empty() {
                let pick_mode = self.writer_pick_mode();
                match no_writer_mode {
                    MeRouteNoWriterMode::AsyncRecoveryFailfast => {
                        let deadline = *no_writer_deadline.get_or_insert_with(|| {
                            Instant::now() + self.route_runtime.me_route_no_writer_wait
                        });
                        if !async_recovery_triggered && !unknown_target_dc {
                            let triggered =
                                self.trigger_async_recovery_for_target_dc(routed_dc).await;
                            if !triggered {
                                self.trigger_async_recovery_global().await;
                            }
                            async_recovery_triggered = true;
                        }
                        if self.wait_for_candidate_until(routed_dc, deadline).await {
                            continue;
                        }
                        self.stats
                            .increment_me_writer_pick_no_candidate_total(pick_mode);
                        self.stats.increment_me_no_writer_failfast_total();
                        return Err(ProxyError::Proxy(
                            "No ME writers available for target DC in failfast window".into(),
                        ));
                    }
                    MeRouteNoWriterMode::InlineRecoveryLegacy => {
                        self.stats.increment_me_inline_recovery_total();
                        if unknown_target_dc {
                            let deadline = *no_writer_deadline.get_or_insert_with(|| {
                                Instant::now() + self.route_runtime.me_route_inline_recovery_wait
                            });
                            if self.wait_for_candidate_until(routed_dc, deadline).await {
                                continue;
                            }
                            self.stats
                                .increment_me_writer_pick_no_candidate_total(pick_mode);
                            self.stats.increment_me_no_writer_failfast_total();
                            return Err(ProxyError::Proxy(
                                "No ME writers available for target DC".into(),
                            ));
                        }
                        if emergency_attempts
                            >= self.route_runtime.me_route_inline_recovery_attempts.max(1)
                        {
                            self.stats
                                .increment_me_writer_pick_no_candidate_total(pick_mode);
                            self.stats.increment_me_no_writer_failfast_total();
                            return Err(ProxyError::Proxy(
                                "No ME writers available for target DC".into(),
                            ));
                        }
                        emergency_attempts += 1;
                        let mut endpoints = self
                            .preferred_endpoints_by_dc
                            .load()
                            .get(&routed_dc)
                            .cloned()
                            .unwrap_or_default();
                        endpoints.shuffle(&mut rand::rng());
                        for addr in endpoints {
                            if self
                                .connect_one_for_dc(addr, routed_dc, self.rng.as_ref())
                                .await
                                .is_ok()
                            {
                                break;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(100 * emergency_attempts as u64))
                            .await;
                        writers_snapshot = self.writers.snapshot();
                        candidate_indices = self
                            .candidate_indices_for_dc(&writers_snapshot, routed_dc, false)
                            .await;
                        if candidate_indices.is_empty() {
                            candidate_indices = self
                                .candidate_indices_for_dc(&writers_snapshot, routed_dc, true)
                                .await;
                        }
                        if candidate_indices.is_empty() {
                            self.stats
                                .increment_me_writer_pick_no_candidate_total(pick_mode);
                            return Err(ProxyError::Proxy(
                                "No ME writers available for target DC".into(),
                            ));
                        }
                    }
                    MeRouteNoWriterMode::HybridAsyncPersistent => {
                        let total_deadline = *hybrid_total_deadline.get_or_insert_with(|| {
                            Instant::now() + self.hybrid_total_wait_budget()
                        });
                        if Instant::now() >= total_deadline {
                            self.on_hybrid_timeout(total_deadline, routed_dc);
                            return Err(ProxyError::Proxy(
                                "No ME writers available for target DC within hybrid timeout"
                                    .into(),
                            ));
                        }
                        if !unknown_target_dc {
                            self.maybe_trigger_hybrid_recovery(
                                routed_dc,
                                &mut hybrid_recovery_round,
                                &mut hybrid_last_recovery_at,
                                hybrid_wait_current,
                            )
                            .await;
                        }
                        let deadline = Instant::now() + hybrid_wait_current;
                        let _ = self.wait_for_candidate_until(routed_dc, deadline).await;
                        hybrid_wait_current =
                            (hybrid_wait_current.saturating_mul(2)).min(Duration::from_millis(400));
                        continue;
                    }
                }
            }
            hybrid_wait_current = hybrid_wait_step;
            let pick_mode = self.writer_pick_mode();
            let pick_sample_size = self.writer_pick_sample_size();
            let writer_ids: Vec<u64> = candidate_indices
                .iter()
                .map(|idx| writers_snapshot[*idx].id)
                .collect();
            let writer_idle_since = self
                .registry
                .writer_idle_since_for_writer_ids(&writer_ids)
                .await;
            let now_epoch_secs = Self::now_epoch_secs();
            let start = self.rr.fetch_add(1, Ordering::Relaxed) as usize % candidate_indices.len();
            let ordered_candidate_indices = if pick_mode == MeWriterPickMode::P2c {
                self.p2c_ordered_candidate_indices(
                    &candidate_indices,
                    &writers_snapshot,
                    &writer_idle_since,
                    now_epoch_secs,
                    start,
                    pick_sample_size,
                )
            } else {
                if self
                    .writer_selection_policy
                    .me_deterministic_writer_sort
                    .load(Ordering::Relaxed)
                {
                    candidate_indices.sort_by(|lhs, rhs| {
                        let left = &writers_snapshot[*lhs];
                        let right = &writers_snapshot[*rhs];
                        let left_key = (
                            self.writer_contour_rank_for_selection(left),
                            (left.generation < self.current_generation()) as usize,
                            left.degraded.load(Ordering::Relaxed) as usize,
                            self.writer_idle_rank_for_selection(
                                left,
                                &writer_idle_since,
                                now_epoch_secs,
                            ),
                            Reverse(left.tx.capacity()),
                            left.addr,
                            left.id,
                        );
                        let right_key = (
                            self.writer_contour_rank_for_selection(right),
                            (right.generation < self.current_generation()) as usize,
                            right.degraded.load(Ordering::Relaxed) as usize,
                            self.writer_idle_rank_for_selection(
                                right,
                                &writer_idle_since,
                                now_epoch_secs,
                            ),
                            Reverse(right.tx.capacity()),
                            right.addr,
                            right.id,
                        );
                        left_key.cmp(&right_key)
                    });
                } else {
                    candidate_indices.sort_by_key(|idx| {
                        let w = &writers_snapshot[*idx];
                        let degraded = w.degraded.load(Ordering::Relaxed);
                        let stale = (w.generation < self.current_generation()) as usize;
                        (
                            self.writer_contour_rank_for_selection(w),
                            stale,
                            degraded as usize,
                            self.writer_idle_rank_for_selection(
                                w,
                                &writer_idle_since,
                                now_epoch_secs,
                            ),
                            Reverse(w.tx.capacity()),
                        )
                    });
                }

                let mut ordered = Vec::<usize>::with_capacity(candidate_indices.len());
                for offset in 0..candidate_indices.len() {
                    ordered.push(candidate_indices[(start + offset) % candidate_indices.len()]);
                }
                ordered
            };
            let mut fallback_blocking_idx: Option<usize> = None;

            for idx in ordered_candidate_indices {
                let w = &writers_snapshot[idx];
                if !self.writer_accepts_new_binding(w) {
                    continue;
                }
                // Keep the advertised proxy IP aligned with the selected ME writer source.
                let effective_our_addr = SocketAddr::new(w.source_ip, our_addr.port());
                let (payload, meta) = build_routed_payload(effective_our_addr);
                match w.tx.clone().try_reserve_owned() {
                    Ok(permit) => {
                        if !self.registry.bind_writer(conn_id, w.id, meta).await {
                            debug!(
                                conn_id,
                                writer_id = w.id,
                                "ME writer disappeared before bind commit, pruning stale writer"
                            );
                            drop(permit);
                            self.remove_writer_and_close_clients(w.id).await;
                            continue;
                        }
                        permit.send(WriterCommand::Data(payload));
                        self.stats
                            .increment_me_writer_pick_success_try_total(pick_mode);
                        if w.generation < self.current_generation() {
                            self.stats.increment_pool_stale_pick_total();
                            debug!(
                                conn_id,
                                writer_id = w.id,
                                writer_generation = w.generation,
                                current_generation = self.current_generation(),
                                "Selected stale ME writer for fallback bind"
                            );
                        }
                        self.note_hybrid_route_success();
                        return Ok(());
                    }
                    Err(TrySendError::Full(_)) => {
                        if fallback_blocking_idx.is_none() {
                            fallback_blocking_idx = Some(idx);
                        }
                    }
                    Err(TrySendError::Closed(_)) => {
                        self.stats.increment_me_writer_pick_closed_total(pick_mode);
                        warn!(writer_id = w.id, "ME writer channel closed");
                        self.remove_writer_and_close_clients(w.id).await;
                        continue;
                    }
                }
            }

            let Some(blocking_idx) = fallback_blocking_idx else {
                self.stats.increment_me_writer_pick_full_total(pick_mode);
                continue;
            };

            let w = writers_snapshot[blocking_idx].clone();
            if !self.writer_accepts_new_binding(&w) {
                self.stats.increment_me_writer_pick_full_total(pick_mode);
                continue;
            }
            self.stats
                .increment_me_writer_pick_blocking_fallback_total();
            // Keep the advertised proxy IP aligned with the selected ME writer source.
            let effective_our_addr = SocketAddr::new(w.source_ip, our_addr.port());
            let (payload, meta) = build_routed_payload(effective_our_addr);
            let reserve_result =
                if let Some(timeout) = self.route_runtime.me_route_blocking_send_timeout {
                    match tokio::time::timeout(timeout, w.tx.clone().reserve_owned()).await {
                        Ok(result) => result,
                        Err(_) => {
                            self.stats.increment_me_writer_pick_full_total(pick_mode);
                            continue;
                        }
                    }
                } else {
                    w.tx.clone().reserve_owned().await
                };
            match reserve_result {
                Ok(permit) => {
                    if !self.registry.bind_writer(conn_id, w.id, meta).await {
                        debug!(
                            conn_id,
                            writer_id = w.id,
                            "ME writer disappeared before fallback bind commit, pruning stale writer"
                        );
                        drop(permit);
                        self.remove_writer_and_close_clients(w.id).await;
                        continue;
                    }
                    permit.send(WriterCommand::Data(payload));
                    self.stats
                        .increment_me_writer_pick_success_fallback_total(pick_mode);
                    if w.generation < self.current_generation() {
                        self.stats.increment_pool_stale_pick_total();
                    }
                    self.note_hybrid_route_success();
                    return Ok(());
                }
                Err(_) => {
                    self.stats.increment_me_writer_pick_closed_total(pick_mode);
                    warn!(writer_id = w.id, "ME writer channel closed (blocking)");
                    self.remove_writer_and_close_clients(w.id).await;
                }
            }
        }
    }

    /// Send RPC_PROXY_REQ while keeping the first bound-writer path allocation-light.
    pub async fn send_proxy_req_pooled(
        self: &Arc<Self>,
        conn_id: u64,
        target_dc: i16,
        client_addr: SocketAddr,
        our_addr: SocketAddr,
        payload: PooledBuffer,
        proto_flags: u32,
        tag_override: Option<[u8; 16]>,
    ) -> Result<()> {
        let tag = tag_override.or_else(|| proxy_tag_array(self.proxy_tag.as_deref()));

        if let Some((current, current_meta)) = self.registry.get_writer_with_meta(conn_id).await {
            let command = WriterCommand::ProxyReq(ProxyReqCommand {
                conn_id,
                client_addr,
                our_addr: current_meta.our_addr,
                proto_flags,
                proxy_tag: tag,
                payload,
            });
            match current.tx.try_send(command) {
                Ok(()) => {
                    self.note_hybrid_route_success();
                    return Ok(());
                }
                Err(TrySendError::Full(cmd)) => {
                    match reserve_writer_command_slot(
                        &current.tx,
                        self.route_runtime.me_route_blocking_send_timeout,
                    )
                    .await
                    {
                        Ok(permit) => {
                            permit.send(cmd);
                            self.note_hybrid_route_success();
                            return Ok(());
                        }
                        Err(WriterCommandReserveError::TimedOut) => {
                            self.stats
                                .increment_me_writer_pick_full_total(self.writer_pick_mode());
                            return Err(ProxyError::Proxy(
                                "ME writer channel full within blocking send timeout".into(),
                            ));
                        }
                        Err(WriterCommandReserveError::Closed) => {
                            let Some(payload) = proxy_req_payload_from_command(cmd) else {
                                return Err(ProxyError::Proxy(
                                    "ME writer rejected unexpected command type".into(),
                                ));
                            };
                            warn!(writer_id = current.writer_id, "ME writer channel closed");
                            self.remove_writer_and_close_clients(current.writer_id)
                                .await;
                            return self
                                .send_proxy_req(
                                    conn_id,
                                    target_dc,
                                    client_addr,
                                    our_addr,
                                    payload.as_ref(),
                                    proto_flags,
                                    tag.as_ref().map(|tag| tag.as_slice()),
                                )
                                .await;
                        }
                    }
                }
                Err(TrySendError::Closed(cmd)) => {
                    let Some(payload) = proxy_req_payload_from_command(cmd) else {
                        return Err(ProxyError::Proxy(
                            "ME writer rejected unexpected command type".into(),
                        ));
                    };
                    warn!(writer_id = current.writer_id, "ME writer channel closed");
                    self.remove_writer_and_close_clients(current.writer_id)
                        .await;
                    return self
                        .send_proxy_req(
                            conn_id,
                            target_dc,
                            client_addr,
                            our_addr,
                            payload.as_ref(),
                            proto_flags,
                            tag.as_ref().map(|tag| tag.as_slice()),
                        )
                        .await;
                }
            }
        }

        self.send_proxy_req(
            conn_id,
            target_dc,
            client_addr,
            our_addr,
            payload.as_ref(),
            proto_flags,
            tag.as_ref().map(|tag| tag.as_slice()),
        )
        .await
    }
}
