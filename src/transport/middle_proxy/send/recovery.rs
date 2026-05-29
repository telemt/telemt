use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tracing::warn;

use super::super::MePool;
use super::{
    HYBRID_GLOBAL_BURST_PERIOD_ROUNDS, HYBRID_RECENT_SUCCESS_WINDOW_MS,
    HYBRID_RECOVERY_TRIGGER_MIN_INTERVAL_MS, HYBRID_TIMEOUT_WARN_RATE_LIMIT_MS,
};

impl MePool {
    pub(super) async fn wait_for_writer_until(&self, deadline: Instant) -> bool {
        let mut rx = self.writer_epoch.subscribe();
        if !self.writers.snapshot().is_empty() {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return !self.writers.snapshot().is_empty();
        }
        let timeout = deadline.saturating_duration_since(now);
        if tokio::time::timeout(timeout, rx.changed()).await.is_ok() {
            return !self.writers.snapshot().is_empty();
        }
        !self.writers.snapshot().is_empty()
    }

    pub(super) async fn wait_for_candidate_until(&self, routed_dc: i32, deadline: Instant) -> bool {
        let mut rx = self.writer_epoch.subscribe();
        loop {
            if self.has_candidate_for_target_dc(routed_dc).await {
                return true;
            }

            let now = Instant::now();
            if now >= deadline {
                return self.has_candidate_for_target_dc(routed_dc).await;
            }

            if self.has_candidate_for_target_dc(routed_dc).await {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.has_candidate_for_target_dc(routed_dc).await;
            }
            if tokio::time::timeout(remaining, rx.changed()).await.is_err() {
                return self.has_candidate_for_target_dc(routed_dc).await;
            }
        }
    }

    pub(super) async fn has_candidate_for_target_dc(&self, routed_dc: i32) -> bool {
        let writers_snapshot = {
            let ws = self.writers.snapshot();
            if ws.is_empty() {
                return false;
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
        !candidate_indices.is_empty()
    }

    pub(super) async fn trigger_async_recovery_for_target_dc(
        self: &Arc<Self>,
        routed_dc: i32,
    ) -> bool {
        let endpoints = self.preferred_endpoints_for_dc(routed_dc).await;
        if endpoints.is_empty() {
            return false;
        }
        self.stats.increment_me_async_recovery_trigger_total();
        for addr in endpoints.into_iter().take(8) {
            self.trigger_immediate_refill_for_dc(addr, routed_dc);
        }
        true
    }

    pub(super) async fn trigger_async_recovery_global(self: &Arc<Self>) {
        self.stats.increment_me_async_recovery_trigger_total();
        let preferred = self.preferred_endpoints_by_dc.load();
        let mut triggered = 0usize;
        for (dc, addrs) in preferred.iter() {
            for addr in addrs {
                self.trigger_immediate_refill_for_dc(*addr, *dc);
                triggered = triggered.saturating_add(1);
                if triggered >= 8 {
                    return;
                }
            }
        }
    }

    pub(super) async fn maybe_trigger_hybrid_recovery(
        self: &Arc<Self>,
        routed_dc: i32,
        hybrid_recovery_round: &mut u32,
        hybrid_last_recovery_at: &mut Option<Instant>,
        hybrid_wait_step: Duration,
    ) {
        if !self.try_consume_hybrid_recovery_trigger_slot(HYBRID_RECOVERY_TRIGGER_MIN_INTERVAL_MS) {
            return;
        }
        if let Some(last) = *hybrid_last_recovery_at
            && last.elapsed() < hybrid_wait_step
        {
            return;
        }

        let round = *hybrid_recovery_round;
        let target_triggered = self.trigger_async_recovery_for_target_dc(routed_dc).await;
        if !target_triggered || round.is_multiple_of(HYBRID_GLOBAL_BURST_PERIOD_ROUNDS) {
            self.trigger_async_recovery_global().await;
        }
        *hybrid_recovery_round = round.saturating_add(1);
        *hybrid_last_recovery_at = Some(Instant::now());
    }

    pub(super) fn hybrid_total_wait_budget(&self) -> Duration {
        let base = self
            .route_runtime
            .me_route_hybrid_max_wait
            .max(Duration::from_millis(50));
        let now_ms = Self::now_epoch_millis();
        let last_success_ms = self
            .route_runtime
            .me_route_last_success_epoch_ms
            .load(Ordering::Relaxed);
        if last_success_ms != 0
            && now_ms.saturating_sub(last_success_ms) <= HYBRID_RECENT_SUCCESS_WINDOW_MS
        {
            return base.saturating_mul(2);
        }
        base
    }

    pub(super) fn note_hybrid_route_success(&self) {
        self.route_runtime
            .me_route_last_success_epoch_ms
            .store(Self::now_epoch_millis(), Ordering::Relaxed);
    }

    pub(super) fn on_hybrid_timeout(&self, deadline: Instant, routed_dc: i32) {
        self.stats.increment_me_hybrid_timeout_total();
        let now_ms = Self::now_epoch_millis();
        let mut last_warn_ms = self
            .route_runtime
            .me_route_hybrid_timeout_warn_epoch_ms
            .load(Ordering::Relaxed);
        while now_ms.saturating_sub(last_warn_ms) >= HYBRID_TIMEOUT_WARN_RATE_LIMIT_MS {
            match self
                .route_runtime
                .me_route_hybrid_timeout_warn_epoch_ms
                .compare_exchange_weak(last_warn_ms, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => {
                    warn!(
                        routed_dc,
                        budget_ms = self.hybrid_total_wait_budget().as_millis() as u64,
                        elapsed_ms = deadline.elapsed().as_millis() as u64,
                        "ME hybrid route timeout reached"
                    );
                    break;
                }
                Err(actual) => last_warn_ms = actual,
            }
        }
    }

    pub(super) fn try_consume_hybrid_recovery_trigger_slot(&self, min_interval_ms: u64) -> bool {
        let now_ms = Self::now_epoch_millis();
        let mut last_trigger_ms = self
            .route_runtime
            .me_async_recovery_last_trigger_epoch_ms
            .load(Ordering::Relaxed);
        loop {
            if now_ms.saturating_sub(last_trigger_ms) < min_interval_ms {
                return false;
            }
            match self
                .route_runtime
                .me_async_recovery_last_trigger_epoch_ms
                .compare_exchange_weak(last_trigger_ms, now_ms, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(actual) => last_trigger_ms = actual,
            }
        }
    }
}
