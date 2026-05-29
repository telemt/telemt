use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;

use super::super::MePool;
use super::super::pool::WriterContour;
use super::{
    IDLE_WRITER_PENALTY_HIGH_SECS, IDLE_WRITER_PENALTY_MID_SECS, PICK_PENALTY_DEGRADED,
    PICK_PENALTY_DRAINING, PICK_PENALTY_STALE, PICK_PENALTY_WARM,
};

impl MePool {
    pub(super) async fn candidate_indices_for_dc(
        &self,
        writers: &[super::super::pool::MeWriter],
        routed_dc: i32,
        include_warm: bool,
    ) -> Vec<usize> {
        let preferred_snapshot = self.preferred_endpoints_by_dc.load();
        let Some(preferred) = preferred_snapshot.get(&routed_dc) else {
            return Vec::new();
        };
        if preferred.is_empty() {
            return Vec::new();
        }

        let mut out = Vec::new();
        for (idx, w) in writers.iter().enumerate() {
            if !self.writer_eligible_for_selection(w, include_warm) {
                continue;
            }
            if w.writer_dc == routed_dc && preferred.binary_search(&w.addr).is_ok() {
                out.push(idx);
            }
        }
        out
    }

    pub(super) fn writer_eligible_for_selection(
        &self,
        writer: &super::super::pool::MeWriter,
        include_warm: bool,
    ) -> bool {
        if !self.writer_accepts_new_binding(writer) {
            return false;
        }

        match WriterContour::from_u8(writer.contour.load(Ordering::Relaxed)) {
            WriterContour::Active => true,
            WriterContour::Warm => include_warm,
            WriterContour::Draining => true,
        }
    }

    pub(super) fn writer_contour_rank_for_selection(
        &self,
        writer: &super::super::pool::MeWriter,
    ) -> usize {
        match WriterContour::from_u8(writer.contour.load(Ordering::Relaxed)) {
            WriterContour::Active => 0,
            WriterContour::Warm => 1,
            WriterContour::Draining => 2,
        }
    }

    pub(super) fn writer_idle_rank_for_selection(
        &self,
        writer: &super::super::pool::MeWriter,
        idle_since_by_writer: &HashMap<u64, u64>,
        now_epoch_secs: u64,
    ) -> usize {
        let Some(idle_since) = idle_since_by_writer.get(&writer.id).copied() else {
            return 0;
        };
        let idle_age_secs = now_epoch_secs.saturating_sub(idle_since);
        if idle_age_secs >= IDLE_WRITER_PENALTY_HIGH_SECS {
            2
        } else if idle_age_secs >= IDLE_WRITER_PENALTY_MID_SECS {
            1
        } else {
            0
        }
    }

    pub(super) fn writer_pick_score(
        &self,
        writer: &super::super::pool::MeWriter,
        idle_since_by_writer: &HashMap<u64, u64>,
        now_epoch_secs: u64,
    ) -> u64 {
        let contour_penalty = match WriterContour::from_u8(writer.contour.load(Ordering::Relaxed)) {
            WriterContour::Active => 0,
            WriterContour::Warm => PICK_PENALTY_WARM,
            WriterContour::Draining => PICK_PENALTY_DRAINING,
        };
        let stale_penalty = if writer.generation < self.current_generation() {
            PICK_PENALTY_STALE
        } else {
            0
        };
        let degraded_penalty = if writer.degraded.load(Ordering::Relaxed) {
            PICK_PENALTY_DEGRADED
        } else {
            0
        };
        let idle_penalty =
            (self.writer_idle_rank_for_selection(writer, idle_since_by_writer, now_epoch_secs)
                as u64)
                * 100;
        let queue_cap = self.writer_lifecycle.writer_cmd_channel_capacity.max(1) as u64;
        let queue_remaining = writer.tx.capacity() as u64;
        let queue_used = queue_cap.saturating_sub(queue_remaining.min(queue_cap));
        let queue_util_pct = queue_used.saturating_mul(100) / queue_cap;
        let queue_penalty = queue_util_pct.saturating_mul(4);
        let rtt_penalty =
            ((writer.rtt_ema_ms_x10.load(Ordering::Relaxed) as u64).saturating_add(5) / 10)
                .min(400);

        contour_penalty
            .saturating_add(stale_penalty)
            .saturating_add(degraded_penalty)
            .saturating_add(idle_penalty)
            .saturating_add(queue_penalty)
            .saturating_add(rtt_penalty)
    }

    pub(super) fn p2c_ordered_candidate_indices(
        &self,
        candidate_indices: &[usize],
        writers_snapshot: &[super::super::pool::MeWriter],
        idle_since_by_writer: &HashMap<u64, u64>,
        now_epoch_secs: u64,
        start: usize,
        sample_size: usize,
    ) -> Vec<usize> {
        let total = candidate_indices.len();
        if total == 0 {
            return Vec::new();
        }

        let mut sampled = Vec::<usize>::with_capacity(sample_size.min(total));
        let mut seen = HashSet::<usize>::with_capacity(total);
        for offset in 0..sample_size.min(total) {
            let idx = candidate_indices[(start + offset) % total];
            if seen.insert(idx) {
                sampled.push(idx);
            }
        }

        sampled.sort_by_key(|idx| {
            let writer = &writers_snapshot[*idx];
            (
                self.writer_pick_score(writer, idle_since_by_writer, now_epoch_secs),
                writer.addr,
                writer.id,
            )
        });

        let mut ordered = Vec::<usize>::with_capacity(total);
        ordered.extend(sampled.iter().copied());
        for offset in 0..total {
            let idx = candidate_indices[(start + offset) % total];
            if seen.insert(idx) {
                ordered.push(idx);
            }
        }
        ordered
    }
}
