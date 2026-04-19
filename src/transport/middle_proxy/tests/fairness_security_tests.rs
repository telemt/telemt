use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::protocol::constants::RPC_FLAG_QUICKACK;
use crate::transport::middle_proxy::fairness::{
    AdmissionDecision, DispatchAction, DispatchFeedback, PressureState, SchedulerDecision,
    WorkerFairnessConfig, WorkerFairnessState,
};

fn enqueue_payload(size: usize) -> Bytes {
    Bytes::from(vec![0xAB; size])
}

#[test]
fn fairness_rejects_when_worker_budget_is_exhausted() {
    let now = Instant::now();
    let mut fairness = WorkerFairnessState::new(
        WorkerFairnessConfig {
            max_total_queued_bytes: 1024,
            max_flow_queued_bytes: 1024,
            ..WorkerFairnessConfig::default()
        },
        now,
    );

    assert_eq!(
        fairness.enqueue_data(1, 0, enqueue_payload(700), now),
        AdmissionDecision::Admit
    );
    assert_eq!(
        fairness.enqueue_data(2, 0, enqueue_payload(400), now),
        AdmissionDecision::RejectWorkerCap
    );

    let snapshot = fairness.snapshot();
    assert!(snapshot.total_queued_bytes <= 1024);
    assert_eq!(snapshot.enqueue_rejects, 1);
}

#[test]
fn fairness_marks_standing_queue_after_stall_and_age_threshold() {
    let mut now = Instant::now();
    let mut fairness = WorkerFairnessState::new(
        WorkerFairnessConfig {
            standing_queue_min_age: Duration::from_millis(50),
            standing_queue_min_backlog_bytes: 256,
            standing_stall_threshold: 1,
            max_flow_queued_bytes: 4096,
            max_total_queued_bytes: 4096,
            ..WorkerFairnessConfig::default()
        },
        now,
    );

    assert_eq!(
        fairness.enqueue_data(11, 0, enqueue_payload(512), now),
        AdmissionDecision::Admit
    );

    now += Duration::from_millis(100);
    let SchedulerDecision::Dispatch(candidate) = fairness.next_decision(now) else {
        panic!("expected dispatch candidate");
    };

    let action = fairness.apply_dispatch_feedback(11, candidate, DispatchFeedback::QueueFull, now);
    assert!(matches!(action, DispatchAction::Continue));

    let snapshot = fairness.snapshot();
    assert_eq!(snapshot.standing_flows, 1);
    assert!(snapshot.backpressured_flows >= 1);
}

#[test]
fn fairness_keeps_fast_flow_progress_under_slow_neighbor() {
    let mut now = Instant::now();
    let mut fairness = WorkerFairnessState::new(
        WorkerFairnessConfig {
            max_total_queued_bytes: 64 * 1024,
            max_flow_queued_bytes: 32 * 1024,
            ..WorkerFairnessConfig::default()
        },
        now,
    );

    for _ in 0..16 {
        assert_eq!(
            fairness.enqueue_data(1, 0, enqueue_payload(512), now),
            AdmissionDecision::Admit
        );
        assert_eq!(
            fairness.enqueue_data(2, 0, enqueue_payload(512), now),
            AdmissionDecision::Admit
        );
    }

    let mut fast_routed = 0u64;
    for _ in 0..128 {
        now += Duration::from_millis(5);
        let SchedulerDecision::Dispatch(candidate) = fairness.next_decision(now) else {
            break;
        };
        let cid = candidate.frame.conn_id;
        let feedback = if cid == 2 {
            DispatchFeedback::QueueFull
        } else {
            fast_routed = fast_routed.saturating_add(1);
            DispatchFeedback::Routed
        };
        let _ = fairness.apply_dispatch_feedback(cid, candidate, feedback, now);
    }

    let snapshot = fairness.snapshot();
    assert!(fast_routed > 0, "fast flow must continue making progress");
    assert!(snapshot.total_queued_bytes <= 64 * 1024);
}

#[test]
fn fairness_prioritizes_quickack_flow_when_weights_enabled() {
    let mut now = Instant::now();
    let mut fairness = WorkerFairnessState::new(
        WorkerFairnessConfig {
            max_total_queued_bytes: 256 * 1024,
            max_flow_queued_bytes: 128 * 1024,
            base_quantum_bytes: 8 * 1024,
            pressured_quantum_bytes: 8 * 1024,
            penalized_quantum_bytes: 8 * 1024,
            default_flow_weight: 1,
            quickack_flow_weight: 4,
            ..WorkerFairnessConfig::default()
        },
        now,
    );

    for _ in 0..8 {
        assert_eq!(
            fairness.enqueue_data(10, RPC_FLAG_QUICKACK, enqueue_payload(16 * 1024), now),
            AdmissionDecision::Admit
        );
        assert_eq!(
            fairness.enqueue_data(20, 0, enqueue_payload(16 * 1024), now),
            AdmissionDecision::Admit
        );
    }

    let mut quickack_dispatched = 0u64;
    let mut bulk_dispatched = 0u64;
    for _ in 0..64 {
        now += Duration::from_millis(1);
        let SchedulerDecision::Dispatch(candidate) = fairness.next_decision(now) else {
            break;
        };

        if candidate.frame.conn_id == 10 {
            quickack_dispatched = quickack_dispatched.saturating_add(1);
        } else if candidate.frame.conn_id == 20 {
            bulk_dispatched = bulk_dispatched.saturating_add(1);
        }

        let _ = fairness.apply_dispatch_feedback(
            candidate.frame.conn_id,
            candidate,
            DispatchFeedback::Routed,
            now,
        );
    }

    assert!(
        quickack_dispatched > bulk_dispatched,
        "quickack flow must receive higher dispatch rate with larger weight"
    );
}

#[test]
fn fairness_pressure_hysteresis_prevents_instant_flapping() {
    let mut now = Instant::now();
    let mut cfg = WorkerFairnessConfig::default();
    cfg.max_total_queued_bytes = 4096;
    cfg.max_flow_queued_bytes = 4096;
    cfg.pressure.evaluate_every_rounds = 1;
    cfg.pressure.transition_hysteresis_rounds = 3;
    cfg.pressure.queue_ratio_pressured_pct = 40;
    cfg.pressure.queue_ratio_shedding_pct = 60;
    cfg.pressure.queue_ratio_saturated_pct = 80;

    let mut fairness = WorkerFairnessState::new(cfg, now);

    for _ in 0..3 {
        assert_eq!(
            fairness.enqueue_data(9, 0, enqueue_payload(900), now),
            AdmissionDecision::Admit
        );
    }

    for _ in 0..2 {
        now += Duration::from_millis(1);
        let _ = fairness.next_decision(now);
    }

    assert_eq!(
        fairness.pressure_state(),
        PressureState::Normal,
        "state must not flip before hysteresis confirmations"
    );
}

#[test]
fn fairness_randomized_sequence_preserves_memory_bounds() {
    let mut now = Instant::now();
    let mut fairness = WorkerFairnessState::new(
        WorkerFairnessConfig {
            max_total_queued_bytes: 32 * 1024,
            max_flow_queued_bytes: 4 * 1024,
            ..WorkerFairnessConfig::default()
        },
        now,
    );

    let mut seed = 0xC0FFEE_u64;
    for _ in 0..4096 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;
        let flow = (seed % 32) + 1;
        let size = ((seed >> 8) % 512 + 64) as usize;
        let _ = fairness.enqueue_data(flow, 0, enqueue_payload(size), now);

        now += Duration::from_millis(1);
        if let SchedulerDecision::Dispatch(candidate) = fairness.next_decision(now) {
            let feedback = if seed & 0x1 == 0 {
                DispatchFeedback::Routed
            } else {
                DispatchFeedback::QueueFull
            };
            let _ =
                fairness.apply_dispatch_feedback(candidate.frame.conn_id, candidate, feedback, now);
        }

        let snapshot = fairness.snapshot();
        let (standing_recomputed, backpressured_recomputed) =
            fairness.debug_recompute_flow_counters(now);
        assert!(snapshot.total_queued_bytes <= 32 * 1024);
        assert_eq!(snapshot.standing_flows, standing_recomputed);
        assert_eq!(snapshot.backpressured_flows, backpressured_recomputed);
        assert!(fairness.debug_check_active_ring_consistency());
        assert!(fairness.debug_max_deficit_bytes() <= 4 * 1024);
    }
}
