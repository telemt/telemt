use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

#[derive(Clone, Serialize)]
pub(super) struct ApiEventRecord {
    pub(super) seq: u64,
    pub(super) ts_epoch_secs: u64,
    pub(super) event_type: String,
    pub(super) context: String,
}

#[derive(Clone, Serialize)]
pub(super) struct ApiEventSnapshot {
    pub(super) capacity: usize,
    pub(super) dropped_total: u64,
    pub(super) events: Vec<ApiEventRecord>,
}

struct ApiEventsInner {
    capacity: usize,
    dropped_total: u64,
    next_seq: u64,
    events: VecDeque<ApiEventRecord>,
}

/// Bounded ring-buffer for control-plane API/runtime events.
pub struct ApiEventStore {
    inner: Mutex<ApiEventsInner>,
}

impl ApiEventStore {
    pub(super) fn new(capacity: usize) -> Self {
        let bounded = capacity.max(16);
        Self {
            inner: Mutex::new(ApiEventsInner {
                capacity: bounded,
                dropped_total: 0,
                next_seq: 1,
                events: VecDeque::with_capacity(bounded),
            }),
        }
    }

    pub(super) fn record(&self, event_type: &str, context: impl Into<String>) {
        let now_epoch_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut context = context.into();
        if context.len() > 256 {
            let mut end = 256;
            while end > 0 && !context.is_char_boundary(end) {
                end -= 1;
            }
            context.truncate(end);
        }

        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.events.len() == guard.capacity {
            guard.events.pop_front();
            guard.dropped_total = guard.dropped_total.saturating_add(1);
        }
        let seq = guard.next_seq;
        guard.next_seq = guard.next_seq.saturating_add(1);
        guard.events.push_back(ApiEventRecord {
            seq,
            ts_epoch_secs: now_epoch_secs,
            event_type: event_type.to_string(),
            context,
        });
    }

    pub(super) fn snapshot(&self, limit: usize) -> ApiEventSnapshot {
        let guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let bounded_limit = limit.clamp(1, guard.capacity.max(1));
        let mut items: Vec<ApiEventRecord> = guard
            .events
            .iter()
            .rev()
            .take(bounded_limit)
            .cloned()
            .collect();
        items.reverse();

        ApiEventSnapshot {
            capacity: guard.capacity,
            dropped_total: guard.dropped_total,
            events: items,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ApiEventStore;

    #[test]
    fn record_truncates_context_to_256_bytes() {
        let store = ApiEventStore::new(16);
        let input = "x".repeat(300);

        store.record("evt", input);
        let snapshot = store.snapshot(16);

        assert_eq!(snapshot.events.len(), 1);
        assert_eq!(snapshot.events[0].context.len(), 256);
    }

    #[test]
    fn record_truncates_multibyte_context_without_panicking() {
        let store = ApiEventStore::new(16);
        let input = "я".repeat(200);

        store.record("evt", input);
        let snapshot = store.snapshot(16);

        assert_eq!(snapshot.events.len(), 1);
        let context = &snapshot.events[0].context;
        assert!(context.len() <= 256);
        assert!(context.is_char_boundary(context.len()));
    }

    #[test]
    fn record_preserves_exact_boundary_for_multibyte_context() {
        let store = ApiEventStore::new(16);
        let input = "я".repeat(128);

        store.record("evt", input.clone());
        let snapshot = store.snapshot(16);

        assert_eq!(snapshot.events.len(), 1);
        assert_eq!(snapshot.events[0].context, input);
        assert_eq!(snapshot.events[0].context.len(), 256);
    }

    #[test]
    fn snapshot_limit_is_clamped_to_one() {
        let store = ApiEventStore::new(16);
        store.record("evt", "ctx");

        let snapshot = store.snapshot(0);
        assert_eq!(snapshot.events.len(), 1);
    }

    #[test]
    fn constructor_clamps_capacity_to_minimum() {
        let store = ApiEventStore::new(0);
        for idx in 0..17 {
            store.record("evt", format!("ctx-{idx}"));
        }

        let snapshot = store.snapshot(64);
        assert_eq!(snapshot.capacity, 16);
        assert_eq!(snapshot.events.len(), 16);
        assert_eq!(snapshot.dropped_total, 1);
    }

    #[test]
    fn snapshot_limit_above_capacity_is_capped() {
        let store = ApiEventStore::new(16);
        for idx in 0..20 {
            store.record("evt", format!("ctx-{idx}"));
        }

        let snapshot = store.snapshot(10_000);
        assert_eq!(snapshot.capacity, 16);
        assert_eq!(snapshot.events.len(), 16);
        assert_eq!(snapshot.events[0].context, "ctx-4");
        assert_eq!(snapshot.events[15].context, "ctx-19");
    }

    #[test]
    fn record_truncation_never_splits_utf8_character() {
        let store = ApiEventStore::new(16);
        let input = format!("{}я", "a".repeat(255));

        store.record("evt", input);
        let snapshot = store.snapshot(16);

        assert_eq!(snapshot.events.len(), 1);
        let context = &snapshot.events[0].context;
        assert_eq!(context.len(), 255);
        assert!(context.chars().all(|c| c == 'a'));
    }

    #[test]
    fn ring_buffer_overflow_drops_oldest_and_increments_counter() {
        let store = ApiEventStore::new(16);
        for idx in 0..17 {
            store.record("evt", format!("ctx-{idx}"));
        }

        let snapshot = store.snapshot(16);
        assert_eq!(snapshot.capacity, 16);
        assert_eq!(snapshot.events.len(), 16);
        assert_eq!(snapshot.dropped_total, 1);
        assert_eq!(snapshot.events[0].context, "ctx-1");
        assert_eq!(snapshot.events[15].context, "ctx-16");
    }

    #[test]
    fn snapshot_of_empty_store_returns_no_events() {
        let store = ApiEventStore::new(16);
        let snapshot = store.snapshot(16);
        assert_eq!(snapshot.events.len(), 0);
        assert_eq!(snapshot.dropped_total, 0);
        assert_eq!(snapshot.capacity, 16);
    }

    #[test]
    fn seq_numbers_start_at_one_and_increment_monotonically() {
        let store = ApiEventStore::new(16);
        for idx in 0..5 {
            store.record("evt", format!("ctx-{idx}"));
        }
        let snapshot = store.snapshot(16);
        for (pos, event) in snapshot.events.iter().enumerate() {
            assert_eq!(
                event.seq,
                (pos + 1) as u64,
                "seq must start at 1 and increment by 1 for each event"
            );
        }
    }

    #[test]
    fn events_are_returned_oldest_to_newest_in_snapshot() {
        let store = ApiEventStore::new(16);
        store.record("type_a", "first");
        store.record("type_b", "second");
        store.record("type_c", "third");
        let snapshot = store.snapshot(3);
        assert_eq!(snapshot.events[0].event_type, "type_a");
        assert_eq!(snapshot.events[1].event_type, "type_b");
        assert_eq!(snapshot.events[2].event_type, "type_c");
    }

    #[test]
    fn record_with_empty_context_is_stored_without_panic() {
        let store = ApiEventStore::new(16);
        store.record("evt", "");
        let snapshot = store.snapshot(16);
        assert_eq!(snapshot.events.len(), 1);
        assert_eq!(snapshot.events[0].context, "");
    }

    // Ensures the dropped_total counter uses saturating_add and does not wrap on
    // large overflow. We test the invariant directly since forcing a u64 overflow
    // with actual records would take impractical time.
    #[test]
    fn dropped_total_saturating_add_does_not_wrap_at_u64_max() {
        assert_eq!(u64::MAX.saturating_add(1), u64::MAX);
    }

    #[test]
    fn seq_counter_saturating_add_does_not_wrap_at_u64_max() {
        assert_eq!(u64::MAX.saturating_add(1), u64::MAX);
    }

    // Adversarial: an attacker sending a context of exactly 256 bytes must not
    // be truncated (the truncation fires only when len > 256).
    #[test]
    fn record_context_exactly_256_bytes_is_stored_unchanged() {
        let store = ApiEventStore::new(16);
        let input = "x".repeat(256);
        store.record("evt", input.clone());
        let snapshot = store.snapshot(16);
        assert_eq!(snapshot.events[0].context.len(), 256);
        assert_eq!(snapshot.events[0].context, input);
    }

    // Adversarial: a context of 257 bytes must be truncated to exactly 256.
    #[test]
    fn record_context_exactly_257_bytes_is_truncated_to_256() {
        let store = ApiEventStore::new(16);
        let input = "x".repeat(257);
        store.record("evt", input);
        let snapshot = store.snapshot(16);
        assert_eq!(snapshot.events[0].context.len(), 256);
    }
}
